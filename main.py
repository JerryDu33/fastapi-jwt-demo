from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext

app = FastAPI(title="FastAPI + JWT Demo")

# ================== 配置部分 ==================
# 实际项目中，请把 SECRET_KEY 换成一个很长很随机的字符串，并放到环境变量里
SECRET_KEY = "change_me_to_a_random_long_string"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # Token 有效时间 60 分钟

# 密码哈希工具
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 告诉 FastAPI：我们的 token 是通过 /login 接口获取的
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# ================== Pydantic 模型 ==================
class UserIn(BaseModel):
    username: str
    full_name: Optional[str] = None
    password: str


class User(BaseModel):
    id: int
    username: str
    full_name: Optional[str] = None


class UserInDB(User):
    hashed_password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


# ================== 假装的数据库（内存） ==================
fake_users_db: Dict[str, UserInDB] = {}
next_user_id = 1

fake_todos_db: Dict[int, List[dict]] = {}


# ================== 工具函数 ==================
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def get_user_by_username(username: str) -> Optional[UserInDB]:
    return fake_users_db.get(username)


def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    user = get_user_by_username(username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    data 通常会包含 {"sub": username}
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# ================== 依赖：从 token 中拿当前用户 ==================
async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # 解码 token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception

    user = get_user_by_username(token_data.username)
    if user is None:
        raise credentials_exception
    return user


# ================== 注册 & 登录 ==================
@app.post("/register", response_model=User)
def register(user_in: UserIn):
    """
    注册接口：
    - 检查用户名是否已存在
    - 存储 hash 后的密码
    """
    global next_user_id

    if user_in.username in fake_users_db:
        raise HTTPException(status_code=400, detail="Username already registered.")

    hashed_pw = get_password_hash(user_in.password)
    user = UserInDB(
        id=next_user_id,
        username=user_in.username,
        full_name=user_in.full_name,
        hashed_password=hashed_pw,
    )
    fake_users_db[user_in.username] = user
    next_user_id += 1

    return User(id=user.id, username=user.username, full_name=user.full_name)


@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    登录接口：
    - 使用表单字段 username, password
    - 成功后返回 access_token
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username},  # 这里把 username 放进去，之后可从 token 里读出来
        expires_delta=access_token_expires,
    )

    return Token(access_token=access_token, token_type="bearer")


# ================== 示例接口：使用当前登录用户 ==================
@app.get("/users/me", response_model=User)
async def read_users_me(current_user: UserInDB = Depends(get_current_user)):
    """
    获取当前登录用户信息
    """
    return User(
        id=current_user.id,
        username=current_user.username,
        full_name=current_user.full_name,
    )


# 更新当前登录用户信息
class UserUpdate(BaseModel):
    full_name: Optional[str] = None


@app.put("/users/me", response_model=User)
async def update_me(
    update_data: UserUpdate,
    current_user: UserInDB = Depends(get_current_user),
):
    if update_data.full_name is not None:
        current_user.full_name = update_data.full_name
        fake_users_db[current_user.username] = current_user

    return User(
        id=current_user.id,
        username=current_user.username,
        full_name=current_user.full_name,
    )


# ================== 示例：用当前用户做 todo（代替 /users/{user_id}/todos） ==================
class TodoIn(BaseModel):
    content: str


class Todo(BaseModel):
    id: int
    content: str


@app.post("/todos", response_model=Todo)
async def create_todo(
    todo_in: TodoIn,
    current_user: UserInDB = Depends(get_current_user),
):
    """
    创建当前登录用户的 todo
    """
    user_id = current_user.id
    if user_id not in fake_todos_db:
        fake_todos_db[user_id] = []

    new_id = len(fake_todos_db[user_id]) + 1
    todo = {"id": new_id, "content": todo_in.content}
    fake_todos_db[user_id].append(todo)
    return Todo(**todo)


@app.get("/todos", response_model=list[Todo])
async def list_todos(
    current_user: UserInDB = Depends(get_current_user),
):
    """
    获取当前登录用户的所有 todo
    """
    user_id = current_user.id
    todos = fake_todos_db.get(user_id, [])
    return [Todo(**t) for t in todos]
