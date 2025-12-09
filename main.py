from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext

app = FastAPI(title="FastAPI + JWT Demo")

# ================== Configuration Section ==================

SECRET_KEY = "change_me_to_a_random_long_string"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # Token time 60 

# Password hashing tool
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# The token is obtained through the /login interface
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# ================== Pydantic Model ==================
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


# ================== Database ==================
fake_users_db: Dict[str, UserInDB] = {}
next_user_id = 1

fake_todos_db: Dict[int, List[dict]] = {}


# ================== Utility function ==================
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
    data  {"sub": username}
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


# ================== Dependency: Take the current user from the token ==================
async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Decoding token
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


# ================== Registration & Login ==================
@app.post("/register", response_model=User)
def register(user_in: UserIn):
    """
    Registration interface
    - Check if the username already exists
    - Store the hash of the password
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
    Login interface：
    -  username, password
    - turn back access_token
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
        data={"sub": user.username},  # Put the username in here, and it can be read out from the token later
        expires_delta=access_token_expires,
    )

    return Token(access_token=access_token, token_type="bearer")


# ================== Use the currently logged-in user ==================
@app.get("/users/me", response_model=User)
async def read_users_me(current_user: UserInDB = Depends(get_current_user)):
    """
    Update information
    """
    return User(
        id=current_user.id,
        username=current_user.username,
        full_name=current_user.full_name,
    )


# Update the information of the currently logged-in user
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


# ================== Use the current user as todo (instead of /users/{user_id}/todos) ==================
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
    Create the todo of the currently logged-in user
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
    Obtain all Todos of the currently logged-in user
    """
    user_id = current_user.id
    todos = fake_todos_db.get(user_id, [])
    return [Todo(**t) for t in todos]
