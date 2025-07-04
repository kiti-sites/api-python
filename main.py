import json
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import List, Optional
from jose import JWTError, jwt
from datetime import datetime, timedelta
from pathlib import Path

app = FastAPI()

# configs token
SECRET_KEY = "supersecreto123"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

USERS_FILE = Path("users.json")
TASKS_FILE = Path("tasks.json")

def load_json(file_path):
    if not file_path.exists():
        return {}
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(file_path, data):
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

# modelos
class UserIn(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class Task(BaseModel):
    id: int
    title: str
    done: bool = False

class TaskUpdate(BaseModel):
    done: Optional[bool] = None
    title: Optional[str] = None

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(username: str):
    users = load_json(USERS_FILE)
    return users.get(username)

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_ex = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="não autorizado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_ex
    except JWTError:
        raise credentials_ex
    user = get_user(username)
    if user is None:
        raise credentials_ex
    return username

# CORS
origins = [
    "https://kiti.dev",
    "http://localhost:5500",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# rotas
@app.post("/register")
def register(user_in: UserIn):
    users = load_json(USERS_FILE)
    if user_in.username in users:
        raise HTTPException(status_code=400, detail="username já existe")
    hashed = get_password_hash(user_in.password)
    users[user_in.username] = {"hashed_password": hashed}
    save_json(USERS_FILE, users)
    tasks = load_json(TASKS_FILE)
    tasks[user_in.username] = []
    save_json(TASKS_FILE, tasks)
    return {"msg": "usuário criado"}

@app.post("/token", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form.username, form.password)
    if not user:
        raise HTTPException(status_code=400, detail="usuário ou senha inválidos")
    token = create_access_token({"sub": form.username}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": token, "token_type": "bearer"}

@app.get("/tasks", response_model=List[Task])
def get_tasks(current_user: str = Depends(get_current_user)):
    tasks = load_json(TASKS_FILE)
    return tasks.get(current_user, [])

@app.post("/tasks")
def create_task(task: Task, current_user: str = Depends(get_current_user)):
    tasks = load_json(TASKS_FILE)
    user_tasks = tasks.get(current_user, [])
    if any(t["id"] == task.id for t in user_tasks):
        raise HTTPException(status_code=400, detail="id já existe, doido!")
    user_tasks.append(task.dict())
    tasks[current_user] = user_tasks
    save_json(TASKS_FILE, tasks)
    return {"message": "tarefa criada", "task": task}

@app.delete("/tasks/{task_id}")
def delete_task(task_id: int, current_user: str = Depends(get_current_user)):
    tasks = load_json(TASKS_FILE)
    user_tasks = tasks.get(current_user, [])
    new_tasks = [t for t in user_tasks if t["id"] != task_id]
    if len(new_tasks) == len(user_tasks):
        raise HTTPException(status_code=404, detail="tarefa não encontrada")
    tasks[current_user] = new_tasks
    save_json(TASKS_FILE, tasks)
    return {"message": f"tarefa com id {task_id} deletada"}

@app.patch("/tasks/{task_id}")
def update_task(task_id: int, task_update: TaskUpdate, current_user: str = Depends(get_current_user)):
    tasks = load_json(TASKS_FILE)
    user_tasks = tasks.get(current_user, [])
    for t in user_tasks:
        if t["id"] == task_id:
            if task_update.done is not None:
                t["done"] = task_update.done
            if task_update.title is not None:
                t["title"] = task_update.title
            tasks[current_user] = user_tasks
            save_json(TASKS_FILE, tasks)
            return {"message": "tarefa atualizada", "task": t}
    raise HTTPException(status_code=404, detail="tarefa não encontrada")
