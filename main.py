import json
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import List, Optional
from jose import JWTError, jwt
from datetime import datetime, timedelta
from pathlib import Path

app = FastAPI()

SECRET_KEY = "segredo_muito_top"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

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
        json.dump(data, f, indent=2, ensure_ascii=False)

class UserIn(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class Task(BaseModel):
    title: str
    done: bool = False

class TaskOut(Task):
    id: int

class TaskUpdate(BaseModel):
    title: Optional[str] = None
    done: Optional[bool] = None

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
    if not user or not verify_password(password, user["hashed_password"]):
        return False
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="token inválido")
    except JWTError:
        raise HTTPException(status_code=401, detail="token inválido")
    user = get_user(username)
    if user is None:
        raise HTTPException(status_code=401, detail="usuário não encontrado")
    return username

def require_admin(user: str = Depends(get_current_user), token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if not payload.get("admin", False):
            raise HTTPException(status_code=403, detail="acesso de admin necessário")
    except JWTError:
        raise HTTPException(status_code=403, detail="token inválido")
    return user

origins = [
    "https://kiti.dev",
    "http://localhost:5500"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/register")
def register(user_in: UserIn):
    users = load_json(USERS_FILE)
    if user_in.username in users:
        raise HTTPException(status_code=400, detail="username já existe")
    is_admin = user_in.username == "admin"
    users[user_in.username] = {
        "hashed_password": get_password_hash(user_in.password),
        "is_admin": is_admin
    }
    save_json(USERS_FILE, users)

    tasks = load_json(TASKS_FILE)
    tasks[user_in.username] = []
    save_json(TASKS_FILE, tasks)

    return {"msg": "usuário criado com sucesso"}

@app.post("/token", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form.username, form.password)
    if not user:
        raise HTTPException(status_code=401, detail="usuário ou senha inválidos")

    token = create_access_token({
        "sub": form.username,
        "admin": user.get("is_admin", False)
    }, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": token, "token_type": "bearer"}

@app.get("/tasks", response_model=List[TaskOut])
def get_tasks(current_user: str = Depends(get_current_user)):
    tasks = load_json(TASKS_FILE)
    return tasks.get(current_user, [])

@app.post("/tasks", response_model=TaskOut)
def create_task(task: Task, current_user: str = Depends(get_current_user)):
    tasks = load_json(TASKS_FILE)
    user_tasks = tasks.get(current_user, [])

    next_id = max([t["id"] for t in user_tasks], default=0) + 1
    new_task = {
        "id": next_id,
        "title": task.title,
        "done": task.done
    }
    user_tasks.append(new_task)
    tasks[current_user] = user_tasks
    save_json(TASKS_FILE, tasks)
    return new_task

@app.patch("/tasks/{task_id}")
def update_task(task_id: int, task_update: TaskUpdate, current_user: str = Depends(get_current_user)):
    tasks = load_json(TASKS_FILE)
    user_tasks = tasks.get(current_user, [])
    for t in user_tasks:
        if t["id"] == task_id:
            if task_update.title is not None:
                t["title"] = task_update.title
            if task_update.done is not None:
                t["done"] = task_update.done
            save_json(TASKS_FILE, tasks)
            return {"message": "tarefa atualizada", "task": t}
    raise HTTPException(status_code=404, detail="tarefa não encontrada")

@app.delete("/tasks/{task_id}")
def delete_task(task_id: int, current_user: str = Depends(get_current_user)):
    tasks = load_json(TASKS_FILE)
    user_tasks = tasks.get(current_user, [])
    new_tasks = [t for t in user_tasks if t["id"] != task_id]
    if len(new_tasks) == len(user_tasks):
        raise HTTPException(status_code=404, detail="tarefa não encontrada")
    tasks[current_user] = new_tasks
    save_json(TASKS_FILE, tasks)
    return {"message": f"tarefa #{task_id} deletada"}

@app.get("/admin/users")
def get_all_users(admin: str = Depends(require_admin)):
    users = load_json(USERS_FILE)
    return list(users.keys())

@app.get("/admin/tasks")
def get_all_tasks(admin: str = Depends(require_admin)):
    return load_json(TASKS_FILE)
