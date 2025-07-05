from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel
from typing import List, Optional
from passlib.context import CryptContext
from jose import JWTError, jwt
import json
import os
import shutil

app = FastAPI()

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

# segurança
SECRET_KEY = "supersecretkeyquenaodeveficarestaqui"  # troca depois
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 dias

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

USERS_FILE = "users.json"
TASKS_FILE = "tasks.json"

# helpers pra carregar e salvar json

def load_json(file_path, default):
    if not os.path.exists(file_path):
        with open(file_path, "w") as f:
            json.dump(default, f)
    with open(file_path, "r") as f:
        return json.load(f)

def save_json(file_path, data):
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

# Models

class User(BaseModel):
    username: str
    password: str

class UserInDB(User):
    hashed_password: str
    admin: bool = False

class Token(BaseModel):
    access_token: str
    token_type: str

class Task(BaseModel):
    id: int
    title: str
    done: bool = False
    owner: str

class TaskCreate(BaseModel):
    title: str
    done: Optional[bool] = False

# Segurança e Auth

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(username: str) -> Optional[dict]:
    users = load_json(USERS_FILE, [])
    for u in users:
        if u["username"] == username:
            return u
    return None

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user["password"]):
        return False
    return user

from datetime import datetime, timedelta

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=401, detail="Token inválido ou expirado", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_admin(user: dict = Depends(get_current_user)):
    if not user.get("admin", False):
        raise HTTPException(status_code=403, detail="Só admin pode aqui, maluco")
    return user

# API

@app.post("/register")
def register(user: User):
    users = load_json(USERS_FILE, [])
    if any(u["username"] == user.username for u in users):
        raise HTTPException(status_code=400, detail="usuário já existe")
    hashed_pw = get_password_hash(user.password)
    users.append({"username": user.username, "password": hashed_pw, "admin": False})
    save_json(USERS_FILE, users)
    return {"msg": "registrado com sucesso, agora faz login"}

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Usuário ou senha inválidos")
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

# tarefas

@app.get("/tasks", response_model=List[Task])
async def get_tasks(user: dict = Depends(get_current_user)):
    tasks = load_json(TASKS_FILE, [])
    return [t for t in tasks if t["owner"] == user["username"]]

@app.post("/tasks", response_model=Task)
async def create_task(task: TaskCreate, user: dict = Depends(get_current_user)):
    tasks = load_json(TASKS_FILE, [])
    new_id = max([t["id"] for t in tasks], default=0) + 1
    new_task = {"id": new_id, "title": task.title, "done": task.done, "owner": user["username"]}
    tasks.append(new_task)
    save_json(TASKS_FILE, tasks)
    return new_task

@app.patch("/tasks/{task_id}", response_model=Task)
async def update_task(task_id: int, task: TaskCreate, user: dict = Depends(get_current_user)):
    tasks = load_json(TASKS_FILE, [])
    for t in tasks:
        if t["id"] == task_id and t["owner"] == user["username"]:
            t["title"] = task.title
            t["done"] = task.done
            save_json(TASKS_FILE, tasks)
            return t
    raise HTTPException(status_code=404, detail="tarefa não encontrada")

@app.delete("/tasks/{task_id}")
async def delete_task(task_id: int, user: dict = Depends(get_current_user)):
    tasks = load_json(TASKS_FILE, [])
    new_tasks = [t for t in tasks if not (t["id"] == task_id and t["owner"] == user["username"])]
    if len(new_tasks) == len(tasks):
        raise HTTPException(status_code=404, detail="tarefa não encontrada")
    save_json(TASKS_FILE, new_tasks)
    return {"msg": "tarefa deletada"}

# backup admin

@app.get("/admin/backup")
async def export_backup(admin: dict = Depends(get_current_admin)):
    files = {}
    for f in [USERS_FILE, TASKS_FILE]:
        if os.path.exists(f):
            with open(f, "rb") as file:
                files[f] = file.read()
    return files  # aqui pode trocar pra zip se quiser (mais complexo)

@app.post("/admin/backup/import")
async def import_backup(file: UploadFile = File(...), admin: dict = Depends(get_current_admin)):
    # salva arquivo enviado (esperando zip ou json) - pra simplificar aceita só json
    content = await file.read()
    data = json.loads(content)
    # tem que validar o json antes de substituir os arquivos, mas isso é básico
    if "users.json" in file.filename:
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            f.write(json.dumps(data, indent=2, ensure_ascii=False))
        return {"msg": "backup de usuários importado"}
    elif "tasks.json" in file.filename:
        with open(TASKS_FILE, "w", encoding="utf-8") as f:
            f.write(json.dumps(data, indent=2, ensure_ascii=False))
        return {"msg": "backup de tarefas importado"}
    else:
        raise HTTPException(status_code=400, detail="arquivo inválido")

