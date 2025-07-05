from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List
import json, zipfile, os
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta

SECRET_KEY = "kiti_super_secreta"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

origins = [
    "http://localhost:5500",
    "https://kiti.dev",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class Task(BaseModel):
    id: int
    title: str
    done: bool = False
    user: str = ""

class TaskIn(BaseModel):
    title: str
    done: bool = False

class User(BaseModel):
    username: str
    password: str

def load_data(file):
    try:
        with open(file, "r") as f:
            return json.load(f)
    except:
        return []

def save_data(file, data):
    with open(file, "w") as f:
        json.dump(data, f, indent=2)

def get_user(username: str):
    users = load_data("users.json")
    return next((u for u in users if u["username"] == username), None)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(p):
    return pwd_context.hash(p)

def create_access_token(data: dict, expires_delta=None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401)
        user = get_user(username)
        if user is None:
            raise HTTPException(status_code=401)
        return user
    except JWTError:
        raise HTTPException(status_code=401)

async def get_current_admin(user=Depends(get_current_user)):
    if not user.get("admin", False):
        raise HTTPException(status_code=403, detail="acesso restrito")
    return user

TASKS_FILE = "tasks.json"
USERS_FILE = "users.json"

@app.post("/register")
def register(user: User):
    users = load_data(USERS_FILE)
    if any(u["username"] == user.username for u in users):
        raise HTTPException(status_code=400, detail="usuário já existe")
    users.append({
        "username": user.username,
        "password": get_password_hash(user.password),
        "admin": False
    })
    save_data(USERS_FILE, users)
    return {"message": "registrado"}

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(form_data.username)
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=400, detail="credenciais inválidas")
    token = create_access_token(data={"sub": user["username"], "admin": user.get("admin", False)},
                                expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": token, "token_type": "bearer"}

@app.get("/tasks")
def get_tasks(user=Depends(get_current_user)):
    tasks = load_data(TASKS_FILE)
    return [t for t in tasks if t["user"] == user["username"]]

@app.post("/tasks")
def add_task(task: TaskIn, user=Depends(get_current_user)):
    tasks = load_data(TASKS_FILE)
    new_id = (max([t["id"] for t in tasks]) + 1) if tasks else 1
    new_task = {"id": new_id, "title": task.title, "done": task.done, "user": user["username"]}
    tasks.append(new_task)
    save_data(TASKS_FILE, tasks)
    return new_task

@app.patch("/tasks/{task_id}")
def update_task(task_id: int, task: TaskIn, user=Depends(get_current_user)):
    tasks = load_data(TASKS_FILE)
    for t in tasks:
        if t["id"] == task_id and t["user"] == user["username"]:
            t["title"], t["done"] = task.title, task.done
            save_data(TASKS_FILE, tasks)
            return t
    raise HTTPException(status_code=404)

@app.delete("/tasks/{task_id}")
def delete_task(task_id: int, user=Depends(get_current_user)):
    tasks = load_data(TASKS_FILE)
    tasks = [t for t in tasks if not (t["id"] == task_id and t["user"] == user["username"])]
    save_data(TASKS_FILE, tasks)
    return {"message": "apagado"}

@app.get("/backup")
def download_backup(admin=Depends(get_current_admin)):
    with zipfile.ZipFile("backup.zip", "w") as zipf:
        zipf.write(TASKS_FILE)
        zipf.write(USERS_FILE)
    return FileResponse("backup.zip", filename="kiti-backup.zip")

@app.post("/import")
def import_backup(file: UploadFile = File(...), admin=Depends(get_current_admin)):
    with open("import.zip", "wb") as f:
        f.write(file.file.read())
    with zipfile.ZipFile("import.zip", "r") as zipf:
        zipf.extractall()
    return {"message": "importado com sucesso"}
