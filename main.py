from fastapi import FastAPI, HTTPException, Depends, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import Optional
import json, time

SECRET_KEY = "kitisekretokkkkk"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 60 * 60 * 24

app = FastAPI()

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

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
ouath_scheme = OAuth2PasswordBearer(tokenUrl="/token")

users_file = "users.json"
tasks_file = "tasks.json"

try:
    with open(users_file, "r") as f:
        users = json.load(f)
except:
    users = {}

try:
    with open(tasks_file, "r") as f:
        tasks = json.load(f)
except:
    tasks = []

class Task(BaseModel):
    id: int
    title: str
    done: bool = False

class User(BaseModel):
    username: str
    password: str

def save_users():
    with open(users_file, "w") as f:
        json.dump(users, f)

def save_tasks():
    with open(tasks_file, "w") as f:
        json.dump(tasks, f)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(username, password):
    if username == "admin":
        return password == "admin123"
    if username in users and verify_password(password, users[username]["password"]):
        return True
    return False

def create_token(username):
    data = {"sub": username, "exp": time.time() + ACCESS_TOKEN_EXPIRE_SECONDS}
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(ouath_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if authenticate_user(form_data.username, form_data.password):
        token = create_token(form_data.username)
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=400, detail="Credenciais inválidas")

@app.post("/register")
def register(user: User):
    if user.username == "admin":
        raise HTTPException(status_code=403, detail="Não pode registrar admin")
    if user.username in users:
        raise HTTPException(status_code=400, detail="Usuário já existe")
    users[user.username] = {"password": get_password_hash(user.password)}
    save_users()
    return {"message": "Registrado"}

@app.get("/tasks")
def get_tasks(username: str = Depends(get_current_user)):
    return [t for t in tasks if t["user"] == username]

@app.post("/tasks")
def add_task(task: Task, username: str = Depends(get_current_user)):
    task.id = int(time.time() * 1000)
    tasks.append({"id": task.id, "title": task.title, "done": task.done, "user": username})
    save_tasks()
    return {"message": "Tarefa adicionada"}

@app.patch("/tasks/{task_id}")
def toggle(task_id: int, data: dict, username: str = Depends(get_current_user)):
    for t in tasks:
        if t["id"] == task_id and t["user"] == username:
            t["done"] = data.get("done", False)
            save_tasks()
            return {"message": "Atualizado"}
    raise HTTPException(status_code=404, detail="Tarefa não encontrada")

@app.delete("/tasks/{task_id}")
def delete(task_id: int, username: str = Depends(get_current_user)):
    global tasks
    tasks = [t for t in tasks if not (t["id"] == task_id and t["user"] == username)]
    save_tasks()
    return {"message": "Deletado"}
