from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional, List
from passlib.context import CryptContext
from jose import JWTError, jwt
import json
from datetime import datetime, timedelta
import os

app = FastAPI()

# CORS (libera acesso do frontend)
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

# secret pros tokens
SECRET_KEY = "esseéumsegredomuitoseguro!"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# pwd hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# admin hardcoded
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "senha123"  # troca essa senha aqui

# usuários comuns ficam num json
USERS_FILE = "users.json"

def get_users():
    if not os.path.isfile(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_admin(username: str, password: str):
    return username == ADMIN_USERNAME and password == ADMIN_PASSWORD

def authenticate_user(username: str, password: str):
    users = get_users()
    if username not in users:
        return False
    if not verify_password(password, users[username]["password"]):
        return False
    return User(username=username)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str

class UserIn(BaseModel):
    username: str
    password: str

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    if authenticate_admin(form_data.username, form_data.password):
        access_token = create_access_token(data={"sub": ADMIN_USERNAME})
        return {"access_token": access_token, "token_type": "bearer"}

    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Usuário ou senha inválidos")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/register")
async def register(user_in: UserIn):
    users = get_users()
    if user_in.username == ADMIN_USERNAME:
        raise HTTPException(status_code=400, detail="Não pode registrar com esse usuário")
    if user_in.username in users:
        raise HTTPException(status_code=400, detail="Usuário já existe")
    hashed = get_password_hash(user_in.password)
    users[user_in.username] = {"password": hashed}
    save_users(users)
    return {"msg": "Registrado com sucesso"}

# modelo da tarefa
class Task(BaseModel):
    id: int
    title: str
    done: bool = False
    owner: str

tasks = []

@app.get("/tasks", response_model=List[Task])
async def get_tasks(token: str = Depends(oauth2_scheme)):
    payload = None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")
    username = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=401, detail="Token inválido")

    # admin vê tudo
    if username == ADMIN_USERNAME:
        return tasks

    # usuário normal só vê as próprias tarefas
    return [t for t in tasks if t.owner == username]

@app.post("/tasks")
async def create_task(task: Task, token: str = Depends(oauth2_scheme)):
    payload = None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")
    username = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=401, detail="Token inválido")

    if any(t.id == task.id for t in tasks):
        raise HTTPException(status_code=400, detail="ID já existe")

    # garante dono certo
    task.owner = username
    tasks.append(task)
    return {"msg": "Tarefa criada"}

@app.patch("/tasks/{task_id}")
async def update_task(task_id: int, done: bool, token: str = Depends(oauth2_scheme)):
    payload = None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")
    username = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=401, detail="Token inválido")

    for t in tasks:
        if t.id == task_id:
            if username != ADMIN_USERNAME and t.owner != username:
                raise HTTPException(status_code=403, detail="Sem permissão")
            t.done = done
            return {"msg": "Atualizado"}
    raise HTTPException(status_code=404, detail="Tarefa não encontrada")

@app.delete("/tasks/{task_id}")
async def delete_task(task_id: int, token: str = Depends(oauth2_scheme)):
    payload = None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")
    username = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=401, detail="Token inválido")

    global tasks
    for t in tasks:
        if t.id == task_id:
            if username != ADMIN_USERNAME and t.owner != username:
                raise HTTPException(status_code=403, detail="Sem permissão")
            tasks = [task for task in tasks if task.id != task_id]
            return {"msg": "Deletado"}
    raise HTTPException(status_code=404, detail="Tarefa não encontrada")
