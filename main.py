from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from typing import Optional
import json
import os

app = FastAPI()

# CORS
origins = ["https://kiti.dev", "http://localhost:5500"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# admin fixo (user + senha hash)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = "$2b$12$TmLyV/RjQyxTR1qGqxw2auUw6H7jL3CRxMY2dBfiC1mT2fQo8ZbGq"  # hash de "supersecreta"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT config
SECRET_KEY = "umsegredomuitoseguroquenaoseidevender"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60*24*7  # 7 dias

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

USERS_FILE = "users.json"

# Modelos
class UserIn(BaseModel):
    username: str
    password: str

class UserOut(BaseModel):
    username: str

class Token(BaseModel):
    access_token: str
    token_type: str

# Helpers
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def load_users():
    if not os.path.isfile(USERS_FILE):
        return {}
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)

def authenticate_admin(username: str, password: str):
    if username == ADMIN_USERNAME and verify_password(password, ADMIN_PASSWORD_HASH):
        return True
    return False

def authenticate_user(username: str, password: str):
    users = load_users()
    if username in users and verify_password(password, users[username]["password"]):
        return True
    return False

def create_access_token(data: dict):
    from datetime import datetime, timedelta
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="token inválido ou expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        is_admin = payload.get("admin", False)
    except JWTError:
        raise credentials_exception
    return {"username": username, "admin": is_admin}

async def get_admin_user(current_user=Depends(get_current_user)):
    if not current_user["admin"]:
        raise HTTPException(status_code=403, detail="não autorizado, só admin pode")
    return current_user

# Rotas

@app.post("/register")
def register(user: UserIn):
    if user.username == ADMIN_USERNAME:
        raise HTTPException(status_code=400, detail="esse usuário é reservado")
    users = load_users()
    if user.username in users:
        raise HTTPException(status_code=400, detail="usuário já existe")
    hashed = get_password_hash(user.password)
    users[user.username] = {"password": hashed}
    save_users(users)
    return {"msg": "usuário registrado"}

@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # admin check
    if authenticate_admin(form_data.username, form_data.password):
        access_token = create_access_token(data={"sub": ADMIN_USERNAME, "admin": True})
        return {"access_token": access_token, "token_type": "bearer"}

    # user check
    if authenticate_user(form_data.username, form_data.password):
        access_token = create_access_token(data={"sub": form_data.username, "admin": False})
        return {"access_token": access_token, "token_type": "bearer"}

    raise HTTPException(status_code=400, detail="usuário ou senha inválidos")

# Agora o sistema de tarefas que todo mundo pode mexer

tasks = {}  # key = username, value = list of tasks
task_id_counter = 1

class TaskIn(BaseModel):
    title: str
    done: Optional[bool] = False

class TaskOut(TaskIn):
    id: int

@app.get("/tasks", response_model=list[TaskOut])
async def get_tasks(current_user=Depends(get_current_user)):
    user = current_user["username"]
    user_tasks = tasks.get(user, [])
    return user_tasks

@app.post("/tasks", response_model=TaskOut)
async def create_task(task: TaskIn, current_user=Depends(get_current_user)):
    global task_id_counter
    user = current_user["username"]
    new_task = {"id": task_id_counter, "title": task.title, "done": task.done}
    task_id_counter += 1
    if user not in tasks:
        tasks[user] = []
    tasks[user].append(new_task)
    return new_task

@app.patch("/tasks/{task_id}", response_model=TaskOut)
async def update_task(task_id: int, task: TaskIn, current_user=Depends(get_current_user)):
    user = current_user["username"]
    user_tasks = tasks.get(user, [])
    for t in user_tasks:
        if t["id"] == task_id:
            t["title"] = task.title
            t["done"] = task.done
            return t
    raise HTTPException(status_code=404, detail="tarefa não encontrada")

@app.delete("/tasks/{task_id}")
async def delete_task(task_id: int, current_user=Depends(get_current_user)):
    user = current_user["username"]
    user_tasks = tasks.get(user, [])
    tasks[user] = [t for t in user_tasks if t["id"] != task_id]
    return {"msg": "tarefa deletada"}

# Rota só pro admin ver o painel

@app.get("/adminpanel")
async def admin_panel(user=Depends(get_admin_user)):
    # só um json fake pra mostrar que só admin vê
    return {"msg": "Bem-vindo ao painel admin, rei " + user["username"]}

