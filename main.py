from fastapi import FastAPI, HTTPException, Depends, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
import json, os, zipfile
from datetime import datetime, timedelta

app = FastAPI()

origins = ["https://kiti.dev", "http://localhost:5500"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "minha_chave_super_secreta"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

DATA_FILE = "tasks.json"
USER_FILE = "users.json"

# modelos
class Task(BaseModel):
    id: int
    title: str
    done: bool = False

class User(BaseModel):
    username: str
    password: str

# helpers
def load_tasks():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return []

def save_tasks(tasks):
    with open(DATA_FILE, "w") as f:
        json.dump(tasks, f)

def load_users():
    if not os.path.exists(USER_FILE):
        return {}
    with open(USER_FILE, "r") as f:
        try:
            return json.load(f)
        except:
            return {}

def save_users(users):
    with open(USER_FILE, "w") as f:
        json.dump(users, f)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def hash_password(pw):
    return pwd_context.hash(pw)

def authenticate_user(username, password):
    if username == "admin":
        return password == "admin123"  # admin fixo
    users = load_users()
    if username in users and verify_password(password, users[username]["password"]):
        return True
    return False

def create_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

# rotas
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if not authenticate_user(form_data.username, form_data.password):
        raise HTTPException(status_code=400, detail="Credenciais inválidas")
    token = create_token({"sub": form_data.username})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/register")
async def register(user: User):
    if user.username == "admin":
        raise HTTPException(status_code=400, detail="Este nome é reservado")
    users = load_users()
    if user.username in users:
        raise HTTPException(status_code=400, detail="Usuário já existe")
    users[user.username] = {"password": hash_password(user.password)}
    save_users(users)
    return {"message": "Usuário registrado"}

@app.get("/")
def root():
    return {"message": "KitiTasks API :3"}

@app.get("/tasks")
def get_tasks(current_user: str = Depends(get_current_user)):
    return [t for t in load_tasks() if t["user"] == current_user]

@app.post("/tasks")
def add_task(task: Task, current_user: str = Depends(get_current_user)):
    tasks = load_tasks()
    task.id = max([t["id"] for t in tasks], default=0) + 1
    tasks.append({**task.dict(), "user": current_user})
    save_tasks(tasks)
    return {"message": "Tarefa criada"}

@app.patch("/tasks/{task_id}")
def update_task(task_id: int, done: bool, current_user: str = Depends(get_current_user)):
    tasks = load_tasks()
    for t in tasks:
        if t["id"] == task_id and t["user"] == current_user:
            t["done"] = done
            save_tasks(tasks)
            return {"message": "Atualizado"}
    raise HTTPException(status_code=404, detail="Tarefa não encontrada")

@app.delete("/tasks/{task_id}")
def delete_task(task_id: int, current_user: str = Depends(get_current_user)):
    tasks = load_tasks()
    tasks = [t for t in tasks if not (t["id"] == task_id and t["user"] == current_user)]
    save_tasks(tasks)
    return {"message": "Removida"}

# rota protegida: só admin vê
@app.get("/admin.html")
def get_admin_page(user: str = Depends(get_current_user)):
    if user != "admin":
        raise HTTPException(status_code=403, detail="Acesso negado")
    return FileResponse("admin.html")

# backup export
@app.get("/backup")
def export_zip(user: str = Depends(get_current_user)):
    if user != "admin":
        raise HTTPException(status_code=403, detail="Só admin")
    with zipfile.ZipFile("backup.zip", "w") as zipf:
        for f in [DATA_FILE, USER_FILE]:
            if os.path.exists(f):
                zipf.write(f)
    return FileResponse("backup.zip", media_type="application/zip", filename="backup.zip")

# backup import
@app.post("/import")
async def import_backup(request: Request, user: str = Depends(get_current_user)):
    if user != "admin":
        raise HTTPException(status_code=403, detail="Só admin")
    form = await request.form()
    file = form["file"]
    with open("imported.zip", "wb") as f:
        f.write(await file.read())
    with zipfile.ZipFile("imported.zip", "r") as zipf:
        zipf.extractall()
    return {"message": "Importado"}
