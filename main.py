from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel
from typing import List
from jose import JWTError, jwt
from datetime import datetime, timedelta

# configurações básicas
SECRET_KEY = "troqueisso1234567890secretkeykiti"  # troca isso depois
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

app = FastAPI()

# CORS liberado só pro seu domínio + localhost p/ teste
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

# só o admin hardcoded
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "12022012"  # troca pra senha forte

# fake db de tarefas, vai perder se reiniciar
tasks = []
task_id_seq = 1

# modelo tarefa
class Task(BaseModel):
    id: int
    title: str
    done: bool = False

# modelo para criar tarefa (sem id)
class TaskCreate(BaseModel):
    title: str
    done: bool = False

# token modelo
class Token(BaseModel):
    access_token: str
    token_type: str

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username != ADMIN_USERNAME:
            raise HTTPException(status_code=401, detail="Usuário não autorizado")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    return verify_token(token)

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username != ADMIN_USERNAME or form_data.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=400, detail="Usuário ou senha incorretos")
    access_token = create_access_token(data={"sub": ADMIN_USERNAME}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/")
async def root():
    return {"message": "Oi, kiti! API na área :3"}

@app.get("/tasks", response_model=List[Task])
async def get_tasks(current_user: str = Depends(get_current_user)):
    return tasks

@app.post("/tasks", response_model=Task)
async def create_task(task: TaskCreate, current_user: str = Depends(get_current_user)):
    global task_id_seq
    new_task = Task(id=task_id_seq, title=task.title, done=task.done)
    tasks.append(new_task)
    task_id_seq += 1
    return new_task

@app.patch("/tasks/{task_id}", response_model=Task)
async def update_task(task_id: int, task: TaskCreate, current_user: str = Depends(get_current_user)):
    for t in tasks:
        if t.id == task_id:
            t.title = task.title
            t.done = task.done
            return t
    raise HTTPException(status_code=404, detail="Tarefa não encontrada")

@app.delete("/tasks/{task_id}")
async def delete_task(task_id: int, current_user: str = Depends(get_current_user)):
    global tasks
    tasks = [t for t in tasks if t.id != task_id]
    return {"message": f"Tarefa {task_id} deletada"}

# backup export (pra admin)
@app.get("/backup")
async def export_backup(current_user: str = Depends(get_current_user)):
    import json
    return {"backup": json.dumps([t.dict() for t in tasks])}

# backup import (pra admin)
@app.post("/backup")
async def import_backup(data: dict, current_user: str = Depends(get_current_user)):
    global tasks, task_id_seq
    import json
    try:
        task_list = json.loads(data.get("backup", "[]"))
        tasks = [Task(**t) for t in task_list]
        task_id_seq = max([t.id for t in tasks], default=0) + 1
        return {"message": "Backup importado com sucesso"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erro no backup: {e}")
