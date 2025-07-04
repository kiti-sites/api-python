from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

# libera acesso da tua UI
origins = [
    "https://kiti.dev",         # teu domínio
    "http://localhost:5500",    # pra testar local
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,      # ou ["*"] se quiser liberar geral
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# banco de dados fake na memória
tasks = []

# modelo da tarefa
class Task(BaseModel):
    id: int
    title: str
    done: bool = False

@app.get("/")
def read_root():
    return {"message": "Oi, kiti! Bem-vindo à API :3"}

@app.get("/tasks")
def get_tasks():
    return tasks

@app.post("/tasks")
def create_task(task: Task):
    if any(t["id"] == task.id for t in tasks):
        raise HTTPException(status_code=400, detail="id já existe, doido!")
    tasks.append(task.dict())
    return {"message": "tarefa criada", "task": task}

@app.delete("/tasks/{task_id}")
def delete_task(task_id: int):
    global tasks
    tasks = [t for t in tasks if t["id"] != task_id]
    return {"message": f"tarefa com id {task_id} deletada"}
