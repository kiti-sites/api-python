from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

app = FastAPI()

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

tasks = []

class Task(BaseModel):
    id: int
    title: str
    done: bool = False

class TaskUpdate(BaseModel):
    done: Optional[bool] = None
    title: Optional[str] = None

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

@app.patch("/tasks/{task_id}")
def update_task(task_id: int, task_update: TaskUpdate):
    for t in tasks:
        if t["id"] == task_id:
            if task_update.done is not None:
                t["done"] = task_update.done
            if task_update.title is not None:
                t["title"] = task_update.title
            return {"message": "tarefa atualizada", "task": t}
    raise HTTPException(status_code=404, detail="tarefa não encontrada")
