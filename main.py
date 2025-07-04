from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

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
    # checa se id já existe
    if any(t["id"] == task.id for t in tasks):
        raise HTTPException(status_code=400, detail="id já existe, doido!")
    tasks.append(task.dict())
    return {"message": "tarefa criada", "task": task}

@app.delete("/tasks/{task_id}")
def delete_task(task_id: int):
    global tasks
    tasks = [t for t in tasks if t["id"] != task_id]
    return {"message": f"tarefa com id {task_id} deletada"}
