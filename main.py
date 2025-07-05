from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

app = FastAPI()

# CORS - só o teu domínio
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

# senha do admin hashed
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = pwd_context.hash("supersecreta")  # muda aqui a senha admin!

# JWT config
SECRET_KEY = "chave-secreta-muito-longa-e-segura"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 dias

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class Token(BaseModel):
    access_token: str
    token_type: str

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_admin(username: str, password: str):
    if username == ADMIN_USERNAME and verify_password(password, ADMIN_PASSWORD_HASH):
        return True
    return False

def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_admin(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="token inválido ou expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username != ADMIN_USERNAME:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return username

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    if not authenticate_admin(form_data.username, form_data.password):
        raise HTTPException(status_code=400, detail="Usuário ou senha inválidos")
    access_token = create_access_token(data={"sub": ADMIN_USERNAME})
    return {"access_token": access_token, "token_type": "bearer"}

# montar uma lista fake de tarefas pra admin
tasks = [
    {"id": 1, "title": "teste admin 1", "done": False},
    {"id": 2, "title": "teste admin 2", "done": True},
]

@app.get("/tasks")
async def get_tasks(admin: str = Depends(get_current_admin)):
    return tasks

@app.post("/tasks")
async def create_task(task: dict, admin: str = Depends(get_current_admin)):
    new_id = max(t["id"] for t in tasks) + 1 if tasks else 1
    task["id"] = new_id
    tasks.append(task)
    return {"message": "Tarefa criada", "task": task}

@app.delete("/tasks/{task_id}")
async def delete_task(task_id: int, admin: str = Depends(get_current_admin)):
    global tasks
    tasks = [t for t in tasks if t["id"] != task_id]
    return {"message": f"Tarefa {task_id} deletada"}

@app.patch("/tasks/{task_id}")
async def update_task(task_id: int, data: dict, admin: str = Depends(get_current_admin)):
    for t in tasks:
        if t["id"] == task_id:
            t.update(data)
            return {"message": "Tarefa atualizada", "task": t}
    raise HTTPException(status_code=404, detail="Tarefa não encontrada")

# serve os arquivos estáticos (html, js, css) da pasta 'static'
app.mount("/static", StaticFiles(directory="static"), name="static")

# rota raiz só pra confirmar que API tá rodando
@app.get("/")
async def root():
    return {"message": "API do admin kiti.dev online"}

# rota pra servir admin.html (apenas pra admin autenticado)
@app.get("/admin.html", response_class=HTMLResponse)
async def get_admin_html(admin: str = Depends(get_current_admin)):
    return FileResponse("static/admin.html")

# rota pra servir index.html (login) - público
@app.get("/index.html", response_class=HTMLResponse)
async def get_index_html():
    return FileResponse("static/index.html")

# redireciona / pra /index.html
from fastapi.responses import RedirectResponse

@app.get("/", include_in_schema=False)
async def root_redirect():
    return RedirectResponse("/index.html")

if __name__ == "__main__":
    uvicorn.run("main:app", port=8000, reload=True)
