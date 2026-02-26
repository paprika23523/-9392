from fastapi import FastAPI, HTTPException, WebSocket
from passlib.hash import bcrypt
from jose import jwt

app = FastAPI()

SECRET_KEY = "supersecretkey"
users = {}
connections = []

@app.get("/")
def home():
    return {"status": "Server working"}

@app.post("/register")
def register(username: str, password: str):
    if username in users:
        raise HTTPException(status_code=400, detail="User exists")
    users[username] = bcrypt.hash(password)
    return {"message": "Registered"}

@app.post("/login")
def login(username: str, password: str):
    if username not in users:
        raise HTTPException(status_code=400, detail="Invalid")

    if not bcrypt.verify(password, users[username]):
        raise HTTPException(status_code=400, detail="Invalid")

    token = jwt.encode({"username": username}, SECRET_KEY, algorithm="HS256")
    return {"token": token}

@app.websocket("/ws/{token}")
async def websocket(ws: WebSocket, token: str):
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = data["username"]
    except:
        await ws.close()
        return

    await ws.accept()
    connections.append((ws, username))

    try:
        while True:
            msg = await ws.receive_text()
            for conn, user in connections:
                await conn.send_text(f"{username}: {msg}")
    except:
        connections.remove((ws, username))
