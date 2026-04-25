import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from state_manager import agent_state

app = FastAPI(title="IDS Agent API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    agent_state.set_loop(asyncio.get_running_loop())

@app.get("/api/metrics")
async def get_metrics():
    return agent_state.get_metrics()

@app.get("/api/live")
async def get_live():
    return {"live": agent_state.get_live()}

@app.get("/api/top")
async def get_top():
    return agent_state.get_top()

@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    agent_state.ws_clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        agent_state.ws_clients.remove(websocket)
    except Exception:
        agent_state.ws_clients.remove(websocket)

def run_api_server():
    # Run uvicorn server in the background
    uvicorn.run(app, host="127.0.0.1", port=8001, log_level="error")
