from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from .api import scan, auth
from .core.websocket import manager
import logging
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('app.log')
    ]
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Cloud Scanner",
    description="AWS Cloud Security Scanner API",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(scan.router, prefix="/api/v1", tags=["scan"])

@app.get("/")
def read_root():
    return {"message": "Cloud Scanner API"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = None):
    """WebSocket endpoint for real-time scan updates"""
    try:
        if not token:
            await websocket.close(code=1008, reason="No authentication token provided")
            return

        current_user = await auth.get_current_user(token)
        if not current_user:
            await websocket.close(code=1008, reason="Invalid authentication token")
            return

        await manager.connect(websocket, current_user.email)
        try:
            while True:
                data = await websocket.receive_text()
                # Handle any incoming messages if needed
        except Exception as e:
            logger.error(f"WebSocket error: {str(e)}")
        finally:
            manager.disconnect(websocket, current_user.email)
    except Exception as e:
        logger.error(f"WebSocket connection error: {str(e)}")
        try:
            await websocket.close(code=1011, reason=str(e))
        except:
            pass
