from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum
from app.api.endpoints import scans, auth
from app.database.mongodb import db
from app.core.auth import get_current_user

app = FastAPI(title="Cloud Scanner API")

# Configure CORS
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)

# Include routers
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(
    scans.router,
    prefix="/api/scans",
    tags=["scans"],
    dependencies=[Depends(get_current_user)]  # Protect all scan endpoints
)

@app.on_event("startup")
async def startup_event():
    await db.connect_db()

@app.on_event("shutdown")
async def shutdown_event():
    await db.close_db()

@app.get("/")
async def root():
    return {"message": "Welcome to Cloud Scanner API"}

# AWS Lambda handler
handler = Mangum(app)
