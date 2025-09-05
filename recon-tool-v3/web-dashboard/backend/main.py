"""
FastAPI Backend for Recon-Tool-v3 Web Dashboard
Phase 6 Implementation - Main Application Entry Point
"""

from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from fastapi.staticfiles import StaticFiles
import uvicorn
import os
import sys
from pathlib import Path

# Add the parent directory to Python path for recon_tool imports
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import application modules
from app.api.routes import scans, reports, users, websocket
from app.core.database import engine, Base
from app.core.websocket_manager import WebSocketManager
from app.core.security import get_current_user

# Create FastAPI application
app = FastAPI(
    title="Recon-Tool-v3 Web Dashboard",
    description="Professional reconnaissance toolkit with real-time web dashboard",
    version="6.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],  # React dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# WebSocket Manager
websocket_manager = WebSocketManager()

# Create database tables
@app.on_event("startup")
async def startup_event():
    """Initialize database and startup tasks"""
    # Create database tables
    Base.metadata.create_all(bind=engine)
    print("🚀 Recon-Tool-v3 Web Dashboard starting up...")
    print("📊 Database initialized")
    print("🌐 WebSocket manager ready")
    print("✅ Backend ready for connections")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup tasks on shutdown"""
    print("🛑 Shutting down Recon-Tool-v3 Web Dashboard...")

# Include API routes
app.include_router(users.router, prefix="/api/v1/users", tags=["users"])
app.include_router(scans.router, prefix="/api/v1/scans", tags=["scans"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["reports"])

# WebSocket endpoint for real-time communication
@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """WebSocket endpoint for real-time communication"""
    await websocket_manager.connect(websocket, client_id)
    try:
        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()
            # Echo message back (can be extended for specific message handling)
            await websocket_manager.send_personal_message(f"Echo: {data}", client_id)
    except WebSocketDisconnect:
        websocket_manager.disconnect(client_id)
        print(f"🔌 Client {client_id} disconnected")

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "recon-tool-v3-dashboard",
        "version": "6.0.0",
        "phase": "6 - Web Dashboard"
    }

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "message": "Recon-Tool-v3 Web Dashboard API",
        "version": "6.0.0",
        "phase": "6 - Web Dashboard with Real-time Monitoring",
        "docs": "/api/docs",
        "health": "/health",
        "websocket": "/ws/{client_id}"
    }

# Development server
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
