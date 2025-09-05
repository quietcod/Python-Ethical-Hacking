"""
WebSocket API Routes for Real-time Communication
Phase 6 - Web Dashboard Backend
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from app.core.websocket_manager import websocket_manager
import json

router = APIRouter()

# Note: WebSocket endpoints are defined in main.py
# This module contains WebSocket-related utilities and message handlers

class WebSocketMessageHandler:
    """Handle different types of WebSocket messages"""
    
    @staticmethod
    async def handle_message(websocket: WebSocket, client_id: str, message: str):
        """Handle incoming WebSocket message"""
        try:
            data = json.loads(message)
            message_type = data.get("type", "unknown")
            
            if message_type == "ping":
                # Respond to ping
                await websocket_manager.send_personal_message(
                    json.dumps({
                        "type": "pong",
                        "timestamp": data.get("timestamp")
                    }),
                    client_id
                )
            
            elif message_type == "subscribe":
                # Handle subscription to specific events
                event_type = data.get("event_type")
                await websocket_manager.send_personal_message(
                    json.dumps({
                        "type": "subscription_confirmed",
                        "event_type": event_type,
                        "message": f"Subscribed to {event_type} events"
                    }),
                    client_id
                )
            
            elif message_type == "scan_status_request":
                # Handle request for scan status
                scan_id = data.get("scan_id")
                # Here you would fetch scan status from database
                await websocket_manager.send_personal_message(
                    json.dumps({
                        "type": "scan_status_response",
                        "scan_id": scan_id,
                        "status": "running",  # This would come from database
                        "progress": 45
                    }),
                    client_id
                )
            
            else:
                # Echo unknown message types
                await websocket_manager.send_personal_message(
                    json.dumps({
                        "type": "echo",
                        "original_message": data
                    }),
                    client_id
                )
                
        except json.JSONDecodeError:
            # Handle invalid JSON
            await websocket_manager.send_error(
                client_id,
                "Invalid JSON message format"
            )
        except Exception as e:
            # Handle other errors
            await websocket_manager.send_error(
                client_id,
                f"Error processing message: {str(e)}"
            )

# Utility functions for sending specific message types
async def send_scan_progress(client_id: str, scan_id: int, progress: int, current_tool: str = None):
    """Send scan progress update"""
    await websocket_manager.send_scan_update(client_id, {
        "scan_id": scan_id,
        "progress": progress,
        "current_tool": current_tool,
        "status": "running"
    })

async def send_scan_completion(client_id: str, scan_id: int, results: dict):
    """Send scan completion notification"""
    await websocket_manager.send_scan_complete(client_id, {
        "scan_id": scan_id,
        "status": "completed",
        "results": results
    })

async def send_report_ready(client_id: str, report_id: int, download_url: str):
    """Send report ready notification"""
    message = json.dumps({
        "type": "report_ready",
        "report_id": report_id,
        "download_url": download_url,
        "message": "Report generation completed"
    })
    await websocket_manager.send_personal_message(message, client_id)

async def broadcast_system_status(status: dict):
    """Broadcast system status to all connected clients"""
    message = json.dumps({
        "type": "system_status",
        "status": status
    })
    await websocket_manager.broadcast(message)
