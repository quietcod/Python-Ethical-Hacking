"""
WebSocket Manager for Real-time Communication
Phase 6 - Web Dashboard Backend
"""

from typing import Dict, List
from fastapi import WebSocket
import json
import asyncio
from datetime import datetime

class WebSocketManager:
    """Manages WebSocket connections for real-time communication"""
    
    def __init__(self):
        # Store active connections
        self.active_connections: Dict[str, WebSocket] = {}
        # Store connection metadata
        self.connection_metadata: Dict[str, dict] = {}
    
    async def connect(self, websocket: WebSocket, client_id: str):
        """Accept and store a new WebSocket connection"""
        await websocket.accept()
        self.active_connections[client_id] = websocket
        self.connection_metadata[client_id] = {
            "connected_at": datetime.utcnow(),
            "last_activity": datetime.utcnow()
        }
        
        # Send connection confirmation
        await self.send_personal_message(
            json.dumps({
                "type": "connection",
                "status": "connected",
                "client_id": client_id,
                "timestamp": datetime.utcnow().isoformat()
            }),
            client_id
        )
        
        print(f"🔌 Client {client_id} connected via WebSocket")
    
    def disconnect(self, client_id: str):
        """Remove a WebSocket connection"""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
        if client_id in self.connection_metadata:
            del self.connection_metadata[client_id]
        print(f"🔌 Client {client_id} disconnected")
    
    async def send_personal_message(self, message: str, client_id: str):
        """Send a message to a specific client"""
        if client_id in self.active_connections:
            try:
                await self.active_connections[client_id].send_text(message)
                # Update last activity
                if client_id in self.connection_metadata:
                    self.connection_metadata[client_id]["last_activity"] = datetime.utcnow()
            except Exception as e:
                print(f"❌ Error sending message to {client_id}: {e}")
                # Remove dead connection
                self.disconnect(client_id)
    
    async def broadcast(self, message: str):
        """Broadcast a message to all connected clients"""
        if self.active_connections:
            # Create list to avoid dictionary changed size during iteration
            clients = list(self.active_connections.keys())
            for client_id in clients:
                await self.send_personal_message(message, client_id)
    
    async def send_scan_update(self, client_id: str, scan_data: dict):
        """Send scan progress update to specific client"""
        message = json.dumps({
            "type": "scan_update",
            "data": scan_data,
            "timestamp": datetime.utcnow().isoformat()
        })
        await self.send_personal_message(message, client_id)
    
    async def send_scan_complete(self, client_id: str, scan_result: dict):
        """Send scan completion notification to specific client"""
        message = json.dumps({
            "type": "scan_complete",
            "data": scan_result,
            "timestamp": datetime.utcnow().isoformat()
        })
        await self.send_personal_message(message, client_id)
    
    async def send_error(self, client_id: str, error_message: str):
        """Send error message to specific client"""
        message = json.dumps({
            "type": "error",
            "message": error_message,
            "timestamp": datetime.utcnow().isoformat()
        })
        await self.send_personal_message(message, client_id)
    
    async def send_log_update(self, client_id: str, log_data: dict):
        """Send log update to specific client"""
        message = json.dumps({
            "type": "log_update",
            "data": log_data,
            "timestamp": datetime.utcnow().isoformat()
        })
        await self.send_personal_message(message, client_id)
    
    def get_connected_clients(self) -> List[str]:
        """Get list of connected client IDs"""
        return list(self.active_connections.keys())
    
    def get_connection_count(self) -> int:
        """Get number of active connections"""
        return len(self.active_connections)
    
    def get_connection_info(self, client_id: str) -> dict:
        """Get connection information for specific client"""
        if client_id in self.connection_metadata:
            return self.connection_metadata[client_id]
        return None
    
    async def ping_all_clients(self):
        """Send ping to all clients to check connection health"""
        ping_message = json.dumps({
            "type": "ping",
            "timestamp": datetime.utcnow().isoformat()
        })
        await self.broadcast(ping_message)

# Global WebSocket manager instance
websocket_manager = WebSocketManager()

# Background task to clean up dead connections
async def cleanup_dead_connections():
    """Background task to clean up inactive connections"""
    while True:
        try:
            current_time = datetime.utcnow()
            dead_clients = []
            
            for client_id, metadata in websocket_manager.connection_metadata.items():
                # Remove connections inactive for more than 5 minutes
                if (current_time - metadata["last_activity"]).total_seconds() > 300:
                    dead_clients.append(client_id)
            
            for client_id in dead_clients:
                websocket_manager.disconnect(client_id)
                print(f"🧹 Cleaned up inactive connection: {client_id}")
            
        except Exception as e:
            print(f"❌ Error in cleanup task: {e}")
        
        # Sleep for 60 seconds before next cleanup
        await asyncio.sleep(60)
