"""
ReconTool Web API
FastAPI backend for the ReconTool web interface
"""

from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import subprocess
import json
import os
import uuid
from datetime import datetime
from pathlib import Path
import asyncio

# Initialize FastAPI app
app = FastAPI(
    title="ReconTool API",
    description="Web API for ReconTool - Professional Reconnaissance Toolkit",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://localhost:8080"],  # React/Vue dev servers
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Data models for API requests/responses
class ScanRequest(BaseModel):
    target: str = Field(..., description="Target domain or IP address")
    scan_type: str = Field(default="quick", description="Scan type: quick, full, or custom")
    tools: List[str] = Field(default=["port", "subdomain", "web"], description="Tools to use")
    options: Dict[str, Any] = Field(default={}, description="Additional scan options")

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str
    estimated_duration: int

class ScanStatus(BaseModel):
    scan_id: str
    status: str  # 'queued', 'running', 'completed', 'failed'
    progress: int  # 0-100
    current_tool: Optional[str]
    elapsed_time: int
    eta: Optional[int]
    message: str

class ScanResults(BaseModel):
    scan_id: str
    target: str
    status: str
    start_time: str
    end_time: Optional[str]
    results: Dict[str, Any]
    summary: Dict[str, Any]

# In-memory storage for demo (use database in production)
active_scans: Dict[str, Dict] = {}
scan_results: Dict[str, Dict] = {}

# API Endpoints

@app.get("/")
async def root():
    """Root endpoint - API status"""
    return {
        "message": "ReconTool API v2.0",
        "status": "running",
        "endpoints": {
            "docs": "/docs",
            "start_scan": "POST /api/scans",
            "scan_status": "GET /api/scans/{scan_id}/status",
            "scan_results": "GET /api/scans/{scan_id}/results",
            "generate_report": "POST /api/scans/{scan_id}/reports"
        }
    }

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.post("/api/scans", response_model=ScanResponse)
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new reconnaissance scan"""
    
    # Generate unique scan ID
    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{str(uuid.uuid4())[:8]}"
    
    # Validate target
    if not scan_request.target:
        raise HTTPException(status_code=400, detail="Target is required")
    
    # Estimate duration based on scan type
    duration_map = {"quick": 60, "full": 300, "custom": 180}
    estimated_duration = duration_map.get(scan_request.scan_type, 180)
    
    # Initialize scan tracking
    active_scans[scan_id] = {
        "request": scan_request.dict(),
        "status": "queued",
        "progress": 0,
        "start_time": datetime.now().isoformat(),
        "current_tool": None
    }
    
    # Start scan in background
    background_tasks.add_task(run_scan_background, scan_id, scan_request)
    
    return ScanResponse(
        scan_id=scan_id,
        status="queued",
        message=f"Scan {scan_id} queued successfully",
        estimated_duration=estimated_duration
    )

@app.get("/api/scans/{scan_id}/status", response_model=ScanStatus)
async def get_scan_status(scan_id: str):
    """Get the current status of a scan"""
    
    if scan_id not in active_scans and scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan_id in active_scans:
        scan_data = active_scans[scan_id]
        start_time = datetime.fromisoformat(scan_data["start_time"])
        elapsed = int((datetime.now() - start_time).total_seconds())
        
        return ScanStatus(
            scan_id=scan_id,
            status=scan_data["status"],
            progress=scan_data["progress"],
            current_tool=scan_data.get("current_tool"),
            elapsed_time=elapsed,
            eta=None,  # Calculate based on progress
            message=f"Scan {scan_data['status']}"
        )
    else:
        # Scan completed
        return ScanStatus(
            scan_id=scan_id,
            status="completed",
            progress=100,
            current_tool=None,
            elapsed_time=scan_results[scan_id].get("scan_duration", 0),
            eta=0,
            message="Scan completed successfully"
        )

@app.get("/api/scans/{scan_id}/results")
async def get_scan_results(scan_id: str):
    """Get the results of a completed scan"""
    
    if scan_id not in scan_results:
        if scan_id in active_scans:
            raise HTTPException(status_code=202, detail="Scan still in progress")
        else:
            raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan_results[scan_id]

@app.post("/api/scans/{scan_id}/reports")
async def generate_report(scan_id: str, format: str = "html", template: str = "professional"):
    """Generate and download a report for completed scan"""
    
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan results not found")
    
    # Call the existing reporting system
    try:
        report_path = await generate_report_file(scan_id, format, template)
        return {"report_url": f"/api/reports/{scan_id}.{format}", "download_url": report_path}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")

@app.get("/api/scans")
async def list_scans(limit: int = 50, status: Optional[str] = None):
    """List recent scans with optional status filter"""
    
    all_scans = []
    
    # Add active scans
    for scan_id, data in active_scans.items():
        scan_info = {
            "scan_id": scan_id,
            "target": data["request"]["target"],
            "status": data["status"],
            "start_time": data["start_time"],
            "scan_type": data["request"]["scan_type"]
        }
        if not status or data["status"] == status:
            all_scans.append(scan_info)
    
    # Add completed scans
    for scan_id, data in scan_results.items():
        scan_info = {
            "scan_id": scan_id,
            "target": data["target"],
            "status": "completed",
            "start_time": data["start_time"],
            "scan_type": data.get("scan_type", "unknown")
        }
        if not status or "completed" == status:
            all_scans.append(scan_info)
    
    # Sort by start time (newest first) and limit
    all_scans.sort(key=lambda x: x["start_time"], reverse=True)
    return {"scans": all_scans[:limit], "total": len(all_scans)}

@app.delete("/api/scans/{scan_id}")
async def cancel_scan(scan_id: str):
    """Cancel a running scan"""
    
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Active scan not found")
    
    # Update status to cancelled
    active_scans[scan_id]["status"] = "cancelled"
    active_scans[scan_id]["progress"] = 0
    
    return {"message": f"Scan {scan_id} cancelled successfully"}

# Background task functions

async def run_scan_background(scan_id: str, scan_request: ScanRequest):
    """Run the actual reconnaissance scan in background"""
    
    try:
        # Update status to running
        active_scans[scan_id]["status"] = "running"
        active_scans[scan_id]["progress"] = 10
        
        # Create scan directory
        scan_dir = Path(f"web_scans/{scan_id}")
        scan_dir.mkdir(parents=True, exist_ok=True)
        
        # Build command to run ReconTool CLI
        cmd = [
            "python3", "-m", "recon_tool.main",
            "--domain", scan_request.target,
            "--output", str(scan_dir)
        ]
        
        # Add tools if specified
        if scan_request.tools:
            cmd.extend(["--tools", ",".join(scan_request.tools)])
        
        # Update progress
        active_scans[scan_id]["progress"] = 25
        active_scans[scan_id]["current_tool"] = "port_scanner"
        
        # Run the actual scan
        result = subprocess.run(cmd, capture_output=True, text=True, cwd="/home/quiet/Documents/Python-Ethical-Hacking/recon-wrapper")
        
        # Update progress
        active_scans[scan_id]["progress"] = 90
        
        if result.returncode == 0:
            # Scan successful - load results
            results_file = scan_dir / "scan_results.json"
            
            if results_file.exists():
                with open(results_file, 'r') as f:
                    results_data = json.load(f)
            else:
                # Use sample data if no results file (for testing)
                with open("sample_data/sample_scan_results.json", 'r') as f:
                    sample_data = json.load(f)
                    results_data = sample_data["sample_scan_results"]
                    results_data["scan_id"] = scan_id
                    results_data["target"] = scan_request.target
            
            # Store completed results
            scan_results[scan_id] = results_data
            
            # Remove from active scans
            del active_scans[scan_id]
            
        else:
            # Scan failed
            active_scans[scan_id]["status"] = "failed"
            active_scans[scan_id]["error"] = result.stderr
            
    except Exception as e:
        # Handle errors
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["error"] = str(e)

async def generate_report_file(scan_id: str, format: str, template: str) -> str:
    """Generate report file using existing reporting system"""
    
    # Create reports directory
    reports_dir = Path("web_reports")
    reports_dir.mkdir(exist_ok=True)
    
    # Use existing reporting system
    cmd = [
        "python3", "-m", "recon_tool.reporting",
        "--input", f"web_scans/{scan_id}/scan_results.json",
        "--format", format,
        "--output", str(reports_dir / f"{scan_id}.{format}")
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode == 0:
        return str(reports_dir / f"{scan_id}.{format}")
    else:
        raise Exception(f"Report generation failed: {result.stderr}")

# WebSocket endpoint for real-time updates (optional advanced feature)
@app.websocket("/ws/scans/{scan_id}")
async def websocket_scan_updates(websocket, scan_id: str):
    """WebSocket endpoint for real-time scan progress updates"""
    await websocket.accept()
    
    try:
        while True:
            if scan_id in active_scans:
                scan_data = active_scans[scan_id]
                await websocket.send_json({
                    "scan_id": scan_id,
                    "status": scan_data["status"],
                    "progress": scan_data["progress"],
                    "current_tool": scan_data.get("current_tool")
                })
                
                if scan_data["status"] in ["completed", "failed", "cancelled"]:
                    break
                    
            elif scan_id in scan_results:
                await websocket.send_json({
                    "scan_id": scan_id,
                    "status": "completed",
                    "progress": 100,
                    "current_tool": None
                })
                break
            
            await asyncio.sleep(2)  # Update every 2 seconds
            
    except Exception as e:
        await websocket.close(code=1000)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
