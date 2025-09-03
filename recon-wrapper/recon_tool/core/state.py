"""
State Management
Handles scan state, checkpoints, and resume functionality
"""

import json
import pickle
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional


class StateManager:
    """Manages scan state and provides resume functionality"""
    
    def __init__(self, output_dir: Path, logger):
        self.output_dir = output_dir
        self.logger = logger
        self.state_file = output_dir / "logs" / "scan_state.json"
        self.checkpoint_dir = output_dir / "logs" / "checkpoints"
        
        # Create directories
        self.state_file.parent.mkdir(exist_ok=True)
        self.checkpoint_dir.mkdir(exist_ok=True)
        
        self.current_state = {
            "scan_id": None,
            "target": None,
            "scan_type": None,
            "start_time": None,
            "last_update": None,
            "completed_phases": [],
            "current_phase": None,
            "results": {},
            "status": "idle"
        }
    
    def initialize_state(self, scan_id: str, target: str, scan_type: str) -> None:
        """Initialize new scan state"""
        self.current_state.update({
            "scan_id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "start_time": datetime.now().isoformat(),
            "last_update": datetime.now().isoformat(),
            "status": "initialized"
        })
        self.save_state_file()
        self.logger.info(f"Initialized state for scan {scan_id}")
    
    def save_state(self, results: Dict[str, Any], current_phase: str = None) -> None:
        """Save current scan state"""
        self.current_state.update({
            "last_update": datetime.now().isoformat(),
            "results": results,
            "current_phase": current_phase
        })
        
        if current_phase and current_phase not in self.current_state["completed_phases"]:
            self.current_state["completed_phases"].append(current_phase)
        
        self.save_state_file()
        self.create_checkpoint(current_phase)
        self.logger.debug(f"State saved for phase: {current_phase}")
    
    def save_state_file(self) -> None:
        """Save state to JSON file"""
        try:
            with open(self.state_file, 'w') as f:
                json.dump(self.current_state, f, indent=2, default=str)
        except Exception as e:
            self.logger.error(f"Failed to save state file: {str(e)}")
    
    def load_state(self) -> Optional[Dict[str, Any]]:
        """Load state from file"""
        try:
            if self.state_file.exists():
                with open(self.state_file, 'r') as f:
                    self.current_state = json.load(f)
                self.logger.info("State loaded from file")
                return self.current_state
        except Exception as e:
            self.logger.error(f"Failed to load state: {str(e)}")
        return None
    
    def create_checkpoint(self, phase_name: str) -> None:
        """Create a checkpoint for the current phase"""
        try:
            checkpoint_file = self.checkpoint_dir / f"{phase_name}_{datetime.now().strftime('%H%M%S')}.pkl"
            
            checkpoint_data = {
                "phase": phase_name,
                "timestamp": datetime.now().isoformat(),
                "results": self.current_state["results"],
                "state": self.current_state.copy()
            }
            
            with open(checkpoint_file, 'wb') as f:
                pickle.dump(checkpoint_data, f)
            
            self.logger.debug(f"Checkpoint created: {checkpoint_file}")
        except Exception as e:
            self.logger.error(f"Failed to create checkpoint: {str(e)}")
    
    def can_resume(self) -> bool:
        """Check if scan can be resumed"""
        return (
            self.state_file.exists() and 
            self.current_state.get("status") in ["running", "paused", "interrupted"]
        )
    
    def get_resume_info(self) -> Optional[Dict[str, Any]]:
        """Get information for resuming scan"""
        if self.can_resume():
            return {
                "scan_id": self.current_state.get("scan_id"),
                "target": self.current_state.get("target"),
                "scan_type": self.current_state.get("scan_type"),
                "completed_phases": self.current_state.get("completed_phases", []),
                "current_phase": self.current_state.get("current_phase"),
                "start_time": self.current_state.get("start_time"),
                "last_update": self.current_state.get("last_update")
            }
        return None
    
    def mark_completed(self) -> None:
        """Mark scan as completed"""
        self.current_state.update({
            "status": "completed",
            "end_time": datetime.now().isoformat(),
            "last_update": datetime.now().isoformat()
        })
        self.save_state_file()
        self.logger.info("Scan marked as completed")
    
    def mark_failed(self, error: str) -> None:
        """Mark scan as failed"""
        self.current_state.update({
            "status": "failed",
            "error": error,
            "end_time": datetime.now().isoformat(),
            "last_update": datetime.now().isoformat()
        })
        self.save_state_file()
        self.logger.error(f"Scan marked as failed: {error}")
    
    def cleanup_old_checkpoints(self, keep_count: int = 10) -> None:
        """Clean up old checkpoint files"""
        try:
            checkpoint_files = sorted(
                self.checkpoint_dir.glob("*.pkl"),
                key=lambda x: x.stat().st_mtime,
                reverse=True
            )
            
            # Remove old checkpoints beyond keep_count
            for checkpoint_file in checkpoint_files[keep_count:]:
                checkpoint_file.unlink()
                self.logger.debug(f"Removed old checkpoint: {checkpoint_file}")
                
        except Exception as e:
            self.logger.error(f"Failed to cleanup checkpoints: {str(e)}")
    
    def get_scan_duration(self) -> Optional[float]:
        """Get scan duration in seconds"""
        try:
            if self.current_state.get("start_time"):
                start = datetime.fromisoformat(self.current_state["start_time"])
                
                if self.current_state.get("end_time"):
                    end = datetime.fromisoformat(self.current_state["end_time"])
                else:
                    end = datetime.now()
                
                return (end - start).total_seconds()
        except:
            pass
        return None
    
    def get_state_summary(self) -> Dict[str, Any]:
        """Get summary of current state"""
        return {
            "scan_id": self.current_state.get("scan_id"),
            "target": self.current_state.get("target"),
            "status": self.current_state.get("status"),
            "progress": len(self.current_state.get("completed_phases", [])),
            "duration": self.get_scan_duration(),
            "last_update": self.current_state.get("last_update")
        }
