#!/usr/bin/env python3
"""
Logging System - Clean Architecture
Centralized logging for all reconnaissance operations
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

def setup_logger(name: str = 'recon-tool', level: str = 'INFO', log_file: Optional[str] = None) -> logging.Logger:
    """Setup and configure logger for the application"""
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    # Clear existing handlers to prevent duplicates
    logger.handlers.clear()
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    simple_formatter = logging.Formatter(
        '%(levelname)s: %(message)s'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(simple_formatter)
    logger.addHandler(console_handler)
    
    # File handler (if specified or default)
    if log_file is None:
        # Create default log file with timestamp
        timestamp = datetime.now().strftime('%Y%m%d')
        log_file = f'logs/recon-tool_{timestamp}.log'
    
    if log_file:
        # Ensure log directory exists
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(detailed_formatter)
        logger.addHandler(file_handler)
    
    # Set third-party loggers to WARNING to reduce noise
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    
    return logger

class ReconLogger:
    """Enhanced logger for reconnaissance operations"""
    
    def __init__(self, name: str = 'recon-tool', level: str = 'INFO'):
        self.logger = setup_logger(name, level)
        self.start_time = datetime.now()
    
    def info(self, message: str) -> None:
        """Log info message"""
        self.logger.info(message)
    
    def debug(self, message: str) -> None:
        """Log debug message"""
        self.logger.debug(message)
    
    def warning(self, message: str) -> None:
        """Log warning message"""
        self.logger.warning(message)
    
    def error(self, message: str) -> None:
        """Log error message"""
        self.logger.error(message)
    
    def critical(self, message: str) -> None:
        """Log critical message"""
        self.logger.critical(message)
    
    def scan_start(self, target: str, tools: list) -> None:
        """Log scan start"""
        self.start_time = datetime.now()
        self.info(f"🚀 Starting reconnaissance scan")
        self.info(f"📍 Target: {target}")
        self.info(f"🔧 Tools: {', '.join(tools)}")
        self.info(f"⏰ Start time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    def scan_complete(self, success: bool, duration: float = None) -> None:
        """Log scan completion"""
        end_time = datetime.now()
        if duration is None:
            duration = (end_time - self.start_time).total_seconds()
        
        status = "✅ completed successfully" if success else "❌ failed"
        self.info(f"🏁 Reconnaissance scan {status}")
        self.info(f"⏱️  Duration: {duration:.1f} seconds")
        self.info(f"🕐 End time: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    def tool_start(self, tool_name: str, target: str) -> None:
        """Log tool execution start"""
        self.info(f"🔧 Starting {tool_name} scan against {target}")
    
    def tool_complete(self, tool_name: str, success: bool, duration: float = None) -> None:
        """Log tool execution completion"""
        status = "✅" if success else "❌"
        duration_str = f" ({duration:.1f}s)" if duration else ""
        self.info(f"{status} {tool_name} completed{duration_str}")
    
    def tool_error(self, tool_name: str, error: str) -> None:
        """Log tool execution error"""
        self.error(f"❌ {tool_name} failed: {error}")

def get_logger(name: str = 'recon-tool') -> ReconLogger:
    """Get configured logger instance"""
    return ReconLogger(name)

# Legacy functions for backward compatibility
def setup_logging(config):
    """Legacy function for logging setup"""
    level = config.get('log_level', 'INFO') if config else 'INFO'
    return setup_logger(level=level)

class StructuredLogger:
    """Legacy structured logger for compatibility"""
    
    def __init__(self, name):
        self.logger = get_logger(name)
    
    def log_scan_start(self, scan_config):
        """Log scan initiation"""
        target = scan_config.get('target', 'unknown')
        tools = scan_config.get('tools', [])
        self.logger.scan_start(target, tools)
    
    def log_tool_execution(self, tool_name, target):
        """Log individual tool execution"""
        self.logger.tool_start(tool_name, target)
    
    def log_results(self, results):
        """Log scan results"""
        self.logger.info(f"📊 Scan results: {len(results)} items")
