"""
Logging System
Centralized logging with multiple outputs and levels
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional


def setup_logger(name: str = "recon_tool", level: int = logging.INFO, log_file: Optional[Path] = None) -> logging.Logger:
    """Simple logger setup function"""
    logger = logging.getLogger(name)
    
    # Clear any existing handlers
    logger.handlers.clear()
    logger.setLevel(level)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler if log_file specified
    if log_file:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    # Prevent duplicate logs
    logger.propagate = False
    
    return logger


class ReconLogger:
    """Centralized logging system for reconnaissance operations"""
    
    def __init__(self, output_dir: Path, config, logger_name: str = "recon_tool"):
        self.output_dir = output_dir
        self.config = config
        self.logger_name = logger_name
        
        # Create logger
        self.logger = logging.getLogger(logger_name)
        self._setup_logger()
    
    def _setup_logger(self) -> None:
        """Setup logger with file and console handlers"""
        # Clear any existing handlers
        self.logger.handlers.clear()
        
        # Get logging configuration
        log_config = self.config.get_section('logging')
        log_level = getattr(logging, log_config.get('level', 'INFO').upper())
        
        self.logger.setLevel(log_level)
        
        # Create formatter
        formatter = logging.Formatter(
            log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        
        # Setup file handler with rotation
        if log_config.get('file_logging', True):
            log_file = self.output_dir / "logs" / "scan.log"
            log_file.parent.mkdir(exist_ok=True)
            
            max_bytes = self._parse_size(log_config.get('max_file_size', '10MB'))
            backup_count = log_config.get('backup_count', 5)
            
            file_handler = logging.handlers.RotatingFileHandler(
                log_file, maxBytes=max_bytes, backupCount=backup_count
            )
            file_handler.setFormatter(formatter)
            file_handler.setLevel(logging.DEBUG)
            self.logger.addHandler(file_handler)
        
        # Setup console handler
        if log_config.get('console_logging', True):
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(ColoredFormatter(
                log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            ))
            console_handler.setLevel(log_level)
            self.logger.addHandler(console_handler)
        
        # Setup error file handler
        error_file = self.output_dir / "logs" / "errors.log"
        error_handler = logging.FileHandler(error_file)
        error_handler.setFormatter(formatter)
        error_handler.setLevel(logging.ERROR)
        self.logger.addHandler(error_handler)
    
    def _parse_size(self, size_str: str) -> int:
        """Parse size string like '10MB' to bytes"""
        size_str = size_str.upper()
        if size_str.endswith('KB'):
            return int(size_str[:-2]) * 1024
        elif size_str.endswith('MB'):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith('GB'):
            return int(size_str[:-2]) * 1024 * 1024 * 1024
        else:
            return int(size_str)
    
    def debug(self, message: str) -> None:
        """Log debug message"""
        self.logger.debug(message)
    
    def info(self, message: str) -> None:
        """Log info message"""
        self.logger.info(message)
    
    def warning(self, message: str) -> None:
        """Log warning message"""
        self.logger.warning(message)
    
    def error(self, message: str) -> None:
        """Log error message"""
        self.logger.error(message)
    
    def critical(self, message: str) -> None:
        """Log critical message"""
        self.logger.critical(message)
    
    def log_scan_start(self, target: str, scan_type: str) -> None:
        """Log scan start"""
        self.info(f"=== SCAN STARTED ===")
        self.info(f"Target: {target}")
        self.info(f"Scan Type: {scan_type}")
        self.info(f"===================")
    
    def log_scan_complete(self, target: str, duration: float) -> None:
        """Log scan completion"""
        self.info(f"=== SCAN COMPLETED ===")
        self.info(f"Target: {target}")
        self.info(f"Duration: {duration:.2f} seconds")
        self.info(f"=====================")
    
    def log_tool_start(self, tool_name: str, target: str) -> None:
        """Log tool execution start"""
        self.info(f"🔧 Starting {tool_name} scan on {target}")
    
    def log_tool_complete(self, tool_name: str, duration: float, results_count: int = 0) -> None:
        """Log tool execution completion"""
        self.info(f"✅ {tool_name} completed in {duration:.2f}s ({results_count} results)")
    
    def log_tool_error(self, tool_name: str, error: str) -> None:
        """Log tool execution error"""
        self.error(f"❌ {tool_name} failed: {error}")
    
    def log_phase_start(self, phase_name: str) -> None:
        """Log scan phase start"""
        self.info(f"🚀 Starting phase: {phase_name}")
    
    def log_phase_complete(self, phase_name: str) -> None:
        """Log scan phase completion"""
        self.info(f"✅ Phase completed: {phase_name}")


class ColoredFormatter(logging.Formatter):
    """Colored console formatter"""
    
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
        'RESET': '\033[0m'       # Reset
    }
    
    def format(self, record):
        # Add color
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset = self.COLORS['RESET']
        
        # Format the message
        formatted = super().format(record)
        
        # Add color to level name only
        formatted = formatted.replace(
            record.levelname, 
            f"{color}{record.levelname}{reset}"
        )
        
        return formatted


class ProgressLogger:
    """Progress tracking logger"""
    
    def __init__(self, logger: ReconLogger, total_steps: int):
        self.logger = logger
        self.total_steps = total_steps
        self.current_step = 0
    
    def update(self, step_name: str, increment: int = 1) -> None:
        """Update progress"""
        self.current_step += increment
        percentage = (self.current_step / self.total_steps) * 100
        self.logger.info(f"📊 Progress: {percentage:.1f}% - {step_name}")
    
    def complete(self) -> None:
        """Mark progress as complete"""
        self.logger.info(f"📊 Progress: 100.0% - All tasks completed")
