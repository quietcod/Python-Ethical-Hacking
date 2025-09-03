"""
Enhanced Logging System
Professional logging with rotation, metrics, and configurable formats
"""

import logging
import logging.handlers
import logging.config
import sys
import time
import json
import functools
from pathlib import Path
from typing import Optional, Dict, Any, Callable
from datetime import datetime
import threading
import traceback
import psutil
import os


class PerformanceMetrics:
    """Track performance metrics for logging"""
    
    def __init__(self):
        self.start_time = time.time()
        self.metrics = {
            'scans_completed': 0,
            'tools_executed': 0,
            'errors_encountered': 0,
            'warnings_generated': 0,
            'total_execution_time': 0,
            'memory_usage_peak': 0,
            'cpu_usage_peak': 0
        }
        self._lock = threading.Lock()
    
    def increment(self, metric: str, value: float = 1) -> None:
        """Thread-safe metric increment"""
        with self._lock:
            if metric in self.metrics:
                self.metrics[metric] += value
    
    def set_peak(self, metric: str, value: float) -> None:
        """Set peak value if current is higher"""
        with self._lock:
            if metric in self.metrics:
                self.metrics[metric] = max(self.metrics[metric], value)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics snapshot"""
        with self._lock:
            current_time = time.time()
            runtime = current_time - self.start_time
            
            # Add system metrics
            try:
                process = psutil.Process()
                memory_mb = process.memory_info().rss / 1024 / 1024
                cpu_percent = process.cpu_percent()
                
                self.set_peak('memory_usage_peak', memory_mb)
                self.set_peak('cpu_usage_peak', cpu_percent)
            except:
                pass
            
            return {
                **self.metrics,
                'runtime_seconds': runtime,
                'runtime_formatted': self._format_duration(runtime),
                'timestamp': datetime.now().isoformat()
            }
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format"""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{seconds/60:.1f}m"
        else:
            return f"{seconds/3600:.1f}h"


class EnhancedLogFormatter(logging.Formatter):
    """Enhanced formatter with context and metrics"""
    
    def __init__(self, fmt=None, datefmt=None, include_context=True, include_metrics=False):
        super().__init__(fmt, datefmt)
        self.include_context = include_context
        self.include_metrics = include_metrics
        
    def format(self, record):
        # Add context information
        if self.include_context:
            record.thread_name = threading.current_thread().name
            record.process_id = os.getpid()
            
            # Add function context
            if hasattr(record, 'funcName') and record.funcName != '<module>':
                record.context = f"{record.module}.{record.funcName}"
            else:
                record.context = record.module
        
        # Add performance context for errors
        if record.levelno >= logging.ERROR and hasattr(record, 'exc_info') and record.exc_info:
            record.stack_trace = ''.join(traceback.format_exception(*record.exc_info))
        else:
            record.stack_trace = ''  # Ensure field always exists
        
        return super().format(record)


class ColoredFormatter(EnhancedLogFormatter):
    """Colored console formatter with enhanced features"""
    
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
        'RESET': '\033[0m'       # Reset
    }
    
    ICONS = {
        'DEBUG': '🔍',
        'INFO': 'ℹ️ ',
        'WARNING': '⚠️ ',
        'ERROR': '❌',
        'CRITICAL': '🚨'
    }
    
    def format(self, record):
        # Add color and icon
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset = self.COLORS['RESET']
        icon = self.ICONS.get(record.levelname, '')
        
        # Format the message with enhanced formatting
        formatted = super().format(record)
        
        # Add color to level name and icon
        colored_level = f"{color}{icon} {record.levelname}{reset}"
        formatted = formatted.replace(record.levelname, colored_level)
        
        return formatted


class JsonFormatter(EnhancedLogFormatter):
    """JSON formatter for structured logging"""
    
    def format(self, record):
        log_obj = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'thread': threading.current_thread().name,
            'process_id': os.getpid()
        }
        
        # Add exception info if present
        if record.exc_info:
            log_obj['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': traceback.format_exception(*record.exc_info)
            }
        
        # Add custom fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 
                          'filename', 'module', 'exc_info', 'exc_text', 'stack_info',
                          'lineno', 'funcName', 'created', 'msecs', 'relativeCreated',
                          'thread', 'threadName', 'processName', 'process', 'getMessage']:
                log_obj[key] = value
        
        return json.dumps(log_obj, default=str)


def performance_logger(func: Callable) -> Callable:
    """Decorator to log function performance"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        logger = logging.getLogger(func.__module__)
        
        try:
            # Log function start
            logger.debug(f"🚀 Starting {func.__name__} with args={len(args)}, kwargs={len(kwargs)}")
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Log successful completion
            duration = time.time() - start_time
            logger.info(f"✅ {func.__name__} completed in {duration:.3f}s")
            
            # Update metrics if available
            if hasattr(args[0], 'metrics') and isinstance(args[0].metrics, PerformanceMetrics):
                args[0].metrics.increment('tools_executed')
                args[0].metrics.increment('total_execution_time', duration)
            
            return result
            
        except Exception as e:
            # Log error with context
            duration = time.time() - start_time
            logger.error(f"❌ {func.__name__} failed after {duration:.3f}s: {str(e)}", exc_info=True)
            
            # Update error metrics
            if hasattr(args[0], 'metrics') and isinstance(args[0].metrics, PerformanceMetrics):
                args[0].metrics.increment('errors_encountered')
            
            raise
    
    return wrapper


def setup_logger(name: str = "recon_tool", level: int = logging.INFO, log_file: Optional[Path] = None) -> logging.Logger:
    """Enhanced logger setup function with all improvements"""
    logger = logging.getLogger(name)
    
    # Clear any existing handlers
    logger.handlers.clear()
    logger.setLevel(level)
    
    # Create enhanced formatter
    formatter = EnhancedLogFormatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(context)s:%(lineno)d] - %(message)s',
        include_context=True
    )
    
    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(ColoredFormatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    logger.addHandler(console_handler)
    
    # File handler with rotation if log_file specified
    if log_file:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10*1024*1024, backupCount=5  # 10MB files, 5 backups
        )
        file_handler.setLevel(logging.DEBUG)  # File gets all logs
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        # JSON log handler for structured logging
        json_log_file = log_file.parent / f"{log_file.stem}_structured.json"
        json_handler = logging.handlers.RotatingFileHandler(
            json_log_file, maxBytes=10*1024*1024, backupCount=3
        )
        json_handler.setLevel(logging.INFO)
        json_handler.setFormatter(JsonFormatter())
        logger.addHandler(json_handler)
    
    # Prevent duplicate logs
    logger.propagate = False
    
    return logger


class ReconLogger:
    """Enhanced centralized logging system for reconnaissance operations"""
    
    def __init__(self, output_dir: Path, config, logger_name: str = "recon_tool"):
        self.output_dir = output_dir
        self.config = config
        self.logger_name = logger_name
        self.metrics = PerformanceMetrics()
        
        # Create logger
        self.logger = logging.getLogger(logger_name)
        self._setup_logger()
        
        # Performance logging
        self._start_time = time.time()
        self._last_metrics_log = time.time()
        
    def _setup_logger(self) -> None:
        """Setup logger with enhanced features"""
        # Clear any existing handlers
        self.logger.handlers.clear()
        
        # Get logging configuration
        log_config = self.config.get_section('logging')
        log_level = getattr(logging, log_config.get('level', 'INFO').upper())
        
        self.logger.setLevel(log_level)
        
        # Create logs directory
        logs_dir = self.output_dir / "logs"
        logs_dir.mkdir(exist_ok=True)
        
        # Setup main log file with rotation
        if log_config.get('file_logging', True):
            main_log_file = logs_dir / "recon_tool.log"
            max_bytes = self._parse_size(log_config.get('max_file_size', '10MB'))
            backup_count = log_config.get('backup_count', 5)
            
            # Enhanced formatter with context
            file_formatter = EnhancedLogFormatter(
                log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - [%(context)s:%(lineno)d] - %(message)s'),
                include_context=True,
                include_metrics=True
            )
            
            file_handler = logging.handlers.RotatingFileHandler(
                main_log_file, maxBytes=max_bytes, backupCount=backup_count
            )
            file_handler.setFormatter(file_formatter)
            file_handler.setLevel(logging.DEBUG)
            self.logger.addHandler(file_handler)
        
        # Setup console handler with colors
        if log_config.get('console_logging', True):
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(ColoredFormatter(
                log_config.get('console_format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            ))
            console_handler.setLevel(log_level)
            self.logger.addHandler(console_handler)
        
        # Setup error file handler
        error_file = logs_dir / "errors.log"
        error_handler = logging.handlers.RotatingFileHandler(
            error_file, maxBytes=5*1024*1024, backupCount=3
        )
        error_formatter = EnhancedLogFormatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(context)s:%(lineno)d] - %(message)s\n%(stack_trace)s',
            include_context=True
        )
        error_handler.setFormatter(error_formatter)
        error_handler.setLevel(logging.ERROR)
        self.logger.addHandler(error_handler)
        
        # Setup JSON structured logging
        json_log_file = logs_dir / "structured.json"
        json_handler = logging.handlers.RotatingFileHandler(
            json_log_file, maxBytes=10*1024*1024, backupCount=3
        )
        json_handler.setFormatter(JsonFormatter())
        json_handler.setLevel(logging.INFO)
        self.logger.addHandler(json_handler)
        
        # Setup performance metrics logging
        metrics_file = logs_dir / "performance.log"
        self.metrics_handler = logging.handlers.RotatingFileHandler(
            metrics_file, maxBytes=5*1024*1024, backupCount=2
        )
        metrics_formatter = logging.Formatter('%(asctime)s - METRICS - %(message)s')
        self.metrics_handler.setFormatter(metrics_formatter)
        
        # Create metrics logger
        self.metrics_logger = logging.getLogger(f"{self.logger_name}.metrics")
        self.metrics_logger.addHandler(self.metrics_handler)
        self.metrics_logger.setLevel(logging.INFO)
        self.metrics_logger.propagate = False
    
    def _parse_size(self, size_str: str) -> int:
        """Parse size string like '10MB' to bytes"""
        size_str = size_str.upper()
        multipliers = {'KB': 1024, 'MB': 1024**2, 'GB': 1024**3}
        
        for suffix, multiplier in multipliers.items():
            if size_str.endswith(suffix):
                return int(size_str[:-len(suffix)]) * multiplier
        
        return int(size_str)
    
    def log_performance_metrics(self, force: bool = False) -> None:
        """Log current performance metrics"""
        current_time = time.time()
        
        # Log metrics every 60 seconds or when forced
        if force or (current_time - self._last_metrics_log) > 60:
            metrics = self.metrics.get_metrics()
            self.metrics_logger.info(json.dumps(metrics, indent=2))
            self._last_metrics_log = current_time
    
    def debug(self, message: str, **kwargs) -> None:
        """Log debug message with context"""
        self.logger.debug(message, extra=kwargs)
    
    def info(self, message: str, **kwargs) -> None:
        """Log info message with context"""
        self.logger.info(message, extra=kwargs)
        self.log_performance_metrics()  # Periodic metrics logging
    
    def warning(self, message: str, **kwargs) -> None:
        """Log warning message with context"""
        self.logger.warning(message, extra=kwargs)
        self.metrics.increment('warnings_generated')
    
    def error(self, message: str, exception: Exception = None, **kwargs) -> None:
        """Log error message with enhanced context"""
        if exception:
            kwargs['exception_type'] = type(exception).__name__
            kwargs['exception_message'] = str(exception)
            self.logger.error(message, exc_info=True, extra=kwargs)
        else:
            self.logger.error(message, extra=kwargs)
        
        self.metrics.increment('errors_encountered')
    
    def critical(self, message: str, **kwargs) -> None:
        """Log critical message with context"""
        self.logger.critical(message, extra=kwargs)
        self.metrics.increment('errors_encountered')
    
    def log_scan_start(self, target: str, scan_type: str, tools: list) -> None:
        """Log scan start with enhanced context"""
        self.info(f"=== SCAN STARTED ===", 
                 target=target, scan_type=scan_type, tools=tools,
                 scan_id=f"scan_{int(time.time())}")
        self.info(f"Target: {target}")
        self.info(f"Scan Type: {scan_type}")
        self.info(f"Tools: {', '.join(tools) if tools else 'All available'}")
        self.info(f"===================")
    
    def log_scan_complete(self, target: str, duration: float, results_summary: dict = None) -> None:
        """Log scan completion with metrics"""
        self.info(f"=== SCAN COMPLETED ===")
        self.info(f"Target: {target}")
        self.info(f"Duration: {duration:.2f} seconds")
        
        if results_summary:
            for key, value in results_summary.items():
                self.info(f"{key.title()}: {value}")
        
        self.info(f"=====================")
        self.metrics.increment('scans_completed')
        self.log_performance_metrics(force=True)
    
    def log_tool_start(self, tool_name: str, target: str, **kwargs) -> None:
        """Log tool execution start with context"""
        self.info(f"🔧 Starting {tool_name} scan on {target}", 
                 tool=tool_name, target=target, **kwargs)
    
    def log_tool_complete(self, tool_name: str, duration: float, results_count: int = 0, **kwargs) -> None:
        """Log tool execution completion with metrics"""
        self.info(f"✅ {tool_name} completed in {duration:.2f}s ({results_count} results)", 
                 tool=tool_name, duration=duration, results_count=results_count, **kwargs)
        self.metrics.increment('tools_executed')
        self.metrics.increment('total_execution_time', duration)
    
    def log_tool_error(self, tool_name: str, error: str, exception: Exception = None, **kwargs) -> None:
        """Log tool execution error with enhanced context"""
        self.error(f"❌ {tool_name} failed: {error}", 
                  exception=exception, tool=tool_name, **kwargs)
    
    def log_phase_start(self, phase_name: str, **kwargs) -> None:
        """Log scan phase start"""
        self.info(f"🚀 Starting phase: {phase_name}", phase=phase_name, **kwargs)
    
    def log_phase_complete(self, phase_name: str, duration: float = None, **kwargs) -> None:
        """Log scan phase completion"""
        if duration:
            self.info(f"✅ Phase completed: {phase_name} ({duration:.2f}s)", 
                     phase=phase_name, duration=duration, **kwargs)
        else:
            self.info(f"✅ Phase completed: {phase_name}", phase=phase_name, **kwargs)
    
    def log_system_info(self) -> None:
        """Log system information for debugging"""
        try:
            import platform
            process = psutil.Process()
            
            system_info = {
                'platform': platform.platform(),
                'python_version': platform.python_version(),
                'memory_total': psutil.virtual_memory().total / 1024**3,  # GB
                'memory_available': psutil.virtual_memory().available / 1024**3,  # GB
                'cpu_count': psutil.cpu_count(),
                'process_memory': process.memory_info().rss / 1024**2,  # MB
                'process_cpu_percent': process.cpu_percent()
            }
            
            self.info("System Information:", **system_info)
            
        except Exception as e:
            self.error(f"Failed to collect system info: {e}")
    
    def close(self) -> None:
        """Close logger and log final metrics"""
        self.log_performance_metrics(force=True)
        
        # Close all handlers
        for handler in self.logger.handlers:
            handler.close()
        
        for handler in self.metrics_logger.handlers:
            handler.close()


class ProgressLogger:
    """Enhanced progress tracking logger with metrics"""
    
    def __init__(self, logger: ReconLogger, total_steps: int, operation_name: str = "Operation"):
        self.logger = logger
        self.total_steps = total_steps
        self.current_step = 0
        self.operation_name = operation_name
        self.start_time = time.time()
        self.step_times = []
    
    def update(self, step_name: str, increment: int = 1, **kwargs) -> None:
        """Update progress with enhanced metrics"""
        step_start = time.time()
        self.current_step += increment
        percentage = (self.current_step / self.total_steps) * 100
        
        # Calculate ETA
        elapsed = step_start - self.start_time
        if self.current_step > 0:
            avg_step_time = elapsed / self.current_step
            remaining_steps = self.total_steps - self.current_step
            eta = remaining_steps * avg_step_time
            eta_str = f", ETA: {eta:.1f}s" if eta > 1 else ""
        else:
            eta_str = ""
        
        self.logger.info(f"📊 Progress: {percentage:.1f}% - {step_name}{eta_str}", 
                        progress=percentage, step=step_name, 
                        operation=self.operation_name, **kwargs)
        
        step_end = time.time()
        self.step_times.append(step_end - step_start)
    
    def complete(self) -> None:
        """Mark progress as complete with final metrics"""
        total_time = time.time() - self.start_time
        avg_step_time = sum(self.step_times) / len(self.step_times) if self.step_times else 0
        
        self.logger.info(f"📊 Progress: 100.0% - {self.operation_name} completed", 
                        total_time=total_time, avg_step_time=avg_step_time,
                        total_steps=self.total_steps)


# Export performance decorator for easy use
__all__ = ['ReconLogger', 'ProgressLogger', 'setup_logger', 'performance_logger', 'PerformanceMetrics']
