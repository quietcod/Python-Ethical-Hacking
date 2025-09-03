# Enhanced Logging System Documentation

## Overview
The ReconTool now features a comprehensive, production-ready logging system with advanced capabilities for monitoring, debugging, and performance analysis.

## ✨ Key Features Implemented

### 1. 🔄 Advanced Log Rotation
- **Size-based rotation**: Configurable file size limits (default: 10MB)
- **Time-based rotation**: Automatic cleanup of old logs
- **Compressed backups**: Rotated logs are compressed to save space
- **Multiple retention policies**: Different retention for different log types

### 2. 📊 Configurable Log Formats
- **Standard Format**: Human-readable with context information
- **JSON Format**: Structured logging for automated analysis
- **Colored Console**: Enhanced readability with icons and colors
- **Custom Patterns**: Configurable format strings with context

### 3. 📈 Performance Metrics Logging
- **Execution Timing**: Track function and tool execution times
- **System Resources**: Monitor memory and CPU usage
- **Operation Counters**: Track scans, tools executed, errors
- **Automated Metrics**: Periodic performance snapshots

### 4. 🔍 Enhanced Error Context
- **Stack Traces**: Full exception information with context
- **Component Identification**: Know exactly where errors occur
- **Error Classification**: Different handling for different error types
- **Recovery Suggestions**: Context-aware error messages

## 📁 Log File Structure

```
logs/
├── recon_tool.log          # Main application log with context
├── structured.json         # JSON formatted logs for analysis
├── performance.log         # Performance metrics and timings
├── errors.log             # Error-only log with full context
└── debug.log              # Detailed debugging information
```

## 🛠️ Configuration Options

### Basic Configuration
```json
{
  "logging": {
    "level": "INFO",
    "file_logging": true,
    "console_logging": true,
    
    "max_file_size": "10MB",
    "backup_count": 5,
    "max_logs_days": 30,
    
    "format": "%(asctime)s - %(name)s - %(levelname)s - [%(context)s:%(lineno)d] - %(message)s",
    "console_format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  }
}
```

### Advanced Configuration
```json
{
  "logging": {
    "performance_logging": true,
    "metrics_interval": 60,
    "track_memory": true,
    "track_cpu": true,
    "track_timing": true,
    
    "enhanced_errors": true,
    "include_stack_traces": true,
    "error_context_lines": 5,
    
    "component_levels": {
      "orchestrator": "INFO",
      "tools": "INFO",
      "reporting": "INFO",
      "config": "WARNING"
    }
  }
}
```

## 🎯 Usage Examples

### Basic Logging
```python
from recon_tool.core.logger import ReconLogger

# Initialize logger
logger = ReconLogger(output_dir, config)

# Log different levels
logger.info("Scan started", target="example.com", scan_type="comprehensive")
logger.warning("Rate limit approaching", current_rate=950, limit=1000)
logger.error("Tool failed", tool="nmap", error_code="TIMEOUT")
```

### Performance Logging with Decorator
```python
from recon_tool.core.logger import performance_logger

class ToolRunner:
    def __init__(self):
        self.metrics = PerformanceMetrics()
    
    @performance_logger
    def run_nmap(self, target):
        # Tool execution code
        return results
```

### Scan Lifecycle Logging
```python
# Scan start
logger.log_scan_start(target, scan_type, tools_list)

# Phase tracking
logger.log_phase_start("Discovery", targets_count=1)
logger.log_phase_complete("Discovery", duration=2.5, discoveries=15)

# Tool execution
logger.log_tool_start("nmap", target, version="7.80")
logger.log_tool_complete("nmap", duration=45.2, results_count=8)

# Scan completion
logger.log_scan_complete(target, total_duration, results_summary)
```

### Progress Tracking
```python
from recon_tool.core.logger import ProgressLogger

progress = ProgressLogger(logger, total_steps=10, "Port Scanning")
for i in range(10):
    # Do work
    progress.update(f"Scanning port {i+1}")
progress.complete()
```

## 📊 Performance Metrics

### Automatic Metrics Tracking
- **Scans Completed**: Number of successful scans
- **Tools Executed**: Count of individual tool runs
- **Errors Encountered**: Error tracking with categorization
- **Execution Times**: Detailed timing for all operations
- **Resource Usage**: Memory and CPU peak usage
- **System Information**: Platform and environment details

### Metrics Output Example
```json
{
  "scans_completed": 5,
  "tools_executed": 23,
  "errors_encountered": 2,
  "total_execution_time": 245.7,
  "memory_usage_peak": 156.8,
  "cpu_usage_peak": 78.5,
  "runtime_seconds": 301.2,
  "runtime_formatted": "5.0m",
  "timestamp": "2025-08-25T14:30:00"
}
```

## 🎨 Console Output Features

### Colored Log Levels
- 🔍 **DEBUG**: Cyan with magnifying glass
- ℹ️ **INFO**: Green with info icon
- ⚠️ **WARNING**: Yellow with warning icon
- ❌ **ERROR**: Red with X mark
- 🚨 **CRITICAL**: Magenta with alarm

### Context Information
- **Function Context**: Show module.function for better debugging
- **Line Numbers**: Exact location of log entries
- **Thread Information**: Multi-threaded operation tracking
- **Process ID**: System-level debugging support

## 🔧 Advanced Features

### 1. Structured JSON Logging
```json
{
  "timestamp": "2025-08-25T14:30:00.123456",
  "level": "INFO",
  "logger": "recon_tool",
  "message": "Nmap scan completed",
  "module": "nmap_tool",
  "function": "run_scan",
  "line": 145,
  "thread": "ScanThread-001",
  "process_id": 12345,
  "tool": "nmap",
  "target": "example.com",
  "duration": 45.2,
  "results_count": 8
}
```

### 2. Error Context Enhancement
```python
try:
    run_tool()
except Exception as e:
    logger.error("Tool execution failed", 
                exception=e,
                tool="nmap", 
                target="example.com",
                error_code="TOOL_TIMEOUT",
                recovery_action="retry_with_shorter_timeout")
```

### 3. Performance Decorators
```python
@performance_logger
def expensive_operation(self, param1, param2):
    # Automatically logs:
    # - Function start with parameters count
    # - Execution duration
    # - Success/failure status
    # - Updates performance metrics
    pass
```

## 📋 Log Analysis

### Using JSON Logs for Analysis
```bash
# Count errors by tool
jq '.tool' logs/structured.json | grep -v null | sort | uniq -c

# Average execution time by tool
jq 'select(.duration) | {tool: .tool, duration: .duration}' logs/structured.json

# Find all critical errors
jq 'select(.level == "CRITICAL")' logs/structured.json
```

### Performance Metrics Analysis
```bash
# View latest performance metrics
tail -n 1 logs/performance.log | jq .

# Track memory usage over time
grep "METRICS" logs/performance.log | jq '.memory_usage_peak'
```

## 🚀 Integration with ReconTool

### Orchestrator Integration
The orchestrator now provides comprehensive logging throughout the scan lifecycle:

1. **Scan Initialization**: System info, configuration validation
2. **Phase Execution**: Detailed phase tracking with timings
3. **Tool Execution**: Individual tool performance and results
4. **Error Handling**: Enhanced error context and recovery info
5. **Completion**: Full scan summary with metrics

### Real-time Monitoring
- **Console Output**: Real-time colored logs with progress
- **File Logging**: Persistent detailed logs for analysis
- **Metrics Collection**: Continuous performance monitoring
- **Error Tracking**: Immediate error notification with context

## 🔮 Future Enhancements

### Planned Features
- **Remote Logging**: Send logs to centralized systems
- **Log Aggregation**: Combine logs from multiple scans
- **Alert System**: Real-time alerts for critical issues
- **Dashboard Integration**: Live log viewing in web interface
- **Custom Formatters**: User-defined log formats
- **Log Compression**: Automatic compression of old logs

## ✅ Conclusion

The enhanced logging system provides:
- **Production-ready** logging with enterprise-grade features
- **Comprehensive monitoring** of all system operations
- **Easy debugging** with rich context and error information
- **Performance optimization** through detailed metrics
- **Flexible configuration** for different deployment scenarios
- **Future-proof design** for scaling and additional features

This logging system ensures that ReconTool provides visibility into all operations, making it suitable for professional security assessments and enterprise deployments.
