"""
Default Configuration Values
Comprehensive default settings for all components
"""

DEFAULT_CONFIG = {
    "general": {
        "version": "2.0",
        "timeout": 300,
        "threads": 20,
        "rate_limit": 1000,
        "verbose": False,
        "offline_mode": False,
        "light_mode": False,
        "output_format": "json",
        "save_raw_output": True
    },
    
    "scanning": {
        "nmap": {
            "basic_flags": "-sV -sC",
            "aggressive_flags": "-A -T4",
            "timeout": 600,
            "max_ports": 65535
        },
        "masscan": {
            "rate": 1000,
            "timeout": 300,
            "max_rate": 10000
        },
        "nikto": {
            "timeout": 600,
            "max_scan_time": 1800
        },
        "gobuster": {
            "threads": 50,
            "timeout": 300,
            "wordlist": "/usr/share/wordlists/dirb/common.txt"
        },
        "ffuf": {
            "threads": 40,
            "timeout": 300,
            "wordlist": "/usr/share/wordlists/dirb/common.txt"
        }
    },
    
    "subdomains": {
        "timeout": 300,
        "threads": 20,
        "max_subdomains": 1000,
        "validate_live": True,
        "tools": ["sublist3r", "assetfinder", "subfinder"]
    },
    
    "web": {
        "timeout": 300,
        "user_agent": "ReconTool/2.0",
        "follow_redirects": True,
        "verify_ssl": False,
        "max_redirects": 5
    },
    
    "ssl": {
        "timeout": 30,
        "check_heartbleed": True,
        "check_poodle": True,
        "check_beast": True,
        "verify_chain": True
    },
    
    "osint": {
        "timeout": 60,
        "shodan_api_key": None,
        "censys_api_id": None,
        "censys_api_secret": None,
        "virustotal_api_key": None,
        "max_results": 100
    },
    
    "reporting": {
        "generate_html": True,
        "generate_json": True,
        "generate_csv": True,
        "generate_pdf": False,
        "include_screenshots": True,
        "risk_scoring": True,
        "compliance_mapping": True
    },
    
    "dashboard": {
        "enabled": True,
        "host": "127.0.0.1",
        "port": 8080,
        "debug": False,
        "auto_refresh": 30,
        "enable_websockets": True
    },
    
    "dns": {
        "servers": ["8.8.8.8", "1.1.1.1"],
        "timeout": 10,
        "retries": 3,
        "check_dnssec": True
    },
    
    "logging": {
        "level": "INFO",
        
        # File Logging Settings
        "file_logging": True,
        "console_logging": True,
        
        # Log Rotation Settings
        "max_file_size": "10MB",
        "backup_count": 5,
        "max_logs_days": 30,  # Auto-cleanup logs older than 30 days
        
        # Log Formats
        "format": "%(asctime)s - %(name)s - %(levelname)s - [%(context)s:%(lineno)d] - %(message)s",
        "console_format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        "json_format": True,  # Enable structured JSON logging
        "include_context": True,  # Include function/module context
        
        # Performance Metrics
        "performance_logging": True,
        "metrics_interval": 60,  # Log metrics every 60 seconds
        "track_memory": True,
        "track_cpu": True,
        "track_timing": True,
        
        # Error Context
        "enhanced_errors": True,
        "include_stack_traces": True,
        "error_context_lines": 5,
        
        # Log Files Structure
        "log_files": {
            "main": "recon_tool.log",
            "errors": "errors.log",
            "structured": "structured.json",
            "performance": "performance.log",
            "debug": "debug.log"
        },
        
        # Log Levels per Component
        "component_levels": {
            "orchestrator": "INFO",
            "tools": "INFO",
            "reporting": "INFO",
            "config": "WARNING",
            "utils": "WARNING"
        },
        
        # Advanced Features
        "log_compression": True,  # Compress rotated logs
        "remote_logging": False,  # For future syslog/remote logging
        "log_filtering": {
            "suppress_warnings": [],  # List of warning patterns to suppress
            "highlight_patterns": []   # Patterns to highlight in logs
        }
    },
    
    "performance": {
        "max_memory_usage": "1GB",
        "max_cpu_usage": 80,
        "disk_space_threshold": "100MB",
        "enable_caching": True,
        "cache_duration": 3600
    }
}
