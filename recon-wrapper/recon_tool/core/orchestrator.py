"""
Orchestrator - The Brain of the Reconnaissance System
Controls scan workflow, decides what runs when, manages resources
"""

import json
import logging
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from .logger import ReconLogger
from .state import StateManager
from .monitor import SystemMonitor  # Fixed: was ResourceMonitor
from .utils import ReconUtils
from .exceptions import ReconError, ScanError
from .validators import TargetValidator

# Import tool categories (commented out - these need to be implemented)
# from ..tools.network.nmap_tool import NmapTool
# from ..tools.network.masscan_tool import MasscanTool
# from ..tools.web.nikto_tool import NiktoTool
# from ..tools.web.gobuster_tool import GobusterTool
# from ..tools.web.ssl_tool import SSLTool
# from ..tools.osint.subdomain_tool import SubdomainTool
# from ..tools.osint.shodan_tool import ShodanTool

# Import reporting (commented out - needs to be implemented)
# from ..reporting.aggregator import ReportAggregator
# from ..reporting.dashboard.server import DashboardServer


class ReconOrchestrator:
    """Main orchestrator class - the brain of the system"""
    
    def __init__(self, config_manager):
        self.config = config_manager
        self.target = None
        self.target_type = None
        self.output_dir = None
        self.scan_id = None
        
        # Core components
        self.logger = None
        self.state_manager = None
        self.resource_monitor = None
        self.validator = TargetValidator()
        self.utils = ReconUtils()
        
        # Results and scanners
        self.results = {}
        self.scanners = {}
        self.scan_status = "idle"
        
        # Dashboard
        self.dashboard_server = None
        
        # Threading
        self.scan_thread = None
        self.stop_event = threading.Event()
    
    def initialize(self, target: str, scan_type: str = "full") -> bool:
        """Initialize orchestrator for scanning"""
        try:
            self.target = target
            self.scan_type = scan_type
            self.scan_id = self.utils.generate_scan_id()
            
            # Validate target
            if not self.validator.validate_target(target):
                raise ReconError(f"Invalid target: {target}")
            
            self.target_type = self.validator.get_target_type(target)
            
            # Setup output directory
            self.output_dir = self._create_output_directory()
            
            # Initialize logging
            self.logger = ReconLogger(self.output_dir, self.config)
            self.logger.info(f"Initializing scan for target: {target}")
            
            # Initialize state management
            self.state_manager = StateManager(self.output_dir, self.logger)
            
            # Initialize resource monitoring
            self.resource_monitor = SystemMonitor(self.logger)  # Fixed: was ResourceMonitor
            
            # Initialize scanners
            self._initialize_scanners()
            
            # Start dashboard if enabled
            if self.config.get('dashboard', 'enabled', True):
                self._start_dashboard()
            
            self.logger.info("Orchestrator initialization complete")
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Initialization failed: {str(e)}")
            else:
                print(f"❌ Initialization failed: {str(e)}")
            return False
    
    def _create_output_directory(self) -> Path:
        """Create output directory structure"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path(f"results/{self.target}_{timestamp}")
        
        # Create subdirectories
        subdirs = [
            "nmap", "subdomains", "web", "ssl", "osint", 
            "screenshots", "reports", "logs", "raw"
        ]
        
        for subdir in subdirs:
            (output_dir / subdir).mkdir(parents=True, exist_ok=True)
        
        return output_dir
    
    def _initialize_scanners(self) -> None:
        """Initialize all scanner tools"""
        self.scanners = {
            # Network scanners
            'nmap': NmapTool(self.output_dir, self.config, self.logger),
            'masscan': MasscanTool(self.output_dir, self.config, self.logger),
            
            # Web scanners
            'nikto': NiktoTool(self.output_dir, self.config, self.logger),
            'gobuster': GobusterTool(self.output_dir, self.config, self.logger),
            'ssl': SSLTool(self.output_dir, self.config, self.logger),
            
            # OSINT scanners
            'subdomain': SubdomainTool(self.output_dir, self.config, self.logger),
            'shodan': ShodanTool(self.output_dir, self.config, self.logger)
        }
        
        self.logger.info(f"Initialized {len(self.scanners)} scanner tools")
    
    def _start_dashboard(self) -> None:
        """Start the dashboard server"""
        try:
            dashboard_config = self.config.get_section('dashboard')
            self.dashboard_server = DashboardServer(
                self, 
                host=dashboard_config.get('host', '127.0.0.1'),
                port=dashboard_config.get('port', 8080)
            )
            self.dashboard_server.start()
            self.logger.info(f"Dashboard started at http://{dashboard_config.get('host')}:{dashboard_config.get('port')}")
        except Exception as e:
            self.logger.warning(f"Failed to start dashboard: {str(e)}")
    
    def start_scan(self) -> bool:
        """Start the reconnaissance scan"""
        try:
            if self.scan_status != "idle":
                raise ReconError("Scan already in progress")
            
            self.scan_status = "running"
            self.logger.info(f"Starting {self.scan_type} scan for {self.target}")
            
            # Start scan in separate thread
            self.scan_thread = threading.Thread(target=self._execute_scan)
            self.scan_thread.start()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start scan: {str(e)}")
            self.scan_status = "failed"
            return False
    
    def _execute_scan(self) -> None:
        """Execute the actual scanning workflow"""
        try:
            # Start resource monitoring
            self.resource_monitor.start_monitoring()
            
            # Determine scan workflow based on scan type
            workflow = self._get_scan_workflow(self.scan_type)
            
            # Execute workflow phases
            for phase_name, phase_config in workflow.items():
                if self.stop_event.is_set():
                    break
                
                self.logger.info(f"Starting phase: {phase_name}")
                self._execute_phase(phase_name, phase_config)
                
                # Save state after each phase
                self.state_manager.save_state(self.results, phase_name)
            
            # Generate reports
            if not self.stop_event.is_set():
                self._generate_reports()
            
            self.scan_status = "completed" if not self.stop_event.is_set() else "stopped"
            self.logger.info(f"Scan {self.scan_status}")
            
        except Exception as e:
            self.logger.error(f"Scan execution failed: {str(e)}")
            self.scan_status = "failed"
        finally:
            self.resource_monitor.stop_monitoring()
    
    def _get_scan_workflow(self, scan_type: str) -> Dict[str, Dict]:
        """Get workflow configuration based on scan type"""
        workflows = {
            "fast": {
                "discovery": {
                    "tools": ["nmap"],
                    "parallel": False,
                    "timeout": 300
                },
                "basic_web": {
                    "tools": ["nikto"],
                    "parallel": False,
                    "timeout": 600
                }
            },
            "full": {
                "network_discovery": {
                    "tools": ["nmap", "masscan"],
                    "parallel": True,
                    "timeout": 600
                },
                "subdomain_enum": {
                    "tools": ["subdomain"],
                    "parallel": False,
                    "timeout": 900
                },
                "web_scanning": {
                    "tools": ["nikto", "gobuster", "ssl"],
                    "parallel": True,
                    "timeout": 1200
                },
                "osint_collection": {
                    "tools": ["shodan"],
                    "parallel": False,
                    "timeout": 300
                }
            },
            "stealth": {
                "slow_discovery": {
                    "tools": ["nmap"],
                    "parallel": False,
                    "timeout": 900,
                    "rate_limit": 100
                }
            }
        }
        
        return workflows.get(scan_type, workflows["full"])
    
    def _execute_phase(self, phase_name: str, phase_config: Dict) -> None:
        """Execute a scan phase"""
        tools = phase_config.get('tools', [])
        parallel = phase_config.get('parallel', False)
        timeout = phase_config.get('timeout', 600)
        
        if parallel:
            self._execute_parallel_phase(phase_name, tools, timeout)
        else:
            self._execute_sequential_phase(phase_name, tools, timeout)
    
    def _execute_parallel_phase(self, phase_name: str, tools: List[str], timeout: int) -> None:
        """Execute tools in parallel"""
        max_workers = min(len(tools), self.config.get('general', 'threads', 5))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_tool = {
                executor.submit(self._run_tool, tool, timeout): tool 
                for tool in tools if tool in self.scanners
            }
            
            for future in as_completed(future_to_tool, timeout=timeout):
                tool = future_to_tool[future]
                try:
                    result = future.result()
                    self.results[tool] = result
                    self.logger.info(f"Tool {tool} completed successfully")
                except Exception as e:
                    self.logger.error(f"Tool {tool} failed: {str(e)}")
    
    def _execute_sequential_phase(self, phase_name: str, tools: List[str], timeout: int) -> None:
        """Execute tools sequentially"""
        for tool in tools:
            if self.stop_event.is_set():
                break
            
            if tool in self.scanners:
                try:
                    result = self._run_tool(tool, timeout)
                    self.results[tool] = result
                    self.logger.info(f"Tool {tool} completed successfully")
                except Exception as e:
                    self.logger.error(f"Tool {tool} failed: {str(e)}")
    
    def _run_tool(self, tool_name: str, timeout: int) -> Dict[str, Any]:
        """Run a specific scanner tool"""
        scanner = self.scanners[tool_name]
        
        # Set timeout for this tool
        scanner.set_timeout(timeout)
        
        # Execute the scan
        return scanner.scan(self.target)
    
    def _generate_reports(self) -> None:
        """Generate comprehensive reports"""
        try:
            self.logger.info("Generating reports...")
            
            aggregator = ReportAggregator(self.output_dir, self.config, self.logger)
            
            # Aggregate all results
            aggregated_results = aggregator.aggregate_results(self.results)
            
            # Generate different report formats
            report_config = self.config.get_section('reporting')
            
            if report_config.get('generate_json', True):
                aggregator.generate_json_report(aggregated_results)
            
            if report_config.get('generate_html', True):
                aggregator.generate_html_report(aggregated_results)
            
            if report_config.get('generate_csv', True):
                aggregator.generate_csv_report(aggregated_results)
            
            self.logger.info("Report generation completed")
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {str(e)}")
    
    def stop_scan(self) -> None:
        """Stop the current scan"""
        self.logger.info("Stopping scan...")
        self.stop_event.set()
        
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(timeout=30)
        
        self.scan_status = "stopped"
    
    def get_scan_status(self) -> Dict[str, Any]:
        """Get current scan status"""
        return {
            "status": self.scan_status,
            "target": self.target,
            "scan_type": self.scan_type,
            "scan_id": self.scan_id,
            "start_time": getattr(self, 'start_time', None),
            "progress": self._calculate_progress(),
            "resource_usage": self.resource_monitor.get_usage() if self.resource_monitor else {}
        }
    
    def _calculate_progress(self) -> float:
        """Calculate scan progress percentage"""
        if self.scan_status == "idle":
            return 0.0
        elif self.scan_status == "completed":
            return 100.0
        else:
            # Calculate based on completed tools
            total_tools = len(self.scanners)
            completed_tools = len(self.results)
            return (completed_tools / total_tools) * 100.0 if total_tools > 0 else 0.0
    
    def cleanup(self) -> None:
        """Cleanup resources"""
        if self.dashboard_server:
            self.dashboard_server.stop()
        
        if self.resource_monitor:
            self.resource_monitor.stop_monitoring()
        
        if self.logger:
            self.logger.info("Orchestrator cleanup completed")
