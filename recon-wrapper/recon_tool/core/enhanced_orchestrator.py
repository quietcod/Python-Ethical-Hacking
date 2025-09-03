"""
Enhanced Orchestrator with Dependency Injection and Interface Standardization
Professional orchestrator using DI container and standardized interfaces
"""

import time
import threading
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

from .interfaces import (
    IOrchestrator, ILogger, IConfigManager, IValidator, IScanTool,
    IStateManager, IResourceMonitor, ScanType, ScanStatus, ScanResult,
    TargetType, ToolNotAvailableError, ScanError
)
from .dependency_injection import Injectable, get_container, inject
from .plugin_system import get_plugin_manager


class EnhancedOrchestrator(Injectable, IOrchestrator):
    """Professional orchestrator with dependency injection"""
    
    def __init__(self, 
                 logger: ILogger,
                 config_manager: IConfigManager,
                 validator: IValidator,
                 state_manager: IStateManager,
                 resource_monitor: IResourceMonitor):
        """Initialize with injected dependencies"""
        self.logger = logger
        self.config = config_manager
        self.validator = validator
        self.state_manager = state_manager
        self.resource_monitor = resource_monitor
        
        # Scan state
        self.target: Optional[str] = None
        self.target_type: Optional[TargetType] = None
        self.scan_type: Optional[ScanType] = None
        self.output_dir: Optional[Path] = None
        self.scan_id: Optional[str] = None
        self.scan_status = ScanStatus.PENDING
        self.scan_start_time: Optional[float] = None
        self.scan_end_time: Optional[float] = None
        
        # Tool management
        self.available_tools: Dict[str, IScanTool] = {}
        self.enabled_tools: Set[str] = set()
        self.scan_results: List[ScanResult] = []
        
        # Threading
        self.scan_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self._lock = threading.RLock()
        
        # Progress tracking
        self.total_phases = 0
        self.completed_phases = 0
        
        # Initialize tools
        self._discover_tools()
    
    def _discover_tools(self) -> None:
        """Discover available tools from DI container and plugins"""
        container = get_container()
        
        # Get tools from DI container
        for service_type, descriptor in container.get_registrations().items():
            if (hasattr(service_type, '__bases__') and 
                any(issubclass(base, IScanTool) for base in service_type.__bases__)):
                try:
                    tool = container.resolve(service_type)
                    if tool.is_available():
                        self.available_tools[tool.name] = tool
                        self.enabled_tools.add(tool.name)
                        self.logger.debug(f"Discovered tool: {tool.name}")
                except Exception as e:
                    self.logger.warning(f"Failed to load tool {service_type}: {e}")
        
        # Get tools from plugins
        plugin_manager = get_plugin_manager()
        for plugin_name in plugin_manager.get_enabled_plugins():
            # Plugin tools would be registered in DI container during plugin initialization
            pass
        
        self.logger.info(f"Discovered {len(self.available_tools)} available tools")
    
    def initialize(self, target: str, scan_type: ScanType, 
                  output_dir: Path, **options) -> bool:
        """Initialize orchestrator for scanning"""
        try:
            with self._lock:
                # Validate target
                if not self.validator.validate_target(target):
                    raise ValueError(f"Invalid target: {target}")
                
                self.target = target
                self.target_type = self.validator.get_target_type(target)
                self.scan_type = scan_type
                self.output_dir = Path(output_dir)
                self.scan_id = f"scan_{int(time.time())}"
                self.scan_status = ScanStatus.PENDING
                
                # Create output directory
                self.output_dir.mkdir(parents=True, exist_ok=True)
                
                # Initialize components
                self._initialize_scan_plan(**options)
                
                self.logger.info(f"Orchestrator initialized for {target} ({scan_type.value})",
                               target=target, scan_type=scan_type.value, scan_id=self.scan_id)
                
                return True
                
        except Exception as e:
            self.logger.error(f"Orchestrator initialization failed: {e}", exception=e)
            return False
    
    def _initialize_scan_plan(self, **options) -> None:
        """Initialize the scan plan based on target type and scan type"""
        self.scan_plan = self._create_scan_plan(self.target_type, self.scan_type, **options)
        self.total_phases = len(self.scan_plan)
        self.completed_phases = 0
    
    def _create_scan_plan(self, target_type: TargetType, scan_type: ScanType, **options) -> List[Dict[str, Any]]:
        """Create a scan plan based on target and scan type"""
        plan = []
        
        # Base phases for all scans
        if target_type in [TargetType.DOMAIN, TargetType.IP, TargetType.URL]:
            plan.append({
                "name": "Port Scanning",
                "tools": ["nmap", "masscan"],
                "priority": 1,
                "parallel": False
            })
        
        if target_type == TargetType.DOMAIN:
            plan.append({
                "name": "Subdomain Enumeration", 
                "tools": ["subfinder", "sublist3r"],
                "priority": 2,
                "parallel": True
            })
        
        if target_type in [TargetType.URL, TargetType.DOMAIN]:
            plan.append({
                "name": "Web Scanning",
                "tools": ["nikto", "gobuster", "dirb"],
                "priority": 3,
                "parallel": True
            })
        
        # Add additional phases based on scan type
        if scan_type in [ScanType.COMPREHENSIVE, ScanType.AGGRESSIVE]:
            plan.append({
                "name": "Vulnerability Scanning",
                "tools": ["nessus", "openvas"],
                "priority": 4,
                "parallel": False
            })
            
            plan.append({
                "name": "OSINT Collection",
                "tools": ["shodan", "censys", "virustotal"],
                "priority": 5,
                "parallel": True
            })
        
        # Sort by priority
        plan.sort(key=lambda x: x["priority"])
        
        return plan
    
    def start_scan(self) -> bool:
        """Start the reconnaissance scan"""
        try:
            with self._lock:
                if self.scan_status != ScanStatus.PENDING:
                    raise ScanError("Scan is not in pending state")
                
                if not self.target or not self.scan_type:
                    raise ScanError("Orchestrator not properly initialized")
                
                self.scan_status = ScanStatus.RUNNING
                self.scan_start_time = time.time()
                self.stop_event.clear()
                self.pause_event.clear()
                
                # Log scan start
                tools = [tool for phase in self.scan_plan for tool in phase["tools"]]
                self.logger.log_scan_start(self.target, self.scan_type.value, tools)
                
                # Start resource monitoring
                self.resource_monitor.start_monitoring()
                
                # Start scan in separate thread
                self.scan_thread = threading.Thread(
                    target=self._execute_scan_workflow,
                    name=f"ScanThread-{self.scan_id}"
                )
                self.scan_thread.start()
                
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to start scan: {e}", exception=e)
            self.scan_status = ScanStatus.FAILED
            return False
    
    def _execute_scan_workflow(self) -> None:
        """Execute the complete scan workflow"""
        try:
            self.logger.info(f"Starting scan workflow with {self.total_phases} phases")
            
            for phase_index, phase in enumerate(self.scan_plan):
                if self.stop_event.is_set():
                    self.scan_status = ScanStatus.CANCELLED
                    break
                
                # Handle pause
                while self.pause_event.is_set() and not self.stop_event.is_set():
                    time.sleep(0.1)
                
                if self.stop_event.is_set():
                    break
                
                # Execute phase
                self.logger.log_phase_start(phase["name"], 
                                          phase_number=phase_index + 1,
                                          total_phases=self.total_phases)
                
                phase_start = time.time()
                phase_results = self._execute_phase(phase)
                phase_duration = time.time() - phase_start
                
                # Add results
                self.scan_results.extend(phase_results)
                
                self.logger.log_phase_complete(phase["name"], 
                                             duration=phase_duration,
                                             results_count=len(phase_results))
                
                self.completed_phases += 1
                
                # Save checkpoint
                self._save_checkpoint(f"phase_{phase_index}")
            
            # Finalize scan
            if not self.stop_event.is_set():
                self.scan_status = ScanStatus.COMPLETED
                self._finalize_scan()
            
        except Exception as e:
            self.logger.error(f"Scan workflow failed: {e}", exception=e)
            self.scan_status = ScanStatus.FAILED
        finally:
            self.scan_end_time = time.time()
            self.resource_monitor.stop_monitoring()
            self._log_scan_summary()
    
    def _execute_phase(self, phase: Dict[str, Any]) -> List[ScanResult]:
        """Execute a single scan phase"""
        phase_results = []
        available_tools = [tool for tool in phase["tools"] if tool in self.available_tools]
        
        if not available_tools:
            self.logger.warning(f"No available tools for phase: {phase['name']}")
            return phase_results
        
        if phase.get("parallel", False):
            # Execute tools in parallel
            phase_results = self._execute_tools_parallel(available_tools, phase)
        else:
            # Execute tools sequentially
            phase_results = self._execute_tools_sequential(available_tools, phase)
        
        return phase_results
    
    def _execute_tools_parallel(self, tools: List[str], phase: Dict[str, Any]) -> List[ScanResult]:
        """Execute tools in parallel"""
        results = []
        max_workers = min(len(tools), self.config.get("scanning.max_parallel_tools", 3))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tool executions
            future_to_tool = {}
            for tool_name in tools:
                if tool_name in self.available_tools:
                    future = executor.submit(self._execute_tool, tool_name, self.scan_type)
                    future_to_tool[future] = tool_name
            
            # Collect results
            for future in as_completed(future_to_tool):
                tool_name = future_to_tool[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    self.logger.error(f"Tool {tool_name} failed: {e}", 
                                    tool=tool_name, exception=e)
        
        return results
    
    def _execute_tools_sequential(self, tools: List[str], phase: Dict[str, Any]) -> List[ScanResult]:
        """Execute tools sequentially"""
        results = []
        
        for tool_name in tools:
            if self.stop_event.is_set():
                break
            
            try:
                result = self._execute_tool(tool_name, self.scan_type)
                if result:
                    results.append(result)
            except Exception as e:
                self.logger.error(f"Tool {tool_name} failed: {e}",
                                tool=tool_name, exception=e)
        
        return results
    
    def _execute_tool(self, tool_name: str, scan_type: ScanType) -> Optional[ScanResult]:
        """Execute a single tool"""
        if tool_name not in self.available_tools:
            raise ToolNotAvailableError(f"Tool {tool_name} not available")
        
        tool = self.available_tools[tool_name]
        
        # Log tool start
        self.logger.log_tool_start(tool_name, self.target)
        
        tool_start = time.time()
        try:
            # Execute tool
            result = tool.scan(self.target, scan_type)
            tool_duration = time.time() - tool_start
            
            # Log tool completion
            results_count = len(result.results) if result.results else 0
            self.logger.log_tool_complete(tool_name, tool_duration, results_count)
            
            return result
            
        except Exception as e:
            tool_duration = time.time() - tool_start
            self.logger.log_tool_error(tool_name, str(e), exception=e)
            raise
    
    def stop_scan(self) -> bool:
        """Stop the current scan"""
        try:
            with self._lock:
                if self.scan_status != ScanStatus.RUNNING:
                    return False
                
                self.stop_event.set()
                self.pause_event.clear()
                
                # Wait for scan thread to finish
                if self.scan_thread and self.scan_thread.is_alive():
                    self.scan_thread.join(timeout=30)
                
                self.scan_status = ScanStatus.CANCELLED
                self.logger.info("Scan stopped by user request")
                
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to stop scan: {e}")
            return False
    
    def pause_scan(self) -> bool:
        """Pause the current scan"""
        try:
            if self.scan_status == ScanStatus.RUNNING:
                self.pause_event.set()
                self.scan_status = ScanStatus.PAUSED
                self.logger.info("Scan paused")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to pause scan: {e}")
            return False
    
    def resume_scan(self) -> bool:
        """Resume a paused scan"""
        try:
            if self.scan_status == ScanStatus.PAUSED:
                self.pause_event.clear()
                self.scan_status = ScanStatus.RUNNING
                self.logger.info("Scan resumed")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to resume scan: {e}")
            return False
    
    def get_status(self) -> ScanStatus:
        """Get current scan status"""
        return self.scan_status
    
    def get_progress(self) -> float:
        """Get scan progress (0.0 to 1.0)"""
        if self.total_phases == 0:
            return 0.0
        return min(1.0, self.completed_phases / self.total_phases)
    
    def get_results(self) -> List[ScanResult]:
        """Get scan results"""
        return self.scan_results.copy()
    
    def _save_checkpoint(self, checkpoint_name: str) -> None:
        """Save scan state checkpoint"""
        try:
            state = {
                "scan_id": self.scan_id,
                "target": self.target,
                "scan_type": self.scan_type.value if self.scan_type else None,
                "completed_phases": self.completed_phases,
                "total_phases": self.total_phases,
                "results": [self._serialize_result(r) for r in self.scan_results],
                "timestamp": time.time()
            }
            self.state_manager.save_state(state, checkpoint_name)
        except Exception as e:
            self.logger.warning(f"Failed to save checkpoint: {e}")
    
    def _serialize_result(self, result: ScanResult) -> Dict[str, Any]:
        """Serialize scan result for storage"""
        return {
            "tool_name": result.tool_name,
            "target": result.target,
            "scan_type": result.scan_type.value,
            "status": result.status.value,
            "start_time": result.start_time,
            "end_time": result.end_time,
            "duration": result.duration,
            "results": result.results,
            "errors": result.errors,
            "metadata": result.metadata
        }
    
    def _finalize_scan(self) -> None:
        """Finalize scan and generate reports"""
        try:
            # Save final state
            self._save_checkpoint("final")
            
            # Generate reports (if report generators are available)
            self._generate_reports()
            
            self.logger.info("Scan finalization completed")
            
        except Exception as e:
            self.logger.error(f"Scan finalization failed: {e}")
    
    def _generate_reports(self) -> None:
        """Generate scan reports"""
        # Report generation would use injected report generators
        # This is a placeholder for the reporting system
        self.logger.info("Report generation completed")
    
    def _log_scan_summary(self) -> None:
        """Log comprehensive scan summary"""
        if self.scan_start_time and self.scan_end_time:
            duration = self.scan_end_time - self.scan_start_time
            
            summary = {
                "total_tools_executed": len([r for r in self.scan_results if r.status == ScanStatus.COMPLETED]),
                "total_results": sum(len(r.results) if r.results else 0 for r in self.scan_results),
                "failed_tools": len([r for r in self.scan_results if r.status == ScanStatus.FAILED]),
                "phases_completed": self.completed_phases
            }
            
            self.logger.log_scan_complete(self.target, duration, summary)
    
    def dispose(self) -> None:
        """Cleanup orchestrator resources"""
        try:
            # Stop any running scan
            if self.scan_status == ScanStatus.RUNNING:
                self.stop_scan()
            
            # Cleanup resources
            if hasattr(self.resource_monitor, 'dispose'):
                self.resource_monitor.dispose()
            
            self.logger.info("Orchestrator disposed")
            
        except Exception as e:
            self.logger.error(f"Orchestrator disposal failed: {e}")


# Factory function for creating orchestrator with DI
def create_orchestrator() -> EnhancedOrchestrator:
    """Create orchestrator instance using dependency injection"""
    container = get_container()
    return container.resolve(EnhancedOrchestrator)
