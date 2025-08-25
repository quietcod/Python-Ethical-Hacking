"""
System Monitoring
Resource usage, performance monitoring, and system health checks
"""

import psutil
import threading
import time
from collections import deque
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable


class SystemMonitor:
    """Monitors system resources and performance"""
    
    def __init__(self, logger, check_interval: float = 1.0):
        self.logger = logger
        self.check_interval = check_interval
        self.monitoring = False
        self.monitor_thread = None
        
        # Performance data storage
        self.cpu_history = deque(maxlen=300)  # 5 minutes at 1s intervals
        self.memory_history = deque(maxlen=300)
        self.disk_history = deque(maxlen=300)
        self.network_history = deque(maxlen=300)
        
        # Resource limits
        self.limits = {
            "cpu_warning": 80.0,
            "cpu_critical": 95.0,
            "memory_warning": 80.0,
            "memory_critical": 95.0,
            "disk_warning": 90.0,
            "disk_critical": 98.0
        }
        
        # Alert callbacks
        self.alert_callbacks: List[Callable] = []
        self.last_alert_time = {}
        self.alert_cooldown = 60  # seconds
    
    def start_monitoring(self) -> None:
        """Start monitoring system resources"""
        if not self.monitoring:
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            self.logger.info("System monitoring started")
    
    def stop_monitoring(self) -> None:
        """Stop monitoring system resources"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        self.logger.info("System monitoring stopped")
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop"""
        while self.monitoring:
            try:
                # Collect metrics
                metrics = self.get_current_metrics()
                
                # Store historical data
                self._store_metrics(metrics)
                
                # Check for alerts
                self._check_alerts(metrics)
                
                time.sleep(self.check_interval)
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {str(e)}")
                time.sleep(self.check_interval)
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """Get current system metrics"""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=None)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            
            # Memory metrics
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            disk_io = psutil.disk_io_counters()
            
            # Network metrics
            network_io = psutil.net_io_counters()
            
            # Process metrics
            process_count = len(psutil.pids())
            
            return {
                "timestamp": datetime.now().isoformat(),
                "cpu": {
                    "percent": cpu_percent,
                    "count": cpu_count,
                    "frequency": cpu_freq.current if cpu_freq else None
                },
                "memory": {
                    "total": memory.total,
                    "available": memory.available,
                    "percent": memory.percent,
                    "used": memory.used,
                    "free": memory.free
                },
                "swap": {
                    "total": swap.total,
                    "used": swap.used,
                    "percent": swap.percent
                },
                "disk": {
                    "total": disk.total,
                    "used": disk.used,
                    "free": disk.free,
                    "percent": disk.used / disk.total * 100,
                    "read_bytes": disk_io.read_bytes if disk_io else 0,
                    "write_bytes": disk_io.write_bytes if disk_io else 0
                },
                "network": {
                    "bytes_sent": network_io.bytes_sent if network_io else 0,
                    "bytes_recv": network_io.bytes_recv if network_io else 0,
                    "packets_sent": network_io.packets_sent if network_io else 0,
                    "packets_recv": network_io.packets_recv if network_io else 0
                },
                "processes": process_count
            }
            
        except Exception as e:
            self.logger.error(f"Error collecting metrics: {str(e)}")
            return {}
    
    def _store_metrics(self, metrics: Dict[str, Any]) -> None:
        """Store metrics in historical data"""
        if not metrics:
            return
            
        try:
            self.cpu_history.append({
                "timestamp": metrics["timestamp"],
                "percent": metrics["cpu"]["percent"]
            })
            
            self.memory_history.append({
                "timestamp": metrics["timestamp"],
                "percent": metrics["memory"]["percent"]
            })
            
            self.disk_history.append({
                "timestamp": metrics["timestamp"],
                "percent": metrics["disk"]["percent"]
            })
            
            if "network" in metrics:
                self.network_history.append({
                    "timestamp": metrics["timestamp"],
                    "bytes_sent": metrics["network"]["bytes_sent"],
                    "bytes_recv": metrics["network"]["bytes_recv"]
                })
                
        except Exception as e:
            self.logger.error(f"Error storing metrics: {str(e)}")
    
    def _check_alerts(self, metrics: Dict[str, Any]) -> None:
        """Check for resource usage alerts"""
        if not metrics:
            return
            
        current_time = time.time()
        
        # CPU alerts
        cpu_percent = metrics.get("cpu", {}).get("percent", 0)
        if cpu_percent >= self.limits["cpu_critical"]:
            self._send_alert("cpu_critical", f"CPU usage critical: {cpu_percent:.1f}%", current_time)
        elif cpu_percent >= self.limits["cpu_warning"]:
            self._send_alert("cpu_warning", f"CPU usage high: {cpu_percent:.1f}%", current_time)
        
        # Memory alerts
        memory_percent = metrics.get("memory", {}).get("percent", 0)
        if memory_percent >= self.limits["memory_critical"]:
            self._send_alert("memory_critical", f"Memory usage critical: {memory_percent:.1f}%", current_time)
        elif memory_percent >= self.limits["memory_warning"]:
            self._send_alert("memory_warning", f"Memory usage high: {memory_percent:.1f}%", current_time)
        
        # Disk alerts
        disk_percent = metrics.get("disk", {}).get("percent", 0)
        if disk_percent >= self.limits["disk_critical"]:
            self._send_alert("disk_critical", f"Disk usage critical: {disk_percent:.1f}%", current_time)
        elif disk_percent >= self.limits["disk_warning"]:
            self._send_alert("disk_warning", f"Disk usage high: {disk_percent:.1f}%", current_time)
    
    def _send_alert(self, alert_type: str, message: str, current_time: float) -> None:
        """Send alert if not in cooldown period"""
        last_alert = self.last_alert_time.get(alert_type, 0)
        
        if current_time - last_alert >= self.alert_cooldown:
            self.logger.warning(f"SYSTEM ALERT: {message}")
            self.last_alert_time[alert_type] = current_time
            
            # Call registered callbacks
            for callback in self.alert_callbacks:
                try:
                    callback(alert_type, message)
                except Exception as e:
                    self.logger.error(f"Error in alert callback: {str(e)}")
    
    def add_alert_callback(self, callback: Callable) -> None:
        """Add callback for alerts"""
        self.alert_callbacks.append(callback)
    
    def get_system_health(self) -> Dict[str, Any]:
        """Get overall system health status"""
        current_metrics = self.get_current_metrics()
        
        if not current_metrics:
            return {"status": "unknown", "message": "Unable to collect metrics"}
        
        # Determine health status
        cpu_percent = current_metrics.get("cpu", {}).get("percent", 0)
        memory_percent = current_metrics.get("memory", {}).get("percent", 0)
        disk_percent = current_metrics.get("disk", {}).get("percent", 0)
        
        critical_issues = []
        warnings = []
        
        if cpu_percent >= self.limits["cpu_critical"]:
            critical_issues.append(f"CPU usage critical ({cpu_percent:.1f}%)")
        elif cpu_percent >= self.limits["cpu_warning"]:
            warnings.append(f"CPU usage high ({cpu_percent:.1f}%)")
        
        if memory_percent >= self.limits["memory_critical"]:
            critical_issues.append(f"Memory usage critical ({memory_percent:.1f}%)")
        elif memory_percent >= self.limits["memory_warning"]:
            warnings.append(f"Memory usage high ({memory_percent:.1f}%)")
        
        if disk_percent >= self.limits["disk_critical"]:
            critical_issues.append(f"Disk usage critical ({disk_percent:.1f}%)")
        elif disk_percent >= self.limits["disk_warning"]:
            warnings.append(f"Disk usage high ({disk_percent:.1f}%)")
        
        # Determine overall status
        if critical_issues:
            status = "critical"
            message = "; ".join(critical_issues)
        elif warnings:
            status = "warning"
            message = "; ".join(warnings)
        else:
            status = "healthy"
            message = "All systems normal"
        
        return {
            "status": status,
            "message": message,
            "metrics": current_metrics,
            "uptime": self._get_uptime()
        }
    
    def _get_uptime(self) -> float:
        """Get system uptime in seconds"""
        try:
            return time.time() - psutil.boot_time()
        except:
            return 0
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary over monitoring period"""
        if not self.cpu_history or not self.memory_history:
            return {"error": "No performance data available"}
        
        try:
            # CPU statistics
            cpu_values = [entry["percent"] for entry in self.cpu_history]
            cpu_stats = {
                "current": cpu_values[-1] if cpu_values else 0,
                "average": sum(cpu_values) / len(cpu_values) if cpu_values else 0,
                "max": max(cpu_values) if cpu_values else 0,
                "min": min(cpu_values) if cpu_values else 0
            }
            
            # Memory statistics
            memory_values = [entry["percent"] for entry in self.memory_history]
            memory_stats = {
                "current": memory_values[-1] if memory_values else 0,
                "average": sum(memory_values) / len(memory_values) if memory_values else 0,
                "max": max(memory_values) if memory_values else 0,
                "min": min(memory_values) if memory_values else 0
            }
            
            # Disk statistics
            disk_values = [entry["percent"] for entry in self.disk_history]
            disk_stats = {
                "current": disk_values[-1] if disk_values else 0,
                "average": sum(disk_values) / len(disk_values) if disk_values else 0,
                "max": max(disk_values) if disk_values else 0,
                "min": min(disk_values) if disk_values else 0
            }
            
            return {
                "monitoring_duration": len(self.cpu_history) * self.check_interval,
                "cpu": cpu_stats,
                "memory": memory_stats,
                "disk": disk_stats,
                "data_points": len(self.cpu_history)
            }
            
        except Exception as e:
            self.logger.error(f"Error generating performance summary: {str(e)}")
            return {"error": str(e)}
