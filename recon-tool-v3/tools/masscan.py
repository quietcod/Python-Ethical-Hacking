#!/usr/bin/env python3
"""
Masscan Port Scanner - Optimized for High-Speed Port Discovery
Ultra-fast port scanning and enumeration using masscan
Specialized for: High-speed port discovery, large-scale scanning, rapid enumeration
"""

import json
import re
from datetime import datetime
from typing import Dict, List

from .base import BaseTool

class MasscanScanner(BaseTool):
    """Optimized Masscan for high-speed port discovery and large-scale enumeration"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.command_name = "masscan"
        self.specialization = "high_speed_port_discovery"
    
    def scan(self, target: str, scan_params: Dict) -> Dict:
        """Execute HIGH-SPEED masscan port discovery optimized for speed"""
        self.start_time = datetime.now()
        
        try:
            self.logger.info(f"� Starting MasscanScanner HIGH-SPEED discovery against {target}")
            
            if not self.verify_installation():
                return self._create_error_result("Masscan not installed")
            
            # HIGH-SPEED optimized command building
            cmd = ['masscan', target, '--output-format', 'json', '--output-filename', '-']
            
            # Speed-optimized port ranges
            port_mode = scan_params.get('port_mode', 'fast')
            if port_mode == 'comprehensive':
                # Wide port range for comprehensive discovery
                ports = scan_params.get('ports', '1-65535')
            elif port_mode == 'top1000':
                # Top 1000 ports for balanced speed/coverage
                ports = scan_params.get('ports', '1-1000')
            else:  # fast mode (default)
                # Most common ports for maximum speed
                ports = scan_params.get('ports', '80,443,22,21,25,53,110,995,993,143,587,465,8080,8443,3389,1433,3306,5432')
            
            cmd.extend(['-p', ports])
            
            # HIGH-SPEED rate optimization
            rate = scan_params.get('rate', '10000')  # Increased default rate for speed
            cmd.extend(['--rate', str(rate)])
            
            # Speed-focused options
            if scan_params.get('aggressive_timing', True):
                cmd.extend(['--wait', '0'])  # Minimal wait time
            
            # Skip banners for speed unless explicitly requested
            if scan_params.get('banners', False):
                cmd.append('--banners')
            
            # Optimize for IPv4 speed
            if not scan_params.get('ipv6', False):
                cmd.append('-4')
            
            # Execute with extended timeout for large scans
            timeout = scan_params.get('timeout', 600)  # 10 minutes default
            result = self.execute_command(cmd, timeout=timeout)
            
            if result.returncode != 0:
                if 'permission denied' in result.stderr.lower() or 'must be root' in result.stderr.lower():
                    return self._create_error_result("Masscan requires root privileges")
                return self._create_error_result(f"Masscan high-speed scan failed: {result.stderr}")
            
            # Parse with speed-focused analysis
            findings = self._parse_high_speed_output(result.stdout, target, port_mode)
            self.save_raw_output(result.stdout, target, 'json')
            
            duration = (datetime.now() - self.start_time).total_seconds()
            
            # High-speed statistics
            open_port_count = len([f for f in findings if f.get('type') == 'open_port'])
            scan_rate = int(open_port_count / max(duration, 0.1) * 60)  # ports per minute
            
            self.logger.info(f"⚡ MasscanScanner HIGH-SPEED discovery completed in {duration:.1f}s - {open_port_count} open ports ({scan_rate} ports/min)")
            
            return {
                'status': 'success',
                'target': target,
                'scan_type': 'masscan_high_speed_port_discovery',
                'specialization': 'high_speed_port_discovery',
                'duration': duration,
                'findings': findings,
                'summary': {
                    'total_findings': len(findings),
                    'open_ports': open_port_count,
                    'scan_rate_per_minute': scan_rate,
                    'port_mode': port_mode,
                    'optimization': 'High-speed port discovery and rapid enumeration'
                }
            }
            
        except Exception as e:
            self.logger.error(f"❌ MasscanScanner error: {e}")
            return self._create_error_result(str(e))
    
    def _parse_high_speed_output(self, output: str, target: str, port_mode: str) -> List[Dict]:
        """Parse masscan JSON output optimized for high-speed discovery"""
        findings = []
        
        for line in output.strip().split('\n'):
            if line.strip():
                try:
                    if data := json.loads(line):
                        if data.get('ports'):
                            for port_info in data['ports']:
                                port = port_info.get('port')
                                proto = port_info.get('proto', 'tcp')
                                status = port_info.get('status', 'open')
                                ip = data.get('ip', target)
                                
                                finding = {
                                    'type': 'open_port',
                                    'ip': ip,
                                    'port': port,
                                    'protocol': proto,
                                    'status': status,
                                    'service': self._identify_common_service(port, proto),
                                    'risk_level': self._assess_port_risk(port, proto),
                                    'source': 'masscan_high_speed',
                                    'method': 'high_speed_discovery',
                                    'timestamp': data.get('timestamp', datetime.now().isoformat()),
                                    'details': f"High-speed discovery of {proto}/{port} - {self._get_port_description(port, proto)}"
                                }
                                findings.append(finding)
                                
                except json.JSONDecodeError:
                    continue
        
        return findings
    
    def _identify_common_service(self, port: int, protocol: str = 'tcp') -> str:
        """Identify common services for high-speed analysis"""
        common_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 587: 'SMTP-TLS',
            993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 8080: 'HTTP-ALT', 8443: 'HTTPS-ALT'
        }
        return common_services.get(port, 'Unknown')
    
    def _assess_port_risk(self, port: int, protocol: str = 'tcp') -> str:
        """Quick risk assessment for high-speed discovery"""
        high_risk_ports = [21, 23, 135, 139, 445, 1433, 3306, 3389, 5432]
        medium_risk_ports = [22, 25, 53, 110, 143, 993, 995]
        
        if port in high_risk_ports:
            return 'HIGH'
        elif port in medium_risk_ports:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_port_description(self, port: int, protocol: str = 'tcp') -> str:
        """Get port description for high-speed discovery"""
        descriptions = {
            21: 'File Transfer Protocol',
            22: 'Secure Shell',
            25: 'Simple Mail Transfer Protocol',
            53: 'Domain Name System',
            80: 'HyperText Transfer Protocol',
            110: 'Post Office Protocol v3',
            143: 'Internet Message Access Protocol',
            443: 'HTTP Secure',
            587: 'SMTP with STARTTLS',
            993: 'IMAP over SSL',
            995: 'POP3 over SSL',
            1433: 'Microsoft SQL Server',
            3306: 'MySQL Database',
            3389: 'Remote Desktop Protocol',
            5432: 'PostgreSQL Database',
            8080: 'HTTP Alternative',
            8443: 'HTTPS Alternative'
        }
        return descriptions.get(port, f'{protocol.upper()} service')
    
    def _parse_output(self, output: str, target: str) -> List[Dict]:
        """Parse masscan JSON output with unified approach (legacy compatibility)"""
        open_ports = []
        
        for line in output.strip().split('\n'):
            if line.strip():
                try:
                    if data := json.loads(line):
                        if data.get('ports'):
                            for port_info in data['ports']:
                                open_ports.append({
                                    'ip': data.get('ip', target),
                                    'port': port_info.get('port'),
                                    'protocol': port_info.get('proto', 'tcp'),
                                    'status': port_info.get('status', 'open'),
                                    'timestamp': data.get('timestamp', datetime.now().isoformat())
                                })
                except json.JSONDecodeError:
                    continue
        
        return open_ports
    
    def _create_error_result(self, error: str) -> Dict:
        """Create standardized error result"""
        return {
            'status': 'error',
            'error': error,
            'target': '',
            'scan_type': 'masscan_port_scan',
            'open_ports': [],
            'summary': {'total_open_ports': 0}
        }
