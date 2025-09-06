#!/usr/bin/env python3
"""
Nmap Scanner - Optimized for Comprehensive Port Analysis
Comprehensive port scanning, service detection, and vulnerability assessment using nmap
Specialized for: Comprehensive port analysis, service fingerprinting, security assessment
"""

import xml.etree.ElementTree as ET
import re
from datetime import datetime
from typing import Dict, List
from .base import RealTool

class NmapScanner(RealTool):
    """Optimized Nmap for comprehensive port analysis and detailed service detection"""
    
    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.command_name = "nmap"
        self.specialization = "comprehensive_port_analysis"
    
    def _execute_real_scan(self, target: str, scan_params: Dict) -> Dict:
        """Execute COMPREHENSIVE Nmap analysis optimized for detailed discovery"""
        self.start_time = datetime.now()
        
        try:
            self.logger.info(f"🔍 Starting NmapScanner COMPREHENSIVE analysis against {target}")
            
            # COMPREHENSIVE analysis command building
            analysis_mode = scan_params.get('analysis_mode', 'comprehensive')
            
            # Comprehensive analysis scan profiles
            scan_profiles = {
                'comprehensive': ["-sS", "-sV", "-sC", "-O", "-A", "-T4"],  # Full comprehensive
                'service_intensive': ["-sV", "-sC", "--version-intensity", "9", "-T4"],  # Deep service detection
                'vulnerability_focused': ["-sS", "-sC", "--script=vuln", "-T3"],  # Security focused
                'detailed_tcp': ["-sS", "-sV", "-sC", "-O", "-p-", "-T4"],  # All TCP ports
                'fast_comprehensive': ["-sS", "-sV", "-sC", "-T4", "--top-ports", "1000"]  # Balanced speed/depth
            }
            
            # Use provided ports or adapt based on mode
            if 'ports' in scan_params:
                base_cmd = ["-sS", "-sV", "-sC", "-T4", "-p", scan_params['ports']]
            else:
                base_cmd = scan_profiles.get(analysis_mode, scan_profiles['comprehensive'])
            
            cmd = ["nmap", "-oX", "-"] + base_cmd + [target]
            
            # Add comprehensive analysis enhancements
            if scan_params.get('aggressive_service_detection', True):
                if "--version-intensity" not in ' '.join(cmd):
                    cmd.extend(["--version-intensity", "7"])
            
            if scan_params.get('script_scanning', True):
                if "-sC" not in cmd:
                    cmd.append("-sC")
            
            if scan_params.get('os_detection', True):
                if "-O" not in cmd:
                    cmd.append("-O")
            
            # Extended timeout for comprehensive analysis
            timeout = scan_params.get('timeout', 1800)  # 30 minutes for comprehensive
            
            # Execute comprehensive scan
            result = self.execute_command(cmd, timeout=timeout)
            if result.returncode != 0:
                raise Exception(f"Nmap comprehensive analysis failed with return code {result.returncode}")
            
            # Parse with comprehensive analysis focus
            hosts_data = self._parse_comprehensive_xml(result.stdout)
            raw_file = self.save_raw_output(result.stdout, target, 'xml')
            
            # Generate comprehensive findings
            findings = self._extract_comprehensive_findings(hosts_data)
            
            duration = (datetime.now() - self.start_time).total_seconds()
            
            # Comprehensive analysis statistics
            total_hosts = len(hosts_data)
            total_open_ports = sum(len([p for p in host.get('ports', []) if p.get('state') == 'open']) for host in hosts_data)
            services_detected = sum(len([p for p in host.get('ports', []) if p.get('service')]) for host in hosts_data)
            
            self.logger.info(f"🔍 NmapScanner COMPREHENSIVE analysis completed in {duration:.1f}s - {total_hosts} hosts, {total_open_ports} open ports, {services_detected} services detected")
            
            return {
                'tool': self.tool_name,
                'target': target,
                'status': 'success',
                'scan_type': 'nmap_comprehensive_port_analysis',
                'specialization': 'comprehensive_port_analysis',
                'timestamp': datetime.now().isoformat(),
                'duration': duration,
                'hosts': hosts_data,
                'findings': findings,
                'summary': {
                    'total_hosts': total_hosts,
                    'total_open_ports': total_open_ports,
                    'services_detected': services_detected,
                    'analysis_mode': analysis_mode,
                    'optimization': 'Comprehensive port analysis and detailed service detection'
                },
                'raw_output_file': raw_file
            }
            
        except Exception as e:
            raise Exception(f"Nmap comprehensive analysis failed: {e}")
    
    def _parse_comprehensive_xml(self, xml_output: str) -> List[Dict]:
        """Parse Nmap XML output with comprehensive analysis focus"""
        try:
            root = ET.fromstring(xml_output)
            hosts = []
            
            for host in root.findall('host'):
                # Extract comprehensive host data
                addresses = [addr.get('addr') for addr in host.findall('address') if addr.get('addrtype') == 'ipv4']
                status = host.find('status')
                status_state = status.get('state') if status is not None else 'unknown'
                
                # Extract OS information for comprehensive analysis
                os_info = {}
                if os_elem := host.find('os'):
                    if osmatch := os_elem.find('osmatch'):
                        os_info = {
                            'name': osmatch.get('name', ''),
                            'accuracy': osmatch.get('accuracy', ''),
                            'line': osmatch.get('line', '')
                        }
                
                # Parse ports with comprehensive service details
                ports = []
                if ports_elem := host.find('ports'):
                    for port in ports_elem.findall('port'):
                        if state := port.find('state'):
                            service = port.find('service')
                            
                            # Extract comprehensive service information
                            service_info = {}
                            if service is not None:
                                service_info = {
                                    'name': service.get('name', ''),
                                    'product': service.get('product', ''),
                                    'version': service.get('version', ''),
                                    'extrainfo': service.get('extrainfo', ''),
                                    'ostype': service.get('ostype', ''),
                                    'method': service.get('method', ''),
                                    'conf': service.get('conf', '')
                                }
                            
                            # Extract script results for vulnerability analysis
                            scripts = []
                            for script in port.findall('script'):
                                scripts.append({
                                    'id': script.get('id', ''),
                                    'output': script.get('output', ''),
                                    'description': self._get_script_description(script.get('id', ''))
                                })
                            
                            port_data = {
                                'port': int(port.get('portid')),
                                'protocol': port.get('protocol'),
                                'state': state.get('state'),
                                'reason': state.get('reason', ''),
                                'service': service_info,
                                'scripts': scripts,
                                'risk_level': self._assess_comprehensive_port_risk(int(port.get('portid')), service_info, scripts)
                            }
                            ports.append(port_data)
                
                # Extract host scripts for comprehensive analysis
                host_scripts = []
                if hostscript := host.find('hostscript'):
                    for script in hostscript.findall('script'):
                        host_scripts.append({
                            'id': script.get('id', ''),
                            'output': script.get('output', ''),
                            'description': self._get_script_description(script.get('id', ''))
                        })
                
                if addresses and status_state == 'up':
                    hosts.append({
                        'address': addresses[0],
                        'status': status_state,
                        'os': os_info,
                        'ports': ports,
                        'host_scripts': host_scripts,
                        'analysis_depth': 'comprehensive'
                    })
            
            return hosts
            
        except ET.ParseError as e:
            raise Exception(f"Failed to parse Nmap comprehensive XML: {e}")
    
    def _get_script_description(self, script_id: str) -> str:
        """Get description for NSE scripts"""
        script_descriptions = {
            'http-title': 'HTTP title and server information',
            'ssl-cert': 'SSL certificate information',
            'ssh-hostkey': 'SSH host key information',
            'smb-os-discovery': 'SMB OS and version detection',
            'http-methods': 'HTTP methods supported',
            'ftp-anon': 'Anonymous FTP access check',
            'smtp-commands': 'SMTP commands supported',
            'dns-nsid': 'DNS NSID information',
            'http-robots.txt': 'Robots.txt file analysis',
            'ssl-enum-ciphers': 'SSL cipher enumeration'
        }
        return script_descriptions.get(script_id, f'NSE script: {script_id}')
    
    def _assess_comprehensive_port_risk(self, port: int, service_info: dict, scripts: list) -> str:
        """Comprehensive risk assessment based on port, service, and script results"""
        # High-risk ports
        high_risk_ports = [21, 23, 135, 139, 445, 1433, 3306, 3389, 5432]
        if port in high_risk_ports:
            return 'HIGH'
        
        # Service-based risk assessment
        service_name = service_info.get('name', '').lower()
        high_risk_services = ['ftp', 'telnet', 'smb', 'mssql', 'mysql', 'rdp', 'postgresql']
        if any(svc in service_name for svc in high_risk_services):
            return 'HIGH'
        
        # Script-based risk assessment
        for script in scripts:
            script_id = script.get('id', '').lower()
            if any(vuln in script_id for vuln in ['vuln', 'cve', 'exploit']):
                return 'HIGH'
            if 'anon' in script_id and 'accessible' in script.get('output', '').lower():
                return 'HIGH'
        
        # Medium-risk ports
        medium_risk_ports = [22, 25, 53, 80, 110, 143, 443, 993, 995]
        if port in medium_risk_ports:
            return 'MEDIUM'
        
        return 'LOW'
    
    def _extract_comprehensive_findings(self, hosts_data: List[Dict]) -> List[Dict]:
        """Extract comprehensive findings with detailed analysis"""
        if not hosts_data:
            return [{'type': 'no_hosts_up', 'description': 'No live hosts found', 'severity': 'info'}]
        
        findings = []
        for host in hosts_data:
            address = host['address']
            open_ports = [p for p in host['ports'] if p['state'] == 'open']
            
            # Host-level findings
            if host.get('os') and host['os'].get('name'):
                findings.append({
                    'type': 'os_detection',
                    'host': address,
                    'description': f"OS detected: {host['os']['name']} (accuracy: {host['os'].get('accuracy', 'unknown')}%)",
                    'severity': 'info',
                    'details': host['os']
                })
            
            # Port-based findings with comprehensive analysis
            if open_ports:
                high_risk_ports = [p for p in open_ports if p.get('risk_level') == 'HIGH']
                if high_risk_ports:
                    port_list = [f"{p['port']}/{p['protocol']}" for p in high_risk_ports]
                    findings.append({
                        'type': 'high_risk_ports',
                        'host': address,
                        'description': f"High-risk ports detected: {', '.join(port_list)}",
                        'severity': 'high',
                        'details': high_risk_ports
                    })
                
                # Service version findings
                for port in open_ports:
                    service = port.get('service', {})
                    if service.get('product') and service.get('version'):
                        findings.append({
                            'type': 'service_version',
                            'host': address,
                            'port': port['port'],
                            'description': f"Service detected: {service['product']} {service['version']} on port {port['port']}",
                            'severity': 'info',
                            'details': service
                        })
                    
                    # Script-based findings
                    for script in port.get('scripts', []):
                        if script.get('output'):
                            findings.append({
                                'type': 'script_result',
                                'host': address,
                                'port': port['port'],
                                'script': script['id'],
                                'description': f"{script['description']}: {script['output'][:100]}{'...' if len(script['output']) > 100 else ''}",
                                'severity': 'info',
                                'details': script
                            })
            
            # Host script findings
            for script in host.get('host_scripts', []):
                findings.append({
                    'type': 'host_script_result',
                    'host': address,
                    'script': script['id'],
                    'description': f"Host analysis - {script['description']}: {script['output'][:100]}{'...' if len(script['output']) > 100 else ''}",
                    'severity': 'info',
                    'details': script
                })
        
        return findings
    
    def _parse_xml(self, xml_output: str) -> List[Dict]:
        """Parse Nmap XML output with unified approach (legacy compatibility)"""
        try:
            root = ET.fromstring(xml_output)
            hosts = []
            
            for host in root.findall('host'):
                # Extract essential data only
                addresses = [addr.get('addr') for addr in host.findall('address') if addr.get('addrtype') == 'ipv4']
                status = host.find('status')
                status_state = status.get('state') if status is not None else 'unknown'
                
                # Parse ports efficiently
                ports = []
                if ports_elem := host.find('ports'):
                    for port in ports_elem.findall('port'):
                        if state := port.find('state'):
                            service = port.find('service')
                            ports.append({
                                'port': int(port.get('portid')),
                                'protocol': port.get('protocol'),
                                'state': state.get('state'),
                                'service': service.get('name', '') if service is not None else '',
                                'version': service.get('version', '') if service is not None else ''
                            })
                
                if addresses and status_state == 'up':
                    hosts.append({
                        'address': addresses[0],
                        'status': status_state,
                        'ports': ports
                    })
            
            return hosts
            
        except ET.ParseError as e:
            raise Exception(f"Failed to parse Nmap XML: {e}")
    
    def _extract_findings(self, hosts_data: List[Dict]) -> List[Dict]:
        """Extract findings with unified analysis (legacy compatibility)"""
        if not hosts_data:
            return [{'type': 'no_hosts_up', 'description': 'No live hosts found', 'severity': 'info'}]
        
        findings = []
        for host in hosts_data:
            address = host['address']
            open_ports = [p for p in host['ports'] if p['state'] == 'open']
            
            if open_ports:
                port_list = [f"{p['port']}/{p['protocol']}" for p in open_ports]
                findings.append({
                    'type': 'open_ports',
                    'description': f"{address}: {len(open_ports)} open ports ({', '.join(port_list[:5])}{'...' if len(port_list) > 5 else ''})",
                    'severity': 'info'
                })
                
                # Service detection findings
                for port in open_ports:
                    if port['service'] and port['version']:
                        findings.append({
                            'type': 'service_detected',
                            'description': f"{address}:{port['port']} - {port['service']} {port['version']}",
                            'severity': 'info'
                        })
        
        return findings
