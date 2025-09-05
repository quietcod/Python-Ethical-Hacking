#!/usr/bin/env python3
"""
Nmap Scanner - Clean Architecture
Real network port scanning and service detection implementation
"""

import xml.etree.ElementTree as ET
from typing import Dict, List
from .base import RealTool

class NmapScanner(RealTool):
    """Real Nmap network scanner implementation"""
    
    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.command_name = "nmap"
        self.version = "7.94"
        self.description = "Network port scanning and service detection"
        self.category = "network_scanning"
        self.version_args = ["-V"]
    
    def _execute_real_scan(self, target: str, scan_params: Dict) -> Dict:
        """Execute real Nmap scan against target"""
        
        # Build Nmap command based on scan type
        scan_type = scan_params.get('scan_type', 'quick')
        cmd = self._build_nmap_command(target, scan_type)
        
        # Execute Nmap with XML output
        try:
            result = self.execute_command(cmd, timeout=300)
            
            if result.returncode != 0:
                raise Exception(f"Nmap failed with return code {result.returncode}")
            
            # Parse XML output
            xml_output = result.stdout
            parsed_results = self._parse_nmap_xml(xml_output, target)
            
            # Save raw output
            raw_file = self.save_raw_output(xml_output, target, 'xml')
            parsed_results['raw_output_file'] = raw_file
            
            # Log findings
            self._log_nmap_findings(parsed_results)
            
            return parsed_results
            
        except Exception as e:
            raise Exception(f"Nmap execution failed: {e}")
    
    def _build_nmap_command(self, target: str, scan_type: str) -> List[str]:
        """Build Nmap command based on scan type"""
        
        # Base command with XML output
        cmd = ["nmap", "-oX", "-"]
        
        # Scan type configurations
        if scan_type == "quick":
            # Quick scan: SYN scan on top 1000 ports
            cmd.extend(["-sS", "-T4", "--top-ports", "1000"])
        elif scan_type == "full":
            # Full scan: SYN scan on all ports with service detection
            cmd.extend(["-sS", "-sV", "-O", "-T4", "-p-"])
        elif scan_type == "stealth":
            # Stealth scan: Slower, less detectable
            cmd.extend(["-sS", "-T2", "--top-ports", "1000"])
        elif scan_type == "service":
            # Service detection scan
            cmd.extend(["-sV", "-sC", "-T4", "--top-ports", "1000"])
        else:
            # Default to quick scan
            cmd.extend(["-sS", "-T4", "--top-ports", "1000"])
        
        # Add target
        cmd.append(target)
        
        return cmd
    
    def _parse_nmap_xml(self, xml_output: str, target: str) -> Dict:
        """Parse Nmap XML output into structured results"""
        try:
            # Parse XML
            root = ET.fromstring(xml_output)
            
            # Initialize results structure
            results = {
                'tool': self.tool_name,
                'target': target,
                'status': 'success',
                'timestamp': self._get_scan_timestamp(root),
                'nmap_version': root.get('version', 'unknown'),
                'scan_stats': self._parse_scan_stats(root),
                'hosts': [],
                'findings': []
            }
            
            # Parse each host
            for host in root.findall('host'):
                host_data = self._parse_host(host)
                if host_data:
                    results['hosts'].append(host_data)
                    results['findings'].extend(self._extract_host_findings(host_data))
            
            return results
            
        except ET.ParseError as e:
            raise Exception(f"Failed to parse Nmap XML output: {e}")
    
    def _get_scan_timestamp(self, root: ET.Element) -> str:
        """Extract scan timestamp from XML"""
        runstats = root.find('runstats')
        if runstats is not None:
            finished = runstats.find('finished')
            if finished is not None:
                return finished.get('timestr', 'unknown')
        return 'unknown'
    
    def _parse_scan_stats(self, root: ET.Element) -> Dict:
        """Parse scan statistics from XML"""
        stats = {}
        
        runstats = root.find('runstats')
        if runstats is not None:
            finished = runstats.find('finished')
            if finished is not None:
                stats['elapsed_time'] = finished.get('elapsed', '0')
                stats['hosts_up'] = finished.get('up', '0')
                stats['hosts_down'] = finished.get('down', '0')
                stats['hosts_total'] = finished.get('total', '0')
        
        return stats
    
    def _parse_host(self, host_elem: ET.Element) -> Dict:
        """Parse individual host information"""
        host_data = {
            'addresses': [],
            'hostnames': [],
            'ports': [],
            'os': {},
            'status': 'unknown'
        }
        
        # Parse addresses
        for address in host_elem.findall('address'):
            addr_info = {
                'addr': address.get('addr'),
                'addrtype': address.get('addrtype')
            }
            host_data['addresses'].append(addr_info)
        
        # Parse hostnames
        hostnames_elem = host_elem.find('hostnames')
        if hostnames_elem is not None:
            for hostname in hostnames_elem.findall('hostname'):
                host_data['hostnames'].append(hostname.get('name'))
        
        # Parse host status
        status_elem = host_elem.find('status')
        if status_elem is not None:
            host_data['status'] = status_elem.get('state', 'unknown')
        
        # Parse ports
        ports_elem = host_elem.find('ports')
        if ports_elem is not None:
            for port in ports_elem.findall('port'):
                port_data = self._parse_port(port)
                if port_data:
                    host_data['ports'].append(port_data)
        
        # Parse OS detection
        os_elem = host_elem.find('os')
        if os_elem is not None:
            host_data['os'] = self._parse_os_detection(os_elem)
        
        return host_data
    
    def _parse_port(self, port_elem: ET.Element) -> Dict:
        """Parse individual port information"""
        port_data = {
            'port': int(port_elem.get('portid')),
            'protocol': port_elem.get('protocol'),
            'state': 'unknown',
            'service': {},
            'scripts': []
        }
        
        # Parse port state
        state_elem = port_elem.find('state')
        if state_elem is not None:
            port_data['state'] = state_elem.get('state')
            port_data['reason'] = state_elem.get('reason')
        
        # Parse service information
        service_elem = port_elem.find('service')
        if service_elem is not None:
            port_data['service'] = {
                'name': service_elem.get('name', ''),
                'product': service_elem.get('product', ''),
                'version': service_elem.get('version', ''),
                'extrainfo': service_elem.get('extrainfo', ''),
                'tunnel': service_elem.get('tunnel', ''),
                'method': service_elem.get('method', '')
            }
        
        # Parse script results
        for script in port_elem.findall('script'):
            script_data = {
                'id': script.get('id'),
                'output': script.get('output', '')
            }
            port_data['scripts'].append(script_data)
        
        return port_data
    
    def _parse_os_detection(self, os_elem: ET.Element) -> Dict:
        """Parse OS detection results"""
        os_data = {
            'matches': [],
            'ports_used': [],
            'fingerprint': ''
        }
        
        # Parse OS matches
        for osmatch in os_elem.findall('osmatch'):
            match = {
                'name': osmatch.get('name'),
                'accuracy': osmatch.get('accuracy'),
                'line': osmatch.get('line')
            }
            os_data['matches'].append(match)
        
        # Parse ports used for OS detection
        for portused in os_elem.findall('portused'):
            port = {
                'state': portused.get('state'),
                'proto': portused.get('proto'),
                'portid': portused.get('portid')
            }
            os_data['ports_used'].append(port)
        
        return os_data
    
    def _extract_host_findings(self, host_data: Dict) -> List[Dict]:
        """Extract security findings from host data"""
        findings = []
        
        # Open ports findings
        open_ports = [p for p in host_data['ports'] if p['state'] == 'open']
        if open_ports:
            port_list = [f"{p['port']}/{p['protocol']}" for p in open_ports]
            findings.append({
                'type': 'open_ports',
                'description': f"Found {len(open_ports)} open ports: {', '.join(port_list)}",
                'severity': 'info',
                'details': open_ports
            })
        
        # Service version findings
        for port in open_ports:
            service = port.get('service', {})
            if service.get('name') and service.get('version'):
                findings.append({
                    'type': 'service_version',
                    'description': f"Port {port['port']}: {service['name']} {service['version']}",
                    'severity': 'info',
                    'details': service
                })
        
        # OS detection findings
        if host_data['os'].get('matches'):
            best_match = host_data['os']['matches'][0]
            findings.append({
                'type': 'os_detection',
                'description': f"OS detected: {best_match['name']} ({best_match['accuracy']}% accuracy)",
                'severity': 'info',
                'details': best_match
            })
        
        return findings
    
    def _log_nmap_findings(self, results: Dict) -> None:
        """Log Nmap findings"""
        for finding in results['findings']:
            self._log_finding(finding['type'], finding['description'], finding['severity'])
