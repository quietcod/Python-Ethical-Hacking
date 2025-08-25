"""
Port Scanner
Nmap and Masscan wrapper for comprehensive port scanning
"""

import json
import logging
import os
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, List, Optional

from ...core.exceptions import ScanError, ToolNotFoundError
from ...core.utils import check_tool_installed, run_command


class PortScanner:
    """Nmap port scanner wrapper with masscan support"""
    
    def __init__(self, output_dir: Path, config: Dict[str, Any], logger: logging.Logger):
        self.output_dir = output_dir
        self.config = config
        self.logger = logger
        
        # Create nmap output directory
        self.nmap_dir = output_dir / 'nmap'
        self.nmap_dir.mkdir(exist_ok=True)
        
    def basic_scan(self, target: str) -> Dict[str, Any]:
        """Run basic port scan"""
        self.logger.info(f"Running basic port scan on {target}")
        
        if not check_tool_installed('nmap'):
            raise ToolNotFoundError('nmap')
        
        flags = self.config.get('basic_flags', '-sV -sC')
        timeout = self.config.get('timeout', 300)
        
        output_file = self.nmap_dir / f'{target}_basic'
        
        cmd = [
            'nmap', 
            *flags.split(),
            '-oA', str(output_file),
            '--open',
            target
        ]
        
        return self._run_nmap_command(cmd, target, 'basic')
    
    def aggressive_scan(self, target: str) -> Dict[str, Any]:
        """Run aggressive port scan with light mode support"""
        self.logger.info(f"Running aggressive port scan on {target}")
        
        if not check_tool_installed('nmap'):
            raise ToolNotFoundError('nmap')
        
        flags = self.config.get('aggressive_flags', '-A -T4')
        
        # Adjust for light mode
        if self.config.get('light_mode', False):
            # Use lighter timing and reduce aggressive features
            flags = flags.replace('-T4', '-T3')  # Slower timing
            flags = flags.replace('-A', '-sV -sC')  # Remove OS detection and traceroute
            self.logger.info("Light mode: Using reduced Nmap flags for lower resource usage")
        
        timeout = self.config.get('timeout', 600)
        
        output_file = self.nmap_dir / f'{target}_aggressive'
        
        cmd = [
            'nmap',
            *flags.split(),
            '-oA', str(output_file),
            '--open',
            target
        ]
        
        return self._run_nmap_command(cmd, target, 'aggressive')
    
    def _run_nmap_command(self, cmd: List[str], target: str, scan_type: str) -> Dict[str, Any]:
        """Execute nmap command and parse results"""
        try:
            self.logger.info(f"Executing: {' '.join(cmd)}")
            
            # Run the command
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.get('timeout', 300)
            )
            
            if result.returncode != 0:
                self.logger.error(f"Nmap scan failed: {result.stderr}")
                raise ScanError(f"Nmap scan failed: {result.stderr}", scan_type="nmap", target=target)
            
            # Parse XML output
            xml_file = f"{cmd[cmd.index('-oA') + 1]}.xml"
            
            if os.path.exists(xml_file):
                return self._parse_nmap_xml(xml_file, target, scan_type)
            else:
                self.logger.warning(f"XML output file not found: {xml_file}")
                return {}
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"Nmap scan timed out for {target}")
            raise ScanError(f"Nmap scan timed out", scan_type="nmap", target=target)
        except Exception as e:
            self.logger.error(f"Error running nmap scan: {str(e)}")
            raise ScanError(f"Nmap scan error: {str(e)}", scan_type="nmap", target=target)
    
    def _parse_nmap_xml(self, xml_file: str, target: str, scan_type: str) -> Dict[str, Any]:
        """Parse Nmap XML output"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            results = {
                'target': target,
                'scan_type': scan_type,
                'timestamp': root.get('startstr'),
                'hosts': [],
                'summary': {
                    'total_hosts': 0,
                    'hosts_up': 0,
                    'total_ports': 0,
                    'open_ports': 0,
                    'filtered_ports': 0,
                    'closed_ports': 0
                }
            }
            
            for host in root.findall('host'):
                host_info = self._parse_host(host)
                if host_info:
                    results['hosts'].append(host_info)
                    results['summary']['total_hosts'] += 1
                    
                    if host_info['status'] == 'up':
                        results['summary']['hosts_up'] += 1
                        
                    for port in host_info.get('ports', []):
                        results['summary']['total_ports'] += 1
                        state = port.get('state', 'unknown')
                        if state == 'open':
                            results['summary']['open_ports'] += 1
                        elif state == 'filtered':
                            results['summary']['filtered_ports'] += 1
                        elif state == 'closed':
                            results['summary']['closed_ports'] += 1
            
            # Save parsed results
            json_file = self.nmap_dir / f'{target}_{scan_type}_parsed.json'
            with open(json_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            self.logger.info(f"Parsed nmap results saved to {json_file}")
            return results
            
        except Exception as e:
            self.logger.error(f"Error parsing XML file {xml_file}: {str(e)}")
            return {}
    
    def _parse_host(self, host_element) -> Optional[Dict[str, Any]]:
        """Parse individual host from XML"""
        try:
            # Get host address
            address_elem = host_element.find('address')
            if address_elem is None:
                return None
                
            host_info = {
                'address': address_elem.get('addr'),
                'address_type': address_elem.get('addrtype'),
                'status': host_element.find('status').get('state'),
                'hostnames': [],
                'ports': [],
                'os': {},
                'scripts': []
            }
            
            # Get hostnames
            hostnames = host_element.find('hostnames')
            if hostnames is not None:
                for hostname in hostnames.findall('hostname'):
                    host_info['hostnames'].append({
                        'name': hostname.get('name'),
                        'type': hostname.get('type')
                    })
            
            # Get ports
            ports = host_element.find('ports')
            if ports is not None:
                for port in ports.findall('port'):
                    port_info = {
                        'port': port.get('portid'),
                        'protocol': port.get('protocol'),
                        'state': port.find('state').get('state'),
                        'reason': port.find('state').get('reason'),
                        'service': {}
                    }
                    
                    # Get service info
                    service = port.find('service')
                    if service is not None:
                        port_info['service'] = {
                            'name': service.get('name', ''),
                            'product': service.get('product', ''),
                            'version': service.get('version', ''),
                            'extrainfo': service.get('extrainfo', '')
                        }
                    
                    host_info['ports'].append(port_info)
            
            return host_info
            
        except Exception as e:
            self.logger.error(f"Error parsing host: {str(e)}")
            return None

    def masscan_scan(self, target: str, port_range: str = "1-65535") -> Optional[Dict[str, Any]]:
        """Run masscan for ultra-fast port discovery"""
        try:
            # Check if masscan is available
            if not check_tool_installed('masscan'):
                self.logger.warning("Masscan not available, will use nmap instead")
                return None
            
            self.logger.info(f"Running masscan on {target} (ports {port_range})")
            
            output_file = self.nmap_dir / f'{target}_masscan.json'
            
            # Masscan command with rate limiting for safety
            cmd = [
                'masscan',
                target,
                '-p', port_range,
                '--rate', '1000',  # Conservative rate
                '--output-format', 'json',
                '--output-filename', str(output_file),
                '--open-only'
            ]
            
            # Run masscan with timeout
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # Parse masscan JSON output
                masscan_results = self._parse_masscan_json(output_file, target)
                self.logger.info(f"Masscan discovered {len(masscan_results.get('ports', []))} open ports")
                return masscan_results
            else:
                self.logger.error(f"Masscan failed: {result.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            self.logger.warning("Masscan timed out")
            return None
        except Exception as e:
            self.logger.error(f"Error running masscan: {str(e)}")
            return None

    def _parse_masscan_json(self, json_file: Path, target: str) -> Dict[str, Any]:
        """Parse masscan JSON output"""
        try:
            results = {
                'target': target,
                'scan_type': 'masscan',
                'ports': [],
                'total_ports': 0
            }
            
            if not json_file.exists():
                return results
            
            with open(json_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and line.startswith('{'):
                        try:
                            port_data = json.loads(line)
                            if 'ports' in port_data:
                                for port_info in port_data['ports']:
                                    results['ports'].append({
                                        'port': port_info.get('port'),
                                        'protocol': port_info.get('proto', 'tcp'),
                                        'state': 'open',
                                        'service': {'name': 'unknown'},
                                        'discovered_by': 'masscan'
                                    })
                        except json.JSONDecodeError:
                            continue
            
            results['total_ports'] = len(results['ports'])
            return results
            
        except Exception as e:
            self.logger.error(f"Error parsing masscan output: {str(e)}")
            return {'target': target, 'scan_type': 'masscan', 'ports': [], 'total_ports': 0}

    def hybrid_scan(self, target: str) -> Dict[str, Any]:
        """Hybrid scan: masscan for discovery + nmap for service detection"""
        self.logger.info(f"Running hybrid scan on {target}")
        
        # Step 1: Fast port discovery with masscan
        masscan_results = self.masscan_scan(target)
        
        if masscan_results and masscan_results['total_ports'] > 0:
            # Step 2: Extract discovered ports
            open_ports = [str(port['port']) for port in masscan_results['ports']]
            port_list = ','.join(open_ports[:100])  # Limit to first 100 ports
            
            self.logger.info(f"Masscan found {len(open_ports)} ports, running nmap service detection")
            
            # Step 3: Service detection with nmap on discovered ports
            output_file = self.nmap_dir / f'{target}_hybrid'
            
            cmd = [
                'nmap',
                '-sV', '-sC',  # Service detection and default scripts
                '-p', port_list,
                '-oA', str(output_file),
                '--open',
                target
            ]
            
            nmap_results = self._run_nmap_command(cmd, target, 'hybrid')
            
            # Merge results
            if nmap_results:
                # Update masscan results with nmap service info
                nmap_ports = {p['port']: p for host in nmap_results.get('hosts', []) for p in host.get('ports', [])}
                
                for port in masscan_results['ports']:
                    port_num = str(port['port'])
                    if port_num in nmap_ports:
                        port.update(nmap_ports[port_num])
                
                masscan_results['scan_type'] = 'hybrid'
                masscan_results['service_detection'] = True
                
            return masscan_results
        else:
            # Fallback to basic nmap scan
            self.logger.info("Masscan found no ports, falling back to nmap basic scan")
            return self.basic_scan(target)
