"""
Network Scanner
Network topology mapping and analysis
"""

import json
import logging
import socket
import subprocess
from pathlib import Path
from typing import Dict, Any, List

from ...core.exceptions import ScanError
from ...core.utils import check_tool_installed


class NetworkScanner:
    """Network topology mapping and analysis tool"""
    
    def __init__(self, output_dir: Path, config: Dict[str, Any], logger: logging.Logger):
        self.output_dir = output_dir
        self.config = config
        self.logger = logger
        
        # Create network output directory
        self.network_dir = output_dir / 'network'
        self.network_dir.mkdir(exist_ok=True)
        
    def scan_network(self, target: str) -> Dict[str, Any]:
        """Run comprehensive network analysis"""
        self.logger.info(f"Starting network scan for {target}")
        
        results = {
            'target': target,
            'network_discovery': {},
            'topology_mapping': {},
            'route_analysis': {},
            'connectivity_tests': {}
        }
        
        try:
            # Network discovery and mapping
            self._discover_network_hosts(target, results)
            
            # Network topology mapping
            self._map_network_topology(target, results)
            
            # Route analysis
            self._analyze_routing(target, results)
            
            # Connectivity tests
            self._perform_connectivity_tests(target, results)
            
            # Save results
            self._save_network_results(target, results)
            
        except Exception as e:
            self.logger.error(f"Network scan failed: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def _discover_network_hosts(self, target: str, results: Dict[str, Any]) -> None:
        """Discover live hosts in network"""
        self.logger.info(f"Discovering network hosts for {target}")
        
        discovery_results = {
            'ping_sweep': {},
            'arp_scan': {},
            'live_hosts': []
        }
        
        try:
            # Determine if target is a network range or single host
            if '/' in target:  # CIDR notation
                network_range = target
            else:
                # Single host - try to determine network
                network_range = self._determine_network_range(target)
            
            if network_range:
                # Ping sweep for network discovery
                if check_tool_installed('nmap'):
                    ping_results = self._nmap_ping_sweep(network_range)
                    discovery_results['ping_sweep'] = ping_results
                else:
                    # Fallback ping sweep
                    ping_results = self._basic_ping_sweep(target)
                    discovery_results['ping_sweep'] = ping_results
                
                # ARP scan (if available and on local network)
                if check_tool_installed('arp-scan'):
                    arp_results = self._arp_scan(network_range)
                    discovery_results['arp_scan'] = arp_results
            else:
                # Single host connectivity test
                single_host_result = self._test_single_host(target)
                discovery_results['ping_sweep'] = {'single_host': single_host_result}
            
        except Exception as e:
            self.logger.error(f"Network discovery error: {str(e)}")
            discovery_results['error'] = str(e)
        
        results['network_discovery'] = discovery_results
    
    def _determine_network_range(self, target: str) -> str:
        """Determine network range for a single host"""
        try:
            # Try to resolve hostname to IP if needed
            if not target.replace('.', '').isdigit():
                ip = socket.gethostbyname(target)
            else:
                ip = target
            
            # Get network interface information to determine likely subnet
            # This is a simplified approach - assumes /24 subnet
            ip_parts = ip.split('.')
            if len(ip_parts) == 4:
                network = '.'.join(ip_parts[:3]) + '.0/24'
                return network
            
        except Exception as e:
            self.logger.debug(f"Could not determine network range: {str(e)}")
        
        return None
    
    def _nmap_ping_sweep(self, network_range: str) -> Dict[str, Any]:
        """Perform ping sweep using nmap"""
        try:
            self.logger.info(f"Running nmap ping sweep on {network_range}")
            
            output_file = self.network_dir / f'ping_sweep_{network_range.replace("/", "_")}.xml'
            
            cmd = [
                'nmap',
                '-sn',  # Ping scan only
                '-PE', '-PP', '-PM',  # Different ping types
                '--reason',
                '-oX', str(output_file),
                network_range
            ]
            
            timeout = self.config.get('network', {}).get('discovery_timeout', 120)
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            ping_results = {
                'command': ' '.join(cmd),
                'return_code': result.returncode,
                'output_file': str(output_file)
            }
            
            if result.returncode == 0:
                # Parse output for live hosts
                live_hosts = self._parse_nmap_ping_output(result.stdout)
                ping_results['live_hosts'] = live_hosts
                ping_results['host_count'] = len(live_hosts)
                
                self.logger.info(f"Ping sweep found {len(live_hosts)} live hosts")
            else:
                ping_results['error'] = result.stderr.strip()
            
            return ping_results
            
        except subprocess.TimeoutExpired:
            return {'error': 'Ping sweep timed out'}
        except Exception as e:
            return {'error': str(e)}
    
    def _basic_ping_sweep(self, target: str) -> Dict[str, Any]:
        """Basic ping test for single host"""
        try:
            self.logger.info(f"Running basic ping test for {target}")
            
            cmd = ['ping', '-c', '4', target]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            ping_results = {
                'command': ' '.join(cmd),
                'return_code': result.returncode,
                'output': result.stdout,
                'alive': result.returncode == 0
            }
            
            if result.returncode == 0:
                # Extract timing information
                ping_results['timing'] = self._parse_ping_timing(result.stdout)
            
            return ping_results
            
        except subprocess.TimeoutExpired:
            return {'error': 'Ping test timed out', 'alive': False}
        except Exception as e:
            return {'error': str(e), 'alive': False}
    
    def _arp_scan(self, network_range: str) -> Dict[str, Any]:
        """Perform ARP scan for local network discovery"""
        try:
            self.logger.info(f"Running ARP scan on {network_range}")
            
            cmd = ['arp-scan', '-l']  # Local network scan
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            arp_results = {
                'command': ' '.join(cmd),
                'return_code': result.returncode,
                'output': result.stdout
            }
            
            if result.returncode == 0:
                # Parse ARP scan output
                arp_hosts = self._parse_arp_output(result.stdout)
                arp_results['hosts'] = arp_hosts
                arp_results['host_count'] = len(arp_hosts)
            
            return arp_results
            
        except subprocess.TimeoutExpired:
            return {'error': 'ARP scan timed out'}
        except Exception as e:
            return {'error': str(e)}
    
    def _test_single_host(self, target: str) -> Dict[str, Any]:
        """Test connectivity to a single host"""
        try:
            # Basic ping test
            ping_result = self._basic_ping_sweep(target)
            
            # Try to resolve hostname
            try:
                ip = socket.gethostbyname(target)
                hostname_resolution = {'resolved': True, 'ip': ip}
            except:
                hostname_resolution = {'resolved': False}
            
            return {
                'ping_test': ping_result,
                'hostname_resolution': hostname_resolution
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _map_network_topology(self, target: str, results: Dict[str, Any]) -> None:
        """Map network topology using traceroute"""
        self.logger.info(f"Mapping network topology for {target}")
        
        topology_results = {
            'traceroute': {},
            'mtr_analysis': {}
        }
        
        try:
            # Traceroute analysis
            if check_tool_installed('traceroute'):
                traceroute_result = self._run_traceroute(target)
                topology_results['traceroute'] = traceroute_result
            
            # MTR analysis (if available)
            if check_tool_installed('mtr'):
                mtr_result = self._run_mtr(target)
                topology_results['mtr_analysis'] = mtr_result
            
        except Exception as e:
            self.logger.error(f"Topology mapping error: {str(e)}")
            topology_results['error'] = str(e)
        
        results['topology_mapping'] = topology_results
    
    def _run_traceroute(self, target: str) -> Dict[str, Any]:
        """Run traceroute to map network path"""
        try:
            cmd = ['traceroute', target]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            traceroute_result = {
                'command': ' '.join(cmd),
                'return_code': result.returncode,
                'output': result.stdout
            }
            
            if result.returncode == 0:
                # Parse traceroute hops
                hops = self._parse_traceroute_output(result.stdout)
                traceroute_result['hops'] = hops
                traceroute_result['hop_count'] = len(hops)
            
            return traceroute_result
            
        except subprocess.TimeoutExpired:
            return {'error': 'Traceroute timed out'}
        except Exception as e:
            return {'error': str(e)}
    
    def _run_mtr(self, target: str) -> Dict[str, Any]:
        """Run MTR for continuous network analysis"""
        try:
            cmd = ['mtr', '-r', '-c', '10', target]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            mtr_result = {
                'command': ' '.join(cmd),
                'return_code': result.returncode,
                'output': result.stdout
            }
            
            if result.returncode == 0:
                # Parse MTR statistics
                stats = self._parse_mtr_output(result.stdout)
                mtr_result['statistics'] = stats
            
            return mtr_result
            
        except subprocess.TimeoutExpired:
            return {'error': 'MTR analysis timed out'}
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_routing(self, target: str, results: Dict[str, Any]) -> None:
        """Analyze routing information"""
        self.logger.info(f"Analyzing routing information for {target}")
        
        routing_results = {
            'routing_table': {},
            'route_to_target': {}
        }
        
        try:
            # Get routing table
            if check_tool_installed('ip'):
                route_table = self._get_routing_table_ip()
                routing_results['routing_table'] = route_table
            elif check_tool_installed('route'):
                route_table = self._get_routing_table_route()
                routing_results['routing_table'] = route_table
            
            # Get specific route to target
            route_to_target = self._get_route_to_target(target)
            routing_results['route_to_target'] = route_to_target
            
        except Exception as e:
            self.logger.error(f"Route analysis error: {str(e)}")
            routing_results['error'] = str(e)
        
        results['route_analysis'] = routing_results
    
    def _get_routing_table_ip(self) -> Dict[str, Any]:
        """Get routing table using ip command"""
        try:
            cmd = ['ip', 'route', 'show']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            return {
                'command': ' '.join(cmd),
                'return_code': result.returncode,
                'output': result.stdout
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _get_routing_table_route(self) -> Dict[str, Any]:
        """Get routing table using route command"""
        try:
            cmd = ['route', '-n']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            return {
                'command': ' '.join(cmd),
                'return_code': result.returncode,
                'output': result.stdout
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _get_route_to_target(self, target: str) -> Dict[str, Any]:
        """Get specific route to target"""
        try:
            if check_tool_installed('ip'):
                cmd = ['ip', 'route', 'get', target]
            else:
                return {'error': 'No route command available'}
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            return {
                'command': ' '.join(cmd),
                'return_code': result.returncode,
                'output': result.stdout
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _perform_connectivity_tests(self, target: str, results: Dict[str, Any]) -> None:
        """Perform various connectivity tests"""
        self.logger.info(f"Performing connectivity tests for {target}")
        
        connectivity_results = {
            'ping_test': {},
            'tcp_connect_tests': {},
            'dns_resolution': {}
        }
        
        try:
            # Basic ping test
            ping_result = self._basic_ping_sweep(target)
            connectivity_results['ping_test'] = ping_result
            
            # TCP connectivity tests on common ports
            common_ports = [22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
            tcp_results = {}
            
            for port in common_ports:
                tcp_results[port] = self._test_tcp_connectivity(target, port)
            
            connectivity_results['tcp_connect_tests'] = tcp_results
            
            # DNS resolution test
            dns_result = self._test_dns_resolution(target)
            connectivity_results['dns_resolution'] = dns_result
            
        except Exception as e:
            self.logger.error(f"Connectivity tests error: {str(e)}")
            connectivity_results['error'] = str(e)
        
        results['connectivity_tests'] = connectivity_results
    
    def _test_tcp_connectivity(self, target: str, port: int) -> Dict[str, Any]:
        """Test TCP connectivity to a specific port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            result = sock.connect_ex((target, port))
            sock.close()
            
            return {
                'port': port,
                'open': result == 0,
                'status': 'open' if result == 0 else 'closed/filtered'
            }
            
        except Exception as e:
            return {
                'port': port,
                'open': False,
                'status': 'error',
                'error': str(e)
            }
    
    def _test_dns_resolution(self, target: str) -> Dict[str, Any]:
        """Test DNS resolution"""
        try:
            # Forward DNS resolution
            ip = socket.gethostbyname(target)
            
            # Reverse DNS resolution
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                reverse_resolution = {'success': True, 'hostname': hostname}
            except:
                reverse_resolution = {'success': False}
            
            return {
                'forward_resolution': {'success': True, 'ip': ip},
                'reverse_resolution': reverse_resolution
            }
            
        except Exception as e:
            return {
                'forward_resolution': {'success': False, 'error': str(e)},
                'reverse_resolution': {'success': False}
            }
    
    def _parse_nmap_ping_output(self, output: str) -> List[str]:
        """Parse nmap ping sweep output"""
        live_hosts = []
        
        for line in output.split('\n'):
            if 'Nmap scan report for' in line:
                # Extract IP or hostname
                parts = line.split()
                if len(parts) >= 5:
                    host = parts[4]
                    if host.startswith('(') and host.endswith(')'):
                        host = host[1:-1]  # Remove parentheses
                    live_hosts.append(host)
        
        return live_hosts
    
    def _parse_ping_timing(self, output: str) -> Dict[str, Any]:
        """Parse ping timing information"""
        timing = {}
        
        for line in output.split('\n'):
            if 'min/avg/max' in line:
                # Extract timing statistics
                parts = line.split('=')
                if len(parts) >= 2:
                    stats = parts[1].strip().split('/')
                    if len(stats) >= 3:
                        timing = {
                            'min': stats[0],
                            'avg': stats[1],
                            'max': stats[2]
                        }
        
        return timing
    
    def _parse_arp_output(self, output: str) -> List[Dict[str, str]]:
        """Parse ARP scan output"""
        hosts = []
        
        for line in output.split('\n'):
            if '\t' in line:  # ARP entries typically have tabs
                parts = line.split('\t')
                if len(parts) >= 2:
                    hosts.append({
                        'ip': parts[0].strip(),
                        'mac': parts[1].strip() if len(parts) > 1 else '',
                        'vendor': parts[2].strip() if len(parts) > 2 else ''
                    })
        
        return hosts
    
    def _parse_traceroute_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse traceroute output"""
        hops = []
        
        for line in output.split('\n'):
            line = line.strip()
            if line and line[0].isdigit():
                # Parse hop line
                parts = line.split()
                if len(parts) >= 3:
                    hop_num = parts[0]
                    hop_info = {
                        'hop': hop_num,
                        'address': parts[1] if len(parts) > 1 else '',
                        'hostname': parts[2] if len(parts) > 2 else '',
                        'times': []
                    }
                    
                    # Extract timing information
                    for part in parts[3:]:
                        if 'ms' in part:
                            hop_info['times'].append(part)
                    
                    hops.append(hop_info)
        
        return hops
    
    def _parse_mtr_output(self, output: str) -> Dict[str, Any]:
        """Parse MTR output"""
        stats = {'hops': []}
        
        for line in output.split('\n'):
            line = line.strip()
            if line and line[0].isdigit():
                # Parse MTR line
                parts = line.split()
                if len(parts) >= 6:
                    hop_stats = {
                        'hop': parts[0],
                        'hostname': parts[1],
                        'loss_percent': parts[2],
                        'sent': parts[3],
                        'last': parts[4],
                        'avg': parts[5],
                        'best': parts[6] if len(parts) > 6 else '',
                        'worst': parts[7] if len(parts) > 7 else ''
                    }
                    stats['hops'].append(hop_stats)
        
        return stats
    
    def _save_network_results(self, target: str, results: Dict[str, Any]) -> None:
        """Save network analysis results"""
        sanitized_target = target.replace(':', '_').replace('/', '_')
        
        # Save JSON results
        json_file = self.network_dir / f'{sanitized_target}_network_results.json'
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        self.logger.info(f"Network results saved to {json_file}")
        
        # Create human-readable summary
        txt_file = self.network_dir / f'{sanitized_target}_network_summary.txt'
        
        with open(txt_file, 'w') as f:
            f.write(f"Network Analysis Summary for {target}\n")
            f.write("=" * 50 + "\n\n")
            
            # Network Discovery
            discovery = results.get('network_discovery', {})
            if discovery:
                f.write("Network Discovery:\n")
                
                ping_sweep = discovery.get('ping_sweep', {})
                if ping_sweep and 'live_hosts' in ping_sweep:
                    f.write(f"  Live Hosts Found: {ping_sweep.get('host_count', 0)}\n")
                    for host in ping_sweep['live_hosts'][:10]:  # Limit to 10
                        f.write(f"    {host}\n")
                
                f.write("\n")
            
            # Topology Mapping
            topology = results.get('topology_mapping', {})
            if topology:
                f.write("Network Topology:\n")
                
                traceroute = topology.get('traceroute', {})
                if traceroute and 'hop_count' in traceroute:
                    f.write(f"  Traceroute Hops: {traceroute['hop_count']}\n")
                
                f.write("\n")
            
            # Connectivity Tests
            connectivity = results.get('connectivity_tests', {})
            if connectivity:
                f.write("Connectivity Tests:\n")
                
                ping_test = connectivity.get('ping_test', {})
                if ping_test:
                    f.write(f"  Ping Test: {'Success' if ping_test.get('alive') else 'Failed'}\n")
                
                tcp_tests = connectivity.get('tcp_connect_tests', {})
                if tcp_tests:
                    open_ports = [port for port, result in tcp_tests.items() if result.get('open')]
                    f.write(f"  Open TCP Ports: {', '.join(map(str, open_ports)) if open_ports else 'None'}\n")
                
                dns_resolution = connectivity.get('dns_resolution', {})
                if dns_resolution:
                    forward = dns_resolution.get('forward_resolution', {})
                    f.write(f"  DNS Resolution: {'Success' if forward.get('success') else 'Failed'}\n")
                    if forward.get('success'):
                        f.write(f"    Resolved IP: {forward.get('ip')}\n")
        
        self.logger.info(f"Network summary saved to {txt_file}")
