#!/usr/bin/env python3
"""
Amass OSINT Enumeration - Optimized Implementation
Streamlined OSINT subdomain and asset discovery using OWASP Amass
"""

import json
from datetime import datetime
from typing import Dict, List, Set
from pathlib import Path

from .base import BaseTool

class AmassEnumerator(BaseTool):
    """Optimized Amass OSINT enumeration implementation"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.command_name = "amass"
        self.version = "v4.0+"
        self.description = "Comprehensive OSINT enumeration"
        self.category = "osint"
        
        # Simplified configuration
        self.timeout = config.get('timeout', 300)
        self.max_dns_queries = config.get('max_dns_queries', 20000)
    
    def scan(self, target: str, scan_params: Dict = None) -> Dict:
        """Execute amass scan against target"""
        if scan_params is None:
            scan_params = {}
            
        self.start_time = datetime.now()
        
        try:
            self.logger.info(f"🔧 Starting AmassEnumerator scan against {target}")
            
            if not self.verify_installation():
                return self._error_result("Amass not installed")
            
            scan_type = scan_params.get('scan_type', 'passive')
            
            # Unified scan execution
            return self._execute_scan(target, scan_type, scan_params)
                
        except Exception as e:
            self.logger.error(f"❌ AmassEnumerator error: {e}")
            return self._error_result(str(e))
    
    def _execute_scan(self, domain: str, scan_type: str, params: Dict) -> Dict:
        """Unified scan execution method"""
        
        # Command mapping with cleaner structure
        commands = {
            'passive': ['amass', 'enum', '-passive', '-d', domain],
            'active': ['amass', 'enum', '-active', '-d', domain] + 
                     (['-brute'] if params.get('brute_force', False) else []),
            'intel': ['amass', 'intel', '-d', domain, '-whois'],
            'comprehensive': None  # Special case handled separately
        }
        
        if scan_type == 'comprehensive':
            return self._comprehensive_scan(domain, params)
        
        if scan_type not in commands:
            return self._error_result(f"Unknown scan type: {scan_type}")
        
        return self._run_command(domain, scan_type, commands[scan_type], params)
    
    def _run_command(self, domain: str, scan_type: str, base_cmd: List, params: Dict) -> Dict:
        """Execute single amass command and parse results"""
        try:
            self.logger.info(f"Running Amass {scan_type} enumeration for {domain}")
            
            # Build command with output
            output_file = self.get_results_dir() / f'amass_{scan_type}.json'
            cmd = base_cmd + ['-json', str(output_file)]
            
            # Add common parameters
            timeout = params.get('timeout', self.timeout)
            cmd.extend(['-timeout', str(timeout)])
            
            if scan_type != 'intel':  # DNS queries don't apply to intel mode
                cmd.extend(['-max-dns-queries', str(params.get('max_dns_queries', self.max_dns_queries))])
            
            # Execute command
            result = self.execute_command(cmd, timeout=timeout + 60)
            
            if result.returncode != 0:
                self.logger.warning(f"Amass {scan_type} returned exit code: {result.returncode}")
            
            # Parse and return results
            parsed_data = self._parse_output(output_file, scan_type == 'intel')
            
            return self._build_result(domain, scan_type, parsed_data, params.get('brute_force', False))
            
        except Exception as e:
            self.logger.error(f"Error in {scan_type} enumeration: {e}")
            return self._error_result(str(e))
    
    def _comprehensive_scan(self, domain: str, params: Dict) -> Dict:
        """Optimized comprehensive enumeration"""
        self.logger.info(f"Running comprehensive Amass enumeration for {domain}")
        
        # Run passive and intel in parallel concept (simplified here)
        passive_result = self._run_command(domain, 'passive', 
                                         ['amass', 'enum', '-passive', '-d', domain], params)
        intel_result = self._run_command(domain, 'intel', 
                                       ['amass', 'intel', '-d', domain, '-whois'], params)
        
        # Combine results efficiently
        combined = self._merge_results([passive_result, intel_result])
        combined.update({
            'scan_type': 'amass_comprehensive',
            'passive_results': passive_result,
            'intel_results': intel_result
        })
        
        return combined
    
    def _parse_output(self, output_file: Path, is_intel: bool = False) -> Dict:
        """Streamlined output parsing"""
        if not output_file.exists():
            return {'subdomains': [], 'assets': [], 'ips': [], 'sources': []}
        
        subdomains, assets, ips, sources = [], [], set(), set()
        
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        
                        if is_intel:
                            # Intel mode parsing
                            assets.append({
                                'domain': data.get('name', ''),
                                'type': data.get('type', 'domain'),
                                'source': data.get('source', 'unknown'),
                                'addresses': data.get('addresses', [])
                            })
                        else:
                            # Enum mode parsing
                            subdomains.append({
                                'name': data['name'],
                                'addresses': data.get('addresses', []),
                                'source': data.get('source', 'unknown')
                            })
                            
                            # Extract IPs efficiently
                            ips.update(addr.get('ip') for addr in data.get('addresses', []) 
                                     if addr.get('ip'))
                        
                        # Common source tracking
                        if 'source' in data:
                            sources.add(data['source'])
                            
                    except (json.JSONDecodeError, KeyError):
                        continue
                        
        except Exception as e:
            self.logger.warning(f"Error parsing output: {e}")
        
        return {
            'subdomains': subdomains,
            'assets': assets,
            'ips': list(ips),
            'sources': list(sources)
        }
    
    def _build_result(self, domain: str, scan_type: str, data: Dict, brute_force: bool = False) -> Dict:
        """Build standardized result dictionary"""
        duration = (datetime.now() - self.start_time).total_seconds()
        
        result = {
            'status': 'success',
            'target': domain,
            'scan_type': f'amass_{scan_type}',
            'duration': duration,
            'timestamp': datetime.now().isoformat()
        }
        
        if scan_type == 'intel':
            result.update({
                'assets': data['assets'],
                'summary': {'total_assets': len(data['assets'])}
            })
        else:
            result.update({
                'subdomains': data['subdomains'],
                'ip_addresses': data['ips'],
                'data_sources': data['sources'],
                'summary': {
                    'total_subdomains': len(data['subdomains']),
                    'total_ips': len(data['ips']),
                    'sources_used': len(data['sources']),
                    'brute_force': brute_force
                }
            })
        
        count = len(data.get('assets' if scan_type == 'intel' else 'subdomains', []))
        self.logger.info(f"✅ AmassEnumerator {scan_type} completed: {count} items in {duration:.1f}s")
        
        return result
    
    def _merge_results(self, results: List[Dict]) -> Dict:
        """Efficiently merge multiple scan results"""
        all_subdomains, all_ips = set(), set()
        
        for result in results:
            if result['status'] == 'success':
                # Extract subdomains
                for sub in result.get('subdomains', []):
                    all_subdomains.add(sub['name'])
                
                # Extract IPs
                all_ips.update(result.get('ip_addresses', []))
                
                # Extract from assets (intel mode)
                for asset in result.get('assets', []):
                    if 'domain' in asset:
                        all_subdomains.add(asset['domain'])
        
        return {
            'status': 'success',
            'combined_summary': {
                'total_unique_subdomains': len(all_subdomains),
                'total_unique_ips': len(all_ips),
                'subdomains': list(all_subdomains),
                'ip_addresses': list(all_ips)
            }
        }
    
    def _error_result(self, error: str) -> Dict:
        """Simplified error result"""
        return {
            'status': 'error',
            'error': error,
            'timestamp': datetime.now().isoformat(),
            'subdomains': [],
            'summary': {'total_subdomains': 0}
        }
    
    # Simplified convenience methods
    def quick_scan(self, domain: str) -> Dict:
        """Quick passive scan (2 minutes)"""
        return self.scan(domain, {'scan_type': 'passive', 'timeout': 120})
    
    def deep_scan(self, domain: str) -> Dict:
        """Deep enumeration (10 minutes with brute force)"""
        return self.scan(domain, {
            'scan_type': 'comprehensive', 
            'timeout': 600, 
            'brute_force': True
        })
