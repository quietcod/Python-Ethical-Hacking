#!/usr/bin/env python3
"""
Shodan Search Engine - Real Implementation
Internet-connected device and service discovery via Shodan API
"""

import re
import json
from datetime import datetime
from typing import Dict, List

from .base import BaseTool

class ShodanScanner(BaseTool):
    """Real Shodan API scanner implementation"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.command_name = "shodan"
        self.api_key = config.get('shodan_api_key', '')
    
    def scan(self, target: str, scan_params: Dict) -> Dict:
        """Execute shodan search against target"""
        self.start_time = datetime.now()
        
        try:
            self.logger.info(f"🔧 Starting ShodanScanner search for {target}")
            
            if not self.api_key:
                return self._create_error_result("Shodan API key not configured")
            
            # Unified command building for different search types
            search_type = scan_params.get('search_type', 'host')
            cmd_map = {
                'host': ['shodan', 'host', target],
                'search': ['shodan', 'search', target],
                'domain': ['shodan', 'domain', target],
                'count': ['shodan', 'count', target]
            }
            
            cmd = cmd_map.get(search_type, cmd_map['search'])
            
            # Add API key
            cmd.extend(['--key', self.api_key])
            
            # Add output format and limits
            if search_type == 'search':
                cmd.extend(['--limit', str(scan_params.get('limit', 100))])
            
            # Execute with walrus operator
            if (result := self.execute_command(cmd, timeout=60)).returncode != 0:
                return self._create_error_result(f"Shodan search failed: {result.stderr}")
            
            # Parse and build results
            shodan_data = self._parse_output(result.stdout, search_type)
            self.save_raw_output(result.stdout, target, 'json')
            
            duration = (datetime.now() - self.start_time).total_seconds()
            result_count = len(shodan_data.get('results', []))
            self.logger.info(f"✅ ShodanScanner completed in {duration:.1f}s - {result_count} results")
            
            return {
                'status': 'success',
                'target': target,
                'scan_type': 'shodan_search',
                'duration': duration,
                'shodan_data': shodan_data,
                'summary': {
                    'results_found': result_count,
                    'search_type': search_type,
                    'unique_ports': len(set(r.get('port', 0) for r in shodan_data.get('results', [])))
                }
            }
            
        except Exception as e:
            self.logger.error(f"❌ ShodanScanner error: {e}")
            return self._create_error_result(str(e))
    
    def _parse_output(self, output: str, search_type: str) -> Dict:
        """Parse shodan JSON output with unified approach"""
        shodan_data = {
            'results': [],
            'statistics': {},
            'metadata': {}
        }
        
        try:
            data = json.loads(output)
            
            if search_type == 'host':
                # Parse single host data
                shodan_data['results'].append({
                    'ip': data.get('ip_str', ''),
                    'hostnames': data.get('hostnames', []),
                    'country': data.get('country_name', ''),
                    'organization': data.get('org', ''),
                    'asn': data.get('asn', ''),
                    'ports': data.get('ports', []),
                    'services': [{
                        'port': service.get('port', 0),
                        'transport': service.get('transport', ''),
                        'product': service.get('product', ''),
                        'version': service.get('version', ''),
                        'banner': service.get('data', '')[:200] if service.get('data') else ''
                    } for service in data.get('data', [])]
                })
            
            elif search_type == 'search':
                # Parse search results
                for match in data.get('matches', []):
                    shodan_data['results'].append({
                        'ip': match.get('ip_str', ''),
                        'port': match.get('port', 0),
                        'transport': match.get('transport', ''),
                        'product': match.get('product', ''),
                        'version': match.get('version', ''),
                        'hostnames': match.get('hostnames', []),
                        'location': {
                            'country': match.get('location', {}).get('country_name', ''),
                            'city': match.get('location', {}).get('city', ''),
                            'latitude': match.get('location', {}).get('latitude', 0),
                            'longitude': match.get('location', {}).get('longitude', 0)
                        },
                        'organization': match.get('org', ''),
                        'banner': match.get('data', '')[:200] if match.get('data') else '',
                        'timestamp': match.get('timestamp', '')
                    })
                
                # Extract metadata
                shodan_data['metadata'] = {
                    'total': data.get('total', 0),
                    'query': data.get('query', ''),
                    'facets': data.get('facets', {})
                }
            
            elif search_type == 'domain':
                # Parse domain information
                shodan_data['results'] = [{
                    'domain': data.get('domain', ''),
                    'subdomains': data.get('subdomains', []),
                    'tags': data.get('tags', [])
                }]
            
        except json.JSONDecodeError:
            # Fallback to text parsing
            lines = output.strip().split('\n')
            for line in lines:
                if ':' in line and any(char.isdigit() for char in line):
                    # Try to extract IP and port information
                    if match := re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line):
                        shodan_data['results'].append({
                            'ip': match.group(1),
                            'port': int(match.group(2)),
                            'raw_data': line
                        })
        
        return shodan_data
    
    def _create_error_result(self, error: str) -> Dict:
        """Create standardized error result"""
        return {
            'status': 'error',
            'error': error,
            'target': '',
            'scan_type': 'shodan_search',
            'shodan_data': {},
            'summary': {'results_found': 0}
        }
