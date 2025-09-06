#!/usr/bin/env python3
"""
Censys Search Engine - Real Implementation
Internet-wide scanning and device discovery via Censys API
"""

import re
import json
from datetime import datetime
from typing import Dict, List

from .base import BaseTool

class CensysScanner(BaseTool):
    """Real Censys API scanner implementation"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.command_name = "censys"
        self.api_id = config.get('censys_api_id', '')
        self.api_secret = config.get('censys_api_secret', '')
    
    def scan(self, target: str, scan_params: Dict) -> Dict:
        """Execute censys search against target"""
        self.start_time = datetime.now()
        
        try:
            self.logger.info(f"🔧 Starting CensysScanner search for {target}")
            
            if not self.api_id or not self.api_secret:
                return self._create_error_result("Censys API credentials not configured")
            
            # Unified command building for different search types
            search_type = scan_params.get('search_type', 'hosts')
            cmd_map = {
                'hosts': ['censys', 'search', 'hosts'],
                'certificates': ['censys', 'search', 'certificates'],
                'data': ['censys', 'view', 'hosts']
            }
            
            cmd = cmd_map.get(search_type, cmd_map['hosts'])
            
            # Build search query
            if search_type == 'hosts':
                query = f'ip:{target}' if self._is_ip(target) else f'autonomous_system.name:"{target}"'
            elif search_type == 'certificates':
                query = f'names:"{target}"'
            else:
                query = target
            
            cmd.extend([query, '--api-id', self.api_id, '--api-secret', self.api_secret])
            
            # Add output format
            cmd.extend(['--format', 'json'])
            
            # Execute with walrus operator
            if (result := self.execute_command(cmd, timeout=60)).returncode != 0:
                return self._create_error_result(f"Censys search failed: {result.stderr}")
            
            # Parse and build results
            censys_data = self._parse_output(result.stdout, search_type)
            self.save_raw_output(result.stdout, target, 'json')
            
            duration = (datetime.now() - self.start_time).total_seconds()
            result_count = len(censys_data.get('results', []))
            self.logger.info(f"✅ CensysScanner completed in {duration:.1f}s - {result_count} results")
            
            return {
                'status': 'success',
                'target': target,
                'scan_type': 'censys_search',
                'duration': duration,
                'censys_data': censys_data,
                'summary': {
                    'results_found': result_count,
                    'search_type': search_type
                }
            }
            
        except Exception as e:
            self.logger.error(f"❌ CensysScanner error: {e}")
            return self._create_error_result(str(e))
    
    def _parse_output(self, output: str, search_type: str) -> Dict:
        """Parse censys JSON output with unified approach"""
        censys_data = {
            'results': [],
            'metadata': {},
            'statistics': {}
        }
        
        try:
            data = json.loads(output)
            
            if search_type == 'hosts':
                # Parse host search results
                for result in data.get('result', {}).get('hits', []):
                    censys_data['results'].append({
                        'ip': result.get('ip', ''),
                        'ports': [p.get('port') for p in result.get('services', [])],
                        'protocols': [p.get('transport_protocol') for p in result.get('services', [])],
                        'autonomous_system': result.get('autonomous_system', {}),
                        'location': result.get('location', {}),
                        'last_updated': result.get('last_updated_at', '')
                    })
            
            elif search_type == 'certificates':
                # Parse certificate search results
                for result in data.get('result', {}).get('hits', []):
                    censys_data['results'].append({
                        'fingerprint': result.get('fingerprint_sha256', ''),
                        'names': result.get('names', []),
                        'issuer': result.get('parsed', {}).get('issuer', {}),
                        'subject': result.get('parsed', {}).get('subject', {}),
                        'validity': result.get('parsed', {}).get('validity', {}),
                        'seen_in_scan': result.get('seen_in_scan', False)
                    })
            
            # Extract metadata
            censys_data['metadata'] = {
                'total_results': data.get('result', {}).get('total', 0),
                'query': data.get('result', {}).get('query', ''),
                'duration': data.get('result', {}).get('duration', 0)
            }
            
        except json.JSONDecodeError:
            # Fallback to text parsing
            censys_data['results'] = [{'raw_output': output}]
        
        return censys_data
    
    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address"""
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target))
    
    def _create_error_result(self, error: str) -> Dict:
        """Create standardized error result"""
        return {
            'status': 'error',
            'error': error,
            'target': '',
            'scan_type': 'censys_search',
            'censys_data': {},
            'summary': {'results_found': 0}
        }
