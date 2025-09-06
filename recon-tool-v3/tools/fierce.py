#!/usr/bin/env python3
"""
Fierce Domain Scanner - DEPRECATED in favor of DNSRecon
Legacy domain enumeration tool - USE DNSRecon INSTEAD for comprehensive DNS analysis
Status: Deprecated - kept for compatibility only
Replacement: DNSRecon (tools/dnsrecon.py) - more comprehensive and feature-rich
"""

import re
from datetime import datetime
from typing import Dict, List

from .base import BaseTool

class FierceScanner(BaseTool):
    """DEPRECATED: Fierce domain enumeration - Use DNSRecon instead"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.command_name = "fierce"
        self.deprecated = True
        self.replacement_tool = "dnsrecon"
    
    def scan(self, domain: str, scan_params: Dict) -> Dict:
        """Execute fierce scan - DEPRECATED, use DNSRecon instead"""
        self.start_time = datetime.now()
        
        # Log deprecation warning
        self.logger.warning(f"⚠️  DEPRECATED: Fierce is deprecated. Use DNSRecon for comprehensive DNS analysis")
        self.logger.info(f"🔧 Starting DEPRECATED FierceScanner scan against {domain}")
        
        try:
            if not self.verify_installation():
                return self._create_error_result("Fierce not installed - Use DNSRecon instead")
            
            # Simplified command for basic compatibility
            cmd = ['fierce', '--domain', domain]
            
            # Basic options only
            if wordlist := scan_params.get('wordlist'):
                cmd.extend(['--wordlist', wordlist])
            
            # Execute with shorter timeout since deprecated
            if (result := self.execute_command(cmd, timeout=180)).returncode not in [0, 1]:
                return self._create_error_result(f"Fierce scan failed: {result.stderr} - Consider using DNSRecon")
            
            # Basic parsing only
            findings = self._parse_basic_output(result.stdout, domain)
            self.save_raw_output(result.stdout, domain, 'txt')
            
            duration = (datetime.now() - self.start_time).total_seconds()
            subdomain_count = len([f for f in findings if f.get('type') == 'subdomain'])
            self.logger.warning(f"⚠️  DEPRECATED FierceScanner completed in {duration:.1f}s - Use DNSRecon for better results")
            
            return {
                'status': 'success',
                'target': domain,
                'scan_type': 'fierce_deprecated',
                'deprecated': True,
                'replacement': 'dnsrecon',
                'duration': duration,
                'findings': findings,
                'summary': {
                    'total_findings': len(findings),
                    'subdomains_found': subdomain_count,
                    'deprecation_notice': 'This tool is deprecated. Use DNSRecon for comprehensive DNS analysis.'
                }
            }
            
        except Exception as e:
            self.logger.error(f"❌ DEPRECATED FierceScanner error: {e}")
            return self._create_error_result(str(e))
    
    def _parse_basic_output(self, output: str, domain: str) -> List[Dict]:
        """Parse fierce output with unified approach"""
        findings = []
        
        for line in output.strip().split('\n'):
            # Parse various fierce output patterns
            if match := re.search(r'(\d+\.\d+\.\d+\.\d+)\s+(.+)', line):
                ip, hostname = match.groups()
                findings.append({
                    'type': 'subdomain',
                    'hostname': hostname.strip(),
                    'ip': ip.strip(),
                    'domain': domain,
                    'found_at': datetime.now().isoformat()
                })
            elif 'Found' in line and domain in line:
                findings.append({
                    'type': 'info',
                    'description': line.strip(),
                    'domain': domain,
                    'found_at': datetime.now().isoformat()
                })
            elif 'NS' in line or 'MX' in line or 'SOA' in line:
                findings.append({
                    'type': 'dns_record',
                    'record': line.strip(),
                    'domain': domain,
                    'found_at': datetime.now().isoformat()
                })
        
        return findings
    
    def _create_error_result(self, error: str) -> Dict:
        """Create standardized error result"""
        return {
            'status': 'error',
            'error': error,
            'target': '',
            'scan_type': 'fierce_domain_enum',
            'findings': [],
            'summary': {'total_findings': 0}
        }
