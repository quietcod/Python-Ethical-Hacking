#!/usr/bin/env python3
"""
TheHarvester OSINT Information Gathering - Real Implementation
Email, subdomain, and host information gathering using theharvester
"""

import re
from datetime import datetime
from typing import Dict, List

from .base import BaseTool

class TheHarvesterOSINT(BaseTool):
    """Real TheHarvester OSINT information gathering implementation"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.command_name = "theharvester"
    
    def scan(self, domain: str, scan_params: Dict) -> Dict:
        """Execute theharvester scan against target domain"""
        self.start_time = datetime.now()
        
        try:
            self.logger.info(f"🔧 Starting TheHarvesterOSINT scan against {domain}")
            
            if not self.verify_installation():
                return self._create_error_result("theHarvester not installed")
            
            # Unified command building
            cmd = ['theharvester', '-d', domain, '-l', '500']
            
            # Add data sources
            sources = scan_params.get('sources', ['google', 'bing', 'duckduckgo'])
            cmd.extend(['-b', ','.join(sources)])
            
            # Add additional options
            if scan_params.get('dns_lookup'):
                cmd.append('-n')
            if scan_params.get('virtual_host'):
                cmd.append('-v')
            
            # Execute with walrus operator
            if (result := self.execute_command(cmd, timeout=300)).returncode not in [0, 1]:
                return self._create_error_result(f"theHarvester scan failed: {result.stderr}")
            
            # Parse and build results
            osint_data = self._parse_output(result.stdout, domain)
            self.save_raw_output(result.stdout, domain, 'txt')
            
            duration = (datetime.now() - self.start_time).total_seconds()
            email_count = len(osint_data.get('emails', []))
            subdomain_count = len(osint_data.get('subdomains', []))
            self.logger.info(f"✅ TheHarvesterOSINT completed in {duration:.1f}s - {email_count} emails, {subdomain_count} subdomains")
            
            return {
                'status': 'success',
                'target': domain,
                'scan_type': 'theharvester_osint',
                'duration': duration,
                'osint_data': osint_data,
                'summary': {
                    'emails_found': email_count,
                    'subdomains_found': subdomain_count,
                    'hosts_found': len(osint_data.get('hosts', []))
                }
            }
            
        except Exception as e:
            self.logger.error(f"❌ TheHarvesterOSINT error: {e}")
            return self._create_error_result(str(e))
    
    def _parse_output(self, output: str, domain: str) -> Dict:
        """Parse theharvester output with unified approach"""
        osint_data = {
            'emails': [],
            'subdomains': [],
            'hosts': [],
            'social_media': []
        }
        
        current_section = None
        
        for line in output.strip().split('\n'):
            line = line.strip()
            
            # Identify sections
            if '[*] Emails found:' in line:
                current_section = 'emails'
                continue
            elif '[*] Hosts found:' in line:
                current_section = 'hosts'
                continue
            elif '[*] Subdomains found:' in line:
                current_section = 'subdomains'
                continue
            
            # Parse data based on current section
            if current_section == 'emails' and '@' in line:
                if email := re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', line):
                    osint_data['emails'].append({
                        'email': email.group(1),
                        'source': 'theharvester',
                        'found_at': datetime.now().isoformat()
                    })
            elif current_section == 'hosts' and domain in line:
                osint_data['hosts'].append({
                    'host': line,
                    'domain': domain,
                    'found_at': datetime.now().isoformat()
                })
            elif current_section == 'subdomains' and domain in line:
                osint_data['subdomains'].append({
                    'subdomain': line,
                    'domain': domain,
                    'found_at': datetime.now().isoformat()
                })
        
        # Remove duplicates
        osint_data['emails'] = list({v['email']: v for v in osint_data['emails']}.values())
        osint_data['subdomains'] = list({v['subdomain']: v for v in osint_data['subdomains']}.values())
        osint_data['hosts'] = list({v['host']: v for v in osint_data['hosts']}.values())
        
        return osint_data
    
    def _create_error_result(self, error: str) -> Dict:
        """Create standardized error result"""
        return {
            'status': 'error',
            'error': error,
            'target': '',
            'scan_type': 'theharvester_osint',
            'osint_data': {},
            'summary': {'emails_found': 0}
        }
