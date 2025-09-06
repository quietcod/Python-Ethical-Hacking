#!/usr/bin/env python3
"""
DNSRecon DNS Enumeration - Optimized as Primary DNS Tool
Comprehensive DNS reconnaissance and enumeration - THE primary DNS analysis tool
Specialized for: Complete DNS enumeration, zone transfers, subdomain discovery, DNS security assessment
"""

import re
import json
from datetime import datetime
from typing import Dict, List

from .base import BaseTool

class DNSReconEnumerator(BaseTool):
    """Primary DNSRecon tool - comprehensive DNS analysis and enumeration"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.command_name = "dnsrecon"
        self.specialization = "comprehensive_dns_analysis"
        self.is_primary_dns_tool = True
    
    def scan(self, domain: str, scan_params: Dict) -> Dict:
        """Execute comprehensive dnsrecon enumeration - primary DNS analysis"""
        self.start_time = datetime.now()
        
        try:
            self.logger.info(f"🔧 Starting DNSReconEnumerator PRIMARY DNS analysis against {domain}")
            
            if not self.verify_installation():
                return self._create_error_result("dnsrecon not installed")
            
            # Enhanced command building for comprehensive analysis
            scan_type = scan_params.get('scan_type', 'comprehensive')
            cmd_map = {
                'comprehensive': ['dnsrecon', '-d', domain, '-a', '-s', '-b', '-y', '-k', '-w'],
                'std': ['dnsrecon', '-d', domain],
                'axfr': ['dnsrecon', '-d', domain, '-a'],
                'bing': ['dnsrecon', '-d', domain, '-b'], 
                'reverse': ['dnsrecon', '-r', domain],
                'zone_walk': ['dnsrecon', '-d', domain, '-z'],
                'brute': ['dnsrecon', '-d', domain, '-D', '/usr/share/dnsrecon/subdomains-top1mil-5000.txt'],
                'security_focused': ['dnsrecon', '-d', domain, '-a', '-s', '-w']  # Zone transfer + security checks
            }
            
            cmd = cmd_map.get(scan_type, cmd_map['comprehensive'])
            
            # Add comprehensive output format
            cmd.extend(['-j', '/tmp/dnsrecon_output.json', '--threads', '10'])
            
            # Add security-focused options
            if scan_params.get('nameserver'):
                cmd.extend(['-n', scan_params['nameserver']])
            if scan_params.get('threads'):
                cmd.extend(['-t', str(scan_params['threads'])])
            
            # Execute with walrus operator - longer timeout for comprehensive scan
            timeout = 600 if scan_type == 'comprehensive' else 300
            if (result := self.execute_command(cmd, timeout=timeout)).returncode not in [0, 1]:
                return self._create_error_result(f"DNSRecon comprehensive scan failed: {result.stderr}")
            
            # Parse and build comprehensive results
            dns_data = self._parse_comprehensive_output(result.stdout, scan_type, domain)
            self.save_raw_output(result.stdout, domain, 'txt')
            
            duration = (datetime.now() - self.start_time).total_seconds()
            record_count = len(dns_data.get('dns_records', []))
            subdomain_count = len(dns_data.get('subdomains', []))
            security_issues = len(dns_data.get('security_findings', []))
            
            self.logger.info(f"✅ DNSReconEnumerator PRIMARY completed in {duration:.1f}s - {record_count} DNS records, {subdomain_count} subdomains, {security_issues} security findings")
            
            return {
                'status': 'success',
                'target': domain,
                'scan_type': 'dnsrecon_primary_comprehensive',
                'specialization': 'primary_dns_analysis',
                'duration': duration,
                'dns_data': dns_data,
                'summary': {
                    'dns_records_found': record_count,
                    'subdomains_found': subdomain_count,
                    'zone_transfer_possible': dns_data.get('zone_transfer_possible', False),
                    'security_findings': security_issues,
                    'nameservers_found': len(dns_data.get('nameservers', []))
                }
            }
            
        except Exception as e:
            self.logger.error(f"❌ DNSReconEnumerator error: {e}")
            return self._create_error_result(str(e))
    
    def _parse_comprehensive_output(self, output: str, scan_type: str, domain: str) -> Dict:
        """Parse dnsrecon output with comprehensive analysis focus"""
        dns_data = {
            'dns_records': [],
            'subdomains': [],
            'nameservers': [],
            'mail_servers': [],
            'security_findings': [],
            'zone_transfer_possible': False,
            'dns_analysis_complete': True
        }
        
        # Try to parse JSON output first for comprehensive data
        try:
            with open('/tmp/dnsrecon_output.json', 'r') as f:
                json_data = json.load(f)
                for record in json_data:
                    dns_record = {
                        'type': record.get('type', ''),
                        'name': record.get('name', ''),
                        'target': record.get('target', ''),
                        'address': record.get('address', ''),
                        'exchange': record.get('exchange', ''),
                        'priority': record.get('priority', ''),
                        'ttl': record.get('ttl', '')
                    }
                    dns_data['dns_records'].append(dns_record)
                    
                    # Comprehensive categorization
                    record_type = record.get('type', '')
                    if record_type == 'A' and record.get('name'):
                        dns_data['subdomains'].append({
                            'subdomain': record['name'],
                            'ip': record.get('address', ''),
                            'discovery_method': 'dns_enumeration'
                        })
                    elif record_type == 'NS':
                        dns_data['nameservers'].append({
                            'nameserver': record.get('target', ''),
                            'domain': domain
                        })
                    elif record_type == 'MX':
                        dns_data['mail_servers'].append({
                            'mail_server': record.get('exchange', ''),
                            'priority': record.get('priority', 0)
                        })
                    
                    # Security analysis
                    if record_type == 'TXT':
                        self._analyze_txt_security(record, dns_data, domain)
                        
        except (FileNotFoundError, json.JSONDecodeError):
            # Enhanced fallback text parsing
            dns_data = self._parse_comprehensive_text(output, domain)
        
        # Additional security checks
        dns_data['security_findings'].extend(self._perform_security_analysis(dns_data, domain))
        
        # Remove duplicates and clean data
        dns_data['subdomains'] = list({v['subdomain']: v for v in dns_data['subdomains']}.values())
        dns_data['nameservers'] = list({v['nameserver']: v for v in dns_data['nameservers']}.values())
        
        return dns_data
    
    def _analyze_txt_security(self, record: Dict, dns_data: Dict, domain: str):
        """Analyze TXT records for security implications"""
        txt_content = record.get('target', '').lower()
        
        # Check for security-relevant TXT records
        if 'spf' in txt_content:
            dns_data['security_findings'].append({
                'type': 'spf_record',
                'content': record.get('target', ''),
                'security_impact': 'email_security'
            })
        elif 'dmarc' in txt_content:
            dns_data['security_findings'].append({
                'type': 'dmarc_record', 
                'content': record.get('target', ''),
                'security_impact': 'email_authentication'
            })
        elif 'google-site-verification' in txt_content:
            dns_data['security_findings'].append({
                'type': 'google_verification',
                'content': record.get('target', ''),
                'security_impact': 'domain_ownership_proof'
            })
    
    def _perform_security_analysis(self, dns_data: Dict, domain: str) -> List[Dict]:
        """Perform additional DNS security analysis"""
        security_findings = []
        
        # Check for zone transfer possibility
        if dns_data.get('zone_transfer_possible'):
            security_findings.append({
                'type': 'zone_transfer_vulnerability',
                'severity': 'HIGH',
                'description': 'DNS zone transfer is possible - information disclosure risk'
            })
        
        # Check for subdomain enumeration exposure
        if len(dns_data.get('subdomains', [])) > 50:
            security_findings.append({
                'type': 'extensive_subdomain_exposure',
                'severity': 'MEDIUM',
                'description': f'Large number of subdomains discovered ({len(dns_data.get("subdomains", []))}) - potential attack surface'
            })
        
        # Check for missing security records
        has_spf = any(f.get('type') == 'spf_record' for f in dns_data.get('security_findings', []))
        has_dmarc = any(f.get('type') == 'dmarc_record' for f in dns_data.get('security_findings', []))
        
        if not has_spf:
            security_findings.append({
                'type': 'missing_spf_record',
                'severity': 'MEDIUM',
                'description': 'No SPF record found - email spoofing vulnerability'
            })
        
        if not has_dmarc:
            security_findings.append({
                'type': 'missing_dmarc_record',
                'severity': 'MEDIUM',
                'description': 'No DMARC record found - email authentication weakness'
            })
        
        return security_findings
    
    def _parse_comprehensive_text(self, output: str, domain: str) -> Dict:
        """Enhanced fallback text parsing with comprehensive analysis"""
        dns_data = {
            'dns_records': [],
            'subdomains': [],
            'nameservers': [],
            'mail_servers': [],
            'security_findings': [],
            'zone_transfer_possible': False
        }
        
        for line in output.strip().split('\n'):
            line = line.strip()
            
            # Enhanced DNS record parsing
            if match := re.search(r'\[.\]\s+(\w+)\s+(\S+)\s+(\S+)', line):
                record_type, name, target = match.groups()
                dns_data['dns_records'].append({
                    'type': record_type,
                    'name': name,
                    'target': target,
                    'found_at': datetime.now().isoformat()
                })
                
                # Comprehensive categorization
                if record_type == 'A':
                    dns_data['subdomains'].append({
                        'subdomain': name,
                        'ip': target,
                        'discovery_method': 'text_parsing'
                    })
                elif record_type == 'NS':
                    dns_data['nameservers'].append({
                        'nameserver': target,
                        'domain': domain
                    })
                elif record_type == 'MX':
                    dns_data['mail_servers'].append({
                        'mail_server': target,
                        'priority': 0
                    })
            
            # Enhanced security checks
            if 'zone transfer' in line.lower() and 'successful' in line.lower():
                dns_data['zone_transfer_possible'] = True
                dns_data['security_findings'].append({
                    'type': 'zone_transfer_success',
                    'severity': 'HIGH',
                    'description': line.strip()
                })
        
        return dns_data
    
    def _create_error_result(self, error: str) -> Dict:
        """Create standardized error result"""
        return {
            'status': 'error',
            'error': error,
            'target': '',
            'scan_type': 'dnsrecon_primary_comprehensive',
            'dns_data': {},
            'summary': {'dns_records_found': 0}
        }
