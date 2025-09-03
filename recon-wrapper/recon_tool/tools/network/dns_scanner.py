"""
DNS Scanner
Comprehensive DNS enumeration and analysis
"""

import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, Any, List

import dns.resolver

from ...core.exceptions import ScanError
from ...core.utils import check_tool_installed


class DNSScanner:
    """Comprehensive DNS enumeration and analysis tool"""
    
    def __init__(self, output_dir: Path, config: Dict[str, Any], logger: logging.Logger):
        self.output_dir = output_dir
        self.config = config
        self.logger = logger
        
        # Create DNS output directory
        self.dns_dir = output_dir / 'dns'
        self.dns_dir.mkdir(exist_ok=True)
        
    def scan_dns(self, target: str) -> Dict[str, Any]:
        """Run comprehensive DNS analysis"""
        self.logger.info(f"Starting DNS scan for {target}")
        
        results = {
            'target': target,
            'dns_records': {},
            'zone_transfer': {},
            'dns_security': {},
            'reverse_dns': {},
            'subdomain_enum': []
        }
        
        try:
            # DNS record enumeration
            self._enumerate_dns_records(target, results)
            
            # Zone transfer attempts
            self._attempt_zone_transfer(target, results)
            
            # DNS security analysis
            self._analyze_dns_security(target, results)
            
            # Reverse DNS lookup
            self._perform_reverse_dns(target, results)
            
            # Basic subdomain enumeration
            self._basic_subdomain_enum(target, results)
            
            # Save results
            self._save_dns_results(target, results)
            
        except Exception as e:
            self.logger.error(f"DNS scan failed: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def _enumerate_dns_records(self, target: str, results: Dict[str, Any]) -> None:
        """Enumerate all DNS record types"""
        self.logger.info(f"Enumerating DNS records for {target}")
        
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'SRV', 'PTR']
        dns_records = {}
        
        # Get custom DNS server if configured
        dns_server = self.config.get('general', {}).get('dns_server')
        dns_servers = self.config.get('dns', {}).get('servers', [])
        
        for record_type in record_types:
            try:
                records = []
                
                # Try dig command first
                if check_tool_installed('dig'):
                    cmd = ['dig', '+short']
                    
                    if dns_server:
                        cmd.append(f'@{dns_server}')
                    elif dns_servers:
                        cmd.append(f'@{dns_servers[0]}')
                    
                    cmd.extend([target, record_type])
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0 and result.stdout.strip():
                        records = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                    
                # Fallback to dns.resolver
                if not records:
                    try:
                        resolver = dns.resolver.Resolver()
                        
                        if dns_server:
                            resolver.nameservers = [dns_server]
                        elif dns_servers:
                            resolver.nameservers = dns_servers
                        
                        answer = resolver.resolve(target, record_type)
                        records = [str(rdata) for rdata in answer]
                        
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        pass  # No records of this type
                    except Exception as e:
                        self.logger.debug(f"DNS resolver error for {record_type}: {str(e)}")
                
                if records:
                    dns_records[record_type] = records
                    self.logger.debug(f"Found {len(records)} {record_type} records")
                    
            except subprocess.TimeoutExpired:
                self.logger.debug(f"DNS query timeout for {record_type}")
            except Exception as e:
                self.logger.debug(f"Error querying {record_type} records: {str(e)}")
        
        results['dns_records'] = dns_records
        
        # Log summary
        total_records = sum(len(records) for records in dns_records.values())
        if total_records > 0:
            summary = ', '.join([f"{rtype}: {len(records)}" for rtype, records in dns_records.items()])
            self.logger.info(f"DNS enumeration found {total_records} records ({summary})")
        else:
            self.logger.info("No DNS records found")
    
    def _attempt_zone_transfer(self, target: str, results: Dict[str, Any]) -> None:
        """Attempt DNS zone transfer (AXFR)"""
        self.logger.info(f"Attempting zone transfer for {target}")
        
        zone_transfer_results = {
            'attempted': False,
            'successful': False,
            'nameservers': [],
            'transferred_records': [],
            'errors': {}
        }
        
        try:
            # Get NS records first
            ns_records = results.get('dns_records', {}).get('NS', [])
            
            if not ns_records and check_tool_installed('dig'):
                # Try to get NS records directly
                cmd = ['dig', '+short', target, 'NS']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and result.stdout.strip():
                    ns_records = [line.strip().rstrip('.') for line in result.stdout.strip().split('\n') if line.strip()]
            
            zone_transfer_results['nameservers'] = ns_records
            
            if not ns_records:
                zone_transfer_results['errors']['general'] = 'No nameservers found'
                results['zone_transfer'] = zone_transfer_results
                return
            
            # Try zone transfer against each nameserver
            for ns in ns_records[:5]:  # Limit to first 5 nameservers
                try:
                    zone_transfer_results['attempted'] = True
                    self.logger.info(f"Attempting zone transfer from {ns}")
                    
                    if check_tool_installed('dig'):
                        cmd = ['dig', f'@{ns}', target, 'AXFR']
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                        
                        if result.returncode == 0 and result.stdout.strip():
                            lines = result.stdout.strip().split('\n')
                            
                            # Check if transfer was successful
                            # Look for multiple records and absence of error messages
                            successful_indicators = ['SOA', 'NS', 'A']
                            error_indicators = ['Transfer failed', 'refused', 'REFUSED']
                            
                            has_records = any(indicator in result.stdout for indicator in successful_indicators)
                            has_errors = any(indicator in result.stdout for indicator in error_indicators)
                            
                            if has_records and not has_errors and len(lines) > 5:
                                zone_transfer_results['successful'] = True
                                zone_transfer_results['transferred_records'] = lines[:100]  # Limit output
                                self.logger.warning(f"Zone transfer successful from {ns}! This is a security issue.")
                                break
                            else:
                                zone_transfer_results['errors'][ns] = 'Transfer refused or no data'
                                self.logger.debug(f"Zone transfer refused by {ns}")
                        else:
                            zone_transfer_results['errors'][ns] = 'Command failed'
                    else:
                        # Try with dns.resolver
                        try:
                            resolver = dns.resolver.Resolver()
                            resolver.nameservers = [ns]
                            
                            answer = resolver.resolve(target, 'AXFR')
                            
                            if answer:
                                zone_transfer_results['successful'] = True
                                zone_transfer_results['transferred_records'] = [str(rdata) for rdata in answer][:100]
                                self.logger.warning(f"Zone transfer successful from {ns}! This is a security issue.")
                                break
                                
                        except Exception as dns_e:
                            zone_transfer_results['errors'][ns] = f'DNS resolver error: {str(dns_e)}'
                    
                except subprocess.TimeoutExpired:
                    zone_transfer_results['errors'][ns] = 'Timeout'
                    self.logger.debug(f"Zone transfer timeout for {ns}")
                except Exception as e:
                    zone_transfer_results['errors'][ns] = str(e)
                    self.logger.debug(f"Zone transfer error for {ns}: {str(e)}")
        
        except Exception as e:
            zone_transfer_results['errors']['general'] = str(e)
            self.logger.error(f"Zone transfer attempt failed: {str(e)}")
        
        results['zone_transfer'] = zone_transfer_results
        
        if zone_transfer_results['successful']:
            self.logger.warning("Zone transfer successful - this indicates a DNS misconfiguration")
        elif zone_transfer_results['attempted']:
            self.logger.info("Zone transfer attempts completed - all refused (good security)")
        else:
            self.logger.info("Zone transfer not attempted - no nameservers available")
    
    def _analyze_dns_security(self, target: str, results: Dict[str, Any]) -> None:
        """Analyze DNS security features"""
        self.logger.info(f"Analyzing DNS security for {target}")
        
        security_results = {
            'dnssec_enabled': False,
            'spf_configured': False,
            'dmarc_configured': False,
            'caa_configured': False,
            'security_score': 0,
            'recommendations': []
        }
        
        try:
            # Check DNSSEC
            if check_tool_installed('dig'):
                cmd = ['dig', '+dnssec', '+short', target, 'A']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if 'RRSIG' in result.stdout or 'ad' in result.stderr.lower():
                    security_results['dnssec_enabled'] = True
                    security_results['security_score'] += 25
                else:
                    security_results['recommendations'].append('Enable DNSSEC for enhanced security')
        except Exception:
            pass
        
        try:
            # Check SPF records in TXT
            txt_records = results.get('dns_records', {}).get('TXT', [])
            
            for record in txt_records:
                if 'v=spf1' in record.lower():
                    security_results['spf_configured'] = True
                    security_results['security_score'] += 25
                    break
            
            if not security_results['spf_configured']:
                security_results['recommendations'].append('Configure SPF records to prevent email spoofing')
        except Exception:
            pass
        
        try:
            # Check DMARC policy
            dmarc_domain = f"_dmarc.{target}"
            
            if check_tool_installed('dig'):
                cmd = ['dig', '+short', dmarc_domain, 'TXT']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if 'v=DMARC1' in result.stdout:
                    security_results['dmarc_configured'] = True
                    security_results['security_score'] += 25
                else:
                    security_results['recommendations'].append('Configure DMARC policy for email security')
        except Exception:
            pass
        
        try:
            # Check CAA records
            if check_tool_installed('dig'):
                cmd = ['dig', '+short', target, 'CAA']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.stdout.strip():
                    security_results['caa_configured'] = True
                    security_results['security_score'] += 25
                else:
                    security_results['recommendations'].append('Configure CAA records to control certificate issuance')
        except Exception:
            pass
        
        results['dns_security'] = security_results
        
        self.logger.info(f"DNS security score: {security_results['security_score']}/100")
    
    def _perform_reverse_dns(self, target: str, results: Dict[str, Any]) -> None:
        """Perform reverse DNS lookup"""
        self.logger.info(f"Performing reverse DNS lookup for {target}")
        
        reverse_dns_results = {
            'ptr_records': [],
            'ip_addresses': []
        }
        
        try:
            # Get A records to perform reverse lookup
            a_records = results.get('dns_records', {}).get('A', [])
            
            for ip in a_records:
                try:
                    # Perform reverse DNS lookup
                    if check_tool_installed('dig'):
                        cmd = ['dig', '+short', '-x', ip]
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                        
                        if result.returncode == 0 and result.stdout.strip():
                            ptr_record = result.stdout.strip().rstrip('.')
                            reverse_dns_results['ptr_records'].append({
                                'ip': ip,
                                'hostname': ptr_record
                            })
                    else:
                        # Use dns.resolver
                        reversed_ip = dns.reversename.from_address(ip)
                        answer = dns.resolver.resolve(reversed_ip, 'PTR')
                        
                        for rdata in answer:
                            reverse_dns_results['ptr_records'].append({
                                'ip': ip,
                                'hostname': str(rdata).rstrip('.')
                            })
                            
                except Exception as e:
                    self.logger.debug(f"Reverse DNS lookup failed for {ip}: {str(e)}")
                    
        except Exception as e:
            self.logger.error(f"Reverse DNS lookup error: {str(e)}")
        
        results['reverse_dns'] = reverse_dns_results
        
        if reverse_dns_results['ptr_records']:
            self.logger.info(f"Found {len(reverse_dns_results['ptr_records'])} reverse DNS records")
    
    def _basic_subdomain_enum(self, target: str, results: Dict[str, Any]) -> None:
        """Basic subdomain enumeration via DNS"""
        self.logger.info(f"Performing basic subdomain enumeration for {target}")
        
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'blog', 'shop', 'secure', 'vpn', 'remote', 'app', 'mobile'
        ]
        
        found_subdomains = []
        
        for subdomain in common_subdomains:
            try:
                full_domain = f"{subdomain}.{target}"
                
                # Check for A record
                if check_tool_installed('dig'):
                    cmd = ['dig', '+short', full_domain, 'A']
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    
                    if result.returncode == 0 and result.stdout.strip():
                        ips = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                        found_subdomains.append({
                            'subdomain': full_domain,
                            'type': 'A',
                            'values': ips
                        })
                        continue
                
                # Check for CNAME record
                if check_tool_installed('dig'):
                    cmd = ['dig', '+short', full_domain, 'CNAME']
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    
                    if result.returncode == 0 and result.stdout.strip():
                        cnames = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                        found_subdomains.append({
                            'subdomain': full_domain,
                            'type': 'CNAME',
                            'values': cnames
                        })
                        
            except Exception as e:
                self.logger.debug(f"Error checking subdomain {subdomain}: {str(e)}")
        
        results['subdomain_enum'] = found_subdomains
        
        if found_subdomains:
            self.logger.info(f"Basic subdomain enumeration found {len(found_subdomains)} subdomains")
    
    def _save_dns_results(self, target: str, results: Dict[str, Any]) -> None:
        """Save DNS analysis results"""
        sanitized_target = target.replace(':', '_').replace('/', '_')
        
        # Save JSON results
        json_file = self.dns_dir / f'{sanitized_target}_dns_results.json'
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        self.logger.info(f"DNS results saved to {json_file}")
        
        # Create human-readable summary
        txt_file = self.dns_dir / f'{sanitized_target}_dns_summary.txt'
        
        with open(txt_file, 'w') as f:
            f.write(f"DNS Analysis Summary for {target}\n")
            f.write("=" * 50 + "\n\n")
            
            # DNS Records
            dns_records = results.get('dns_records', {})
            if dns_records:
                f.write("DNS Records:\n")
                for record_type, records in dns_records.items():
                    f.write(f"  {record_type}:\n")
                    for record in records[:5]:  # Limit to 5 records per type
                        f.write(f"    {record}\n")
                    if len(records) > 5:
                        f.write(f"    ... and {len(records) - 5} more\n")
                f.write("\n")
            
            # DNS Security
            dns_security = results.get('dns_security', {})
            if dns_security:
                f.write("DNS Security Analysis:\n")
                f.write(f"  Security Score: {dns_security.get('security_score', 0)}/100\n")
                f.write(f"  DNSSEC: {'Enabled' if dns_security.get('dnssec_enabled') else 'Disabled'}\n")
                f.write(f"  SPF: {'Configured' if dns_security.get('spf_configured') else 'Not Configured'}\n")
                f.write(f"  DMARC: {'Configured' if dns_security.get('dmarc_configured') else 'Not Configured'}\n")
                f.write(f"  CAA: {'Configured' if dns_security.get('caa_configured') else 'Not Configured'}\n")
                
                recommendations = dns_security.get('recommendations', [])
                if recommendations:
                    f.write("  Recommendations:\n")
                    for rec in recommendations:
                        f.write(f"    • {rec}\n")
                f.write("\n")
            
            # Zone Transfer
            zone_transfer = results.get('zone_transfer', {})
            if zone_transfer.get('attempted'):
                f.write("Zone Transfer Analysis:\n")
                f.write(f"  Attempted: Yes\n")
                f.write(f"  Successful: {'Yes (SECURITY ISSUE!)' if zone_transfer.get('successful') else 'No (Good)'}\n")
                f.write(f"  Nameservers Tested: {len(zone_transfer.get('nameservers', []))}\n")
                
                if zone_transfer.get('successful'):
                    f.write("  WARNING: Zone transfer is enabled! This exposes internal DNS structure.\n")
                f.write("\n")
            
            # Reverse DNS
            reverse_dns = results.get('reverse_dns', {})
            ptr_records = reverse_dns.get('ptr_records', [])
            if ptr_records:
                f.write("Reverse DNS Records:\n")
                for ptr in ptr_records:
                    f.write(f"  {ptr['ip']} -> {ptr['hostname']}\n")
                f.write("\n")
            
            # Subdomains
            subdomains = results.get('subdomain_enum', [])
            if subdomains:
                f.write("Found Subdomains:\n")
                for sub in subdomains:
                    f.write(f"  {sub['subdomain']} ({sub['type']}) -> {', '.join(sub['values'])}\n")
        
        self.logger.info(f"DNS summary saved to {txt_file}")
