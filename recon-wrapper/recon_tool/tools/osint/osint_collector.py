"""
OSINT Collector
Open Source Intelligence gathering and analysis
"""

import json
import logging
import socket
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

import dns.resolver
import requests

from ...core.exceptions import ScanError
from ...core.utils import check_tool_installed

# Optional imports
try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False


class OSINTCollector:
    """OSINT data collection and analysis tool"""
    
    def __init__(self, output_dir: Path, config: Dict[str, Any], logger: logging.Logger):
        self.output_dir = output_dir
        self.config = config
        self.logger = logger
        
        # Create OSINT output directory
        self.osint_dir = output_dir / 'osint'
        self.osint_dir.mkdir(exist_ok=True)
        
    def collect(self, target: str) -> Dict[str, Any]:
        """Run comprehensive OSINT collection"""
        self.logger.info(f"Starting OSINT collection for {target}")
        
        results = {
            'target': target,
            'whois': {},
            'dns_records': {},
            'shodan': {},
            'wayback': {},
            'github_dorking': {},
            'enhanced_dns': {}
        }
        
        # Check if we're in offline mode
        offline_mode = (
            self.config.get('mode') == 'offline' or 
            self.config.get('general', {}).get('offline_mode', False)
        )
        
        if offline_mode:
            self.logger.info("Running in offline mode - skipping internet-based OSINT sources")
            
            # Only run DNS record enumeration in offline mode
            dns_results = self._enumerate_dns_records(target)
            results['dns_records'] = dns_results
            
            # Set skipped sources with appropriate messages
            results['whois'] = {'error': 'skipped_offline_mode'}
            results['shodan'] = {'error': 'skipped_offline_mode'}
            results['wayback'] = {'error': 'skipped_offline_mode'}
            results['github_dorking'] = {'error': 'skipped_offline_mode'}
        else:
            # Online mode: run all OSINT sources
            
            # WHOIS lookup
            if HAS_WHOIS:
                whois_results = self._run_whois_lookup(target)
                results['whois'] = whois_results
            else:
                self.logger.warning("python-whois library not available")
                results['whois'] = {'error': 'library_not_available'}
            
            # DNS record enumeration
            dns_results = self._enumerate_dns_records(target)
            results['dns_records'] = dns_results
            
            # Enhanced DNS enumeration
            enhanced_dns = self.enhanced_dns_enumeration(target)
            results['enhanced_dns'] = enhanced_dns
            
            # Shodan lookup (if API key available)
            shodan_results = self._query_shodan(target)
            results['shodan'] = shodan_results
            
            # Wayback Machine analysis
            wayback_results = self.wayback_analysis(target)
            results['wayback'] = wayback_results
            
            # GitHub dorking
            github_results = self.github_dorking(target)
            results['github_dorking'] = github_results
        
        # Save results
        self._save_osint_results(target, results)
        
        return results
    
    def _run_whois_lookup(self, target: str) -> Dict[str, Any]:
        """Perform WHOIS lookup"""
        try:
            self.logger.info(f"Performing WHOIS lookup for {target}")
            
            # Remove protocol if present
            if target.startswith('http'):
                target = urlparse(target).netloc
            
            whois_info = whois.whois(target)
            
            whois_results = {
                'domain_name': str(whois_info.domain_name) if whois_info.domain_name else None,
                'registrar': whois_info.registrar,
                'creation_date': str(whois_info.creation_date) if whois_info.creation_date else None,
                'expiration_date': str(whois_info.expiration_date) if whois_info.expiration_date else None,
                'updated_date': str(whois_info.updated_date) if whois_info.updated_date else None,
                'country': whois_info.country,
                'name_servers': whois_info.name_servers if whois_info.name_servers else [],
                'status': whois_info.status if whois_info.status else []
            }
            
            return whois_results
            
        except Exception as e:
            self.logger.error(f"Error performing WHOIS lookup: {str(e)}")
            return {'error': str(e)}
    
    def _enumerate_dns_records(self, target: str) -> Dict[str, Any]:
        """Enumerate basic DNS records"""
        try:
            self.logger.info(f"Enumerating DNS records for {target}")
            
            # Remove protocol if present
            if target.startswith('http'):
                target = urlparse(target).netloc
            
            dns_results = {
                'A': [],
                'AAAA': [],
                'MX': [],
                'NS': [],
                'TXT': [],
                'CNAME': [],
                'SOA': []
            }
            
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
            
            # Check for custom DNS servers
            dns_servers = self.config.get('dns', {}).get('servers', [])
            custom_dns = self.config.get('general', {}).get('dns_server', '')
            
            # Use custom DNS server if provided
            dns_server_arg = []
            resolver_nameservers = None
            
            if custom_dns:
                dns_server_arg = [f'@{custom_dns}']
                resolver_nameservers = [custom_dns]
                self.logger.info(f"Using custom DNS server: {custom_dns}")
            elif dns_servers:
                dns_server_arg = [f'@{dns_servers[0]}']
                resolver_nameservers = dns_servers
                self.logger.info(f"Using DNS server from config: {dns_servers[0]}")
            else:
                self.logger.debug("Using system default DNS servers")
            
            for record_type in record_types:
                try:
                    # Try dig command first
                    if check_tool_installed('dig'):
                        cmd = ['dig', '+short'] + dns_server_arg + [target, record_type]
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                        
                        if result.returncode == 0 and result.stdout.strip():
                            records = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                            dns_results[record_type] = records
                            self.logger.debug(f"Found {len(records)} {record_type} records via dig")
                            continue
                    
                    # Fallback to dns.resolver
                    try:
                        resolver = dns.resolver.Resolver()
                        if resolver_nameservers:
                            resolver.nameservers = resolver_nameservers
                        
                        answer = resolver.resolve(target, record_type)
                        records = [str(rdata) for rdata in answer]
                        dns_results[record_type] = records
                        self.logger.debug(f"Found {len(records)} {record_type} records via dns.resolver")
                        
                    except dns.resolver.NXDOMAIN:
                        self.logger.debug(f"No {record_type} records found (NXDOMAIN)")
                    except dns.resolver.NoAnswer:
                        self.logger.debug(f"No {record_type} records found (NODATA)")
                    except Exception as resolver_e:
                        self.logger.debug(f"dns.resolver failed for {record_type}: {str(resolver_e)}")
                        
                except subprocess.TimeoutExpired:
                    self.logger.debug(f"dig timeout for {record_type} records")
                except Exception as e:
                    self.logger.debug(f"Error querying {record_type} records: {str(e)}")
            
            # Summary logging
            total_records = sum(len(records) for records in dns_results.values())
            if total_records > 0:
                summary = ', '.join([f"{rtype}: {len(records)}" for rtype, records in dns_results.items() if records])
                self.logger.info(f"DNS enumeration found {total_records} total records ({summary})")
            else:
                self.logger.info("No DNS records found")
            
            return dns_results
            
        except Exception as e:
            self.logger.error(f"Error enumerating DNS records: {str(e)}")
            return {'error': str(e)}
    
    def enhanced_dns_enumeration(self, target: str) -> Dict[str, Any]:
        """Enhanced DNS enumeration with advanced techniques"""
        self.logger.info(f"Starting enhanced DNS enumeration for {target}")
        
        # Clean target
        if target.startswith('http'):
            target = urlparse(target).netloc
        
        results = {
            'target': target,
            'basic_records': {},
            'advanced_records': {},
            'dns_security': {},
            'subdomain_bruteforce': [],
            'zone_transfer': {},
            'dns_bruteforce': []
        }
        
        try:
            # Basic DNS records (existing functionality)
            results['basic_records'] = self._enumerate_dns_records(target)
            
            # Advanced DNS records
            results['advanced_records'] = self._enumerate_advanced_dns_records(target)
            
            # DNS security checks
            results['dns_security'] = self._check_dns_security(target)
            
            # DNS-based subdomain bruteforce
            results['subdomain_bruteforce'] = self._dns_subdomain_bruteforce(target)
            
            # Zone transfer attempts
            results['zone_transfer'] = self._attempt_zone_transfer(target)
            
        except Exception as e:
            self.logger.error(f"Enhanced DNS enumeration error: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def _enumerate_advanced_dns_records(self, target: str) -> Dict[str, Any]:
        """Enumerate additional DNS record types"""
        advanced_records = {
            'PTR': [],     # Reverse DNS
            'SRV': [],     # Service records
            'CAA': [],     # Certificate Authority Authorization
            'DMARC': [],   # DMARC policy
            'SPF': [],     # SPF records
            'DKIM': []     # DKIM records
        }
        
        record_types = ['PTR', 'SRV', 'CAA']
        
        for record_type in record_types:
            try:
                if check_tool_installed('dig'):
                    cmd = ['dig', '+short', target, record_type]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0 and result.stdout.strip():
                        records = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                        advanced_records[record_type] = records
                        
            except Exception as e:
                self.logger.debug(f"Error getting {record_type} records: {str(e)}")
        
        # Check for DMARC policy
        try:
            dmarc_domain = f"_dmarc.{target}"
            if check_tool_installed('dig'):
                cmd = ['dig', '+short', dmarc_domain, 'TXT']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and result.stdout.strip():
                    advanced_records['DMARC'] = [result.stdout.strip()]
        except Exception:
            pass
        
        # Check for SPF records in TXT
        try:
            if check_tool_installed('dig'):
                cmd = ['dig', '+short', target, 'TXT']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and result.stdout.strip():
                    txt_records = result.stdout.strip().split('\n')
                    spf_records = [record for record in txt_records if 'v=spf1' in record.lower()]
                    advanced_records['SPF'] = spf_records
        except Exception:
            pass
        
        return advanced_records
    
    def _check_dns_security(self, target: str) -> Dict[str, Any]:
        """Check DNS security configurations"""
        security_results = {
            'dnssec_enabled': False,
            'spf_configured': False,
            'dmarc_configured': False,
            'caa_configured': False,
            'security_score': 0
        }
        
        try:
            # Check DNSSEC
            if check_tool_installed('dig'):
                cmd = ['dig', '+dnssec', '+short', target, 'A']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if 'RRSIG' in result.stdout:
                    security_results['dnssec_enabled'] = True
                    security_results['security_score'] += 25
        except Exception:
            pass
        
        try:
            # Check SPF
            if check_tool_installed('dig'):
                cmd = ['dig', '+short', target, 'TXT']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if 'v=spf1' in result.stdout.lower():
                    security_results['spf_configured'] = True
                    security_results['security_score'] += 25
        except Exception:
            pass
        
        try:
            # Check DMARC
            dmarc_domain = f"_dmarc.{target}"
            if check_tool_installed('dig'):
                cmd = ['dig', '+short', dmarc_domain, 'TXT']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if 'v=DMARC1' in result.stdout:
                    security_results['dmarc_configured'] = True
                    security_results['security_score'] += 25
        except Exception:
            pass
        
        try:
            # Check CAA
            if check_tool_installed('dig'):
                cmd = ['dig', '+short', target, 'CAA']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.stdout.strip():
                    security_results['caa_configured'] = True
                    security_results['security_score'] += 25
        except Exception:
            pass
        
        return security_results
    
    def _dns_subdomain_bruteforce(self, target: str) -> List[Dict[str, Any]]:
        """DNS-based subdomain bruteforce"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'prod', 'blog', 'shop', 'store', 'portal', 'support', 'help',
            'docs', 'cdn', 'static', 'media', 'images', 'assets', 'secure',
            'vpn', 'remote', 'app', 'mobile', 'beta', 'demo', 'lab',
            'git', 'svn', 'repo', 'backup', 'db', 'database', 'mysql',
            'postgres', 'redis', 'elastic', 'kibana', 'grafana'
        ]
        
        found_subdomains = []
        
        for subdomain in common_subdomains:
            try:
                full_domain = f"{subdomain}.{target}"
                
                # Try A record
                if check_tool_installed('dig'):
                    cmd = ['dig', '+short', full_domain, 'A']
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    
                    if result.returncode == 0 and result.stdout.strip():
                        ip_addresses = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                        found_subdomains.append({
                            'subdomain': full_domain,
                            'type': 'A',
                            'values': ip_addresses
                        })
                        continue
                
                # Try CNAME record
                if check_tool_installed('dig'):
                    cmd = ['dig', '+short', full_domain, 'CNAME']
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    
                    if result.returncode == 0 and result.stdout.strip():
                        cname_values = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                        found_subdomains.append({
                            'subdomain': full_domain,
                            'type': 'CNAME',
                            'values': cname_values
                        })
                        
            except Exception as e:
                self.logger.debug(f"Error checking subdomain {subdomain}: {str(e)}")
                continue
        
        self.logger.info(f"DNS bruteforce found {len(found_subdomains)} subdomains")
        return found_subdomains
    
    def _attempt_zone_transfer(self, target: str) -> Dict[str, Any]:
        """Attempt DNS zone transfer"""
        zone_transfer_results = {
            'attempted': False,
            'successful': False,
            'nameservers': [],
            'transferred_records': []
        }
        
        try:
            # Get nameservers
            if check_tool_installed('dig'):
                cmd = ['dig', '+short', target, 'NS']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and result.stdout.strip():
                    nameservers = [line.strip().rstrip('.') for line in result.stdout.strip().split('\n') if line.strip()]
                    zone_transfer_results['nameservers'] = nameservers
                    
                    # Try zone transfer against each nameserver
                    for ns in nameservers[:3]:  # Limit to first 3 NS
                        try:
                            zone_transfer_results['attempted'] = True
                            self.logger.info(f"Attempting zone transfer from {ns}")
                            
                            cmd = ['dig', f'@{ns}', target, 'AXFR']
                            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                            
                            if result.returncode == 0 and result.stdout.strip():
                                # Check if transfer was successful (contains multiple records)
                                lines = result.stdout.strip().split('\n')
                                if len(lines) > 5:  # More than just SOA records
                                    zone_transfer_results['successful'] = True
                                    zone_transfer_results['transferred_records'] = lines[:50]  # Limit output
                                    self.logger.warning(f"Zone transfer successful from {ns}!")
                                    break
                                    
                        except Exception as e:
                            self.logger.debug(f"Zone transfer failed for {ns}: {str(e)}")
                            
        except Exception as e:
            self.logger.error(f"Error in zone transfer attempt: {str(e)}")
        
        return zone_transfer_results
    
    def _query_shodan(self, target: str) -> Dict[str, Any]:
        """Query Shodan API for target information"""
        try:
            api_key = self.config.get('osint', {}).get('shodan_api_key')
            if not api_key:
                return {'error': 'no_api_key'}
            
            self.logger.info(f"Querying Shodan for {target}")
            
            # Remove protocol if present
            if target.startswith('http'):
                target = urlparse(target).netloc
            
            # Resolve target to IP if it's a domain
            try:
                ip = socket.gethostbyname(target)
            except Exception:
                ip = target
            
            url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                shodan_results = {
                    'ip': data.get('ip_str'),
                    'country': data.get('country_name'),
                    'city': data.get('city'),
                    'isp': data.get('isp'),
                    'organization': data.get('org'),
                    'ports': data.get('ports', [])[:10],  # Limit ports
                    'vulnerabilities': data.get('vulns', [])[:5],  # Limit vulns
                    'last_update': data.get('last_update'),
                    'hostnames': data.get('hostnames', [])[:5]  # Limit hostnames
                }
                
                return shodan_results
            else:
                return {'error': f'API error: {response.status_code}'}
                
        except Exception as e:
            self.logger.error(f"Error querying Shodan: {str(e)}")
            return {'error': str(e)}
    
    def wayback_analysis(self, target: str) -> Dict[str, Any]:
        """Analyze target using Wayback Machine data"""
        self.logger.info(f"Analyzing Wayback Machine data for {target}")
        
        results = {
            'target': target,
            'snapshots': [],
            'interesting_files': [],
            'technologies_history': [],
            'status': 'success'
        }
        
        try:
            # Get snapshots from Wayback Machine API
            snapshots = self._get_wayback_snapshots(target)
            results['snapshots'] = snapshots
            
            # Analyze snapshots for interesting files
            interesting_files = self._find_interesting_files(snapshots)
            results['interesting_files'] = interesting_files
            
            # Technology stack evolution
            tech_history = self._analyze_technology_evolution(snapshots)
            results['technologies_history'] = tech_history
            
            self.logger.info(f"Found {len(snapshots)} snapshots and {len(interesting_files)} interesting files")
            
        except Exception as e:
            self.logger.error(f"Wayback analysis failed: {str(e)}")
            results['status'] = 'failed'
            results['error'] = str(e)
        
        return results
    
    def _get_wayback_snapshots(self, target: str) -> List[Dict[str, Any]]:
        """Get snapshots from Wayback Machine CDX API"""
        try:
            # Clean target URL
            if target.startswith('http'):
                domain = urlparse(target).netloc
            else:
                domain = target
                
            # Query Wayback CDX API
            cdx_url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=1000"
            
            response = requests.get(cdx_url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            if not data:
                return []
            
            # Skip header row
            snapshots = []
            for row in data[1:]:
                if len(row) >= 7:
                    snapshots.append({
                        'timestamp': row[1],
                        'url': row[2],
                        'status_code': row[4],
                        'mimetype': row[3],
                        'length': row[5],
                        'wayback_url': f"http://web.archive.org/web/{row[1]}/{row[2]}"
                    })
            
            return snapshots
            
        except Exception as e:
            self.logger.error(f"Error getting Wayback snapshots: {str(e)}")
            return []
    
    def _find_interesting_files(self, snapshots: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find interesting files from Wayback snapshots"""
        interesting_extensions = [
            '.sql', '.bak', '.backup', '.old', '.orig', '.tmp',
            '.config', '.conf', '.ini', '.env', '.log',
            '.zip', '.tar', '.gz', '.rar', '.7z',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx',
            '.xml', '.json', '.csv', '.txt'
        ]
        
        interesting_paths = [
            'admin', 'config', 'backup', 'test', 'dev',
            'staging', 'api', 'private', 'internal',
            'upload', 'uploads', 'files', 'documents'
        ]
        
        interesting_files = []
        
        for snapshot in snapshots:
            url = snapshot['url'].lower()
            
            # Check for interesting file extensions
            for ext in interesting_extensions:
                if url.endswith(ext):
                    interesting_files.append({
                        'url': snapshot['url'],
                        'wayback_url': snapshot['wayback_url'],
                        'timestamp': snapshot['timestamp'],
                        'type': 'interesting_extension',
                        'reason': f'Contains {ext} extension'
                    })
                    break
            
            # Check for interesting paths
            for path in interesting_paths:
                if f'/{path}/' in url or f'/{path}.' in url:
                    interesting_files.append({
                        'url': snapshot['url'],
                        'wayback_url': snapshot['wayback_url'],
                        'timestamp': snapshot['timestamp'],
                        'type': 'interesting_path',
                        'reason': f'Contains {path} in path'
                    })
                    break
        
        # Remove duplicates
        seen_urls = set()
        unique_files = []
        for file_info in interesting_files:
            if file_info['url'] not in seen_urls:
                seen_urls.add(file_info['url'])
                unique_files.append(file_info)
        
        return unique_files[:50]  # Limit to 50 most interesting
    
    def _analyze_technology_evolution(self, snapshots: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze technology stack evolution over time"""
        tech_history = []
        
        # Group snapshots by year
        yearly_snapshots = {}
        for snapshot in snapshots:
            year = snapshot['timestamp'][:4]
            if year not in yearly_snapshots:
                yearly_snapshots[year] = []
            yearly_snapshots[year].append(snapshot)
        
        # Analyze each year
        for year in sorted(yearly_snapshots.keys()):
            year_snapshots = yearly_snapshots[year]
            
            # Look for technology indicators in URLs
            technologies = set()
            
            for snapshot in year_snapshots:
                url = snapshot['url'].lower()
                
                # Common technology indicators
                if 'wp-' in url or 'wordpress' in url:
                    technologies.add('WordPress')
                if '.php' in url:
                    technologies.add('PHP')
                if '.asp' in url or '.aspx' in url:
                    technologies.add('ASP.NET')
                if '.jsp' in url:
                    technologies.add('JSP')
                if 'jquery' in url:
                    technologies.add('jQuery')
                if 'bootstrap' in url:
                    technologies.add('Bootstrap')
                if 'angular' in url:
                    technologies.add('Angular')
                if 'react' in url:
                    technologies.add('React')
                if 'vue' in url:
                    technologies.add('Vue.js')
            
            if technologies:
                tech_history.append({
                    'year': year,
                    'technologies': list(technologies),
                    'snapshots_count': len(year_snapshots)
                })
        
        return tech_history
    
    def github_dorking(self, target: str) -> Dict[str, Any]:
        """Search GitHub for potential sensitive information"""
        self.logger.info(f"Performing GitHub dorking for {target}")
        
        results = {
            'target': target,
            'potential_leaks': [],
            'repositories': [],
            'status': 'success'
        }
        
        try:
            # Clean domain name
            if target.startswith('http'):
                domain = urlparse(target).netloc
            else:
                domain = target
            
            # Remove www. prefix if present
            domain = domain.replace('www.', '')
            
            # Common search queries for sensitive information
            search_queries = [
                f'"{domain}" password',
                f'"{domain}" api_key',
                f'"{domain}" secret',
                f'"{domain}" token',
                f'"{domain}" config',
                f'"{domain}" database',
                f'"{domain}" credentials',
                f'site:{domain} filetype:env',
                f'site:{domain} filetype:config',
                f'site:{domain} filetype:sql'
            ]
            
            # Note: This is a placeholder implementation
            # Real implementation would require GitHub API token
            for query in search_queries[:3]:  # Limit to avoid rate limiting
                self.logger.info(f"Searching GitHub for: {query}")
                # Simulated search results
                results['potential_leaks'].append({
                    'query': query,
                    'note': 'GitHub API integration required for actual search',
                    'recommendation': f'Manually search GitHub for: {query}'
                })
            
            self.logger.info(f"GitHub dorking completed with {len(search_queries)} queries")
            
        except Exception as e:
            self.logger.error(f"GitHub dorking failed: {str(e)}")
            results['status'] = 'failed'
            results['error'] = str(e)
        
        return results
    
    def _save_osint_results(self, target: str, results: Dict[str, Any]) -> None:
        """Save OSINT results"""
        sanitized_target = target.replace(':', '_').replace('/', '_')
        json_file = self.osint_dir / f'{sanitized_target}_osint_results.json'
        
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        self.logger.info(f"OSINT results saved to {json_file}")
        
        # Create human-readable summary
        txt_file = self.osint_dir / f'{sanitized_target}_osint_summary.txt'
        
        with open(txt_file, 'w') as f:
            f.write(f"OSINT Collection Summary for {target}\n")
            f.write("=" * 50 + "\n\n")
            
            # WHOIS information
            whois_info = results.get('whois', {})
            if whois_info and 'error' not in whois_info:
                f.write("WHOIS Information:\n")
                f.write(f"  Domain: {whois_info.get('domain_name', 'N/A')}\n")
                f.write(f"  Registrar: {whois_info.get('registrar', 'N/A')}\n")
                f.write(f"  Created: {whois_info.get('creation_date', 'N/A')}\n")
                f.write(f"  Expires: {whois_info.get('expiration_date', 'N/A')}\n")
                f.write(f"  Country: {whois_info.get('country', 'N/A')}\n")
                f.write("\n")
            
            # DNS records
            dns_records = results.get('dns_records', {})
            if dns_records and 'error' not in dns_records:
                f.write("DNS Records:\n")
                for record_type, records in dns_records.items():
                    if records:
                        f.write(f"  {record_type}: {', '.join(records[:3])}\n")
                        if len(records) > 3:
                            f.write(f"    ... and {len(records) - 3} more\n")
                f.write("\n")
            
            # Shodan results
            shodan_info = results.get('shodan', {})
            if shodan_info and 'error' not in shodan_info:
                f.write("Shodan Information:\n")
                f.write(f"  IP: {shodan_info.get('ip', 'N/A')}\n")
                f.write(f"  Country: {shodan_info.get('country', 'N/A')}\n")
                f.write(f"  ISP: {shodan_info.get('isp', 'N/A')}\n")
                f.write(f"  Open Ports: {', '.join(map(str, shodan_info.get('ports', [])))}\n")
                f.write("\n")
            
            # Wayback analysis
            wayback_info = results.get('wayback', {})
            if wayback_info and wayback_info.get('status') == 'success':
                f.write("Wayback Machine Analysis:\n")
                f.write(f"  Snapshots Found: {len(wayback_info.get('snapshots', []))}\n")
                f.write(f"  Interesting Files: {len(wayback_info.get('interesting_files', []))}\n")
                f.write("\n")
        
        self.logger.info(f"OSINT summary saved to {txt_file}")
