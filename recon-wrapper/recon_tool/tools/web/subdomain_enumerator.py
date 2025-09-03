"""
Subdomain Enumerator
Comprehensive subdomain discovery using multiple techniques
"""

import json
import logging
import os
import socket
import ssl
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, Any, List, Set

import dns.resolver
import requests

try:
    import dns.query
    import dns.zone
    import dns.exception
    HAS_DNS_QUERY = True
except ImportError:
    HAS_DNS_QUERY = False

from ...core.exceptions import ScanError, ToolNotFoundError
from ...core.utils import check_tool_installed


class SubdomainEnumerator:
    """Subdomain enumeration using multiple tools and techniques"""
    
    def __init__(self, output_dir: Path, config: Dict[str, Any], logger: logging.Logger):
        self.output_dir = output_dir
        self.config = config
        self.logger = logger
        self.subdomains: Set[str] = set()
        
        # Create subdomains output directory
        self.subdomains_dir = output_dir / 'subdomains'
        self.subdomains_dir.mkdir(exist_ok=True)
        
    def enumerate(self, domain: str) -> List[str]:
        """Run comprehensive subdomain enumeration"""
        self.logger.info(f"Starting subdomain enumeration for {domain}")
        
        # Create results structure
        results = {
            'domain': domain,
            'subdomains': [],
            'live_subdomains': [],
            'tools_used': [],
            'total_found': 0,
            'total_live': 0
        }
        
        # Check if we're in offline mode
        offline_mode = self.config.get('offline_mode', False)
        
        if offline_mode:
            # Run offline enumeration methods
            self.logger.info("Running in offline mode - using internal enumeration methods")
            self._dns_bruteforce(domain, results)
            self._zone_transfer(domain, results)
            self._san_from_cert(domain, results)
        else:
            # Run online enumeration methods
            self._run_sublist3r(domain, results)
            self._run_assetfinder(domain, results)
            self._run_subfinder(domain, results)
            self._run_crtsh(domain, results)
        
        # Deduplicate and validate subdomains
        unique_subdomains = list(self.subdomains)
        results['subdomains'] = unique_subdomains
        results['total_found'] = len(unique_subdomains)
        
        # Check which subdomains are live
        live_subdomains = self._validate_subdomains(unique_subdomains[:50])  # Limit for performance
        results['live_subdomains'] = live_subdomains
        results['total_live'] = len(live_subdomains)
        
        # Save results
        self._save_results(domain, results)
        
        self.logger.info(f"Found {results['total_found']} subdomains, {results['total_live']} live")
        return [sub['subdomain'] for sub in live_subdomains]
    
    def _run_sublist3r(self, domain: str, results: Dict[str, Any]) -> None:
        """Run Sublist3r for subdomain enumeration"""
        try:
            if not check_tool_installed('sublist3r'):
                self.logger.warning("Sublist3r not available")
                return
                
            self.logger.info("Running Sublist3r...")
            output_file = self.subdomains_dir / f'{domain}_sublist3r.txt'
            
            cmd = [
                'sublist3r',
                '-d', domain,
                '-o', str(output_file)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.get('timeout', 300)
            )
            
            if result.returncode == 0 and output_file.exists():
                with open(output_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
                    self.subdomains.update(subdomains)
                    results['tools_used'].append('sublist3r')
                    self.logger.info(f"Sublist3r found {len(subdomains)} subdomains")
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.logger.warning(f"Sublist3r error: {str(e)}")
    
    def _run_assetfinder(self, domain: str, results: Dict[str, Any]) -> None:
        """Run Assetfinder for subdomain enumeration"""
        try:
            if not check_tool_installed('assetfinder'):
                self.logger.warning("Assetfinder not available")
                return
                
            self.logger.info("Running Assetfinder...")
            
            cmd = ['assetfinder', domain]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.get('timeout', 300)
            )
            
            if result.returncode == 0:
                subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                self.subdomains.update(subdomains)
                results['tools_used'].append('assetfinder')
                
                # Save output
                output_file = self.subdomains_dir / f'{domain}_assetfinder.txt'
                with open(output_file, 'w') as f:
                    f.write(result.stdout)
                
                self.logger.info(f"Assetfinder found {len(subdomains)} subdomains")
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.logger.warning(f"Assetfinder error: {str(e)}")
    
    def _run_subfinder(self, domain: str, results: Dict[str, Any]) -> None:
        """Run Subfinder for subdomain enumeration"""
        try:
            if not check_tool_installed('subfinder'):
                self.logger.warning("Subfinder not available")
                return
                
            self.logger.info("Running Subfinder...")
            output_file = self.subdomains_dir / f'{domain}_subfinder.txt'
            
            cmd = [
                'subfinder',
                '-d', domain,
                '-o', str(output_file),
                '-silent'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.get('timeout', 300)
            )
            
            if result.returncode == 0 and output_file.exists():
                with open(output_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
                    self.subdomains.update(subdomains)
                    results['tools_used'].append('subfinder')
                    self.logger.info(f"Subfinder found {len(subdomains)} subdomains")
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.logger.warning(f"Subfinder error: {str(e)}")
    
    def _run_crtsh(self, domain: str, results: Dict[str, Any]) -> None:
        """Query crt.sh for certificate transparency logs"""
        try:
            self.logger.info("Querying crt.sh...")
            
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                
                for entry in data[:100]:  # Limit results
                    name_value = entry.get('name_value', '')
                    if name_value:
                        # Handle multiple names in one entry
                        names = name_value.split('\n')
                        for name in names:
                            name = name.strip()
                            if name and domain in name:
                                subdomains.add(name)
                
                self.subdomains.update(subdomains)
                results['tools_used'].append('crt.sh')
                
                self.logger.info(f"crt.sh found {len(subdomains)} subdomains")
            
        except Exception as e:
            self.logger.warning(f"Error querying crt.sh: {str(e)}")
    
    def _dns_bruteforce(self, domain: str, results: Dict[str, Any]) -> None:
        """DNS bruteforce using local/internal resolver"""
        try:
            self.logger.info("Running DNS bruteforce...")
            
            # Load DNS wordlist with comprehensive error handling
            wordlist_path = self.config.get('dns_wordlist', '/usr/share/wordlists/subdomains.txt')
            
            # Create a basic fallback wordlist
            basic_words = [
                'www', 'mail', 'admin', 'ftp', 'blog', 'test', 'dev', 'staging', 'api',
                'portal', 'intranet', 'vpn', 'secure', 'app', 'web', 'server', 'host',
                'database', 'db', 'sql', 'backup', 'store', 'shop', 'cdn', 'static',
                'img', 'images', 'media', 'assets', 'files', 'docs', 'help', 'support'
            ]
            
            # Attempt to load custom wordlist with proper error handling
            if not wordlist_path or not os.path.exists(wordlist_path):
                if wordlist_path:
                    self.logger.warning(f"DNS wordlist not found: {wordlist_path}, using built-in wordlist")
                else:
                    self.logger.info("No DNS wordlist specified, using built-in wordlist")
                self.logger.info(f"Using built-in DNS wordlist ({len(basic_words)} words)")
                wordlist = basic_words
            else:
                try:
                    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                        wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')][:1000]  # Limit for performance
                        if wordlist:
                            self.logger.info(f"Loaded DNS wordlist from {wordlist_path} ({len(wordlist)} words)")
                        else:
                            self.logger.warning(f"DNS wordlist is empty: {wordlist_path}, using built-in wordlist")
                            wordlist = basic_words
                except (IOError, OSError, PermissionError) as e:
                    self.logger.error(f"Cannot read DNS wordlist '{wordlist_path}': {str(e)}, using built-in wordlist")
                    wordlist = basic_words
                except Exception as e:
                    self.logger.error(f"Unexpected error loading DNS wordlist '{wordlist_path}': {str(e)}, using built-in wordlist")
                    wordlist = basic_words
            
            # Configure DNS resolver
            resolver = dns.resolver.Resolver()
            dns_servers = self.config.get('dns_servers', [])
            if dns_servers:
                resolver.nameservers = dns_servers
                self.logger.info(f"Using DNS servers: {dns_servers}")
            
            # Detect wildcard DNS by testing multiple random labels
            wildcard_ips = set()
            try:
                import random
                import string
                
                # Test multiple random labels to catch round-robin wildcards
                for i in range(3):
                    # Generate a truly random label
                    random_string = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
                    random_label = f"nonexistent-{random_string}-{i}.{domain}"
                    
                    try:
                        answer = resolver.resolve(random_label, 'A')
                        # Collect all IPs from the response (in case of multiple A records)
                        for record in answer:
                            wildcard_ips.add(str(record))
                        self.logger.debug(f"Wildcard test {i+1}: {random_label} -> {[str(r) for r in answer]}")
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        # This is good - means no wildcard for this test
                        pass
                    except Exception as e:
                        self.logger.debug(f"Wildcard test {i+1} error: {str(e)}")
                
                if wildcard_ips:
                    self.logger.info(f"Wildcard DNS detected! IPs: {sorted(wildcard_ips)}")
                else:
                    self.logger.info("No wildcard DNS detected")
                    
            except Exception as e:
                self.logger.warning(f"Wildcard detection error: {str(e)}")
                wildcard_ips = set()  # Continue without wildcard detection
            
            # Bruteforce subdomains
            found_subdomains = []
            for word in wordlist[:500]:  # Limit for performance
                subdomain = f"{word}.{domain}"
                try:
                    answer = resolver.resolve(subdomain, 'A')
                    
                    # Check all A records returned
                    subdomain_ips = set(str(record) for record in answer)
                    
                    # Skip if all IPs match wildcard IPs
                    if wildcard_ips and subdomain_ips.issubset(wildcard_ips):
                        self.logger.debug(f"Skipping {subdomain} - matches wildcard IP(s)")
                        continue
                    
                    # Also skip if ANY IP matches wildcard (more conservative approach)
                    if wildcard_ips and subdomain_ips.intersection(wildcard_ips):
                        self.logger.debug(f"Skipping {subdomain} - contains wildcard IP")
                        continue
                    
                    found_subdomains.append(subdomain)
                    self.subdomains.add(subdomain)
                    
                except dns.resolver.NXDOMAIN:
                    pass  # Domain doesn't exist
                except Exception as e:
                    self.logger.debug(f"DNS error for {subdomain}: {str(e)}")
            
            results['tools_used'].append('dns_bruteforce')
            
            # Save bruteforce results
            output_file = self.subdomains_dir / f'{domain}_dns_bruteforce.txt'
            with open(output_file, 'w') as f:
                for subdomain in found_subdomains:
                    f.write(f"{subdomain}\n")
            
            self.logger.info(f"DNS bruteforce found {len(found_subdomains)} subdomains")
            
        except Exception as e:
            self.logger.warning(f"DNS bruteforce error: {str(e)}")
    
    def _zone_transfer(self, domain: str, results: Dict[str, Any]) -> None:
        """Attempt zone transfer (AXFR)"""
        try:
            self.logger.info("Attempting zone transfer (AXFR)...")
            
            # Get NS records using dig
            ns_records = []
            try:
                cmd = ['dig', '+short', domain, 'NS']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    ns_records = [line.strip().rstrip('.') for line in result.stdout.strip().split('\n') if line.strip()]
            except Exception as e:
                self.logger.debug(f"Error getting NS records with dig: {str(e)}")
            
            # Fallback to dns.resolver for NS records
            if not ns_records:
                try:
                    resolver = dns.resolver.Resolver()
                    dns_servers = self.config.get('dns_servers', [])
                    if dns_servers:
                        resolver.nameservers = dns_servers
                    
                    answer = resolver.resolve(domain, 'NS')
                    ns_records = [str(rdata).rstrip('.') for rdata in answer]
                except Exception as e:
                    self.logger.debug(f"Error getting NS records with resolver: {str(e)}")
            
            if not ns_records:
                self.logger.info("No NS records found for zone transfer")
                return
            
            self.logger.info(f"Found {len(ns_records)} NS records: {ns_records}")
            
            # Try zone transfer on each NS
            transfer_results = []
            for ns in ns_records[:3]:  # Limit NS servers
                try:
                    self.logger.info(f"Trying zone transfer from {ns}")
                    
                    # Use dns.query.xfr for zone transfer if available
                    if HAS_DNS_QUERY:
                        try:
                            self.logger.debug(f"Attempting AXFR from {ns}...")
                            xfr = dns.query.xfr(ns, domain, timeout=30)
                            zone = dns.zone.from_xfr(xfr)
                            
                            # Extract subdomains from zone
                            for name, node in zone.nodes.items():
                                if name != dns.name.empty:
                                    subdomain = f"{name}.{domain}".rstrip('.')
                                    if subdomain != domain:  # Exclude apex domain
                                        transfer_results.append(subdomain)
                                        self.subdomains.add(subdomain)
                            
                            self.logger.info(f"Zone transfer successful from {ns}: {len(transfer_results)} records")
                            break  # Success, no need to try other NS
                            
                        except dns.exception.DNSException as e:
                            # Specific DNS exceptions (refused, timeout, etc.)
                            if "refused" in str(e).lower() or "REFUSED" in str(e):
                                self.logger.info(f"AXFR refused by {ns} (expected security measure)")
                            elif "timeout" in str(e).lower() or "TIMEOUT" in str(e):
                                self.logger.info(f"AXFR timeout from {ns}")
                            elif "NOTAUTH" in str(e):
                                self.logger.info(f"AXFR not authorized by {ns}")
                            else:
                                self.logger.info(f"AXFR failed from {ns}: {str(e)}")
                        except Exception as e:
                            # Other non-DNS exceptions
                            self.logger.debug(f"Zone transfer error from {ns}: {str(e)}")
                    else:
                        self.logger.info("dns.query not available - skipping zone transfer")
                        break
                        
                except Exception as e:
                    self.logger.debug(f"Error with NS {ns}: {str(e)}")
            
            if transfer_results:
                results['tools_used'].append('zone_transfer')
                
                # Save zone transfer results
                output_file = self.subdomains_dir / f'{domain}_zone_transfer.txt'
                with open(output_file, 'w') as f:
                    for subdomain in transfer_results:
                        f.write(f"{subdomain}\n")
                
                self.logger.info(f"Zone transfer found {len(transfer_results)} subdomains")
            else:
                self.logger.info("Zone transfer not allowed or failed")
                
        except Exception as e:
            self.logger.warning(f"Zone transfer error: {str(e)}")
    
    def _san_from_cert(self, domain: str, results: Dict[str, Any]) -> None:
        """Extract subdomains from certificate Subject Alternative Names (SAN)"""
        try:
            self.logger.info("Extracting subdomains from SSL certificates...")
            
            # Get target IPs
            target_ips = []
            try:
                # Try to resolve domain to IP
                ip = socket.gethostbyname(domain)
                target_ips.append(ip)
            except:
                # If resolution fails, try the domain itself if it looks like an IP
                try:
                    ipaddress.ip_address(domain)
                    target_ips.append(domain)
                except:
                    self.logger.info(f"Could not resolve {domain} to IP for certificate analysis")
                    return
            
            # Common SSL ports to check
            ssl_ports = [443, 8443, 8080, 8000, 9443]
            found_subdomains = []
            
            for ip in target_ips:
                for port in ssl_ports:
                    try:
                        self.logger.debug(f"Checking SSL certificate on {ip}:{port}")
                        
                        # Create SSL context
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        
                        # Connect and get certificate
                        with socket.create_connection((ip, port), timeout=10) as sock:
                            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                                # Fallback to basic certificate parsing
                                cert_info = ssock.getpeercert()
                                san_list = cert_info.get('subjectAltName', [])
                                
                                for san_type, san_value in san_list:
                                    if san_type == 'DNS':
                                        if san_value.endswith(f'.{domain}') or san_value == domain:
                                            found_subdomains.append(san_value)
                                            self.subdomains.add(san_value)
                                
                                self.logger.info(f"Found {len(san_list)} SAN entries on {ip}:{port}")
                        
                        # If we found a working SSL port, we can stop checking other ports for this IP
                        if found_subdomains:
                            break
                            
                    except (ConnectionRefusedError, ssl.SSLError, socket.timeout):
                        # Port not open or SSL not available
                        continue
                    except Exception as e:
                        self.logger.debug(f"SSL error on {ip}:{port}: {str(e)}")
                        continue
            
            if found_subdomains:
                results['tools_used'].append('cert_san')
                
                # Remove duplicates
                unique_sans = list(set(found_subdomains))
                
                # Save SAN results
                output_file = self.subdomains_dir / f'{domain}_cert_san.txt'
                with open(output_file, 'w') as f:
                    for subdomain in unique_sans:
                        f.write(f"{subdomain}\n")
                
                self.logger.info(f"Certificate SAN analysis found {len(unique_sans)} subdomains")
            else:
                self.logger.info("No subdomains found in certificate SANs")
                
        except Exception as e:
            self.logger.warning(f"Certificate SAN analysis error: {str(e)}")
    
    def _validate_subdomains(self, subdomains: List[str]) -> List[Dict[str, Any]]:
        """Validate which subdomains are live using HTTP probes"""
        self.logger.info("Validating live subdomains...")
        
        live_subdomains = []
        
        def check_http(subdomain):
            for scheme in ['https', 'http']:
                try:
                    url = f"{scheme}://{subdomain}"
                    response = requests.head(url, timeout=5, allow_redirects=True)
                    if response.status_code < 400:
                        return {
                            'subdomain': subdomain,
                            'url': url,
                            'status_code': response.status_code
                        }
                except:
                    continue
            return None
        
        threads = min(self.config.get('threads', 20), 20)  # Limit threads
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(check_http, sub) for sub in subdomains]
            
            for future in futures:
                try:
                    result = future.result(timeout=10)
                    if result:
                        live_subdomains.append(result)
                except:
                    continue
        
        return live_subdomains
    
    def _save_results(self, domain: str, results: Dict[str, Any]) -> None:
        """Save enumeration results"""
        # Save JSON results
        json_file = self.subdomains_dir / f'{domain}_results.json'
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Save all subdomains to text file
        all_subs_file = self.subdomains_dir / f'{domain}_all_subdomains.txt'
        with open(all_subs_file, 'w') as f:
            for subdomain in sorted(results['subdomains']):
                f.write(f"{subdomain}\n")
        
        self.logger.info(f"Subdomain results saved to {json_file}")
