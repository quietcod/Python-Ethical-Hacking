#!/usr/bin/env python3
"""
Amass OSINT Enumeration - Phase 4 Implementation
Real comprehensive OSINT subdomain and asset discovery using OWASP Amass
"""

import json
import subprocess
import time
from datetime import datetime
from typing import Dict, Any, List, Set, Optional
from pathlib import Path

from .base import BaseTool

class AmassEnumerator(BaseTool):
    """Real Amass OSINT enumeration implementation"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.command_name = "amass"
        self.version = "v4.0+"
        self.description = "Comprehensive OSINT enumeration"
        self.category = "osint"
        
        # Amass-specific configuration
        self.passive_mode = config.get('passive_mode', True)
        self.active_mode = config.get('active_mode', False)
        self.brute_force = config.get('brute_force', False)
        self.timeout = config.get('timeout', 300)
        self.max_dns_queries = config.get('max_dns_queries', 20000)
        
        # Data sources configuration
        self.data_sources = config.get('data_sources', [
            'AlienVault', 'Ask', 'Baidu', 'Bing', 'CertSpotter',
            'CIRCL', 'CommonCrawl', 'Crtsh', 'DNSDB', 'DNSDumpster',
            'Entrust', 'Google', 'HackerTarget', 'IPv4Info', 'Netcraft',
            'PTRArchive', 'Riddler', 'Robtex', 'SecurityTrails', 'SiteDossier',
            'Spyse', 'Sublist3r', 'ThreatCrowd', 'VirusTotal', 'Yahoo'
        ])
        
        # Output configuration
        self.output_format = config.get('output_format', 'json')
        self.include_sources = config.get('include_sources', True)
        self.include_ips = config.get('include_ips', True)
    
    def scan(self, target: str, scan_params: Dict) -> Dict:
        """Execute amass scan against target"""
        self.start_time = datetime.now()
        
        try:
            self.logger.info(f"🔧 Starting AmassEnumerator scan against {target}")
            
            # Verify tool installation
            if not self.verify_installation():
                return self._create_error_result("Amass not installed")
            
            # Determine scan type
            scan_type = scan_params.get('scan_type', 'passive')
            
            if scan_type == 'passive':
                return self.passive_enumeration(target, scan_params)
            elif scan_type == 'active':
                return self.active_enumeration(target, scan_params)
            elif scan_type == 'intel':
                return self.intel_gathering(target, scan_params)
            elif scan_type == 'comprehensive':
                return self._comprehensive_enumeration(target, scan_params)
            else:
                return self._create_error_result(f"Unknown scan type: {scan_type}")
                
        except Exception as e:
            self.logger.error(f"❌ AmassEnumerator error: {e}")
            return self._create_error_result(str(e))
    
    def passive_enumeration(self, domain: str, scan_params: Dict = {}) -> Dict:
        """Passive OSINT enumeration"""
        try:
            self.logger.info(f"Running Amass passive enumeration for {domain}")
            
            # Create output file
            output_file = self.get_results_dir() / 'amass_passive.json'
            
            # Build amass enum command
            cmd = [
                'amass', 'enum',
                '-passive',
                '-d', domain,
                '-json', str(output_file)
            ]
            
            # Add timeout
            timeout = scan_params.get('timeout', self.timeout)
            if timeout:
                cmd.extend(['-timeout', str(timeout)])
            
            # Add max DNS queries limit
            max_queries = scan_params.get('max_dns_queries', self.max_dns_queries)
            if max_queries:
                cmd.extend(['-max-dns-queries', str(max_queries)])
            
            # Execute amass
            result = self.execute_command(cmd, timeout=timeout + 60)
            
            if result.returncode != 0:
                self.logger.warning(f"Amass returned non-zero exit code: {result.returncode}")
            
            # Parse results
            results = self._parse_amass_output(output_file, domain)
            
            # Save raw output
            if result.stdout:
                self.save_raw_output(result.stdout, domain, 'txt')
            
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            
            subdomain_count = len(results.get('subdomains', []))
            self.logger.info(f"ℹ️ [AmassEnumerator] passive: Found {subdomain_count} subdomains")
            self.logger.info(f"✅ AmassEnumerator passive completed in {duration:.1f}s")
            
            return {
                'status': 'success',
                'target': domain,
                'scan_type': 'amass_passive',
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat(),
                'duration': duration,
                'subdomains': results.get('subdomains', []),
                'ip_addresses': results.get('ip_addresses', []),
                'data_sources': results.get('data_sources', []),
                'summary': {
                    'total_subdomains': subdomain_count,
                    'total_ips': len(results.get('ip_addresses', [])),
                    'sources_used': len(results.get('data_sources', [])),
                    'mode': 'passive'
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error in passive enumeration: {e}")
            return self._create_error_result(str(e))
    
    def active_enumeration(self, domain: str, scan_params: Dict = {}) -> Dict:
        """Active enumeration with DNS queries"""
        try:
            self.logger.info(f"Running Amass active enumeration for {domain}")
            
            # Create output file
            output_file = self.get_results_dir() / 'amass_active.json'
            
            # Build amass enum command
            cmd = [
                'amass', 'enum',
                '-active',
                '-d', domain,
                '-json', str(output_file)
            ]
            
            # Add brute force if enabled
            if scan_params.get('brute_force', self.brute_force):
                cmd.append('-brute')
            
            # Add timeout
            timeout = scan_params.get('timeout', self.timeout)
            if timeout:
                cmd.extend(['-timeout', str(timeout)])
            
            # Execute amass
            result = self.execute_command(cmd, timeout=timeout + 60)
            
            if result.returncode != 0:
                self.logger.warning(f"Amass active returned non-zero exit code: {result.returncode}")
            
            # Parse results
            results = self._parse_amass_output(output_file, domain)
            
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            
            subdomain_count = len(results.get('subdomains', []))
            self.logger.info(f"ℹ️ [AmassEnumerator] active: Found {subdomain_count} subdomains")
            self.logger.info(f"✅ AmassEnumerator active completed in {duration:.1f}s")
            
            return {
                'status': 'success',
                'target': domain,
                'scan_type': 'amass_active',
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat(),
                'duration': duration,
                'subdomains': results.get('subdomains', []),
                'ip_addresses': results.get('ip_addresses', []),
                'data_sources': results.get('data_sources', []),
                'summary': {
                    'total_subdomains': subdomain_count,
                    'total_ips': len(results.get('ip_addresses', [])),
                    'sources_used': len(results.get('data_sources', [])),
                    'mode': 'active',
                    'brute_force': scan_params.get('brute_force', False)
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error in active enumeration: {e}")
            return self._create_error_result(str(e))
    
    def intel_gathering(self, domain: str, scan_params: Dict = {}) -> Dict:
        """Intelligence gathering mode"""
        try:
            self.logger.info(f"Running Amass intelligence gathering for {domain}")
            
            # Create output file
            output_file = self.get_results_dir() / 'amass_intel.json'
            
            # Build amass intel command
            cmd = [
                'amass', 'intel',
                '-d', domain,
                '-json', str(output_file)
            ]
            
            # Add WHOIS info
            cmd.append('-whois')
            
            # Add timeout
            timeout = scan_params.get('timeout', self.timeout // 2)  # Intel is usually faster
            if timeout:
                cmd.extend(['-timeout', str(timeout)])
            
            # Execute amass intel
            result = self.execute_command(cmd, timeout=timeout + 30)
            
            if result.returncode != 0:
                self.logger.warning(f"Amass intel returned non-zero exit code: {result.returncode}")
            
            # Parse results
            results = self._parse_amass_intel_output(output_file, domain)
            
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            
            asset_count = len(results.get('assets', []))
            self.logger.info(f"ℹ️ [AmassEnumerator] intel: Found {asset_count} assets")
            self.logger.info(f"✅ AmassEnumerator intel completed in {duration:.1f}s")
            
            return {
                'status': 'success',
                'target': domain,
                'scan_type': 'amass_intel',
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat(),
                'duration': duration,
                'assets': results.get('assets', []),
                'related_domains': results.get('related_domains', []),
                'network_blocks': results.get('network_blocks', []),
                'summary': {
                    'total_assets': asset_count,
                    'related_domains': len(results.get('related_domains', [])),
                    'network_blocks': len(results.get('network_blocks', [])),
                    'mode': 'intelligence'
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error in intelligence gathering: {e}")
            return self._create_error_result(str(e))
    
    def asset_discovery(self, organization: str, scan_params: Dict = {}) -> Dict:
        """Discover assets by organization"""
        try:
            self.logger.info(f"Running Amass asset discovery for organization: {organization}")
            
            # Create output file
            output_file = self.get_results_dir() / 'amass_assets.json'
            
            # Build amass intel command for organization
            cmd = [
                'amass', 'intel',
                '-org', organization,
                '-json', str(output_file)
            ]
            
            # Add WHOIS info
            cmd.append('-whois')
            
            # Execute amass
            timeout = scan_params.get('timeout', self.timeout)
            result = self.execute_command(cmd, timeout=timeout + 30)
            
            if result.returncode != 0:
                self.logger.warning(f"Amass asset discovery returned non-zero exit code: {result.returncode}")
            
            # Parse results
            results = self._parse_amass_intel_output(output_file, organization)
            
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            
            asset_count = len(results.get('assets', []))
            self.logger.info(f"ℹ️ [AmassEnumerator] assets: Found {asset_count} assets for {organization}")
            
            return {
                'status': 'success',
                'target': organization,
                'scan_type': 'amass_asset_discovery',
                'duration': duration,
                'assets': results.get('assets', []),
                'domains': results.get('related_domains', []),
                'summary': {
                    'total_assets': asset_count,
                    'organization': organization
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error in asset discovery: {e}")
            return self._create_error_result(str(e))
    
    def _comprehensive_enumeration(self, domain: str, scan_params: Dict) -> Dict:
        """Comprehensive enumeration combining multiple modes"""
        try:
            self.logger.info(f"Running comprehensive Amass enumeration for {domain}")
            
            # Run passive enumeration first
            passive_results = self.passive_enumeration(domain, scan_params)
            
            # Run intelligence gathering
            intel_results = self.intel_gathering(domain, scan_params)
            
            # Combine results
            all_subdomains = set()
            all_ips = set()
            all_sources = set()
            
            if passive_results['status'] == 'success':
                all_subdomains.update([sub['name'] for sub in passive_results.get('subdomains', [])])
                all_ips.update(passive_results.get('ip_addresses', []))
                all_sources.update(passive_results.get('data_sources', []))
            
            if intel_results['status'] == 'success':
                for asset in intel_results.get('assets', []):
                    if 'domain' in asset:
                        all_subdomains.add(asset['domain'])
            
            self.end_time = datetime.now()
            total_duration = (self.end_time - self.start_time).total_seconds()
            
            self.logger.info(f"✅ AmassEnumerator comprehensive completed in {total_duration:.1f}s")
            
            return {
                'status': 'success',
                'target': domain,
                'scan_type': 'amass_comprehensive',
                'duration': total_duration,
                'passive_results': passive_results,
                'intel_results': intel_results,
                'combined_summary': {
                    'total_unique_subdomains': len(all_subdomains),
                    'total_unique_ips': len(all_ips),
                    'total_sources_used': len(all_sources),
                    'subdomains': list(all_subdomains),
                    'ip_addresses': list(all_ips)
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error in comprehensive enumeration: {e}")
            return self._create_error_result(str(e))
    
    def _parse_amass_output(self, output_file: Path, domain: str) -> Dict:
        """Parse amass JSON output"""
        results = {
            'subdomains': [],
            'ip_addresses': set(),
            'data_sources': set()
        }
        
        try:
            if not output_file.exists():
                return results
            
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        
                        if 'name' in data:
                            subdomain_info = {
                                'name': data['name'],
                                'domain': data.get('domain', domain),
                                'addresses': data.get('addresses', []),
                                'tag': data.get('tag', ''),
                                'source': data.get('source', 'unknown'),
                                'timestamp': data.get('timestamp', datetime.now().isoformat())
                            }
                            
                            results['subdomains'].append(subdomain_info)
                            
                            # Collect IP addresses
                            for addr in data.get('addresses', []):
                                if 'ip' in addr:
                                    results['ip_addresses'].add(addr['ip'])
                            
                            # Collect data sources
                            if 'source' in data:
                                results['data_sources'].add(data['source'])
                                
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            self.logger.warning(f"Error parsing amass output: {e}")
        
        # Convert sets to lists for JSON serialization
        results['ip_addresses'] = list(results['ip_addresses'])
        results['data_sources'] = list(results['data_sources'])
        
        return results
    
    def _parse_amass_intel_output(self, output_file: Path, target: str) -> Dict:
        """Parse amass intel JSON output"""
        results = {
            'assets': [],
            'related_domains': set(),
            'network_blocks': set()
        }
        
        try:
            if not output_file.exists():
                return results
            
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        
                        asset_info = {
                            'domain': data.get('name', ''),
                            'type': data.get('type', 'domain'),
                            'source': data.get('source', 'unknown'),
                            'timestamp': data.get('timestamp', datetime.now().isoformat())
                        }
                        
                        # Add network information if available
                        if 'addresses' in data:
                            asset_info['addresses'] = data['addresses']
                            for addr in data['addresses']:
                                if 'cidr' in addr:
                                    results['network_blocks'].add(addr['cidr'])
                        
                        results['assets'].append(asset_info)
                        
                        # Collect related domains
                        if 'name' in data and data['name']:
                            results['related_domains'].add(data['name'])
                            
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            self.logger.warning(f"Error parsing amass intel output: {e}")
        
        # Convert sets to lists
        results['related_domains'] = list(results['related_domains'])
        results['network_blocks'] = list(results['network_blocks'])
        
        return results
    
    def _create_error_result(self, error: str) -> Dict:
        """Create standardized error result"""
        return {
            'status': 'error',
            'error': error,
            'target': '',
            'scan_type': 'amass_scan',
            'timestamp': datetime.now().isoformat(),
            'subdomains': [],
            'summary': {'total_subdomains': 0}
        }
    
    def quick_passive_scan(self, domain: str) -> Dict:
        """Convenience method for quick passive scan"""
        scan_params = {
            'scan_type': 'passive',
            'timeout': 120,
            'max_dns_queries': 5000
        }
        return self.scan(domain, scan_params)
    
    def deep_enumeration(self, domain: str) -> Dict:
        """Convenience method for deep enumeration"""
        scan_params = {
            'scan_type': 'comprehensive',
            'timeout': 600,
            'brute_force': True,
            'max_dns_queries': 50000
        }
        return self.scan(domain, scan_params)
