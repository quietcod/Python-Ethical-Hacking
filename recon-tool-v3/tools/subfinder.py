#!/usr/bin/env python3
"""
Subfinder Scanner - Real Implementation
Fast passive subdomain discovery using Project Discovery's subfinder
"""

import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from .base import BaseTool

class SubfinderScanner(BaseTool):
    """Real Subfinder passive subdomain discovery implementation"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.command_name = "subfinder"
        self.version = "v2.8.0+"
        self.description = "Fast passive subdomain discovery"
        self.category = "subdomain"
        
        # Subfinder-specific configuration
        self.max_enumerating_time = config.get('max_enumerating_time', 10)
        self.timeout = config.get('timeout', 30)
        self.threads = config.get('threads', 20)
        self.rate_limit = config.get('rate_limit', 100)
        self.verbose = config.get('verbose', False)
        
        # API sources configuration
        self.sources = config.get('sources', [
            'alienvault', 'anubis', 'bevigil', 'binaryedge', 'bufferover',
            'c99', 'censys', 'certspotter', 'chaos', 'chinaz', 'commoncrawl',
            'crtsh', 'dnsdb', 'dnsdumpster', 'fullhunt', 'github', 'hackertarget',
            'hunter', 'intelx', 'passivetotal', 'projectdiscovery', 'quake',
            'rapiddns', 'recondev', 'robtex', 'securitytrails', 'shodan',
            'spyse', 'sublist3r', 'threatbook', 'threatminer', 'urlscan',
            'virustotal', 'waybackarchive', 'whoisxmlapi', 'zoomeye'
        ])
        
        # Output configuration  
        self.output_format = config.get('output_format', 'json')
        self.include_sources = config.get('include_sources', True)
        self.include_ip = config.get('include_ip', False)
        
    def scan(self, domain: str, scan_params: Dict) -> Dict:
        """Execute subfinder scan against target domain"""
        self.start_time = datetime.now()
        
        try:
            self.logger.info(f"🔧 Starting SubfinderScanner scan against {domain}")
            
            # Verify tool installation
            if not self.verify_installation():
                return self._create_error_result("Subfinder not installed")
            
            # Determine scan type
            scan_type = scan_params.get('scan_type', 'passive')
            
            if scan_type == 'passive':
                return self._passive_enumeration(domain, scan_params)
            elif scan_type == 'source_specific':
                return self._source_specific_scan(domain, scan_params)
            elif scan_type == 'comprehensive':
                return self._comprehensive_scan(domain, scan_params)
            else:
                return self._create_error_result(f"Unknown scan type: {scan_type}")
                
        except Exception as e:
            self.logger.error(f"❌ SubfinderScanner error: {e}")
            return self._create_error_result(str(e))
    
    def _passive_enumeration(self, domain: str, scan_params: Dict) -> Dict:
        """Perform passive subdomain enumeration"""
        try:
            # Build subfinder command
            cmd = self._build_subfinder_command(domain, scan_params)
            
            # Execute subfinder scan
            result = self.execute_command(cmd, timeout=300)  # 5 minute timeout
            
            if result.returncode != 0:
                return self._create_error_result(f"Subfinder scan failed: {result.stderr}")
            
            # Parse results
            results = self._parse_subfinder_output(result.stdout, domain)
            
            # Save raw output
            self.save_raw_output(result.stdout, domain, 'txt')
            
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            
            # Log findings summary
            subdomain_count = len(results.get('subdomains', []))
            source_count = len(results.get('sources_used', []))
            self.logger.info(f"ℹ️ [SubfinderScanner] subdomains: Found {subdomain_count} subdomains from {source_count} sources")
            
            self.logger.info(f"✅ SubfinderScanner completed in {duration:.1f}s")
            
            return {
                'status': 'success',
                'target': domain,
                'scan_type': 'subfinder_passive_enum',
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat(),
                'duration': duration,
                'subdomains': results.get('subdomains', []),
                'summary': {
                    'total_found': subdomain_count,
                    'sources_used': results.get('sources_used', []),
                    'source_count': source_count,
                    'unique_subdomains': results.get('unique_subdomains', []),
                    'wildcard_detected': results.get('wildcard_detected', False)
                },
                'raw_output_file': results.get('raw_output_file', None)
            }
            
        except Exception as e:
            self.logger.error(f"❌ Passive enumeration error: {e}")
            return self._create_error_result(str(e))
    
    def _source_specific_scan(self, domain: str, scan_params: Dict) -> Dict:
        """Perform source-specific subdomain enumeration"""
        try:
            # Build command with specific sources
            cmd = self._build_subfinder_command(domain, scan_params)
            
            # Add source-specific parameters
            sources = scan_params.get('sources', ['crtsh', 'certspotter', 'threatcrowd'])
            if sources:
                cmd.extend(['-sources', ','.join(sources)])
            
            # Execute scan
            result = self.execute_command(cmd, timeout=180)
            
            if result.returncode != 0:
                return self._create_error_result(f"Source-specific scan failed: {result.stderr}")
            
            # Parse results
            results = self._parse_subfinder_output(result.stdout, domain)
            
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            
            subdomain_count = len(results.get('subdomains', []))
            self.logger.info(f"ℹ️ [SubfinderScanner] source-specific: Found {subdomain_count} subdomains")
            
            return {
                'status': 'success',
                'target': domain,
                'scan_type': 'subfinder_source_specific',
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat(),
                'duration': duration,
                'subdomains': results.get('subdomains', []),
                'summary': {
                    'total_found': subdomain_count,
                    'sources_requested': sources,
                    'sources_used': results.get('sources_used', [])
                }
            }
            
        except Exception as e:
            self.logger.error(f"❌ Source-specific scan error: {e}")
            return self._create_error_result(str(e))
    
    def _comprehensive_scan(self, domain: str, scan_params: Dict) -> Dict:
        """Perform comprehensive subdomain enumeration with all sources"""
        try:
            # Build comprehensive command
            cmd = self._build_subfinder_command(domain, scan_params)
            cmd.extend(['-all'])  # Use all available sources
            
            # Execute comprehensive scan
            result = self.execute_command(cmd, timeout=600)  # 10 minute timeout
            
            if result.returncode != 0:
                return self._create_error_result(f"Comprehensive scan failed: {result.stderr}")
            
            # Parse results
            results = self._parse_subfinder_output(result.stdout, domain)
            
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            
            subdomain_count = len(results.get('subdomains', []))
            source_count = len(results.get('sources_used', []))
            self.logger.info(f"ℹ️ [SubfinderScanner] comprehensive: Found {subdomain_count} subdomains from {source_count} sources")
            
            return {
                'status': 'success',
                'target': domain,
                'scan_type': 'subfinder_comprehensive',
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat(),
                'duration': duration,
                'subdomains': results.get('subdomains', []),
                'summary': {
                    'total_found': subdomain_count,
                    'sources_used': results.get('sources_used', []),
                    'source_count': source_count,
                    'comprehensive_mode': True
                }
            }
            
        except Exception as e:
            self.logger.error(f"❌ Comprehensive scan error: {e}")
            return self._create_error_result(str(e))
    
    def _build_subfinder_command(self, domain: str, scan_params: Dict) -> List[str]:
        """Build subfinder command based on parameters"""
        cmd = [self.command_name, '-d', domain]
        
        # Silent mode for clean output
        cmd.extend(['-silent'])
        
        # Performance options
        threads = scan_params.get('threads', self.threads)
        if threads:
            cmd.extend(['-t', str(threads)])
        
        timeout = scan_params.get('timeout', self.timeout)
        if timeout:
            cmd.extend(['-timeout', str(timeout)])
        
        rate_limit = scan_params.get('rate_limit', self.rate_limit)
        if rate_limit:
            cmd.extend(['-rate-limit', str(rate_limit)])
        
        # Max enumeration time
        max_time = scan_params.get('max_enumerating_time', self.max_enumerating_time)
        if max_time:
            cmd.extend(['-max-time', str(max_time)])
        
        return cmd
    
    def _parse_subfinder_output(self, output: str, domain: str) -> Dict:
        """Parse subfinder output"""
        subdomains = []
        sources_used = set()
        unique_subdomains = set()
        
        try:
            lines = output.strip().split('\n')
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Subfinder outputs plain subdomains, one per line
                if line and '.' in line and line not in unique_subdomains:
                    entry = {
                        'subdomain': line,
                        'source': 'mixed',  # Subfinder doesn't specify source in simple mode
                        'found_at': datetime.now().isoformat(),
                        'input': domain
                    }
                    subdomains.append(entry)
                    unique_subdomains.add(line)
                    sources_used.add('subfinder')
                        
        except Exception as e:
            self.logger.warning(f"⚠️ Error parsing subfinder output: {e}")
        
        return {
            'subdomains': subdomains,
            'sources_used': list(sources_used),
            'unique_subdomains': list(unique_subdomains),
            'wildcard_detected': self._detect_wildcard(unique_subdomains, domain)
        }
    
    def _detect_wildcard(self, subdomains: set, domain: str) -> bool:
        """Simple wildcard detection heuristic"""
        if len(subdomains) > 100:  # Too many subdomains might indicate wildcard
            return True
        return False
    
    def _create_error_result(self, error: str) -> Dict:
        """Create standardized error result"""
        return {
            'status': 'error',
            'error': error,
            'target': '',
            'scan_type': 'subfinder_scan',
            'timestamp': datetime.now().isoformat(),
            'subdomains': [],
            'summary': {'total_found': 0}
        }
    
    def passive_subdomain_enumeration(self, domain: str) -> Dict:
        """Convenience method for passive subdomain enumeration"""
        scan_params = {
            'scan_type': 'passive',
            'threads': 20,
            'timeout': 30,
            'verbose': False
        }
        return self.scan(domain, scan_params)
    
    def quick_scan(self, domain: str) -> Dict:
        """Convenience method for quick subdomain scan"""
        scan_params = {
            'scan_type': 'source_specific',
            'sources': ['crtsh', 'certspotter', 'threatcrowd', 'dnsdumpster'],
            'threads': 10,
            'timeout': 15
        }
        return self.scan(domain, scan_params)
    
    def comprehensive_scan(self, domain: str) -> Dict:
        """Convenience method for comprehensive subdomain scan"""
        scan_params = {
            'scan_type': 'comprehensive',
            'threads': 30,
            'timeout': 60,
            'include_ip': True,
            'recursive': True
        }
        return self.scan(domain, scan_params)
