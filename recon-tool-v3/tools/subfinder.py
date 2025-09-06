#!/usr/bin/env python3
"""
Subfinder Scanner - Real Implementation
Fast passive subdomain discovery using Project Discovery's subfinder
"""

import re
from datetime import datetime
from typing import Dict, List

from .base import BaseTool

class SubfinderScanner(BaseTool):
    """Real Subfinder passive subdomain discovery implementation"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.command_name = "subfinder"
        
    #!/usr/bin/env python3
"""
Subfinder Scanner - Optimized for Fast Passive Subdomain Discovery
Fast passive subdomain enumeration using Project Discovery's subfinder
Specialized for: Speed-focused passive subdomain discovery, API-based enumeration, quick reconnaissance
"""

import re
from datetime import datetime
from typing import Dict, List

from .base import BaseTool

class SubfinderScanner(BaseTool):
    """Optimized Subfinder for fast passive subdomain discovery"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.command_name = "subfinder"
        self.specialization = "fast_passive_subdomains"
        
    def scan(self, domain: str, scan_params: Dict) -> Dict:
        """Execute fast subfinder passive subdomain discovery"""
        self.start_time = datetime.now()
        
        try:
            self.logger.info(f"🔧 Starting SubfinderScanner FAST passive discovery against {domain}")
            
            if not self.verify_installation():
                return self._create_error_result("Subfinder not installed")
            
            # Fast passive discovery command
            cmd = ['subfinder', '-d', domain]
            
            # Speed optimizations
            cmd.extend(['-t', str(scan_params.get('threads', 50))])  # High thread count for speed
            cmd.extend(['-timeout', str(scan_params.get('timeout', 30))])  # Quick timeout
            
            # Output format for easy parsing
            cmd.extend(['-o', '/dev/stdout'])  # Output to stdout
            cmd.append('-silent')  # Reduce noise for faster processing
            
            # Optional: All sources for comprehensive passive discovery
            if scan_params.get('all_sources', True):
                cmd.append('-all')
            
            # Optional: Recursive subdomain discovery (if time allows)
            if scan_params.get('recursive', False):
                cmd.append('-recursive')
            
            # Execute with optimized timeout for fast discovery
            result = self.execute_command(cmd, timeout=120)  # 2 minutes max for fast discovery
            if result.returncode not in [0, 1]:
                return self._create_error_result(f"Subfinder scan failed: {result.stderr}")
            
            # Fast parsing focused on subdomain collection
            findings = self._parse_fast_output(result.stdout, domain)
            self.save_raw_output(result.stdout, domain, 'txt')
            
            duration = (datetime.now() - self.start_time).total_seconds()
            subdomain_count = len(findings)
            
            self.logger.info(f"✅ SubfinderScanner FAST passive discovery completed in {duration:.1f}s - {subdomain_count} subdomains")
            
            return {
                'status': 'success',
                'target': domain,
                'scan_type': 'subfinder_fast_passive',
                'specialization': 'fast_passive_subdomains',
                'duration': duration,
                'findings': findings,
                'summary': {
                    'total_findings': len(findings),
                    'subdomains_found': subdomain_count,
                    'optimization': 'Fast passive subdomain discovery with API sources'
                }
            }
            
        except Exception as e:
            self.logger.error(f"❌ SubfinderScanner error: {e}")
            return self._create_error_result(str(e))
    
    def _parse_fast_output(self, output: str, domain: str) -> List[Dict]:
        """Parse subfinder output optimized for fast processing"""
        findings = []
        seen_subdomains = set()
        
        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('[') or line.startswith('*'):
                continue
            
            # Clean subdomain extraction
            subdomain = line.strip()
            if subdomain and subdomain not in seen_subdomains:
                seen_subdomains.add(subdomain)
                
                finding = {
                    'type': 'subdomain',
                    'subdomain': subdomain,
                    'domain': domain,
                    'source': 'subfinder_passive',
                    'method': 'passive_discovery',
                    'risk_level': self._assess_subdomain_risk(subdomain),
                    'details': 'Fast passive subdomain discovery'
                }
                
                findings.append(finding)
        
        return findings
    
    def _assess_subdomain_risk(self, subdomain: str) -> str:
        """Quick risk assessment for subdomains"""
        # High-interest subdomains for quick identification
        high_interest = ['admin', 'api', 'dev', 'test', 'staging', 'beta', 'internal', 'vpn', 'mail']
        medium_interest = ['www', 'blog', 'shop', 'support', 'ftp', 'db', 'database']
        
        subdomain_lower = subdomain.lower()
        
        if any(keyword in subdomain_lower for keyword in high_interest):
            return 'HIGH'
        elif any(keyword in subdomain_lower for keyword in medium_interest):
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def verify_installation(self) -> bool:
        """Verify subfinder installation"""
        try:
            result = self.execute_command(['subfinder', '-version'], timeout=10)
            return result.returncode == 0
        except Exception:
            return False
    
    def _parse_output(self, output: str, domain: str) -> List[Dict]:
        """Parse subfinder output with unified approach"""
        subdomains = []
        unique_subs = set()
        
        for line in output.strip().split('\n'):
            if (line := line.strip()) and '.' in line and line not in unique_subs:
                unique_subs.add(line)
                subdomains.append({
                    'subdomain': line,
                    'source': 'subfinder',
                    'found_at': datetime.now().isoformat(),
                    'input': domain
                })
        
        return subdomains
    
    def _create_error_result(self, error: str) -> Dict:
        """Create standardized error result"""
        return {
            'status': 'error',
            'error': error,
            'target': '',
            'scan_type': 'subfinder_scan',
            'subdomains': [],
            'summary': {'total_found': 0}
        }
