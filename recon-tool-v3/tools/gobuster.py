#!/usr/bin/env python3
"""
Gobuster Directory Scanner - Optimized for Fast Directory Discovery
Fast directory and file brute-forcing using Gobuster
Specialized for: Quick directory enumeration, common file discovery, basic web content discovery
"""

import re
from datetime import datetime
from typing import Dict, List

from .base import BaseTool

class GobusterScanner(BaseTool):
    """Optimized Gobuster for fast directory and file enumeration"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.command_name = "gobuster"
        self.specialization = "fast_directory_discovery"
        self.wordlists = {
            'common': '/usr/share/wordlists/dirb/common.txt',
            'medium': '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
            'quick': '/usr/share/wordlists/dirb/small.txt'
        }
    
    def scan(self, target: str, scan_params: Dict) -> Dict:
        """Execute fast gobuster scan focused on directory discovery"""
        self.start_time = datetime.now()
        
        try:
            self.logger.info(f"🔧 Starting GobusterScanner FAST directory discovery against {target}")
            
            if not self.verify_installation():
                return self._create_error_result("Gobuster not installed")
            
            # Fast-focused command building
            cmd = ['gobuster', 'dir', '-u', target]
            
            # Optimize for speed
            wordlist = scan_params.get('wordlist', self.wordlists['quick'])  # Default to quick wordlist
            cmd.extend(['-w', wordlist])
            
            # Fast scan optimizations
            threads = scan_params.get('threads', 50)  # High thread count for speed
            cmd.extend(['-t', str(threads)])
            
            # Quick timeout for fast scanning
            timeout_val = scan_params.get('timeout', 10)
            cmd.extend(['--timeout', f'{timeout_val}s'])
            
            # Add status codes for directories and files
            status_codes = scan_params.get('status_codes', '200,204,301,302,307,401,403')
            cmd.extend(['-s', status_codes])
            
            # Add extensions for file discovery
            if extensions := scan_params.get('extensions'):
                cmd.extend(['-x', extensions])
            elif scan_params.get('include_files', True):
                cmd.extend(['-x', 'php,html,js,txt,xml,json'])  # Common file extensions
            
            # Execute with optimized timeout for fast scanning
            result = self.execute_command(cmd, timeout=180)  # 3 minute max for fast discovery
            if result.returncode not in [0, 1]:
                return self._create_error_result(f"Gobuster scan failed: {result.stderr}")
            
            # Fast-focused parsing
            findings = self._parse_fast_output(result.stdout, target)
            self.save_raw_output(result.stdout, target, 'txt')
            
            duration = (datetime.now() - self.start_time).total_seconds()
            directory_count = len([f for f in findings if f.get('type') == 'directory'])
            file_count = len([f for f in findings if f.get('type') == 'file'])
            
            self.logger.info(f"✅ GobusterScanner FAST discovery completed in {duration:.1f}s - {directory_count} directories, {file_count} files")
            
            return {
                'status': 'success',
                'target': target,
                'scan_type': 'gobuster_fast_directory',
                'specialization': 'fast_directory_discovery',
                'duration': duration,
                'findings': findings,
                'summary': {
                    'total_findings': len(findings),
                    'directories_found': directory_count,
                    'files_found': file_count,
                    'optimization': 'Fast directory enumeration with common wordlists'
                }
            }
            
        except Exception as e:
            self.logger.error(f"❌ GobusterScanner error: {e}")
            return self._create_error_result(str(e))
    
    def _parse_fast_output(self, output: str, target: str) -> List[Dict]:
        """Parse gobuster output with focus on fast discovery"""
        findings = []
        
        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('=') or 'Gobuster' in line:
                continue
            
            # Pattern: /path (Status: 200) [Size: 1234]
            if match := re.search(r'(/.+?)\s+\(Status:\s+(\d+)\)(?:\s+\[Size:\s+(\d+)\])?', line):
                path, status_code, size = match.groups()
                
                # Determine type based on path
                finding_type = 'directory' if path.endswith('/') else 'file'
                
                finding = {
                    'type': finding_type,
                    'path': path,
                    'url': f"{target.rstrip('/')}{path}",
                    'status_code': int(status_code),
                    'method': 'GET',
                    'source': 'gobuster_fast',
                    'risk_level': self._assess_fast_risk(path, status_code),
                    'details': f"Fast directory discovery - {finding_type}"
                }
                
                if size:
                    finding['size'] = int(size)
                
                findings.append(finding)
        
        return findings
    
    def _assess_fast_risk(self, path: str, status_code: str) -> str:
        """Quick risk assessment for fast scanning"""
        status_int = int(status_code)
        
        # High risk paths for quick identification
        high_risk_paths = ['/admin', '/backup', '/config', '/database', '/db', '/test', '/dev']
        if any(risk_path in path.lower() for risk_path in high_risk_paths):
            return 'HIGH'
        
        # Medium risk for accessible content
        if status_int in [200, 301, 302]:
            return 'MEDIUM'
        
        # Low risk for protected/forbidden
        if status_int in [401, 403]:
            return 'LOW'
        
        return 'INFO'
    
    def verify_installation(self) -> bool:
        """Verify gobuster installation"""
        try:
            result = self.execute_command(['gobuster', 'version'], timeout=10)
            return result.returncode == 0
        except Exception:
            return False

import re
from datetime import datetime
from typing import Dict, List

from .base import BaseTool

class GobusterScanner(BaseTool):
    """Real Gobuster directory/file scanner implementation"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.command_name = "gobuster"
        self.wordlists = {
            'common': '/usr/share/wordlists/dirb/common.txt',
            'medium': '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
        }
    
    def scan(self, target: str, scan_params: Dict) -> Dict:
        """Execute gobuster scan against target"""
        self.start_time = datetime.now()
        
        try:
            self.logger.info(f"🔧 Starting GobusterScanner scan against {target}")
            
            if not self.verify_installation():
                return self._create_error_result("Gobuster not installed")
            
            # Unified command building
            scan_type = scan_params.get('scan_type', 'dir')
            cmd = self._build_command(target, scan_type, scan_params)
            
            # Execute scan
            if (result := self.execute_command(cmd, timeout=600)).returncode != 0:
                return self._create_error_result(f"Gobuster {scan_type} scan failed: {result.stderr}")
            
            # Parse results based on type
            results = self._parse_output(result.stdout, target, scan_type)
            self.save_raw_output(result.stdout, target, 'txt')
            
            duration = (datetime.now() - self.start_time).total_seconds()
            self.logger.info(f"✅ GobusterScanner completed in {duration:.1f}s")
            
            return self._build_result(target, scan_type, results, duration)
                
        except Exception as e:
            self.logger.error(f"❌ GobusterScanner error: {e}")
            return self._create_error_result(str(e))
    
    def _build_command(self, target: str, scan_type: str, params: Dict) -> List[str]:
        """Build unified gobuster command"""
        cmd_map = {
            'dir': ['gobuster', 'dir', '-u', target, '-x', ','.join(params.get('extensions', ['php', 'html']))],
            'dns': ['gobuster', 'dns', '-d', target],
            'vhost': ['gobuster', 'vhost', '-u', target]
        }
        
        cmd = cmd_map.get(scan_type, cmd_map['dir'])
        wordlist = self.wordlists.get(params.get('wordlist', 'common'), '/usr/share/wordlists/dirb/common.txt')
        cmd.extend(['-w', wordlist, '-t', str(params.get('threads', 10)), '-q'])
        
        return cmd
    
    def _parse_output(self, output: str, target: str, scan_type: str) -> Dict:
        """Parse gobuster output based on scan type"""
        results = {'items': [], 'count': 0}
        
        for line in output.strip().split('\n'):
            if not (line := line.strip()) or line.startswith('='):
                continue
                
            if scan_type == 'dir' and '(Status:' in line:
                if match := re.search(r'^(.*?)\s+\(Status:\s*(\d+)\)', line):
                    path, status = match.groups()
                    results['items'].append({
                        'path': path,
                        'status_code': int(status),
                        'url': f"{target.rstrip('/')}{path}"
                    })
            elif scan_type in ['dns', 'vhost'] and 'Found:' in line:
                if found := line.split('Found:')[1].strip():
                    results['items'].append({'found': found.split()[0]})
        
        results['count'] = len(results['items'])
        return results
    
    def _build_result(self, target: str, scan_type: str, results: Dict, duration: float) -> Dict:
        """Build unified result structure"""
        return {
            'status': 'success',
            'target': target,
            'scan_type': f'gobuster_{scan_type}_scan',
            'duration': duration,
            'summary': {'total_found': results['count']},
            **{f"{scan_type}s" if scan_type == 'dir' else scan_type: results['items']}
        }
    
    def _create_error_result(self, error: str) -> Dict:
        """Create standardized error result"""
        return {
            'status': 'error',
            'error': error,
            'target': '',
            'scan_type': 'gobuster_scan',
            'summary': {'total_found': 0}
        }
