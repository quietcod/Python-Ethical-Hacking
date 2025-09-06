#!/usr/bin/env python3
"""
Dirb Directory Scanner - Real Implementation
Traditional directory and file brute forcing using dirb
"""

import re
from datetime import datetime
from typing import Dict, List

from .base import BaseTool

class DirbScanner(BaseTool):
    """Real Dirb directory scanner implementation"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.command_name = "dirb"
    
    def scan(self, target: str, scan_params: Dict) -> Dict:
        """Execute dirb scan against target"""
        self.start_time = datetime.now()
        
        try:
            self.logger.info(f"🔧 Starting DirbScanner scan against {target}")
            
            if not self.verify_installation():
                return self._create_error_result("Dirb not installed")
            
            # Unified command building
            wordlist = scan_params.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
            cmd = ['dirb', target, wordlist, '-S', '-w']  # -S = silent, -w = don't stop on warning
            
            # Add extensions
            if extensions := scan_params.get('extensions'):
                cmd.extend(['-X', ','.join(extensions)])
            
            # Add recursion option
            if scan_params.get('recursive'):
                cmd.append('-r')
            
            # Execute with walrus operator
            if (result := self.execute_command(cmd, timeout=600)).returncode not in [0, 1]:
                return self._create_error_result(f"Dirb scan failed: {result.stderr}")
            
            # Parse and build results
            directories = self._parse_output(result.stdout, target)
            self.save_raw_output(result.stdout, target, 'txt')
            
            duration = (datetime.now() - self.start_time).total_seconds()
            self.logger.info(f"✅ DirbScanner completed in {duration:.1f}s - {len(directories)} directories")
            
            return {
                'status': 'success',
                'target': target,
                'scan_type': 'dirb_directory_scan',
                'duration': duration,
                'directories': directories,
                'summary': {'total_found': len(directories)}
            }
            
        except Exception as e:
            self.logger.error(f"❌ DirbScanner error: {e}")
            return self._create_error_result(str(e))
    
    def _parse_output(self, output: str, target: str) -> List[Dict]:
        """Parse dirb output with unified approach"""
        directories = []
        
        for line in output.strip().split('\n'):
            # Parse dirb output format: ==> DIRECTORY: http://example.com/admin/
            # Or: + http://example.com/admin.php (CODE:200|SIZE:1234)
            if line.startswith('==> DIRECTORY:'):
                directory_url = line.replace('==> DIRECTORY:', '').strip()
                directories.append({
                    'type': 'directory',
                    'url': directory_url,
                    'path': directory_url.replace(target, ''),
                    'found_at': datetime.now().isoformat()
                })
            elif line.startswith('+ ') and '(CODE:' in line:
                # Extract URL and response code
                if match := re.search(r'\+ (.+?) \(CODE:(\d+)\|SIZE:(\d+)\)', line):
                    url, code, size = match.groups()
                    directories.append({
                        'type': 'file',
                        'url': url.strip(),
                        'path': url.replace(target, ''),
                        'status_code': int(code),
                        'size': int(size),
                        'found_at': datetime.now().isoformat()
                    })
        
        return directories
    
    def _create_error_result(self, error: str) -> Dict:
        """Create standardized error result"""
        return {
            'status': 'error',
            'error': error,
            'target': '',
            'scan_type': 'dirb_directory_scan',
            'directories': [],
            'summary': {'total_found': 0}
        }
