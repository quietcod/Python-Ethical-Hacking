#!/usr/bin/env python3
"""
Aquatone Screenshot Tool - Real Implementation
Web application visual reconnaissance and screenshot capture
"""

import re
import json
import os
from datetime import datetime
from typing import Dict, List

from .base import BaseTool

class AquatoneScreenshot(BaseTool):
    """Real Aquatone screenshot implementation"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.command_name = "aquatone"
    
    def scan(self, targets: str, scan_params: Dict) -> Dict:
        """Execute aquatone screenshot capture"""
        self.start_time = datetime.now()
        
        try:
            self.logger.info(f"🔧 Starting AquatoneScreenshot for targets")
            
            if not self.verify_installation():
                return self._create_error_result("aquatone not installed")
            
            # Prepare targets file
            targets_file = f"/tmp/aquatone_targets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(targets_file, 'w') as f:
                f.write(targets)
            
            # Unified command building
            scan_type = scan_params.get('scan_type', 'screenshot')
            cmd_map = {
                'screenshot': ['aquatone', '-chrome-path', '/usr/bin/google-chrome'],
                'ports': ['aquatone', '-ports', 'xlarge'],
                'scan': ['aquatone', '-scan-timeout', '300']
            }
            
            cmd = cmd_map.get(scan_type, cmd_map['screenshot'])
            
            # Add options
            if scan_params.get('ports'):
                cmd.extend(['-ports', scan_params['ports']])
            if scan_params.get('timeout'):
                cmd.extend(['-scan-timeout', str(scan_params['timeout'])])
            if scan_params.get('resolution'):
                cmd.extend(['-resolution', scan_params['resolution']])
            
            # Execute with walrus operator
            if (result := self.execute_command(cmd, stdin=targets, timeout=600)).returncode != 0:
                return self._create_error_result(f"Aquatone scan failed: {result.stderr}")
            
            # Parse and build results
            screenshot_data = self._parse_output(result.stdout)
            self.save_raw_output(result.stdout, 'aquatone_results', 'txt')
            
            duration = (datetime.now() - self.start_time).total_seconds()
            screenshot_count = len(screenshot_data.get('screenshots', []))
            self.logger.info(f"✅ AquatoneScreenshot completed in {duration:.1f}s - {screenshot_count} screenshots")
            
            return {
                'status': 'success',
                'targets': targets,
                'scan_type': 'aquatone_screenshot',
                'duration': duration,
                'screenshot_data': screenshot_data,
                'summary': {
                    'screenshots_captured': screenshot_count,
                    'responsive_targets': len([s for s in screenshot_data.get('screenshots', []) if s.get('responsive')])
                }
            }
            
        except Exception as e:
            self.logger.error(f"❌ AquatoneScreenshot error: {e}")
            return self._create_error_result(str(e))
        finally:
            # Cleanup temp file
            if 'targets_file' in locals() and os.path.exists(targets_file):
                os.remove(targets_file)
    
    def _parse_output(self, output: str) -> Dict:
        """Parse aquatone output with unified approach"""
        screenshot_data = {
            'screenshots': [],
            'responsive_hosts': [],
            'technologies': []
        }
        
        for line in output.strip().split('\n'):
            line = line.strip()
            
            # Parse screenshot captures
            if 'screenshot saved to' in line.lower():
                if match := re.search(r'(\S+):(\d+)\s+.*screenshot saved to\s+(\S+)', line):
                    screenshot_data['screenshots'].append({
                        'host': match.group(1),
                        'port': int(match.group(2)),
                        'screenshot_path': match.group(3),
                        'responsive': True,
                        'captured_at': datetime.now().isoformat()
                    })
            
            # Parse responsive hosts
            elif 'responsive' in line.lower() and '200' in line:
                if match := re.search(r'(\S+):(\d+)', line):
                    screenshot_data['responsive_hosts'].append({
                        'host': match.group(1),
                        'port': int(match.group(2)),
                        'status': 'responsive'
                    })
            
            # Parse technology detection
            elif 'tech:' in line.lower():
                if match := re.search(r'tech:\s*(\S+)', line):
                    screenshot_data['technologies'].append({
                        'technology': match.group(1),
                        'detected_at': datetime.now().isoformat()
                    })
        
        return screenshot_data
    
    def _create_error_result(self, error: str) -> Dict:
        """Create standardized error result"""
        return {
            'status': 'error',
            'error': error,
            'targets': '',
            'scan_type': 'aquatone_screenshot',
            'screenshot_data': {},
            'summary': {'screenshots_captured': 0}
        }
