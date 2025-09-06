#!/usr/bin/env python3
"""
Wfuzz Web Application Fuzzer - Optimized for Advanced Parameter Fuzzing
Advanced web application parameter discovery and vulnerability fuzzing
Specialized for: Parameter fuzzing, form analysis, injection testing, advanced web discovery
"""

import re
import json
from datetime import datetime
from typing import Dict, List

from .base import BaseTool

class WfuzzFuzzer(BaseTool):
    """Optimized Wfuzz for advanced web application parameter fuzzing and vulnerability testing"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.command_name = "wfuzz"
        self.specialization = "advanced_web_fuzzing"
    
    def scan(self, target: str, scan_params: Dict) -> Dict:
        """Execute advanced wfuzz parameter fuzzing and vulnerability analysis"""
        self.start_time = datetime.now()
        
        try:
            self.logger.info(f"🔧 Starting WfuzzFuzzer ADVANCED parameter analysis against {target}")
            
            if not self.verify_installation():
                return self._create_error_result("Wfuzz not installed")
            
            # Advanced fuzzing command building
            fuzzing_mode = scan_params.get('mode', 'parameter')
            
            # Specialized command maps for different fuzzing types
            cmd_map = {
                'parameter': ['wfuzz', '-c', '-z', 'file,/usr/share/wordlists/wfuzz/general/common.txt', 
                             '--hc', '404,403', f'{target}?FUZZ=test'],
                'post_parameter': ['wfuzz', '-c', '-z', 'file,/usr/share/wordlists/wfuzz/general/common.txt',
                                  '--hc', '404,403', '-d', 'FUZZ=test', target],
                'header_injection': ['wfuzz', '-c', '-z', 'file,/usr/share/wordlists/wfuzz/injections/All_attack.txt',
                                    '--hc', '404,403', '-H', 'X-Test: FUZZ', target],
                'sql_injection': ['wfuzz', '-c', '-z', 'file,/usr/share/wordlists/wfuzz/injections/SQL.txt',
                                 '--hc', '404,403', f'{target}?id=FUZZ'],
                'xss_testing': ['wfuzz', '-c', '-z', 'file,/usr/share/wordlists/wfuzz/injections/XSS.txt',
                               '--hc', '404,403', f'{target}?q=FUZZ']
            }
            
            cmd = cmd_map.get(fuzzing_mode, cmd_map['parameter'])
            
            # Add advanced options
            if threads := scan_params.get('threads', 20):
                cmd[1:1] = ['-t', str(threads)]  # Insert after wfuzz
                
            # Execute with extended timeout for comprehensive analysis
            result = self.execute_command(cmd, timeout=600)
            if result.returncode not in [0, 1]:
                return self._create_error_result(f"Wfuzz advanced scan failed: {result.stderr}")
            
            # Advanced parsing focused on vulnerability indicators
            findings = self._parse_advanced_output(result.stdout, target, fuzzing_mode)
            self.save_raw_output(result.stdout, target, 'txt')
            
            duration = (datetime.now() - self.start_time).total_seconds()
            param_count = len([f for f in findings if f.get('type') == 'parameter'])
            vuln_indicators = len([f for f in findings if f.get('risk_level') in ['HIGH', 'CRITICAL']])
            
            self.logger.info(f"✅ WfuzzFuzzer ADVANCED analysis completed in {duration:.1f}s - {param_count} parameters, {vuln_indicators} potential vulnerabilities")
            
            return {
                'status': 'success',
                'target': target,
                'scan_type': 'wfuzz_advanced_fuzzing',
                'specialization': 'advanced_web_fuzzing',
                'fuzzing_mode': fuzzing_mode,
                'duration': duration,
                'findings': findings,
                'summary': {
                    'total_findings': len(findings),
                    'parameters_found': param_count,
                    'vulnerability_indicators': vuln_indicators,
                    'optimization': 'Advanced parameter fuzzing and vulnerability testing'
                }
            }
            
        except Exception as e:
            self.logger.error(f"❌ WfuzzFuzzer error: {e}")
            return self._create_error_result(str(e))
    
    def _parse_advanced_output(self, output: str, target: str, mode: str) -> List[Dict]:
        """Parse wfuzz output with focus on vulnerability indicators and advanced analysis"""
        findings = []
        
        for line in output.split('\n'):
            line = line.strip()
            if not line or 'Target:' in line or '========' in line:
                continue
            
            # Pattern: ID   Response   Lines    Word     Chars       Payload
            if match := re.search(r'(\d+)\s+(\d+)\s+L\s+(\d+)\s+W\s+(\d+)\s+Ch\s+"(.+?)"', line):
                request_id, status_code, lines, words, chars, payload = match.groups()
                
                finding = {
                    'type': 'parameter' if mode in ['parameter', 'post_parameter'] else 'injection_test',
                    'payload': payload,
                    'status_code': int(status_code),
                    'response_length': int(chars),
                    'response_lines': int(lines),
                    'response_words': int(words),
                    'method': 'POST' if 'post' in mode else 'GET',
                    'source': f'wfuzz_advanced_{mode}',
                    'risk_level': self._assess_vulnerability_risk(status_code, chars, mode, payload),
                    'details': f"Advanced fuzzing - {mode} testing"
                }
                
                # Add specific details based on fuzzing mode
                if mode == 'sql_injection':
                    finding['vulnerability_type'] = 'SQL Injection'
                    finding['details'] += ' - SQL injection testing'
                elif mode == 'xss_testing':
                    finding['vulnerability_type'] = 'XSS'
                    finding['details'] += ' - XSS vulnerability testing'
                elif mode == 'header_injection':
                    finding['vulnerability_type'] = 'Header Injection'
                    finding['details'] += ' - HTTP header injection testing'
                
                findings.append(finding)
        
        return findings
    
    def _assess_vulnerability_risk(self, status_code: str, response_length: str, mode: str, payload: str) -> str:
        """Advanced risk assessment based on response characteristics and fuzzing mode"""
        status_int = int(status_code)
        length_int = int(response_length)
        
        # Critical indicators for injection testing
        if mode in ['sql_injection', 'xss_testing', 'header_injection']:
            # Look for error responses or unusual response lengths
            if status_int == 500:  # Internal server error
                return 'CRITICAL'
            if length_int > 10000:  # Very large response (possible error dump)
                return 'HIGH'
            if status_int == 200 and length_int > 1000:  # Successful but large response
                return 'HIGH'
        
        # Parameter discovery risk assessment
        if mode in ['parameter', 'post_parameter']:
            if status_int in [200, 302]:  # Successful parameter discovery
                return 'MEDIUM'
            if status_int == 500:  # Parameter caused error
                return 'HIGH'
        
        # Standard risk levels
        if status_int in [200, 301, 302]:
            return 'MEDIUM'
        elif status_int in [401, 403]:
            return 'LOW'
        
        return 'INFO'
    
    def verify_installation(self) -> bool:
        """Verify wfuzz installation"""
        try:
            result = self.execute_command(['wfuzz', '--version'], timeout=10)
            return result.returncode == 0
        except Exception:
            return False
    
    def _create_error_result(self, error: str) -> Dict:
        """Create standardized error result"""
        return {
            'status': 'error',
            'error': error,
            'target': '',
            'scan_type': 'wfuzz_advanced_fuzzing',
            'findings': [],
            'summary': {'total_findings': 0}
        }
