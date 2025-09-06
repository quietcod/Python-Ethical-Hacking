#!/usr/bin/env python3
"""
SSLScan SSL/TLS Analysis - Optimized for Speed
Fast SSL/TLS cipher enumeration and basic security assessment
Specialized for: Quick SSL scanning, cipher identification, basic protocol analysis
"""

import re
from datetime import datetime
from typing import Dict, List

from .base import BaseTool

class SSLScanner(BaseTool):
    """Optimized SSLScan for fast SSL/TLS cipher and protocol analysis"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.command_name = "sslscan"
        self.specialization = "fast_ssl_enumeration"
    
    def scan(self, target: str, scan_params: Dict) -> Dict:
        """Execute fast sslscan focused on cipher enumeration and basic analysis"""
        self.start_time = datetime.now()
        
        try:
            self.logger.info(f"🔧 Starting SSLScanner FAST cipher analysis against {target}")
            
            if not self.verify_installation():
                return self._create_error_result("SSLScan not installed")
            
            # Optimized command for speed - focus on essential SSL data
            cmd = ['sslscan', '--xml=-', '--no-check-certificate', target]
            
            # Add port if specified
            if ':' not in target and (port := scan_params.get('port')):
                cmd[-1] = f"{target}:{port}"
            
            # Fast mode - skip detailed analysis if requested
            if scan_params.get('fast_mode', True):
                cmd.append('--no-compression')
                cmd.append('--no-heartbleed')
            
            # Execute with walrus operator - shorter timeout for speed
            if (result := self.execute_command(cmd, timeout=60)).returncode not in [0, 1]:
                return self._create_error_result(f"SSLScan failed: {result.stderr}")
            
            # Parse and build results - focused on cipher analysis
            ssl_analysis = self._parse_cipher_focused_output(result.stdout, target)
            self.save_raw_output(result.stdout, target, 'xml')
            
            duration = (datetime.now() - self.start_time).total_seconds()
            cipher_count = len(ssl_analysis.get('ciphers', []))
            self.logger.info(f"✅ SSLScanner FAST completed in {duration:.1f}s - {cipher_count} ciphers analyzed")
            
            return {
                'status': 'success',
                'target': target,
                'scan_type': 'sslscan_fast_cipher_analysis',
                'specialization': 'cipher_enumeration',
                'duration': duration,
                'ssl_analysis': ssl_analysis,
                'summary': {
                    'total_ciphers': cipher_count,
                    'weak_ciphers': len([c for c in ssl_analysis.get('ciphers', []) if c.get('strength') == 'weak']),
                    'supported_protocols': len(ssl_analysis.get('protocols', []))
                }
            }
            
        except Exception as e:
            self.logger.error(f"❌ SSLScanner error: {e}")
            return self._create_error_result(str(e))
    
    def _parse_cipher_focused_output(self, output: str, target: str) -> Dict:
        """Parse sslscan output focused on cipher enumeration and basic SSL info"""
        ssl_analysis = {
            'target': target,
            'protocols': [],
            'ciphers': [],
            'basic_certificate': {},
            'scan_focus': 'cipher_enumeration'
        }
        
        # Parse supported protocols - quick identification
        for line in output.split('\n'):
            if 'Enabled' in line and ('TLS' in line or 'SSL' in line):
                if match := re.search(r'(SSL|TLS)v?(\d+\.?\d*)', line):
                    protocol = f"{match.group(1)}v{match.group(2)}"
                    ssl_analysis['protocols'].append({
                        'protocol': protocol,
                        'status': 'enabled'
                    })
            
            # Parse ciphers - focus on cipher strength classification
            elif 'Accepted' in line and 'bits' in line:
                if match := re.search(r'(\S+)\s+(\d+)\s+bits', line):
                    cipher_name, bits = match.groups()
                    bits = int(bits)
                    
                    # Classify cipher strength for quick assessment
                    if bits < 128:
                        strength = 'weak'
                        risk_level = 'high'
                    elif bits < 256:
                        strength = 'medium'
                        risk_level = 'medium'
                    else:
                        strength = 'strong'
                        risk_level = 'low'
                    
                    ssl_analysis['ciphers'].append({
                        'name': cipher_name,
                        'bits': bits,
                        'strength': strength,
                        'risk_level': risk_level
                    })
            
            # Basic certificate info only - no deep analysis
            elif 'Subject:' in line:
                ssl_analysis['basic_certificate']['subject'] = line.split('Subject:')[1].strip()
            elif 'Issuer:' in line:
                ssl_analysis['basic_certificate']['issuer'] = line.split('Issuer:')[1].strip()
        
        return ssl_analysis
    
    def _create_error_result(self, error: str) -> Dict:
        """Create standardized error result"""
        return {
            'status': 'error',
            'error': error,
            'target': '',
            'scan_type': 'sslscan_fast_cipher_analysis',
            'ssl_analysis': {},
            'summary': {'total_ciphers': 0}
        }
