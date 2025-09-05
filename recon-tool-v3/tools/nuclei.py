#!/usr/bin/env python3
"""
Nuclei Vulnerability Scanner - Real Implementation
Template-based vulnerability detection using Project Discovery's Nuclei
"""

import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from .base import BaseTool

class NucleiScanner(BaseTool):
    """Real Nuclei vulnerability scanner implementation"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        self.command_name = "nuclei"
        self.version = "3.0+"
        self.description = "Template-based vulnerability scanner"
        self.category = "security"
        
        # Nuclei-specific configuration
        self.templates_path = config.get('templates_path', '')
        self.severity_levels = ['info', 'low', 'medium', 'high', 'critical']
        self.default_templates = [
            'cves',
            'vulnerabilities',
            'misconfiguration',
            'technologies',
            'exposures'
        ]
        self.concurrency = config.get('concurrency', 25)
        self.timeout = config.get('timeout', 5)
        self.retries = config.get('retries', 1)
    
    def scan(self, target: str, scan_params: Dict) -> Dict:
        """Execute nuclei vulnerability scan against target"""
        self.start_time = datetime.now()
        
        try:
            self.logger.info(f"🔧 Starting NucleiScanner scan against {target}")
            
            # Verify tool installation
            if not self.verify_installation():
                return self._create_error_result("Nuclei not installed")
            
            # Build nuclei command
            cmd = self._build_nuclei_command(target, scan_params)
            
            # Execute nuclei scan
            result = self.execute_command(cmd, timeout=300)  # 5 minute timeout
            
            if result.returncode != 0:
                return self._create_error_result(f"Nuclei execution failed: {result.stderr}")
            
            # Parse results
            results = self._parse_nuclei_output(result.stdout, target)
            
            # Save raw output
            self.save_raw_output(result.stdout, target, 'json')
            
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            
            # Log findings summary
            finding_count = len(results.get('vulnerabilities', []))
            if finding_count > 0:
                severities = {}
                for vuln in results.get('vulnerabilities', []):
                    sev = vuln.get('severity', 'unknown')
                    severities[sev] = severities.get(sev, 0) + 1
                
                severity_summary = ', '.join([f"{count} {sev}" for sev, count in severities.items()])
                self.logger.info(f"ℹ️ [NucleiScanner] vulnerabilities: Found {finding_count} issues ({severity_summary})")
            else:
                self.logger.info(f"ℹ️ [NucleiScanner] vulnerabilities: No vulnerabilities found")
            
            self.logger.info(f"✅ NucleiScanner completed in {duration:.1f}s")
            
            return {
                'status': 'success',
                'target': target,
                'scan_type': 'nuclei_vulnerability_scan',
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat(),
                'duration': duration,
                'vulnerabilities': results.get('vulnerabilities', []),
                'summary': {
                    'total_findings': finding_count,
                    'severity_breakdown': severities if finding_count > 0 else {},
                    'templates_used': results.get('templates_used', []),
                    'scan_stats': results.get('scan_stats', {})
                },
                'raw_output_file': results.get('raw_output_file', None)
            }
            
        except Exception as e:
            self.logger.error(f"❌ NucleiScanner error: {e}")
            return self._create_error_result(str(e))
    
    def _create_error_result(self, error: str) -> Dict:
        """Create standardized error result"""
        return {
            'status': 'error',
            'error': error,
            'target': '',
            'scan_type': 'nuclei_vulnerability_scan',
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'summary': {'total_findings': 0}
        }
    
    def custom_template_scan(self, target: str, template_path: str) -> Dict:
        """Scan with custom template file or directory"""
        scan_params = {
            'custom_templates': template_path
        }
        return self.scan(target, scan_params)
    
    def _save_raw_output(self, output: str, target: str, tool_name: str) -> Optional[str]:
        """Save raw output to file"""
        try:
            output_dir = Path('results') / 'raw_output'
            output_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            safe_target = target.replace('/', '_').replace(':', '_').replace('.', '_')
            filename = f"{tool_name}_{safe_target}_{timestamp}.json"
            filepath = output_dir / filename
            
            with open(filepath, 'w') as f:
                f.write(output)
            
            self.logger.debug(f"💾 Raw output saved: {filepath}")
            return str(filepath)
            
        except Exception as e:
            self.logger.error(f"❌ Failed to save raw output: {e}")
            return None
    
    def _create_error_result(self, error: str) -> Dict:
        """Create standardized error result"""
        return {
            'status': 'error',
            'error': error,
            'target': '',
            'scan_type': 'nuclei_vulnerability_scan',
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'summary': {'total_findings': 0}
        }
    
    def _build_nuclei_command(self, target, scan_params):
        """Build nuclei command based on parameters"""
        cmd = ["nuclei", "-target", target, "-j"]  # Use -j for JSONL output
        
        template = scan_params.get('template')
        severity = scan_params.get('severity')
        limit = scan_params.get('limit')
        
        if template:
            cmd.extend(["-t", template])
        if severity:
            cmd.extend(["-s", severity])
        if limit:
            cmd.extend(["-rl", str(limit)])  # Rate limit
            
        return cmd
    
    def _parse_nuclei_output(self, output: str, target: str) -> Dict:
        """Parse nuclei JSON output"""
        vulnerabilities = []
        templates_used = set()
        scan_stats = {
            'total_requests': 0,
            'templates_loaded': 0,
            'targets_scanned': 1
        }
        
        try:
            lines = output.strip().split('\n')
            for line in lines:
                if not line.strip():
                    continue
                    
                try:
                    finding = json.loads(line)
                    
                    # Extract vulnerability information
                    vuln_data = {
                        'template_id': finding.get('template-id', 'unknown'),
                        'template_name': finding.get('info', {}).get('name', 'Unknown'),
                        'severity': finding.get('info', {}).get('severity', 'info'),
                        'description': finding.get('info', {}).get('description', ''),
                        'reference': finding.get('info', {}).get('reference', []),
                        'classification': finding.get('info', {}).get('classification', {}),
                        'target': finding.get('host', target),
                        'matched_at': finding.get('matched-at', ''),
                        'matcher_name': finding.get('matcher-name', ''),
                        'extracted_results': finding.get('extracted-results', []),
                        'curl_command': finding.get('curl-command', ''),
                        'timestamp': finding.get('timestamp', datetime.now().isoformat()),
                        'metadata': {
                            'template_path': finding.get('template-path', ''),
                            'template_url': finding.get('template-url', ''),
                            'matcher_status': finding.get('matcher-status', False),
                            'matched_line': finding.get('matched-line', ''),
                        }
                    }
                    
                    vulnerabilities.append(vuln_data)
                    templates_used.add(finding.get('template-id', 'unknown'))
                    
                except json.JSONDecodeError:
                    # Handle non-JSON lines (might be statistics or errors)
                    if 'Templates loaded' in line:
                        # Try to extract template count
                        try:
                            import re
                            match = re.search(r'(\d+)', line)
                            if match:
                                scan_stats['templates_loaded'] = int(match.group(1))
                        except:
                            pass
                    continue
                    
        except Exception as e:
            self.logger.warning(f"⚠️ Error parsing nuclei output: {e}")
        
        return {
            'vulnerabilities': vulnerabilities,
            'templates_used': list(templates_used),
            'scan_stats': scan_stats
        }
    
    def vulnerability_scan(self, target: str, severity: str = 'medium,high,critical') -> Dict:
        """Convenience method for vulnerability scanning"""
        scan_params = {
            'severity': severity,
            'templates': ['cves', 'vulnerabilities', 'misconfiguration']
        }
        return self.scan(target, scan_params)
    
    def technology_detection(self, target: str) -> Dict:
        """Scan for technology detection and fingerprinting"""
        scan_params = {
            'severity': 'info',
            'templates': ['technologies', 'fingerprinting']
        }
        return self.scan(target, scan_params)
    
    def cve_scan(self, target: str) -> Dict:
        """Focused CVE scanning"""
        scan_params = {
            'severity': 'medium,high,critical',
            'templates': ['cves']
        }
        return self.scan(target, scan_params)
    
    def custom_template_scan(self, target: str, template_path: str) -> Dict:
        """Scan with custom template file or directory"""
        scan_params = {
            'custom_templates': template_path
        }
        return self.scan(target, scan_params)
