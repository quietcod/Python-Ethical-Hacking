"""
Report Manager for Recon-Tool-v3
Coordinates generation of HTML, PDF, and JSON reports
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Any, Optional

try:
    from .generators.html_generator import HTMLReportGenerator
    HAS_ADVANCED_HTML = True
except ImportError:
    HAS_ADVANCED_HTML = False

try:
    from .generators.simple_html_generator import SimpleHTMLReportGenerator
    HAS_SIMPLE_HTML = True
except ImportError:
    HAS_SIMPLE_HTML = False

try:
    from .generators.pdf_generator import PDFReportGenerator
    HAS_PDF = True
except ImportError:
    HAS_PDF = False

class ReportManager:
    """Manage report generation across multiple formats"""
    
    def __init__(self, output_dir: str = None):
        """Initialize the report manager"""
        if output_dir is None:
            output_dir = os.path.join(os.path.dirname(__file__), '..', 'results', 'reports')
        
        self.output_dir = output_dir
        
        # Initialize available generators
        if HAS_ADVANCED_HTML:
            self.html_generator = HTMLReportGenerator()
        elif HAS_SIMPLE_HTML:
            self.html_generator = SimpleHTMLReportGenerator()
        else:
            self.html_generator = None
            
        if HAS_PDF:
            self.pdf_generator = PDFReportGenerator()
        else:
            self.pdf_generator = None
        
        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate_all_reports(self, 
                           scan_data: Dict[str, Any], 
                           target: str,
                           formats: List[str] = None) -> Dict[str, str]:
        """
        Generate reports in all requested formats
        
        Args:
            scan_data: Dictionary containing all scan results
            target: Target domain/IP being scanned
            formats: List of formats to generate ['html', 'pdf', 'json']
            
        Returns:
            Dictionary mapping format to file path
        """
        
        if formats is None:
            formats = ['html', 'pdf', 'json']
        
        # Create timestamp for this report session
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace('.', '_').replace(':', '_')
        
        generated_reports = {}
        
        # Generate HTML report
        if 'html' in formats:
            html_path = os.path.join(
                self.output_dir, 
                f"{safe_target}_{timestamp}_report.html"
            )
            try:
                if self.html_generator:
                    self.html_generator.generate_report(scan_data, target, html_path)
                    generated_reports['html'] = html_path
                    print(f"✅ HTML report generated: {html_path}")
                else:
                    print("❌ HTML generator not available (missing dependencies)")
                    generated_reports['html'] = None
            except Exception as e:
                print(f"❌ HTML report generation failed: {e}")
                generated_reports['html'] = None
        
        # Generate PDF report
        if 'pdf' in formats:
            pdf_path = os.path.join(
                self.output_dir, 
                f"{safe_target}_{timestamp}_report.pdf"
            )
            try:
                if self.pdf_generator:
                    self.pdf_generator.generate_report(scan_data, target, pdf_path)
                    generated_reports['pdf'] = pdf_path
                    print(f"✅ PDF report generated: {pdf_path}")
                else:
                    print("❌ PDF generator not available (missing dependencies)")
                    generated_reports['pdf'] = None
            except Exception as e:
                print(f"❌ PDF report generation failed: {e}")
                generated_reports['pdf'] = None
        
        # Generate JSON report
        if 'json' in formats:
            json_path = os.path.join(
                self.output_dir, 
                f"{safe_target}_{timestamp}_report.json"
            )
            try:
                self._generate_json_report(scan_data, target, json_path)
                generated_reports['json'] = json_path
                print(f"✅ JSON report generated: {json_path}")
            except Exception as e:
                print(f"❌ JSON report generation failed: {e}")
                generated_reports['json'] = None
        
        return generated_reports
    
    def generate_executive_summary(self, 
                                 scan_data: Dict[str, Any], 
                                 target: str) -> str:
        """Generate executive summary PDF for stakeholders"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace('.', '_').replace(':', '_')
        
        pdf_path = os.path.join(
            self.output_dir, 
            f"{safe_target}_{timestamp}_executive_summary.pdf"
        )
        
        try:
            if self.pdf_generator:
                self.pdf_generator.generate_report(
                    scan_data, target, pdf_path, report_type='executive'
                )
                print(f"✅ Executive summary generated: {pdf_path}")
                return pdf_path
            else:
                print("❌ PDF generator not available (missing dependencies)")
                return None
        except Exception as e:
            print(f"❌ Executive summary generation failed: {e}")
            return None
    
    def generate_technical_report(self, 
                                scan_data: Dict[str, Any], 
                                target: str) -> str:
        """Generate detailed technical report for security teams"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace('.', '_').replace(':', '_')
        
        pdf_path = os.path.join(
            self.output_dir, 
            f"{safe_target}_{timestamp}_technical_report.pdf"
        )
        
        try:
            if self.pdf_generator:
                self.pdf_generator.generate_report(
                    scan_data, target, pdf_path, report_type='technical'
                )
                print(f"✅ Technical report generated: {pdf_path}")
                return pdf_path
            else:
                print("❌ PDF generator not available (missing dependencies)")
                return None
        except Exception as e:
            print(f"❌ Technical report generation failed: {e}")
            return None
    
    def _generate_json_report(self, 
                            scan_data: Dict[str, Any], 
                            target: str, 
                            output_path: str) -> str:
        """Generate machine-readable JSON report"""
        
        # Structure the JSON report
        json_report = {
            'metadata': {
                'target': target,
                'scan_date': datetime.now().isoformat(),
                'report_version': '3.0.0',
                'generator': 'recon-tool-v3',
                'scan_id': datetime.now().strftime("%Y%m%d_%H%M%S")
            },
            'summary': self._generate_summary_stats(scan_data, target),
            'findings': self._structure_findings_for_json(scan_data),
            'raw_data': scan_data
        }
        
        # Write JSON report
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(json_report, f, indent=2, ensure_ascii=False)
        
        return output_path
    
    def _generate_summary_stats(self, scan_data: Dict[str, Any], target: str) -> Dict[str, Any]:
        """Generate summary statistics for JSON report"""
        
        summary = {
            'target': target,
            'total_tools_used': len(scan_data),
            'total_subdomains': 0,
            'total_ports': 0,
            'total_vulnerabilities': 0,
            'total_urls': 0,
            'vulnerability_breakdown': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            },
            'risk_score': 0,
            'risk_level': 'LOW'
        }
        
        # Count findings
        for tool_name, results in scan_data.items():
            if not isinstance(results, dict):
                continue
            
            if 'subdomains' in results:
                summary['total_subdomains'] += len(results['subdomains'])
            
            if 'ports' in results:
                summary['total_ports'] += len(results['ports'])
            
            if 'urls' in results:
                summary['total_urls'] += len(results['urls'])
            
            if 'vulnerabilities' in results:
                for vuln in results['vulnerabilities']:
                    severity = vuln.get('severity', 'info').lower()
                    if severity in summary['vulnerability_breakdown']:
                        summary['vulnerability_breakdown'][severity] += 1
                        summary['total_vulnerabilities'] += 1
        
        # Calculate risk score (0-100)
        risk_score = (
            summary['vulnerability_breakdown']['critical'] * 20 +
            summary['vulnerability_breakdown']['high'] * 10 +
            summary['vulnerability_breakdown']['medium'] * 5 +
            summary['vulnerability_breakdown']['low'] * 2 +
            summary['vulnerability_breakdown']['info'] * 1
        )
        
        summary['risk_score'] = min(risk_score, 100)
        
        # Determine risk level
        if summary['vulnerability_breakdown']['critical'] > 0:
            summary['risk_level'] = 'CRITICAL'
        elif summary['vulnerability_breakdown']['high'] > 5:
            summary['risk_level'] = 'HIGH'
        elif summary['vulnerability_breakdown']['high'] > 0:
            summary['risk_level'] = 'MEDIUM'
        elif summary['vulnerability_breakdown']['medium'] > 5:
            summary['risk_level'] = 'LOW'
        else:
            summary['risk_level'] = 'MINIMAL'
        
        return summary
    
    def _structure_findings_for_json(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Structure findings in a standardized format for JSON export"""
        
        structured_findings = {
            'vulnerabilities': [],
            'infrastructure': {
                'subdomains': [],
                'ports': [],
                'services': []
            },
            'web_assets': {
                'urls': [],
                'technologies': [],
                'directories': []
            },
            'intelligence': {
                'certificates': [],
                'dns_records': [],
                'historical_data': []
            }
        }
        
        for tool_name, results in scan_data.items():
            if not isinstance(results, dict):
                continue
            
            # Process vulnerabilities
            if 'vulnerabilities' in results:
                for vuln in results['vulnerabilities']:
                    structured_findings['vulnerabilities'].append({
                        'id': f"{tool_name}_{len(structured_findings['vulnerabilities'])}",
                        'source_tool': tool_name,
                        'title': vuln.get('title', ''),
                        'severity': vuln.get('severity', 'info'),
                        'description': vuln.get('description', ''),
                        'host': vuln.get('host', ''),
                        'port': vuln.get('port', ''),
                        'path': vuln.get('path', ''),
                        'cve': vuln.get('cve', ''),
                        'cvss_score': vuln.get('cvss', ''),
                        'discovered_at': datetime.now().isoformat()
                    })
            
            # Process infrastructure findings
            if 'subdomains' in results:
                for subdomain in results['subdomains']:
                    structured_findings['infrastructure']['subdomains'].append({
                        'subdomain': subdomain,
                        'discovered_by': tool_name,
                        'discovered_at': datetime.now().isoformat(),
                        'resolved': True  # Could add actual DNS resolution check
                    })
            
            if 'ports' in results:
                for port in results['ports']:
                    structured_findings['infrastructure']['ports'].append({
                        'port': port.get('port', ''),
                        'protocol': port.get('protocol', 'tcp'),
                        'service': port.get('service', ''),
                        'state': port.get('state', 'open'),
                        'version': port.get('version', ''),
                        'discovered_by': tool_name,
                        'discovered_at': datetime.now().isoformat()
                    })
            
            # Process web assets
            if 'urls' in results:
                for url in results['urls']:
                    structured_findings['web_assets']['urls'].append({
                        'url': url,
                        'discovered_by': tool_name,
                        'discovered_at': datetime.now().isoformat(),
                        'status_code': None,  # Could add HTTP status checking
                        'content_type': None
                    })
        
        return structured_findings
    
    def list_reports(self, target: str = None) -> List[Dict[str, Any]]:
        """List all generated reports, optionally filtered by target"""
        
        reports = []
        
        if not os.path.exists(self.output_dir):
            return reports
        
        for filename in os.listdir(self.output_dir):
            if filename.endswith(('.html', '.pdf', '.json')):
                file_path = os.path.join(self.output_dir, filename)
                file_stat = os.stat(file_path)
                
                # Parse filename to extract info
                parts = filename.split('_')
                if len(parts) >= 3:
                    report_target = parts[0].replace('_', '.')
                    timestamp = parts[1] + '_' + parts[2].split('.')[0]
                    file_type = filename.split('.')[-1]
                    
                    if target is None or target in report_target:
                        reports.append({
                            'target': report_target,
                            'timestamp': timestamp,
                            'type': file_type,
                            'filename': filename,
                            'path': file_path,
                            'size': file_stat.st_size,
                            'created': datetime.fromtimestamp(file_stat.st_ctime).isoformat()
                        })
        
        # Sort by creation time (newest first)
        reports.sort(key=lambda x: x['created'], reverse=True)
        return reports
    
    def cleanup_old_reports(self, days: int = 30) -> int:
        """Clean up reports older than specified days"""
        
        if not os.path.exists(self.output_dir):
            return 0
        
        cutoff_time = datetime.now().timestamp() - (days * 24 * 60 * 60)
        removed_count = 0
        
        for filename in os.listdir(self.output_dir):
            if filename.endswith(('.html', '.pdf', '.json')):
                file_path = os.path.join(self.output_dir, filename)
                if os.path.getctime(file_path) < cutoff_time:
                    try:
                        os.remove(file_path)
                        removed_count += 1
                        print(f"Removed old report: {filename}")
                    except Exception as e:
                        print(f"Failed to remove {filename}: {e}")
        
        return removed_count

def demo_report_generation():
    """Demonstrate report generation capabilities"""
    
    # Sample comprehensive scan data
    sample_data = {
        'subfinder': {
            'timestamp': datetime.now().isoformat(),
            'subdomains': [
                'api.example.com', 'www.example.com', 'mail.example.com',
                'blog.example.com', 'shop.example.com'
            ]
        },
        'nmap': {
            'timestamp': datetime.now().isoformat(),
            'ports': [
                {'port': 80, 'service': 'http', 'state': 'open', 'version': 'Apache 2.4'},
                {'port': 443, 'service': 'https', 'state': 'open', 'version': 'Apache 2.4'},
                {'port': 22, 'service': 'ssh', 'state': 'open', 'version': 'OpenSSH 8.0'},
                {'port': 3306, 'service': 'mysql', 'state': 'open', 'version': 'MySQL 8.0'}
            ]
        },
        'nuclei': {
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [
                {
                    'title': 'SSL Certificate Weak Encryption',
                    'severity': 'high',
                    'description': 'SSL certificate uses weak SHA-1 encryption',
                    'host': 'example.com',
                    'port': '443',
                    'cve': 'CVE-2021-12345'
                },
                {
                    'title': 'Directory Listing Enabled',
                    'severity': 'medium',
                    'description': 'Web server allows directory listing on /uploads/',
                    'host': 'example.com',
                    'port': '80',
                    'path': '/uploads/'
                },
                {
                    'title': 'MySQL Database Exposed',
                    'severity': 'critical',
                    'description': 'MySQL database accessible without authentication',
                    'host': 'example.com',
                    'port': '3306'
                }
            ]
        },
        'waybackurls': {
            'timestamp': datetime.now().isoformat(),
            'urls': [
                'https://example.com/admin/login.php',
                'https://example.com/api/v1/users',
                'https://example.com/backup/database.sql',
                'https://example.com/config/settings.json'
            ]
        }
    }
    
    # Initialize report manager
    manager = ReportManager()
    
    # Generate all reports
    print("🚀 Generating comprehensive reports...")
    reports = manager.generate_all_reports(sample_data, 'example.com')
    
    # Generate executive summary
    print("📊 Generating executive summary...")
    exec_report = manager.generate_executive_summary(sample_data, 'example.com')
    
    # List all reports
    print("\n📋 Generated Reports:")
    for report in manager.list_reports():
        print(f"  - {report['type'].upper()}: {report['filename']} ({report['size']} bytes)")
    
    return reports

if __name__ == "__main__":
    demo_report_generation()
