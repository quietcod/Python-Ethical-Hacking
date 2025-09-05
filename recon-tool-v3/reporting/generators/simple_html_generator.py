"""
Simplified HTML Report Generator for Phase 5
Works without external plot libraries, uses basic HTML/CSS charts
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

class SimpleHTMLReportGenerator:
    """Generate HTML reports using pure HTML/CSS without external dependencies"""
    
    def __init__(self):
        """Initialize the simple HTML report generator"""
        self.template = self._get_html_template()
    
    def generate_report(self, 
                       scan_data: Dict[str, Any], 
                       target: str,
                       output_path: str) -> str:
        """
        Generate comprehensive HTML report without external dependencies
        
        Args:
            scan_data: Dictionary containing all scan results
            target: Target domain/IP being scanned
            output_path: Path to save the HTML report
            
        Returns:
            Path to generated HTML file
        """
        
        # Process the scan data
        processed_data = self._process_scan_data(scan_data, target)
        
        # Generate the report content
        html_content = self._render_template(processed_data)
        
        # Save the report
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        return output_path
    
    def _process_scan_data(self, scan_data: Dict[str, Any], target: str) -> Dict[str, Any]:
        """Process raw scan data into structured format for reporting"""
        
        # Initialize counters
        summary = {
            'target': target,
            'total_subdomains': 0,
            'total_ports_found': 0,
            'total_vulnerabilities': 0,
            'total_urls_discovered': 0,
            'vulnerability_breakdown': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'risk_level': 'LOW',
            'tools_used': []
        }
        
        findings = {
            'vulnerabilities': [],
            'subdomains': [],
            'ports': [],
            'urls': []
        }
        
        # Process each tool's results
        for tool_name, results in scan_data.items():
            if not isinstance(results, dict):
                continue
                
            summary['tools_used'].append(tool_name)
            
            # Process subdomains
            if 'subdomains' in results:
                for subdomain in results['subdomains']:
                    findings['subdomains'].append({
                        'tool': tool_name,
                        'subdomain': subdomain
                    })
                    summary['total_subdomains'] += 1
            
            # Process ports
            if 'ports' in results:
                for port in results['ports']:
                    findings['ports'].append({
                        'tool': tool_name,
                        'port': port.get('port', ''),
                        'service': port.get('service', ''),
                        'state': port.get('state', 'open'),
                        'version': port.get('version', '')
                    })
                    summary['total_ports_found'] += 1
            
            # Process vulnerabilities
            if 'vulnerabilities' in results:
                for vuln in results['vulnerabilities']:
                    severity = vuln.get('severity', 'info').lower()
                    findings['vulnerabilities'].append({
                        'tool': tool_name,
                        'title': vuln.get('title', ''),
                        'severity': severity,
                        'description': vuln.get('description', ''),
                        'host': vuln.get('host', ''),
                        'port': vuln.get('port', ''),
                        'path': vuln.get('path', '')
                    })
                    summary['total_vulnerabilities'] += 1
                    if severity in summary['vulnerability_breakdown']:
                        summary['vulnerability_breakdown'][severity] += 1
            
            # Process URLs
            if 'urls' in results:
                for url in results['urls'][:50]:  # Limit to 50 for display
                    findings['urls'].append({
                        'tool': tool_name,
                        'url': url
                    })
                    summary['total_urls_discovered'] += 1
        
        # Determine risk level
        if summary['vulnerability_breakdown']['critical'] > 0:
            summary['risk_level'] = 'CRITICAL'
        elif summary['vulnerability_breakdown']['high'] > 3:
            summary['risk_level'] = 'HIGH'
        elif summary['vulnerability_breakdown']['high'] > 0:
            summary['risk_level'] = 'MEDIUM'
        elif summary['vulnerability_breakdown']['medium'] > 5:
            summary['risk_level'] = 'LOW'
        else:
            summary['risk_level'] = 'MINIMAL'
        
        return {
            'target': target,
            'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'summary': summary,
            'findings': findings,
            'recommendations': self._generate_recommendations(summary)
        }
    
    def _generate_recommendations(self, summary: Dict[str, Any]) -> List[Dict]:
        """Generate security recommendations based on findings"""
        
        recommendations = []
        
        vuln_breakdown = summary['vulnerability_breakdown']
        
        if vuln_breakdown['critical'] > 0:
            recommendations.append({
                'priority': 'IMMEDIATE',
                'title': f'Address {vuln_breakdown["critical"]} Critical Vulnerabilities',
                'description': 'Critical vulnerabilities pose immediate risk to the organization.',
                'action': 'Patch or mitigate all critical vulnerabilities within 24 hours.'
            })
        
        if vuln_breakdown['high'] > 0:
            recommendations.append({
                'priority': 'HIGH',
                'title': f'Remediate {vuln_breakdown["high"]} High Severity Issues',
                'description': 'High severity vulnerabilities require prompt attention.',
                'action': 'Address all high severity vulnerabilities within 72 hours.'
            })
        
        if summary['total_subdomains'] > 10:
            recommendations.append({
                'priority': 'MEDIUM',
                'title': 'Large Attack Surface Detected',
                'description': f'Discovered {summary["total_subdomains"]} subdomains which increases attack surface.',
                'action': 'Review each subdomain for necessity and implement proper access controls.'
            })
        
        if summary['total_ports_found'] > 5:
            recommendations.append({
                'priority': 'MEDIUM',
                'title': 'Multiple Open Ports Found',
                'description': f'Found {summary["total_ports_found"]} open ports that may expose services.',
                'action': 'Close unnecessary ports and implement firewall rules.'
            })
        
        if not recommendations:
            recommendations.append({
                'priority': 'INFO',
                'title': 'Good Security Baseline',
                'description': 'No major security issues were identified in this scan.',
                'action': 'Continue regular security assessments and monitoring.'
            })
        
        return recommendations
    
    def _render_template(self, data: Dict[str, Any]) -> str:
        """Render the HTML template with data"""
        
        # Replace placeholders in template
        html = self.template
        
        # Basic replacements
        html = html.replace('{{TARGET}}', data['target'])
        html = html.replace('{{SCAN_DATE}}', data['scan_date'])
        html = html.replace('{{TOTAL_SUBDOMAINS}}', str(data['summary']['total_subdomains']))
        html = html.replace('{{TOTAL_VULNERABILITIES}}', str(data['summary']['total_vulnerabilities']))
        html = html.replace('{{TOTAL_PORTS}}', str(data['summary']['total_ports_found']))
        html = html.replace('{{TOTAL_URLS}}', str(data['summary']['total_urls_discovered']))
        html = html.replace('{{RISK_LEVEL}}', data['summary']['risk_level'])
        html = html.replace('{{TOOLS_USED}}', ', '.join(data['summary']['tools_used']))
        
        # Generate vulnerability chart data
        vuln_chart = self._generate_vulnerability_chart(data['summary']['vulnerability_breakdown'])
        html = html.replace('{{VULNERABILITY_CHART}}', vuln_chart)
        
        # Generate findings tables
        vuln_table = self._generate_vulnerability_table(data['findings']['vulnerabilities'])
        html = html.replace('{{VULNERABILITY_TABLE}}', vuln_table)
        
        subdomain_table = self._generate_subdomain_table(data['findings']['subdomains'])
        html = html.replace('{{SUBDOMAIN_TABLE}}', subdomain_table)
        
        port_table = self._generate_port_table(data['findings']['ports'])
        html = html.replace('{{PORT_TABLE}}', port_table)
        
        # Generate recommendations
        recommendations_html = self._generate_recommendations_html(data['recommendations'])
        html = html.replace('{{RECOMMENDATIONS}}', recommendations_html)
        
        return html
    
    def _generate_vulnerability_chart(self, vuln_breakdown: Dict[str, int]) -> str:
        """Generate CSS-based vulnerability chart"""
        
        total = sum(vuln_breakdown.values())
        if total == 0:
            return '<div class="chart-placeholder">No vulnerabilities found</div>'
        
        chart_html = '<div class="vuln-chart">'
        
        colors = {
            'critical': '#dc3545',
            'high': '#fd7e14', 
            'medium': '#ffc107',
            'low': '#198754',
            'info': '#0dcaf0'
        }
        
        for severity, count in vuln_breakdown.items():
            if count > 0:
                percentage = (count / total) * 100
                chart_html += f'''
                <div class="chart-bar">
                    <div class="chart-label">{severity.upper()}: {count}</div>
                    <div class="chart-fill" style="width: {percentage}%; background-color: {colors[severity]};"></div>
                </div>
                '''
        
        chart_html += '</div>'
        return chart_html
    
    def _generate_vulnerability_table(self, vulnerabilities: List[Dict]) -> str:
        """Generate vulnerability findings table"""
        
        if not vulnerabilities:
            return '<p class="no-findings">No vulnerabilities found</p>'
        
        table_html = '''
        <div class="table-responsive">
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Title</th>
                        <th>Host</th>
                        <th>Port</th>
                        <th>Tool</th>
                    </tr>
                </thead>
                <tbody>
        '''
        
        for vuln in vulnerabilities:
            severity_class = f"severity-{vuln['severity']}"
            table_html += f'''
                <tr>
                    <td><span class="badge {severity_class}">{vuln['severity'].upper()}</span></td>
                    <td>{vuln['title']}</td>
                    <td>{vuln['host']}</td>
                    <td>{vuln['port']}</td>
                    <td><span class="tool-badge">{vuln['tool']}</span></td>
                </tr>
            '''
        
        table_html += '</tbody></table></div>'
        return table_html
    
    def _generate_subdomain_table(self, subdomains: List[Dict]) -> str:
        """Generate subdomain findings table"""
        
        if not subdomains:
            return '<p class="no-findings">No subdomains found</p>'
        
        table_html = '''
        <div class="subdomain-grid">
        '''
        
        for subdomain in subdomains:
            table_html += f'''
            <div class="subdomain-item">
                <div class="subdomain-name">{subdomain['subdomain']}</div>
                <div class="subdomain-tool">{subdomain['tool']}</div>
            </div>
            '''
        
        table_html += '</div>'
        return table_html
    
    def _generate_port_table(self, ports: List[Dict]) -> str:
        """Generate port findings table"""
        
        if not ports:
            return '<p class="no-findings">No open ports found</p>'
        
        table_html = '''
        <div class="table-responsive">
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Service</th>
                        <th>State</th>
                        <th>Version</th>
                        <th>Tool</th>
                    </tr>
                </thead>
                <tbody>
        '''
        
        for port in ports:
            state_class = 'state-open' if port['state'] == 'open' else 'state-closed'
            table_html += f'''
                <tr>
                    <td><strong>{port['port']}</strong></td>
                    <td>{port['service']}</td>
                    <td><span class="badge {state_class}">{port['state']}</span></td>
                    <td>{port['version']}</td>
                    <td><span class="tool-badge">{port['tool']}</span></td>
                </tr>
            '''
        
        table_html += '</tbody></table></div>'
        return table_html
    
    def _generate_recommendations_html(self, recommendations: List[Dict]) -> str:
        """Generate recommendations section"""
        
        recommendations_html = ''
        
        for i, rec in enumerate(recommendations, 1):
            priority_class = f"priority-{rec['priority'].lower()}"
            recommendations_html += f'''
            <div class="recommendation {priority_class}">
                <div class="rec-priority">{rec['priority']}</div>
                <div class="rec-content">
                    <h4>{rec['title']}</h4>
                    <p>{rec['description']}</p>
                    <div class="rec-action"><strong>Action:</strong> {rec['action']}</div>
                </div>
            </div>
            '''
        
        return recommendations_html
    
    def _get_html_template(self) -> str:
        """Get the HTML template with embedded CSS"""
        
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reconnaissance Report - {{TARGET}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 { font-size: 2.5rem; margin-bottom: 10px; }
        .header p { font-size: 1.2rem; opacity: 0.9; }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }
        
        .stat-card:hover { transform: translateY(-5px); }
        
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            color: #3498db;
            display: block;
        }
        
        .stat-label {
            color: #666;
            margin-top: 5px;
            font-weight: 500;
        }
        
        .content {
            padding: 30px;
        }
        
        .section {
            margin-bottom: 40px;
        }
        
        .section h2 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
            font-size: 1.8rem;
        }
        
        .vuln-chart {
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .chart-bar {
            margin-bottom: 15px;
        }
        
        .chart-label {
            font-weight: 600;
            margin-bottom: 5px;
            color: #2c3e50;
        }
        
        .chart-fill {
            height: 25px;
            border-radius: 4px;
            position: relative;
            display: flex;
            align-items: center;
            padding-left: 10px;
            color: white;
            font-weight: bold;
        }
        
        .findings-table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .findings-table th {
            background: #34495e;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }
        
        .findings-table td {
            padding: 12px 15px;
            border-bottom: 1px solid #ecf0f1;
        }
        
        .findings-table tr:hover {
            background: #f8f9fa;
        }
        
        .badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .severity-critical { background: #e74c3c; color: white; }
        .severity-high { background: #e67e22; color: white; }
        .severity-medium { background: #f39c12; color: white; }
        .severity-low { background: #27ae60; color: white; }
        .severity-info { background: #3498db; color: white; }
        
        .state-open { background: #27ae60; color: white; }
        .state-closed { background: #e74c3c; color: white; }
        
        .tool-badge {
            background: #9b59b6;
            color: white;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
        }
        
        .subdomain-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .subdomain-item {
            background: white;
            border: 2px solid #ecf0f1;
            border-radius: 8px;
            padding: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: border-color 0.3s ease;
        }
        
        .subdomain-item:hover {
            border-color: #3498db;
        }
        
        .subdomain-name {
            font-weight: 600;
            color: #2c3e50;
        }
        
        .subdomain-tool {
            background: #3498db;
            color: white;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
        }
        
        .recommendation {
            display: flex;
            margin-bottom: 20px;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .rec-priority {
            width: 120px;
            padding: 20px;
            color: white;
            font-weight: bold;
            text-align: center;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .rec-content {
            flex: 1;
            padding: 20px;
            background: white;
        }
        
        .rec-content h4 {
            color: #2c3e50;
            margin-bottom: 10px;
        }
        
        .rec-action {
            margin-top: 10px;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 4px;
        }
        
        .priority-immediate .rec-priority { background: #e74c3c; }
        .priority-high .rec-priority { background: #e67e22; }
        .priority-medium .rec-priority { background: #f39c12; }
        .priority-low .rec-priority { background: #27ae60; }
        .priority-info .rec-priority { background: #3498db; }
        
        .risk-badge {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .risk-critical { background: #e74c3c; color: white; }
        .risk-high { background: #e67e22; color: white; }
        .risk-medium { background: #f39c12; color: white; }
        .risk-low { background: #27ae60; color: white; }
        .risk-minimal { background: #3498db; color: white; }
        
        .no-findings {
            text-align: center;
            color: #7f8c8d;
            font-style: italic;
            padding: 20px;
        }
        
        .table-responsive {
            overflow-x: auto;
        }
        
        @media (max-width: 768px) {
            .summary {
                grid-template-columns: 1fr;
            }
            
            .subdomain-grid {
                grid-template-columns: 1fr;
            }
            
            .recommendation {
                flex-direction: column;
            }
            
            .rec-priority {
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Reconnaissance Report</h1>
            <p>Target: {{TARGET}} | Generated: {{SCAN_DATE}}</p>
        </div>
        
        <div class="summary">
            <div class="stat-card">
                <span class="stat-number">{{TOTAL_SUBDOMAINS}}</span>
                <div class="stat-label">Subdomains</div>
            </div>
            <div class="stat-card">
                <span class="stat-number">{{TOTAL_VULNERABILITIES}}</span>
                <div class="stat-label">Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <span class="stat-number">{{TOTAL_PORTS}}</span>
                <div class="stat-label">Open Ports</div>
            </div>
            <div class="stat-card">
                <span class="stat-number">{{TOTAL_URLS}}</span>
                <div class="stat-label">URLs Found</div>
            </div>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>📊 Risk Assessment</h2>
                <p><strong>Overall Risk Level:</strong> <span class="risk-badge risk-{{RISK_LEVEL|lower}}">{{RISK_LEVEL}}</span></p>
                <p><strong>Tools Used:</strong> {{TOOLS_USED}}</p>
                
                <h3>Vulnerability Breakdown</h3>
                {{VULNERABILITY_CHART}}
            </div>
            
            <div class="section">
                <h2>🚨 Security Vulnerabilities</h2>
                {{VULNERABILITY_TABLE}}
            </div>
            
            <div class="section">
                <h2>🌐 Discovered Subdomains</h2>
                {{SUBDOMAIN_TABLE}}
            </div>
            
            <div class="section">
                <h2>🔌 Open Ports & Services</h2>
                {{PORT_TABLE}}
            </div>
            
            <div class="section">
                <h2>💡 Security Recommendations</h2>
                {{RECOMMENDATIONS}}
            </div>
        </div>
    </div>
</body>
</html>'''

# Demo function
def demo_simple_html_report():
    """Create a demonstration HTML report"""
    
    # Create comprehensive test data
    test_data = {
        'subfinder': {
            'subdomains': ['api.example.com', 'www.example.com', 'mail.example.com', 'blog.example.com']
        },
        'nmap': {
            'ports': [
                {'port': 80, 'service': 'http', 'state': 'open', 'version': 'Apache 2.4.41'},
                {'port': 443, 'service': 'https', 'state': 'open', 'version': 'Apache 2.4.41'},
                {'port': 22, 'service': 'ssh', 'state': 'open', 'version': 'OpenSSH 8.2'},
                {'port': 3306, 'service': 'mysql', 'state': 'open', 'version': 'MySQL 8.0.25'}
            ]
        },
        'nuclei': {
            'vulnerabilities': [
                {
                    'title': 'MySQL Database Exposed',
                    'severity': 'critical',
                    'description': 'MySQL database accessible without authentication',
                    'host': 'example.com',
                    'port': '3306'
                },
                {
                    'title': 'SSL Certificate Weak Encryption',
                    'severity': 'high',
                    'description': 'SSL certificate uses weak SHA-1 encryption',
                    'host': 'example.com',
                    'port': '443'
                },
                {
                    'title': 'Directory Listing Enabled',
                    'severity': 'medium',
                    'description': 'Web server allows directory listing',
                    'host': 'example.com',
                    'port': '80'
                },
                {
                    'title': 'Missing Security Headers',
                    'severity': 'low',
                    'description': 'Web application missing security headers',
                    'host': 'example.com',
                    'port': '443'
                }
            ]
        },
        'waybackurls': {
            'urls': [
                'https://example.com/admin/login.php',
                'https://example.com/api/v1/users',
                'https://example.com/backup/database.sql',
                'https://example.com/config/settings.json'
            ]
        }
    }
    
    # Generate report
    generator = SimpleHTMLReportGenerator()
    output_path = '/home/quietcod/Documents/Python-Ethical-Hacking/recon-tool-v3/results/phase5_demo_report.html'
    
    generated_path = generator.generate_report(test_data, 'example.com', output_path)
    
    print(f"✅ Phase 5 HTML report generated: {generated_path}")
    print(f"🌐 Open in browser: file://{os.path.abspath(generated_path)}")
    
    return generated_path

if __name__ == "__main__":
    demo_simple_html_report()
