"""
Advanced HTML Report Generator for Recon-Tool-v3
Generates professional, interactive HTML reports with visualizations
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from jinja2 import Environment, FileSystemLoader
import plotly.graph_objects as go
import plotly.express as px
from plotly.offline import plot
import pandas as pd

class HTMLReportGenerator:
    """Generate comprehensive HTML reports with interactive visualizations"""
    
    def __init__(self, template_dir: str = None):
        """Initialize the HTML report generator"""
        if template_dir is None:
            template_dir = os.path.join(os.path.dirname(__file__), '..', 'templates', 'html')
        
        self.template_dir = template_dir
        self.env = Environment(loader=FileSystemLoader(template_dir))
        
    def generate_report(self, 
                       scan_data: Dict[str, Any], 
                       target: str,
                       output_path: str) -> str:
        """
        Generate comprehensive HTML report
        
        Args:
            scan_data: Dictionary containing all scan results
            target: Target domain/IP being scanned
            output_path: Path to save the HTML report
            
        Returns:
            Path to generated HTML file
        """
        # Process and analyze the scan data
        processed_data = self._process_scan_data(scan_data, target)
        
        # Generate visualizations
        charts = self._generate_charts(processed_data)
        
        # Prepare template context
        context = {
            'target': target,
            'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'summary': processed_data['summary'],
            'findings': processed_data['findings'],
            'charts': charts,
            'timeline': processed_data['timeline'],
            'recommendations': self._generate_recommendations(processed_data),
            'metadata': processed_data['metadata']
        }
        
        # Render the report
        template = self.env.get_template('main_report.html')
        html_content = template.render(**context)
        
        # Save the report
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        return output_path
    
    def _process_scan_data(self, scan_data: Dict[str, Any], target: str) -> Dict[str, Any]:
        """Process raw scan data into structured format for reporting"""
        
        processed = {
            'summary': self._generate_summary(scan_data, target),
            'findings': self._categorize_findings(scan_data),
            'timeline': self._create_timeline(scan_data),
            'metadata': self._extract_metadata(scan_data)
        }
        
        return processed
    
    def _generate_summary(self, scan_data: Dict[str, Any], target: str) -> Dict[str, Any]:
        """Generate executive summary statistics"""
        
        summary = {
            'target': target,
            'total_subdomains': 0,
            'total_ports_found': 0,
            'total_vulnerabilities': 0,
            'total_urls_discovered': 0,
            'risk_level': 'LOW',
            'scan_duration': '0:00:00',
            'tools_used': []
        }
        
        # Count findings from different tools
        for tool_name, results in scan_data.items():
            if not isinstance(results, dict):
                continue
                
            summary['tools_used'].append(tool_name)
            
            # Subfinder/Amass results
            if tool_name in ['subfinder', 'amass'] and 'subdomains' in results:
                summary['total_subdomains'] += len(results['subdomains'])
            
            # Nmap results
            elif tool_name == 'nmap' and 'ports' in results:
                summary['total_ports_found'] += len(results['ports'])
            
            # Nuclei results
            elif tool_name == 'nuclei' and 'vulnerabilities' in results:
                summary['total_vulnerabilities'] += len(results['vulnerabilities'])
            
            # Waybackurls results
            elif tool_name == 'waybackurls' and 'urls' in results:
                summary['total_urls_discovered'] += len(results['urls'])
        
        # Determine risk level
        if summary['total_vulnerabilities'] > 10:
            summary['risk_level'] = 'HIGH'
        elif summary['total_vulnerabilities'] > 5:
            summary['risk_level'] = 'MEDIUM'
        elif summary['total_vulnerabilities'] > 0:
            summary['risk_level'] = 'LOW'
        else:
            summary['risk_level'] = 'MINIMAL'
            
        return summary
    
    def _categorize_findings(self, scan_data: Dict[str, Any]) -> Dict[str, List[Dict]]:
        """Categorize findings by type and severity"""
        
        findings = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': [],
            'subdomains': [],
            'ports': [],
            'urls': []
        }
        
        for tool_name, results in scan_data.items():
            if not isinstance(results, dict):
                continue
            
            # Process vulnerability findings
            if 'vulnerabilities' in results:
                for vuln in results['vulnerabilities']:
                    severity = vuln.get('severity', 'info').lower()
                    if severity in findings:
                        findings[severity].append({
                            'tool': tool_name,
                            'title': vuln.get('title', 'Unknown'),
                            'description': vuln.get('description', ''),
                            'severity': severity,
                            'host': vuln.get('host', ''),
                            'port': vuln.get('port', ''),
                            'path': vuln.get('path', '')
                        })
            
            # Process subdomain findings
            if 'subdomains' in results:
                for subdomain in results['subdomains']:
                    findings['subdomains'].append({
                        'tool': tool_name,
                        'subdomain': subdomain,
                        'resolved': True  # Could add DNS resolution check
                    })
            
            # Process port findings
            if 'ports' in results:
                for port_info in results['ports']:
                    findings['ports'].append({
                        'tool': tool_name,
                        'port': port_info.get('port', ''),
                        'service': port_info.get('service', ''),
                        'state': port_info.get('state', 'open'),
                        'version': port_info.get('version', '')
                    })
            
            # Process URL findings
            if 'urls' in results:
                for url in results['urls'][:100]:  # Limit to top 100 for report
                    findings['urls'].append({
                        'tool': tool_name,
                        'url': url,
                        'status': 'discovered'
                    })
        
        return findings
    
    def _create_timeline(self, scan_data: Dict[str, Any]) -> List[Dict]:
        """Create timeline of scan activities"""
        
        timeline = []
        
        for tool_name, results in scan_data.items():
            if isinstance(results, dict) and 'timestamp' in results:
                timeline.append({
                    'time': results['timestamp'],
                    'tool': tool_name,
                    'action': f'{tool_name} scan completed',
                    'findings': len(results.get('subdomains', [])) + 
                               len(results.get('ports', [])) + 
                               len(results.get('vulnerabilities', []))
                })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x['time'])
        return timeline
    
    def _extract_metadata(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract scan metadata and statistics"""
        
        metadata = {
            'scan_id': datetime.now().strftime("%Y%m%d_%H%M%S"),
            'total_tools': len(scan_data),
            'scan_type': 'comprehensive',
            'duration': '0:00:00',
            'version': '3.0.0'
        }
        
        return metadata
    
    def _generate_charts(self, processed_data: Dict[str, Any]) -> Dict[str, str]:
        """Generate interactive charts using Plotly"""
        
        charts = {}
        
        # Vulnerability severity chart
        charts['vulnerability_chart'] = self._create_vulnerability_chart(processed_data['findings'])
        
        # Tool usage chart
        charts['tool_usage_chart'] = self._create_tool_usage_chart(processed_data['findings'])
        
        # Timeline chart
        charts['timeline_chart'] = self._create_timeline_chart(processed_data['timeline'])
        
        return charts
    
    def _create_vulnerability_chart(self, findings: Dict[str, List]) -> str:
        """Create vulnerability severity distribution chart"""
        
        severities = ['critical', 'high', 'medium', 'low', 'info']
        counts = [len(findings.get(sev, [])) for sev in severities]
        colors = ['#dc3545', '#fd7e14', '#ffc107', '#198754', '#0dcaf0']
        
        fig = go.Figure(data=[
            go.Bar(
                x=severities,
                y=counts,
                marker_color=colors,
                text=counts,
                textposition='auto'
            )
        ])
        
        fig.update_layout(
            title='Vulnerability Distribution by Severity',
            xaxis_title='Severity Level',
            yaxis_title='Number of Vulnerabilities',
            template='plotly_white',
            height=400
        )
        
        return plot(fig, output_type='div', include_plotlyjs=False)
    
    def _create_tool_usage_chart(self, findings: Dict[str, List]) -> str:
        """Create tool usage statistics chart"""
        
        tool_counts = {}
        
        for category, items in findings.items():
            for item in items:
                tool = item.get('tool', 'unknown')
                tool_counts[tool] = tool_counts.get(tool, 0) + 1
        
        if not tool_counts:
            return "<div>No tool usage data available</div>"
        
        fig = go.Figure(data=[
            go.Pie(
                labels=list(tool_counts.keys()),
                values=list(tool_counts.values()),
                hole=0.3
            )
        ])
        
        fig.update_layout(
            title='Findings by Tool',
            template='plotly_white',
            height=400
        )
        
        return plot(fig, output_type='div', include_plotlyjs=False)
    
    def _create_timeline_chart(self, timeline: List[Dict]) -> str:
        """Create scan timeline visualization"""
        
        if not timeline:
            return "<div>No timeline data available</div>"
        
        df = pd.DataFrame(timeline)
        
        fig = px.timeline(
            df,
            x_start='time',
            x_end='time',
            y='tool',
            title='Scan Timeline',
            color='findings'
        )
        
        fig.update_layout(
            template='plotly_white',
            height=400
        )
        
        return plot(fig, output_type='div', include_plotlyjs=False)
    
    def _generate_recommendations(self, processed_data: Dict[str, Any]) -> List[Dict]:
        """Generate security recommendations based on findings"""
        
        recommendations = []
        
        # Check vulnerability count
        vuln_count = (len(processed_data['findings']['critical']) +
                     len(processed_data['findings']['high']) +
                     len(processed_data['findings']['medium']))
        
        if vuln_count > 0:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Vulnerability Management',
                'title': 'Address Critical and High Severity Vulnerabilities',
                'description': f'Found {vuln_count} vulnerabilities that require immediate attention.',
                'action': 'Review and patch all critical and high severity vulnerabilities within 24-48 hours.'
            })
        
        # Check subdomain exposure
        subdomain_count = len(processed_data['findings']['subdomains'])
        if subdomain_count > 10:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Attack Surface',
                'title': 'Large Attack Surface Detected',
                'description': f'Discovered {subdomain_count} subdomains which increases attack surface.',
                'action': 'Review each subdomain for necessity and implement proper access controls.'
            })
        
        # Check open ports
        port_count = len(processed_data['findings']['ports'])
        if port_count > 5:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Network Security',
                'title': 'Multiple Open Ports Found',
                'description': f'Found {port_count} open ports that may expose services.',
                'action': 'Close unnecessary ports and implement firewall rules.'
            })
        
        if not recommendations:
            recommendations.append({
                'priority': 'INFO',
                'category': 'Security Posture',
                'title': 'Good Security Baseline',
                'description': 'No major security issues were identified in this scan.',
                'action': 'Continue regular security assessments and monitoring.'
            })
        
        return recommendations

def create_sample_report():
    """Create a sample report for demonstration"""
    
    # Sample scan data
    sample_data = {
        'subfinder': {
            'timestamp': datetime.now().isoformat(),
            'subdomains': ['api.example.com', 'www.example.com', 'mail.example.com']
        },
        'nmap': {
            'timestamp': datetime.now().isoformat(),
            'ports': [
                {'port': 80, 'service': 'http', 'state': 'open'},
                {'port': 443, 'service': 'https', 'state': 'open'},
                {'port': 22, 'service': 'ssh', 'state': 'open'}
            ]
        },
        'nuclei': {
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [
                {
                    'title': 'SSL Certificate Issue',
                    'severity': 'medium',
                    'description': 'SSL certificate has weak encryption',
                    'host': 'example.com',
                    'port': '443'
                }
            ]
        }
    }
    
    # Generate report
    generator = HTMLReportGenerator()
    output_path = '/tmp/sample_report.html'
    generator.generate_report(sample_data, 'example.com', output_path)
    print(f"Sample report generated: {output_path}")

if __name__ == "__main__":
    create_sample_report()
