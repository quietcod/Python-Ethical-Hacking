"""
HTML Report Generator
Professional HTML reports with embedded CSS and JavaScript
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from .base_reporter import BaseReportGenerator
from ..core.exceptions import ScanError


class HTMLReportGenerator(BaseReportGenerator):
    """HTML format report generator with embedded CSS/JS"""
    
    def generate_report(self) -> str:
        """Generate HTML report"""
        try:
            self.logger.info("Generating HTML report...")
            
            # Calculate summary stats
            summary = self._calculate_summary_stats()
            
            # Build HTML report
            html_content = self._build_html_report(summary)
            
            # Save report
            filename = self._get_report_filename('report', 'html')
            report_file = self.reports_dir / filename
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"HTML report saved to {report_file}")
            return str(report_file)
            
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {str(e)}")
            raise ScanError(f"Failed to generate HTML report: {str(e)}")
    
    def _build_html_report(self, summary: Dict[str, Any]) -> str:
        """Build complete HTML report"""
        
        # Build mode banner
        mode_banner_html = ""
        if self.scan_metadata['mode'] == 'offline':
            mode_banner_html = '''
            <div class="alert alert-info">
                <i class="fas fa-lock"></i>
                <strong>Run Mode: Offline</strong> - Internet-based sources intentionally skipped
            </div>
            '''
        
        # Generate content sections
        nmap_section = self._generate_nmap_html()
        subdomain_section = self._generate_subdomain_html()
        web_section = self._generate_web_html()
        ssl_section = self._generate_ssl_html()
        security_section = self._generate_security_html()
        osint_section = self._generate_osint_html()
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reconnaissance Report - {self.target}</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        {self._get_css_styles()}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="header">
            <h1><i class="fas fa-search"></i> Reconnaissance Report</h1>
            <div class="target-info">
                <h2>Target: <span class="target">{self.target}</span></h2>
                <p class="scan-date">Scan Date: {self.scan_metadata['report_generated_at']}</p>
            </div>
        </header>
        
        {mode_banner_html}
        
        <!-- Executive Summary -->
        <section class="summary">
            <h2><i class="fas fa-chart-pie"></i> Executive Summary</h2>
            <p>This report contains the results of a comprehensive reconnaissance scan performed on the target <code>{self.target}</code>.</p>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{summary['subdomains_found']}</div>
                    <div class="stat-label">Subdomains Found</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{summary['open_ports']}</div>
                    <div class="stat-label">Open Ports</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(summary['web_technologies'])}</div>
                    <div class="stat-label">Web Technologies</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{summary['security_issues']}</div>
                    <div class="stat-label">Security Issues</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{summary['directories_found']}</div>
                    <div class="stat-label">Directories Found</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{summary['vulnerabilities']}</div>
                    <div class="stat-label">Vulnerabilities</div>
                </div>
            </div>
        </section>
        
        <!-- Detailed Findings -->
        <div class="findings">
            {nmap_section}
            {subdomain_section}
            {web_section}
            {ssl_section}
            {security_section}
            {osint_section}
        </div>
        
        <!-- Footer -->
        <footer class="footer">
            <p><i class="fas fa-shield-alt"></i> Report generated by ReconTool - Professional Reconnaissance Framework</p>
            <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </footer>
    </div>
    
    <script>
        {self._get_javascript()}
    </script>
</body>
</html>'''
        
        return html
    
    def _get_css_styles(self) -> str:
        """Get embedded CSS styles"""
        return '''
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f4f4f4;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            border-radius: 10px;
            margin-bottom: 2rem;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 1rem;
        }
        
        .target-info h2 {
            font-size: 1.5rem;
            margin-bottom: 0.5rem;
        }
        
        .target {
            color: #ffd700;
            font-weight: bold;
        }
        
        .scan-date {
            opacity: 0.9;
            font-size: 1rem;
        }
        
        .alert {
            padding: 1rem;
            border-radius: 5px;
            margin-bottom: 2rem;
        }
        
        .alert-info {
            background-color: #d1ecf1;
            border: 1px solid #bee5eb;
            color: #0c5460;
        }
        
        .summary {
            background: white;
            padding: 2rem;
            border-radius: 10px;
            margin-bottom: 2rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .summary h2 {
            color: #667eea;
            margin-bottom: 1rem;
            font-size: 1.8rem;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            margin-top: 2rem;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            padding: 1.5rem;
            border-radius: 8px;
            text-align: center;
            transition: transform 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-number {
            font-size: 2rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }
        
        .stat-label {
            font-size: 0.9rem;
            opacity: 0.9;
        }
        
        .section {
            background: white;
            padding: 2rem;
            border-radius: 10px;
            margin-bottom: 2rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .section h3 {
            color: #667eea;
            margin-bottom: 1.5rem;
            font-size: 1.5rem;
            border-bottom: 2px solid #e9ecef;
            padding-bottom: 0.5rem;
        }
        
        .section h4 {
            color: #495057;
            margin: 1.5rem 0 1rem 0;
            font-size: 1.2rem;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }
        
        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        
        th {
            background-color: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }
        
        tr:hover {
            background-color: #f8f9fa;
        }
        
        .badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            font-size: 0.75rem;
            font-weight: 700;
            line-height: 1;
            text-align: center;
            white-space: nowrap;
            vertical-align: baseline;
            border-radius: 0.25rem;
        }
        
        .badge-success {
            color: #155724;
            background-color: #d4edda;
        }
        
        .badge-warning {
            color: #856404;
            background-color: #fff3cd;
        }
        
        .badge-danger {
            color: #721c24;
            background-color: #f8d7da;
        }
        
        .badge-info {
            color: #0c5460;
            background-color: #d1ecf1;
        }
        
        .list-group {
            padding-left: 0;
            margin-bottom: 0;
        }
        
        .list-group-item {
            position: relative;
            display: block;
            padding: 0.5rem 1rem;
            margin-bottom: -1px;
            background-color: #fff;
            border: 1px solid rgba(0,0,0,.125);
        }
        
        .list-group-item:first-child {
            border-top-left-radius: 0.25rem;
            border-top-right-radius: 0.25rem;
        }
        
        .list-group-item:last-child {
            margin-bottom: 0;
            border-bottom-right-radius: 0.25rem;
            border-bottom-left-radius: 0.25rem;
        }
        
        code {
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            background-color: #f8f9fa;
            padding: 0.2rem 0.4rem;
            border-radius: 3px;
            color: #e83e8c;
        }
        
        .footer {
            text-align: center;
            padding: 2rem;
            background-color: #343a40;
            color: white;
            border-radius: 10px;
            margin-top: 2rem;
        }
        
        .collapse-toggle {
            cursor: pointer;
            user-select: none;
        }
        
        .collapse-toggle:hover {
            color: #667eea;
        }
        
        .collapse-content {
            margin-top: 1rem;
        }
        
        @media (max-width: 768px) {
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .container {
                padding: 10px;
            }
        }
        '''
    
    def _get_javascript(self) -> str:
        """Get embedded JavaScript"""
        return '''
        // Collapsible sections
        document.addEventListener('DOMContentLoaded', function() {
            const toggles = document.querySelectorAll('.collapse-toggle');
            
            toggles.forEach(toggle => {
                toggle.addEventListener('click', function() {
                    const content = this.nextElementSibling;
                    if (content && content.classList.contains('collapse-content')) {
                        content.style.display = content.style.display === 'none' ? 'block' : 'none';
                        
                        // Toggle icon
                        const icon = this.querySelector('i');
                        if (icon) {
                            icon.classList.toggle('fa-chevron-down');
                            icon.classList.toggle('fa-chevron-up');
                        }
                    }
                });
            });
            
            // Add smooth scrolling to anchor links
            document.querySelectorAll('a[href^="#"]').forEach(anchor => {
                anchor.addEventListener('click', function (e) {
                    e.preventDefault();
                    const target = document.querySelector(this.getAttribute('href'));
                    if (target) {
                        target.scrollIntoView({
                            behavior: 'smooth'
                        });
                    }
                });
            });
        });
        '''
    
    def _generate_nmap_html(self) -> str:
        """Generate HTML for port scan results"""
        try:
            content = '''
            <section class="section">
                <h3><i class="fas fa-network-wired"></i> Port Scan Results</h3>
            '''
            
            # Check for port scan results
            nmap_results = self.results.get('nmap_scan', {})
            port_scan_results = self.results.get('port_scan', {})
            
            if not nmap_results and not port_scan_results:
                content += '<p>No port scan results available.</p>'
            else:
                # Process nmap results
                if nmap_results:
                    for host, data in nmap_results.items():
                        if isinstance(data, dict) and 'tcp' in data:
                            content += f'<h4>Host: {host}</h4>'
                            content += '''
                            <table>
                                <thead>
                                    <tr>
                                        <th>Port</th>
                                        <th>State</th>
                                        <th>Service</th>
                                        <th>Version</th>
                                    </tr>
                                </thead>
                                <tbody>
                            '''
                            
                            for port, port_data in data['tcp'].items():
                                state = port_data.get('state', 'unknown')
                                service = port_data.get('name', 'unknown')
                                version = port_data.get('version', 'unknown')
                                
                                state_class = 'success' if state == 'open' else 'warning'
                                content += f'''
                                <tr>
                                    <td><code>{port}</code></td>
                                    <td><span class="badge badge-{state_class}">{state}</span></td>
                                    <td>{service}</td>
                                    <td>{version}</td>
                                </tr>
                                '''
                            
                            content += '</tbody></table>'
                
                # Process port scanner results
                if port_scan_results and 'open_ports' in port_scan_results:
                    open_ports = port_scan_results['open_ports']
                    if open_ports:
                        content += '<h4>Open Ports Summary</h4>'
                        content += '''
                        <table>
                            <thead>
                                <tr>
                                    <th>Port</th>
                                    <th>Protocol</th>
                                    <th>Service</th>
                                </tr>
                            </thead>
                            <tbody>
                        '''
                        
                        for port_info in open_ports:
                            if isinstance(port_info, dict):
                                port = port_info.get('port', 'N/A')
                                protocol = port_info.get('protocol', 'tcp')
                                service = port_info.get('service', 'unknown')
                                content += f'''
                                <tr>
                                    <td><code>{port}</code></td>
                                    <td>{protocol}</td>
                                    <td>{service}</td>
                                </tr>
                                '''
                        
                        content += '</tbody></table>'
            
            content += '</section>'
            return content
            
        except Exception as e:
            self.logger.error(f"Error generating Nmap HTML section: {str(e)}")
            return '<section class="section"><h3><i class="fas fa-network-wired"></i> Port Scan Results</h3><p>Error generating port scan section.</p></section>'
    
    def _generate_subdomain_html(self) -> str:
        """Generate HTML for subdomain enumeration"""
        try:
            content = '''
            <section class="section">
                <h3><i class="fas fa-sitemap"></i> Subdomain Enumeration</h3>
            '''
            
            subdomains = self.results.get('subdomains', [])
            subdomain_results = self.results.get('subdomain_enumeration', {})
            
            if not subdomains and not subdomain_results:
                content += '<p>No subdomains found.</p>'
            else:
                # Process basic subdomain list
                if subdomains:
                    content += f'<p>Total subdomains found: <strong>{len(subdomains)}</strong></p>'
                    
                    # Limit display to first 50
                    display_subdomains = subdomains[:50]
                    
                    content += '''
                    <table>
                        <thead>
                            <tr>
                                <th>Subdomain</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                    '''
                    
                    for subdomain in display_subdomains:
                        if isinstance(subdomain, dict):
                            domain = subdomain.get('domain', 'unknown')
                            status = 'Live' if subdomain.get('live', False) else 'Unknown'
                            status_class = 'success' if status == 'Live' else 'info'
                        else:
                            domain = str(subdomain)
                            status = 'Found'
                            status_class = 'info'
                        
                        content += f'''
                        <tr>
                            <td><code>{domain}</code></td>
                            <td><span class="badge badge-{status_class}">{status}</span></td>
                        </tr>
                        '''
                    
                    content += '</tbody></table>'
                    
                    if len(subdomains) > 50:
                        content += f'<p><em>... and {len(subdomains) - 50} more subdomains</em></p>'
            
            content += '</section>'
            return content
            
        except Exception as e:
            self.logger.error(f"Error generating subdomain HTML section: {str(e)}")
            return '<section class="section"><h3><i class="fas fa-sitemap"></i> Subdomain Enumeration</h3><p>Error generating subdomain section.</p></section>'
    
    def _generate_web_html(self) -> str:
        """Generate HTML for web application scan"""
        try:
            content = '''
            <section class="section">
                <h3><i class="fas fa-globe"></i> Web Application Scan</h3>
            '''
            
            web_results = self.results.get('web_scan', {})
            
            if not web_results:
                content += '<p>No web application scan results available.</p>'
            else:
                for target, data in web_results.items():
                    if isinstance(data, dict):
                        content += f'<h4>Target: {target}</h4>'
                        
                        # Technologies
                        technologies = data.get('technologies', [])
                        if technologies:
                            content += '<h5>Technologies Detected:</h5>'
                            content += '<div class="list-group">'
                            for tech in technologies[:10]:  # Limit to first 10
                                content += f'<div class="list-group-item">{tech}</div>'
                            content += '</div><br>'
                        
                        # Directories
                        directories = data.get('directories', [])
                        if directories:
                            content += '<h5>Directories Found:</h5>'
                            content += '<div class="list-group">'
                            for directory in directories[:20]:  # Limit to first 20
                                content += f'<div class="list-group-item"><code>{directory}</code></div>'
                            content += '</div><br>'
                        
                        # Files
                        files = data.get('files', [])
                        if files:
                            content += '<h5>Interesting Files:</h5>'
                            content += '<div class="list-group">'
                            for file in files[:15]:  # Limit to first 15
                                content += f'<div class="list-group-item"><code>{file}</code></div>'
                            content += '</div><br>'
            
            content += '</section>'
            return content
            
        except Exception as e:
            self.logger.error(f"Error generating web HTML section: {str(e)}")
            return '<section class="section"><h3><i class="fas fa-globe"></i> Web Application Scan</h3><p>Error generating web application section.</p></section>'
    
    def _generate_ssl_html(self) -> str:
        """Generate HTML for SSL/TLS analysis"""
        try:
            content = '''
            <section class="section">
                <h3><i class="fas fa-lock"></i> SSL/TLS Analysis</h3>
            '''
            
            ssl_results = self.results.get('security_analysis', {}).get('ssl_analysis', {})
            ssl_scan = self.results.get('ssl_scan', {})
            
            if not ssl_results and not ssl_scan:
                content += '<p>No SSL/TLS analysis results available.</p>'
            else:
                # Process SSL scan results
                if ssl_scan:
                    vulnerabilities = ssl_scan.get('vulnerabilities', [])
                    if vulnerabilities:
                        content += '<h4>SSL/TLS Vulnerabilities:</h4>'
                        content += '<div class="list-group">'
                        for vuln in vulnerabilities:
                            if isinstance(vuln, dict):
                                name = vuln.get('name', 'Unknown')
                                severity = vuln.get('severity', 'unknown').upper()
                                severity_class = 'danger' if severity == 'CRITICAL' else 'warning' if severity == 'HIGH' else 'info'
                                content += f'<div class="list-group-item"><span class="badge badge-{severity_class}">{severity}</span> {name}</div>'
                            else:
                                content += f'<div class="list-group-item">{vuln}</div>'
                        content += '</div>'
            
            content += '</section>'
            return content
            
        except Exception as e:
            self.logger.error(f"Error generating SSL HTML section: {str(e)}")
            return '<section class="section"><h3><i class="fas fa-lock"></i> SSL/TLS Analysis</h3><p>Error generating SSL/TLS section.</p></section>'
    
    def _generate_security_html(self) -> str:
        """Generate HTML for security analysis"""
        try:
            content = '''
            <section class="section">
                <h3><i class="fas fa-shield-alt"></i> Security Analysis</h3>
            '''
            
            security_results = self.results.get('security_analysis', {})
            vulnerability_results = self.results.get('vulnerability_scan', {})
            
            if not security_results and not vulnerability_results:
                content += '<p>No security analysis results available.</p>'
            else:
                # Summary of security findings
                total_vulns = 0
                critical_vulns = 0
                
                # Count vulnerabilities from SSL analysis
                ssl_analysis = security_results.get('ssl_analysis', {})
                for port_data in ssl_analysis.values():
                    vulns = port_data.get('vulnerabilities', [])
                    total_vulns += len(vulns)
                    critical_vulns += len([v for v in vulns if v.get('severity') == 'critical'])
                
                # Count vulnerabilities from vulnerability scanner
                if vulnerability_results:
                    vuln_count = vulnerability_results.get('vulnerability_count', {})
                    if isinstance(vuln_count, dict):
                        total_vulns += sum(vuln_count.values())
                        critical_vulns += vuln_count.get('critical', 0)
                    elif isinstance(vuln_count, int):
                        total_vulns += vuln_count
                
                content += '''
                <div class="stats-grid">
                    <div class="stat-card">
                '''
                content += f'<div class="stat-number">{total_vulns}</div>'
                content += '''
                        <div class="stat-label">Total Vulnerabilities</div>
                    </div>
                    <div class="stat-card">
                '''
                content += f'<div class="stat-number">{critical_vulns}</div>'
                content += '''
                        <div class="stat-label">Critical Vulnerabilities</div>
                    </div>
                </div>
                '''
                
                if total_vulns > 0:
                    content += '<h4>Recommendations:</h4>'
                    content += '<div class="list-group">'
                    if critical_vulns > 0:
                        content += '<div class="list-group-item"><span class="badge badge-danger">HIGH PRIORITY</span> Address critical vulnerabilities immediately</div>'
                    content += '<div class="list-group-item">Implement SSL/TLS best practices</div>'
                    content += '<div class="list-group-item">Regular security assessments recommended</div>'
                    content += '</div>'
            
            content += '</section>'
            return content
            
        except Exception as e:
            self.logger.error(f"Error generating security HTML section: {str(e)}")
            return '<section class="section"><h3><i class="fas fa-shield-alt"></i> Security Analysis</h3><p>Error generating security analysis section.</p></section>'
    
    def _generate_osint_html(self) -> str:
        """Generate HTML for OSINT findings"""
        try:
            content = '''
            <section class="section">
                <h3><i class="fas fa-search"></i> OSINT Findings</h3>
            '''
            
            osint_results = self.results.get('osint', {})
            
            if not osint_results:
                content += '<p>No OSINT findings available.</p>'
            else:
                # DNS records
                dns_records = osint_results.get('dns_records', {})
                if dns_records:
                    content += '<h4>DNS Records:</h4>'
                    content += '<div class="list-group">'
                    for record_type, records in dns_records.items():
                        if records:
                            content += f'<div class="list-group-item"><strong>{record_type.upper()}:</strong> {len(records)} records</div>'
                    content += '</div><br>'
                
                # WHOIS information
                whois_data = osint_results.get('whois', {})
                if whois_data:
                    content += '<h4>WHOIS Information:</h4>'
                    content += '<div class="list-group">'
                    if 'registrar' in whois_data:
                        content += f'<div class="list-group-item"><strong>Registrar:</strong> {whois_data["registrar"]}</div>'
                    if 'creation_date' in whois_data:
                        content += f'<div class="list-group-item"><strong>Created:</strong> {whois_data["creation_date"]}</div>'
                    if 'expiration_date' in whois_data:
                        content += f'<div class="list-group-item"><strong>Expires:</strong> {whois_data["expiration_date"]}</div>'
                    content += '</div><br>'
                
                # Wayback Machine
                wayback_data = osint_results.get('wayback_machine', {})
                if wayback_data:
                    urls = wayback_data.get('urls', [])
                    if urls:
                        content += f'<h4>Wayback Machine:</h4>'
                        content += f'<p>{len(urls)} historical URLs found</p><br>'
                
                # Shodan results
                shodan_data = osint_results.get('shodan', {})
                if shodan_data:
                    results = shodan_data.get('results', [])
                    if results:
                        content += f'<h4>Shodan Intelligence:</h4>'
                        content += f'<p>{len(results)} entries found</p><br>'
            
            content += '</section>'
            return content
            
        except Exception as e:
            self.logger.error(f"Error generating OSINT HTML section: {str(e)}")
            return '<section class="section"><h3><i class="fas fa-search"></i> OSINT Findings</h3><p>Error generating OSINT section.</p></section>'
