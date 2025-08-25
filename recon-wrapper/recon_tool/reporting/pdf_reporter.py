"""
PDF Report Generator
Professional PDF reports using reportlab
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.platypus.frames import Frame
    from reportlab.platypus.doctemplate import PageTemplate
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

from .base_reporter import BaseReportGenerator
from ..core.exceptions import ScanError


class PDFReportGenerator(BaseReportGenerator):
    """PDF format report generator using reportlab"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        if not REPORTLAB_AVAILABLE:
            self.logger.warning("reportlab not available - PDF generation disabled")
            raise ImportError("reportlab package required for PDF generation")
    
    def generate_report(self) -> str:
        """Generate PDF report"""
        try:
            self.logger.info("Generating PDF report...")
            
            # Calculate summary stats
            summary = self._calculate_summary_stats()
            
            # Create PDF
            filename = self._get_report_filename('report', 'pdf')
            report_file = self.reports_dir / filename
            
            # Build PDF document
            doc = SimpleDocTemplate(str(report_file), pagesize=A4)
            story = self._build_pdf_story(summary)
            doc.build(story)
            
            self.logger.info(f"PDF report saved to {report_file}")
            return str(report_file)
            
        except Exception as e:
            self.logger.error(f"Error generating PDF report: {str(e)}")
            raise ScanError(f"Failed to generate PDF report: {str(e)}")
    
    def _build_pdf_story(self, summary: Dict[str, Any]) -> list:
        """Build PDF document story"""
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#667eea'),
            alignment=1  # Center
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceBefore=20,
            spaceAfter=12,
            textColor=colors.HexColor('#667eea')
        )
        
        subheading_style = ParagraphStyle(
            'CustomSubHeading',
            parent=styles['Heading3'],
            fontSize=14,
            spaceBefore=15,
            spaceAfter=8,
            textColor=colors.HexColor('#495057')
        )
        
        # Title page
        story.append(Paragraph("Reconnaissance Report", title_style))
        story.append(Spacer(1, 20))
        
        # Target information
        story.append(Paragraph(f"<b>Target:</b> {self.target}", styles['Normal']))
        story.append(Paragraph(f"<b>Scan Date:</b> {self.scan_metadata['report_generated_at']}", styles['Normal']))
        story.append(Spacer(1, 30))
        
        # Mode banner
        if self.scan_metadata['mode'] == 'offline':
            mode_text = "<b>Run Mode: Offline</b> - Internet-based sources intentionally skipped"
            story.append(Paragraph(mode_text, styles['Normal']))
            story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        story.append(Paragraph(f"This report contains the results of a comprehensive reconnaissance scan performed on the target <i>{self.target}</i>.", styles['Normal']))
        story.append(Spacer(1, 15))
        
        # Summary statistics table
        summary_data = [
            ['Metric', 'Count'],
            ['Subdomains Found', str(summary['subdomains_found'])],
            ['Open Ports', str(summary['open_ports'])],
            ['Web Technologies', str(len(summary['web_technologies']))],
            ['Security Issues', str(summary['security_issues'])],
            ['Directories Found', str(summary['directories_found'])],
            ['Files Found', str(summary['files_found'])],
            ['Vulnerabilities', str(summary['vulnerabilities'])]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(summary_table)
        story.append(PageBreak())
        
        # Detailed findings sections
        story.extend(self._generate_pdf_nmap_section(styles, heading_style, subheading_style))
        story.extend(self._generate_pdf_subdomain_section(styles, heading_style, subheading_style))
        story.extend(self._generate_pdf_web_section(styles, heading_style, subheading_style))
        story.extend(self._generate_pdf_ssl_section(styles, heading_style, subheading_style))
        story.extend(self._generate_pdf_security_section(styles, heading_style, subheading_style))
        story.extend(self._generate_pdf_osint_section(styles, heading_style, subheading_style))
        
        # Footer
        story.append(Spacer(1, 30))
        footer_text = f"Report generated by ReconTool - Professional Reconnaissance Framework<br/>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        story.append(Paragraph(footer_text, styles['Normal']))
        
        return story
    
    def _generate_pdf_nmap_section(self, styles, heading_style, subheading_style) -> list:
        """Generate PDF section for port scan results"""
        section = []
        
        try:
            section.append(Paragraph("Port Scan Results", heading_style))
            
            # Check for port scan results
            nmap_results = self.results.get('nmap_scan', {})
            port_scan_results = self.results.get('port_scan', {})
            
            if not nmap_results and not port_scan_results:
                section.append(Paragraph("No port scan results available.", styles['Normal']))
            else:
                # Process nmap results
                if nmap_results:
                    for host, data in nmap_results.items():
                        if isinstance(data, dict) and 'tcp' in data:
                            section.append(Paragraph(f"Host: {host}", subheading_style))
                            
                            # Create ports table
                            port_data = [['Port', 'State', 'Service', 'Version']]
                            for port, port_info in data['tcp'].items():
                                state = port_info.get('state', 'unknown')
                                service = port_info.get('name', 'unknown')
                                version = port_info.get('version', 'unknown')
                                port_data.append([str(port), state, service, version])
                            
                            if len(port_data) > 1:  # Has data beyond header
                                port_table = Table(port_data, colWidths=[1*inch, 1*inch, 1.5*inch, 2.5*inch])
                                port_table.setStyle(TableStyle([
                                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                                ]))
                                section.append(port_table)
                                section.append(Spacer(1, 15))
                
                # Process port scanner results
                if port_scan_results and 'open_ports' in port_scan_results:
                    open_ports = port_scan_results['open_ports']
                    if open_ports:
                        section.append(Paragraph("Open Ports Summary", subheading_style))
                        
                        port_data = [['Port', 'Protocol', 'Service']]
                        for port_info in open_ports:
                            if isinstance(port_info, dict):
                                port = port_info.get('port', 'N/A')
                                protocol = port_info.get('protocol', 'tcp')
                                service = port_info.get('service', 'unknown')
                                port_data.append([str(port), protocol, service])
                        
                        if len(port_data) > 1:  # Has data beyond header
                            port_table = Table(port_data, colWidths=[2*inch, 2*inch, 2*inch])
                            port_table.setStyle(TableStyle([
                                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                                ('FONTSIZE', (0, 0), (-1, -1), 10),
                                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                                ('GRID', (0, 0), (-1, -1), 1, colors.black)
                            ]))
                            section.append(port_table)
            
            section.append(Spacer(1, 20))
            
        except Exception as e:
            self.logger.error(f"Error generating PDF Nmap section: {str(e)}")
            section.append(Paragraph("Error generating port scan section.", styles['Normal']))
        
        return section
    
    def _generate_pdf_subdomain_section(self, styles, heading_style, subheading_style) -> list:
        """Generate PDF section for subdomain enumeration"""
        section = []
        
        try:
            section.append(Paragraph("Subdomain Enumeration", heading_style))
            
            subdomains = self.results.get('subdomains', [])
            subdomain_results = self.results.get('subdomain_enumeration', {})
            
            # Handle different subdomain data structures
            subdomain_list = []
            if isinstance(subdomains, dict) and 'domains' in subdomains:
                # Sample data structure
                subdomain_list = subdomains.get('domains', [])
            elif isinstance(subdomains, list):
                # Direct list structure
                subdomain_list = subdomains
            elif subdomain_results and 'discovered_subdomains' in subdomain_results:
                # Alternative structure
                subdomain_list = subdomain_results.get('discovered_subdomains', [])
            
            if not subdomain_list and not subdomain_results:
                section.append(Paragraph("No subdomains found.", styles['Normal']))
            else:
                # Process basic subdomain list
                if subdomain_list:
                    section.append(Paragraph(f"Total subdomains found: <b>{len(subdomain_list)}</b>", styles['Normal']))
                    section.append(Spacer(1, 10))
                    
                    # Create subdomains table (limit to first 50)
                    display_subdomains = subdomain_list[:50] if len(subdomain_list) >= 50 else subdomain_list
                    subdomain_data = [['Subdomain', 'Status']]
                    
                    for subdomain in display_subdomains:
                        if isinstance(subdomain, dict):
                            # Handle both 'domain' and 'subdomain' keys
                            domain = subdomain.get('domain') or subdomain.get('subdomain', 'unknown')
                            status = subdomain.get('status', 'unknown')
                            if status == 'live':
                                status = 'Live'
                            elif subdomain.get('live', False):
                                status = 'Live'
                            else:
                                status = 'Found'
                        else:
                            domain = str(subdomain)
                            status = 'Found'
                        
                        subdomain_data.append([domain, status])
                    
                    if len(subdomain_data) > 1:  # Has data beyond header
                        subdomain_table = Table(subdomain_data, colWidths=[4*inch, 2*inch])
                        subdomain_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                            ('FONTSIZE', (0, 0), (-1, -1), 10),
                            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                            ('GRID', (0, 0), (-1, -1), 1, colors.black)
                        ]))
                        section.append(subdomain_table)
                    
                    if len(subdomain_list) > 50:
                        section.append(Spacer(1, 10))
                        section.append(Paragraph(f"<i>... and {len(subdomain_list) - 50} more subdomains</i>", styles['Normal']))
            
            section.append(Spacer(1, 20))
            
        except Exception as e:
            self.logger.error(f"Error generating PDF subdomain section: {str(e)}")
            section.append(Paragraph("Error generating subdomain section.", styles['Normal']))
        
        return section
    
    def _generate_pdf_web_section(self, styles, heading_style, subheading_style) -> list:
        """Generate PDF section for web application scan"""
        section = []
        
        try:
            section.append(Paragraph("Web Application Scan", heading_style))
            
            web_results = self.results.get('web', {})
            web_scan_results = self.results.get('web_scan', {})
            
            if not web_results and not web_scan_results:
                section.append(Paragraph("No web application scan results available.", styles['Normal']))
            else:
                # Process the actual scan structure first
                if web_results:
                    # Technologies from the new structure
                    technologies = web_results.get('technologies', {})
                    if technologies:
                        section.append(Paragraph("<b>Technologies Detected:</b>", styles['Normal']))
                        for url, tech_info in technologies.items():
                            # Handle case where tech_info might be None
                            if tech_info is not None and isinstance(tech_info, dict):
                                server = tech_info.get('server', '')
                                if server:
                                    section.append(Paragraph(f"• Server: {server}", styles['Normal']))
                                
                                frameworks = tech_info.get('framework', [])
                                if frameworks and isinstance(frameworks, list):
                                    for fw in frameworks:
                                        if fw and isinstance(fw, dict):
                                            name = fw.get('name', '')
                                            confidence = fw.get('confidence', 0)
                                            section.append(Paragraph(f"• Framework: {name} ({confidence}% confidence)", styles['Normal']))
                                
                                languages = tech_info.get('language', [])
                                if languages and isinstance(languages, list):
                                    for lang in languages:
                                        if lang and isinstance(lang, dict):
                                            name = lang.get('name', '')
                                            confidence = lang.get('confidence', 0)
                                            section.append(Paragraph(f"• Language: {name} ({confidence}% confidence)", styles['Normal']))
                        section.append(Spacer(1, 10))
                    
                    # Directories from the new structure
                    directories = web_results.get('directories', [])
                    if directories:
                        section.append(Paragraph("<b>Directories Found:</b>", styles['Normal']))
                        # Show first 20 directories
                        display_dirs = directories[:20] if len(directories) > 20 else directories
                        for dir_info in display_dirs:
                            if isinstance(dir_info, dict):
                                path = dir_info.get('path', 'unknown')
                                url = dir_info.get('url', '')
                                status = dir_info.get('status_code', '')
                                section.append(Paragraph(f"• {path} (Status: {status})", styles['Normal']))
                            else:
                                section.append(Paragraph(f"• {dir_info}", styles['Normal']))
                        
                        if len(directories) > 20:
                            section.append(Paragraph(f"<i>... and {len(directories) - 20} more directories</i>", styles['Normal']))
                        section.append(Spacer(1, 10))
                    
                    # Security headers
                    security_headers = web_results.get('security_headers', {})
                    if security_headers:
                        section.append(Paragraph("<b>Security Analysis:</b>", styles['Normal']))
                        for url, headers in security_headers.items():
                            # Handle case where headers might be None
                            if headers is not None and isinstance(headers, dict):
                                missing = headers.get('missing_headers', [])
                                if missing:
                                    section.append(Paragraph("Missing Security Headers:", styles['Normal']))
                                    for header in missing:
                                        section.append(Paragraph(f"• {header}", styles['Normal']))
                        section.append(Spacer(1, 10))
                
                # Process legacy web_scan structure
                if web_scan_results:
                    for target, data in web_scan_results.items():
                        if isinstance(data, dict):
                            section.append(Paragraph(f"Target: {target}", subheading_style))
                            
                            # Technologies
                            technologies = data.get('technologies', [])
                            if technologies:
                                section.append(Paragraph("<b>Technologies Detected:</b>", styles['Normal']))
                                tech_text = ", ".join(technologies[:10])  # Limit to first 10
                                section.append(Paragraph(tech_text, styles['Normal']))
                                section.append(Spacer(1, 10))
                            
                            # Directories
                            directories = data.get('directories', [])
                            if directories:
                                section.append(Paragraph("<b>Directories Found:</b>", styles['Normal']))
                                dir_text = "<br/>".join([f"• {d}" for d in directories[:20]])  # Limit to first 20
                                section.append(Paragraph(dir_text, styles['Normal']))
                                section.append(Spacer(1, 10))
                            
                            # Files
                            files = data.get('files', [])
                            if files:
                                section.append(Paragraph("<b>Interesting Files:</b>", styles['Normal']))
                                file_text = "<br/>".join([f"• {f}" for f in files[:15]])  # Limit to first 15
                                section.append(Paragraph(file_text, styles['Normal']))
                                section.append(Spacer(1, 10))
            
            section.append(Spacer(1, 20))
            
        except Exception as e:
            self.logger.error(f"Error generating PDF web section: {str(e)}")
            section.append(Paragraph("Error generating web application section.", styles['Normal']))
        
        return section
    
    def _generate_pdf_ssl_section(self, styles, heading_style, subheading_style) -> list:
        """Generate PDF section for SSL/TLS analysis"""
        section = []
        
        try:
            section.append(Paragraph("SSL/TLS Analysis", heading_style))
            
            ssl_results = self.results.get('security_analysis', {}).get('ssl_analysis', {})
            ssl_scan = self.results.get('ssl_scan', {})
            
            if not ssl_results and not ssl_scan:
                section.append(Paragraph("No SSL/TLS analysis results available.", styles['Normal']))
            else:
                # Process SSL scan results
                if ssl_scan:
                    vulnerabilities = ssl_scan.get('vulnerabilities', [])
                    if vulnerabilities:
                        section.append(Paragraph("<b>SSL/TLS Vulnerabilities:</b>", styles['Normal']))
                        for vuln in vulnerabilities:
                            if isinstance(vuln, dict):
                                name = vuln.get('name', 'Unknown')
                                severity = vuln.get('severity', 'unknown').upper()
                                section.append(Paragraph(f"• <b>{severity}:</b> {name}", styles['Normal']))
                            else:
                                section.append(Paragraph(f"• {vuln}", styles['Normal']))
                        section.append(Spacer(1, 10))
            
            section.append(Spacer(1, 20))
            
        except Exception as e:
            self.logger.error(f"Error generating PDF SSL section: {str(e)}")
            section.append(Paragraph("Error generating SSL/TLS section.", styles['Normal']))
        
        return section
    
    def _generate_pdf_security_section(self, styles, heading_style, subheading_style) -> list:
        """Generate PDF section for security analysis"""
        section = []
        
        try:
            section.append(Paragraph("Security Analysis", heading_style))
            
            security_results = self.results.get('security_analysis', {})
            vulnerability_results = self.results.get('vulnerability_scan', {})
            
            if not security_results and not vulnerability_results:
                section.append(Paragraph("No security analysis results available.", styles['Normal']))
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
                
                section.append(Paragraph(f"<b>Total Vulnerabilities:</b> {total_vulns}", styles['Normal']))
                section.append(Paragraph(f"<b>Critical Vulnerabilities:</b> {critical_vulns}", styles['Normal']))
                section.append(Spacer(1, 10))
                
                if total_vulns > 0:
                    section.append(Paragraph("<b>Recommendations:</b>", styles['Normal']))
                    if critical_vulns > 0:
                        section.append(Paragraph("• Address critical vulnerabilities immediately", styles['Normal']))
                    section.append(Paragraph("• Implement SSL/TLS best practices", styles['Normal']))
                    section.append(Paragraph("• Regular security assessments recommended", styles['Normal']))
            
            section.append(Spacer(1, 20))
            
        except Exception as e:
            self.logger.error(f"Error generating PDF security section: {str(e)}")
            section.append(Paragraph("Error generating security analysis section.", styles['Normal']))
        
        return section
    
    def _generate_pdf_osint_section(self, styles, heading_style, subheading_style) -> list:
        """Generate PDF section for OSINT findings"""
        section = []
        
        try:
            section.append(Paragraph("OSINT Findings", heading_style))
            
            osint_results = self.results.get('osint', {})
            
            if not osint_results:
                section.append(Paragraph("No OSINT findings available.", styles['Normal']))
            else:
                # DNS records
                dns_records = osint_results.get('dns_records', {})
                if dns_records:
                    section.append(Paragraph("<b>DNS Records:</b>", styles['Normal']))
                    for record_type, records in dns_records.items():
                        if records:
                            section.append(Paragraph(f"• {record_type.upper()}: {len(records)} records", styles['Normal']))
                    section.append(Spacer(1, 10))
                
                # WHOIS information
                whois_data = osint_results.get('whois', {})
                if whois_data:
                    section.append(Paragraph("<b>WHOIS Information:</b>", styles['Normal']))
                    if 'registrar' in whois_data:
                        section.append(Paragraph(f"• Registrar: {whois_data['registrar']}", styles['Normal']))
                    if 'creation_date' in whois_data:
                        section.append(Paragraph(f"• Created: {whois_data['creation_date']}", styles['Normal']))
                    if 'expiration_date' in whois_data:
                        section.append(Paragraph(f"• Expires: {whois_data['expiration_date']}", styles['Normal']))
                    section.append(Spacer(1, 10))
                
                # Wayback Machine
                wayback_data = osint_results.get('wayback_machine', {})
                if wayback_data:
                    urls = wayback_data.get('urls', [])
                    if urls:
                        section.append(Paragraph(f"<b>Wayback Machine:</b> {len(urls)} historical URLs found", styles['Normal']))
                        section.append(Spacer(1, 10))
                
                # Shodan results
                shodan_data = osint_results.get('shodan', {})
                if shodan_data:
                    results = shodan_data.get('results', [])
                    if results:
                        section.append(Paragraph(f"<b>Shodan Intelligence:</b> {len(results)} entries found", styles['Normal']))
                        section.append(Spacer(1, 10))
            
            section.append(Spacer(1, 20))
            
        except Exception as e:
            self.logger.error(f"Error generating PDF OSINT section: {str(e)}")
            section.append(Paragraph("Error generating OSINT section.", styles['Normal']))
        
        return section
