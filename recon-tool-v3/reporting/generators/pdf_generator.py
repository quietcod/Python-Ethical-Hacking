"""
Advanced PDF Report Generator for Recon-Tool-v3
Generates professional PDF reports for executive and technical audiences
"""

import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, KeepTogether
)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
import matplotlib.pyplot as plt
import io
import base64

class PDFReportGenerator:
    """Generate comprehensive PDF reports with professional formatting"""
    
    def __init__(self):
        """Initialize the PDF report generator"""
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        
    def _setup_custom_styles(self):
        """Setup custom paragraph styles for the report"""
        
        # Executive Summary Style
        self.styles.add(ParagraphStyle(
            name='ExecutiveSummary',
            parent=self.styles['Normal'],
            fontSize=12,
            spaceAfter=12,
            alignment=TA_JUSTIFY
        ))
        
        # Finding Title Style
        self.styles.add(ParagraphStyle(
            name='FindingTitle',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=colors.darkblue,
            spaceAfter=6
        ))
        
        # Critical Finding Style
        self.styles.add(ParagraphStyle(
            name='CriticalFinding',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.red,
            leftIndent=20
        ))
        
        # High Finding Style
        self.styles.add(ParagraphStyle(
            name='HighFinding',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.orange,
            leftIndent=20
        ))
        
        # Medium Finding Style
        self.styles.add(ParagraphStyle(
            name='MediumFinding',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.goldenrod,
            leftIndent=20
        ))
        
        # Recommendation Style
        self.styles.add(ParagraphStyle(
            name='Recommendation',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=8,
            leftIndent=15,
            bulletIndent=10
        ))
    
    def generate_report(self, 
                       scan_data: Dict[str, Any], 
                       target: str,
                       output_path: str,
                       report_type: str = 'comprehensive') -> str:
        """
        Generate comprehensive PDF report
        
        Args:
            scan_data: Dictionary containing all scan results
            target: Target domain/IP being scanned
            output_path: Path to save the PDF report
            report_type: Type of report ('executive', 'technical', 'comprehensive')
            
        Returns:
            Path to generated PDF file
        """
        
        # Process the scan data
        processed_data = self._process_scan_data(scan_data, target)
        
        # Create PDF document
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        # Build the story (content)
        story = []
        
        if report_type in ['executive', 'comprehensive']:
            story.extend(self._build_executive_summary(processed_data, target))
            
        if report_type in ['technical', 'comprehensive']:
            story.extend(self._build_technical_details(processed_data))
            
        story.extend(self._build_recommendations(processed_data))
        story.extend(self._build_appendix(processed_data))
        
        # Build the PDF
        doc.build(story)
        
        return output_path
    
    def _process_scan_data(self, scan_data: Dict[str, Any], target: str) -> Dict[str, Any]:
        """Process raw scan data into structured format for PDF reporting"""
        
        processed = {
            'target': target,
            'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'summary': self._generate_summary(scan_data, target),
            'findings': self._categorize_findings(scan_data),
            'recommendations': self._generate_recommendations(scan_data),
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
            'critical_issues': 0,
            'high_issues': 0,
            'medium_issues': 0,
            'tools_used': []
        }
        
        # Count findings from different tools
        for tool_name, results in scan_data.items():
            if not isinstance(results, dict):
                continue
                
            summary['tools_used'].append(tool_name)
            
            # Count subdomains
            if 'subdomains' in results:
                summary['total_subdomains'] += len(results['subdomains'])
            
            # Count ports
            if 'ports' in results:
                summary['total_ports_found'] += len(results['ports'])
            
            # Count vulnerabilities and categorize
            if 'vulnerabilities' in results:
                for vuln in results['vulnerabilities']:
                    severity = vuln.get('severity', 'info').lower()
                    if severity == 'critical':
                        summary['critical_issues'] += 1
                    elif severity == 'high':
                        summary['high_issues'] += 1
                    elif severity == 'medium':
                        summary['medium_issues'] += 1
                    summary['total_vulnerabilities'] += 1
            
            # Count URLs
            if 'urls' in results:
                summary['total_urls_discovered'] += len(results['urls'])
        
        # Determine overall risk level
        if summary['critical_issues'] > 0:
            summary['risk_level'] = 'CRITICAL'
        elif summary['high_issues'] > 5:
            summary['risk_level'] = 'HIGH'
        elif summary['high_issues'] > 0 or summary['medium_issues'] > 10:
            summary['risk_level'] = 'MEDIUM'
        elif summary['medium_issues'] > 0:
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
                            'path': vuln.get('path', ''),
                            'cve': vuln.get('cve', ''),
                            'cvss': vuln.get('cvss', '')
                        })
            
            # Process other findings
            if 'subdomains' in results:
                findings['subdomains'].extend([
                    {'tool': tool_name, 'subdomain': sub} 
                    for sub in results['subdomains']
                ])
            
            if 'ports' in results:
                findings['ports'].extend([
                    {
                        'tool': tool_name,
                        'port': port.get('port', ''),
                        'service': port.get('service', ''),
                        'state': port.get('state', ''),
                        'version': port.get('version', '')
                    }
                    for port in results['ports']
                ])
        
        return findings
    
    def _generate_recommendations(self, scan_data: Dict[str, Any]) -> List[Dict]:
        """Generate security recommendations based on findings"""
        
        recommendations = []
        
        # Analyze vulnerabilities
        vuln_count = 0
        critical_count = 0
        high_count = 0
        
        for tool_name, results in scan_data.items():
            if 'vulnerabilities' in results:
                for vuln in results['vulnerabilities']:
                    vuln_count += 1
                    severity = vuln.get('severity', 'info').lower()
                    if severity == 'critical':
                        critical_count += 1
                    elif severity == 'high':
                        high_count += 1
        
        # Critical vulnerabilities
        if critical_count > 0:
            recommendations.append({
                'priority': 'IMMEDIATE',
                'category': 'Critical Security',
                'title': f'Address {critical_count} Critical Vulnerabilities',
                'description': 'Critical vulnerabilities pose immediate risk to the organization.',
                'action': 'Patch or mitigate all critical vulnerabilities within 24 hours.',
                'timeline': '24 hours'
            })
        
        # High vulnerabilities
        if high_count > 0:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'High Priority Security',
                'title': f'Remediate {high_count} High Severity Issues',
                'description': 'High severity vulnerabilities require prompt attention.',
                'action': 'Address all high severity vulnerabilities within 72 hours.',
                'timeline': '72 hours'
            })
        
        # General recommendations
        recommendations.extend([
            {
                'priority': 'MEDIUM',
                'category': 'Security Monitoring',
                'title': 'Implement Continuous Security Monitoring',
                'description': 'Regular scanning helps identify new vulnerabilities.',
                'action': 'Schedule automated security scans weekly.',
                'timeline': '2 weeks'
            },
            {
                'priority': 'LOW',
                'category': 'Security Awareness',
                'title': 'Security Training and Awareness',
                'description': 'Human factor is critical in security posture.',
                'action': 'Conduct security awareness training for all staff.',
                'timeline': '1 month'
            }
        ])
        
        return recommendations
    
    def _extract_metadata(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract scan metadata and statistics"""
        
        metadata = {
            'scan_id': datetime.now().strftime("%Y%m%d_%H%M%S"),
            'total_tools': len(scan_data),
            'scan_duration': '0:00:00',
            'version': '3.0.0',
            'report_type': 'Comprehensive Security Assessment'
        }
        
        return metadata
    
    def _build_executive_summary(self, data: Dict[str, Any], target: str) -> List:
        """Build executive summary section"""
        
        story = []
        
        # Title Page
        story.append(Spacer(1, 2*inch))
        story.append(Paragraph(
            "SECURITY ASSESSMENT REPORT",
            self.styles['Title']
        ))
        story.append(Spacer(1, 0.5*inch))
        story.append(Paragraph(
            f"Target: {target}",
            self.styles['Heading1']
        ))
        story.append(Spacer(1, 0.3*inch))
        story.append(Paragraph(
            f"Assessment Date: {data['scan_date']}",
            self.styles['Normal']
        ))
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph(
            f"Report ID: {data['metadata']['scan_id']}",
            self.styles['Normal']
        ))
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph(
            "Generated by Recon-Tool-v3",
            self.styles['Normal']
        ))
        
        story.append(PageBreak())
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", self.styles['Heading1']))
        story.append(Spacer(1, 12))
        
        summary_text = f"""
        This report presents the findings of a comprehensive security assessment conducted on {target} 
        on {data['scan_date']}. The assessment identified {data['summary']['total_vulnerabilities']} 
        security vulnerabilities across {data['summary']['total_subdomains']} discovered subdomains 
        and {data['summary']['total_ports_found']} open network services.
        
        The overall risk level for this assessment has been classified as <b>{data['summary']['risk_level']}</b>.
        """
        
        if data['summary']['critical_issues'] > 0:
            summary_text += f"""
            <br/><br/>
            <b>CRITICAL FINDINGS:</b> {data['summary']['critical_issues']} critical vulnerabilities 
            require immediate attention within 24 hours.
            """
        
        story.append(Paragraph(summary_text, self.styles['ExecutiveSummary']))
        story.append(Spacer(1, 12))
        
        # Summary Statistics Table
        summary_data = [
            ['Metric', 'Count', 'Risk Level'],
            ['Total Subdomains', str(data['summary']['total_subdomains']), 'Info'],
            ['Open Ports', str(data['summary']['total_ports_found']), 'Medium'],
            ['Critical Vulnerabilities', str(data['summary']['critical_issues']), 'Critical'],
            ['High Vulnerabilities', str(data['summary']['high_issues']), 'High'],
            ['Medium Vulnerabilities', str(data['summary']['medium_issues']), 'Medium'],
            ['Overall Risk Level', data['summary']['risk_level'], data['summary']['risk_level']]
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 1*inch, 1.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(summary_table)
        story.append(PageBreak())
        
        return story
    
    def _build_technical_details(self, data: Dict[str, Any]) -> List:
        """Build technical findings section"""
        
        story = []
        
        story.append(Paragraph("Technical Findings", self.styles['Heading1']))
        story.append(Spacer(1, 12))
        
        # Critical Vulnerabilities
        if data['findings']['critical']:
            story.append(Paragraph("Critical Vulnerabilities", self.styles['Heading2']))
            for vuln in data['findings']['critical']:
                story.append(KeepTogether([
                    Paragraph(f"• {vuln['title']}", self.styles['CriticalFinding']),
                    Paragraph(f"Host: {vuln['host']} | Tool: {vuln['tool']}", 
                             self.styles['Normal']),
                    Paragraph(f"Description: {vuln['description']}", 
                             self.styles['Normal']),
                    Spacer(1, 6)
                ]))
        
        # High Vulnerabilities
        if data['findings']['high']:
            story.append(Paragraph("High Severity Vulnerabilities", self.styles['Heading2']))
            for vuln in data['findings']['high']:
                story.append(KeepTogether([
                    Paragraph(f"• {vuln['title']}", self.styles['HighFinding']),
                    Paragraph(f"Host: {vuln['host']} | Tool: {vuln['tool']}", 
                             self.styles['Normal']),
                    Paragraph(f"Description: {vuln['description']}", 
                             self.styles['Normal']),
                    Spacer(1, 6)
                ]))
        
        # Discovered Infrastructure
        if data['findings']['subdomains']:
            story.append(Paragraph("Discovered Subdomains", self.styles['Heading2']))
            subdomain_data = [['Subdomain', 'Discovery Tool']]
            for sub in data['findings']['subdomains'][:20]:  # Limit to top 20
                subdomain_data.append([sub['subdomain'], sub['tool']])
            
            subdomain_table = Table(subdomain_data, colWidths=[3*inch, 1.5*inch])
            subdomain_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(subdomain_table)
        
        return story
    
    def _build_recommendations(self, data: Dict[str, Any]) -> List:
        """Build recommendations section"""
        
        story = []
        
        story.append(PageBreak())
        story.append(Paragraph("Security Recommendations", self.styles['Heading1']))
        story.append(Spacer(1, 12))
        
        for i, rec in enumerate(data['recommendations'], 1):
            story.append(KeepTogether([
                Paragraph(f"{i}. {rec['title']}", self.styles['Heading3']),
                Paragraph(f"Priority: {rec['priority']}", self.styles['Normal']),
                Paragraph(f"Category: {rec['category']}", self.styles['Normal']),
                Paragraph(f"Description: {rec['description']}", self.styles['Normal']),
                Paragraph(f"Recommended Action: {rec['action']}", self.styles['Recommendation']),
                Paragraph(f"Timeline: {rec.get('timeline', 'As soon as possible')}", 
                         self.styles['Normal']),
                Spacer(1, 12)
            ]))
        
        return story
    
    def _build_appendix(self, data: Dict[str, Any]) -> List:
        """Build appendix section"""
        
        story = []
        
        story.append(PageBreak())
        story.append(Paragraph("Appendix", self.styles['Heading1']))
        story.append(Spacer(1, 12))
        
        # Scan Metadata
        story.append(Paragraph("Scan Metadata", self.styles['Heading2']))
        metadata_data = [
            ['Attribute', 'Value'],
            ['Scan ID', data['metadata']['scan_id']],
            ['Tools Used', str(data['metadata']['total_tools'])],
            ['Report Version', data['metadata']['version']],
            ['Scan Date', data['scan_date']]
        ]
        
        metadata_table = Table(metadata_data, colWidths=[2*inch, 3*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(metadata_table)
        story.append(Spacer(1, 12))
        
        # Disclaimer
        story.append(Paragraph("Disclaimer", self.styles['Heading2']))
        disclaimer = """
        This security assessment was conducted using automated tools and may not identify all 
        vulnerabilities present in the target systems. The findings should be validated through 
        manual testing and additional security measures should be implemented as part of a 
        comprehensive security program.
        """
        story.append(Paragraph(disclaimer, self.styles['Normal']))
        
        return story

def create_sample_pdf_report():
    """Create a sample PDF report for demonstration"""
    
    # Sample scan data
    sample_data = {
        'nmap': {
            'ports': [
                {'port': 80, 'service': 'http', 'state': 'open'},
                {'port': 443, 'service': 'https', 'state': 'open'},
                {'port': 22, 'service': 'ssh', 'state': 'open'}
            ]
        },
        'nuclei': {
            'vulnerabilities': [
                {
                    'title': 'SSL Certificate Weak Encryption',
                    'severity': 'high',
                    'description': 'SSL certificate uses weak encryption algorithm',
                    'host': 'example.com',
                    'port': '443',
                    'cve': 'CVE-2021-12345'
                },
                {
                    'title': 'Directory Listing Enabled',
                    'severity': 'medium',
                    'description': 'Web server allows directory listing',
                    'host': 'example.com',
                    'port': '80'
                }
            ]
        },
        'subfinder': {
            'subdomains': ['api.example.com', 'www.example.com', 'mail.example.com']
        }
    }
    
    # Generate report
    generator = PDFReportGenerator()
    output_path = '/tmp/sample_security_report.pdf'
    generator.generate_report(sample_data, 'example.com', output_path)
    print(f"Sample PDF report generated: {output_path}")

if __name__ == "__main__":
    create_sample_pdf_report()
