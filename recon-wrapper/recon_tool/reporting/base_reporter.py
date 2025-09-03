"""
Base Report Generator
Core reporting functionality for all report types
"""

import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from ..core.exceptions import ScanError


class BaseReportGenerator(ABC):
    """Abstract base class for all report generators"""
    
    def __init__(self, output_dir: Path, results: Dict[str, Any], target: str, config: Optional[Dict[str, Any]] = None):
        self.output_dir = Path(output_dir)
        self.results = results
        self.target = target
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Create reports directory
        self.reports_dir = self.output_dir / 'reports'
        self.reports_dir.mkdir(exist_ok=True)
        
        # Common metadata
        self.scan_metadata = {
            'target': target,
            'scan_date': datetime.now().isoformat(),
            'mode': self._get_scan_mode(),
            'report_generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def _get_scan_mode(self) -> str:
        """Determine scan mode from config"""
        if self.config:
            offline_mode = (
                self.config.get('mode', {}).get('offline', False) or 
                self.config.get('general', {}).get('offline_mode', False)
            )
            return 'offline' if offline_mode else 'online'
        return 'unknown'
    
    @abstractmethod
    def generate_report(self) -> str:
        """Generate report and return file path"""
        pass
    
    def _calculate_summary_stats(self) -> Dict[str, Any]:
        """Calculate summary statistics from results"""
        stats = {
            'subdomains_found': 0,
            'open_ports': 0,
            'web_technologies': [],
            'security_issues': 0,
            'directories_found': 0,
            'files_found': 0,
            'vulnerabilities': 0
        }
        
        try:
            # Subdomains - check the actual structure
            subdomain_results = self.results.get('subdomain', {})
            if isinstance(subdomain_results, dict):
                stats['subdomains_found'] = subdomain_results.get('subdomains_found', 0)
            else:
                # Legacy structure
                subdomains = self.results.get('subdomains', [])
                stats['subdomains_found'] = len(subdomains) if subdomains else 0
            
            # Open ports - check the actual structure
            port_results = self.results.get('port', {})
            if isinstance(port_results, dict):
                stats['open_ports'] = port_results.get('open_ports', 0)
            else:
                # Fallback to counting manually
                stats['open_ports'] = self._count_open_ports()
            
            # Web technologies - check the actual structure
            web_results = self.results.get('web', {})
            if isinstance(web_results, dict):
                technologies = web_results.get('technologies', {})
                tech_list = []
                for url, tech_info in technologies.items():
                    if isinstance(tech_info, dict):
                        server = tech_info.get('server', '')
                        if server:
                            tech_list.append(server)
                        
                        frameworks = tech_info.get('framework', [])
                        for fw in frameworks:
                            if isinstance(fw, dict):
                                tech_list.append(fw.get('name', ''))
                        
                        languages = tech_info.get('language', [])
                        for lang in languages:
                            if isinstance(lang, dict):
                                tech_list.append(lang.get('name', ''))
                
                stats['web_technologies'] = list(filter(None, tech_list))
            else:
                # Legacy web technologies
                stats['web_technologies'] = self._get_web_technologies()
            
            # Directories and files - check the actual structure
            if isinstance(web_results, dict):
                directories = web_results.get('directories', [])
                stats['directories_found'] = len(directories) if directories else 0
            else:
                # Legacy structure
                for tool_result in self.results.values():
                    if isinstance(tool_result, dict):
                        if 'directories_found' in tool_result:
                            dirs = tool_result['directories_found']
                            stats['directories_found'] += len(dirs) if dirs else 0
                        
                        if 'files_found' in tool_result:
                            files = tool_result['files_found']
                            stats['files_found'] += len(files) if files else 0
            
            # Security issues and vulnerabilities
            stats['security_issues'] = self._count_security_issues()
            stats['vulnerabilities'] = self._count_vulnerabilities()
            
        except Exception as e:
            self.logger.error(f"Error calculating summary stats: {str(e)}")
        
        return stats
    
    def _count_open_ports(self) -> int:
        """Count total open ports from scan results"""
        count = 0
        
        try:
            # Check nmap results
            nmap_results = self.results.get('nmap_scan', {})
            if isinstance(nmap_results, dict):
                for host_data in nmap_results.values():
                    if isinstance(host_data, dict) and 'tcp' in host_data:
                        tcp_ports = host_data['tcp']
                        count += len([p for p in tcp_ports.values() if p.get('state') == 'open'])
            
            # Check port scanner results
            for tool_result in self.results.values():
                if isinstance(tool_result, dict) and 'open_ports' in tool_result:
                    ports = tool_result['open_ports']
                    count += len(ports) if ports else 0
                    
        except Exception as e:
            self.logger.debug(f"Error counting open ports: {str(e)}")
        
        return count
    
    def _get_web_technologies(self) -> List[str]:
        """Get detected web technologies"""
        technologies = set()
        
        try:
            # Check web scan results
            web_results = self.results.get('web_scan', {})
            if isinstance(web_results, dict):
                for target_data in web_results.values():
                    if isinstance(target_data, dict) and 'technologies' in target_data:
                        tech_list = target_data['technologies']
                        if tech_list:
                            technologies.update(tech_list)
            
            # Check other tool results for technology detection
            for tool_result in self.results.values():
                if isinstance(tool_result, dict):
                    if 'technologies' in tool_result:
                        tech_list = tool_result['technologies']
                        if tech_list:
                            technologies.update(tech_list)
                    
                    if 'web_technologies' in tool_result:
                        tech_list = tool_result['web_technologies']
                        if tech_list:
                            technologies.update(tech_list)
                            
        except Exception as e:
            self.logger.debug(f"Error getting web technologies: {str(e)}")
        
        return list(technologies)
    
    def _count_security_issues(self) -> int:
        """Count total security issues"""
        count = 0
        
        try:
            # SSL/TLS issues
            ssl_results = self.results.get('ssl_scan', {})
            if isinstance(ssl_results, dict):
                vulnerabilities = ssl_results.get('vulnerabilities', [])
                count += len(vulnerabilities) if vulnerabilities else 0
            
            # Security analysis results
            security_results = self.results.get('security_analysis', {})
            if isinstance(security_results, dict):
                ssl_analysis = security_results.get('ssl_analysis', {})
                for port_data in ssl_analysis.values():
                    if isinstance(port_data, dict):
                        vulns = port_data.get('vulnerabilities', [])
                        count += len(vulns) if vulns else 0
            
            # Check other security-related results
            for tool_result in self.results.values():
                if isinstance(tool_result, dict):
                    if 'security_issues' in tool_result:
                        issues = tool_result['security_issues']
                        count += len(issues) if issues else 0
                    
                    if 'vulnerabilities' in tool_result:
                        vulns = tool_result['vulnerabilities']
                        count += len(vulns) if vulns else 0
                        
        except Exception as e:
            self.logger.debug(f"Error counting security issues: {str(e)}")
        
        return count
    
    def _count_vulnerabilities(self) -> int:
        """Count total vulnerabilities"""
        count = 0
        
        try:
            # Check vulnerability scanner results
            for tool_result in self.results.values():
                if isinstance(tool_result, dict):
                    if 'vulnerabilities_found' in tool_result:
                        vulns = tool_result['vulnerabilities_found']
                        count += len(vulns) if vulns else 0
                    
                    if 'vulnerability_count' in tool_result:
                        vuln_count = tool_result['vulnerability_count']
                        if isinstance(vuln_count, int):
                            count += vuln_count
                        elif isinstance(vuln_count, dict):
                            count += sum(vuln_count.values())
                            
        except Exception as e:
            self.logger.debug(f"Error counting vulnerabilities: {str(e)}")
        
        return count
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for safe file creation"""
        # Replace invalid characters
        invalid_chars = '<>:"/\\|?*'
        for char in invalid_chars:
            filename = filename.replace(char, '_')
        
        # Remove leading/trailing spaces and dots
        filename = filename.strip(' .')
        
        # Limit length
        if len(filename) > 200:
            filename = filename[:200]
        
        return filename
    
    def _get_report_filename(self, suffix: str, extension: str) -> str:
        """Generate report filename"""
        sanitized_target = self._sanitize_filename(self.target)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"{sanitized_target}_{suffix}_{timestamp}.{extension}"


class JSONReportGenerator(BaseReportGenerator):
    """JSON format report generator"""
    
    def generate_report(self) -> str:
        """Generate JSON report"""
        try:
            self.logger.info("Generating JSON report...")
            
            # Build complete JSON report
            json_report = {
                'metadata': self.scan_metadata,
                'target': self.target,
                'summary': self._calculate_summary_stats(),
                'results': self.results
            }
            
            # Save report
            filename = self._get_report_filename('report', 'json')
            report_file = self.reports_dir / filename
            
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(json_report, f, indent=2, default=str, ensure_ascii=False)
            
            self.logger.info(f"JSON report saved to {report_file}")
            return str(report_file)
            
        except Exception as e:
            self.logger.error(f"Error generating JSON report: {str(e)}")
            raise ScanError(f"Failed to generate JSON report: {str(e)}")


class MarkdownReportGenerator(BaseReportGenerator):
    """Markdown format report generator"""
    
    def generate_report(self) -> str:
        """Generate Markdown report"""
        try:
            self.logger.info("Generating Markdown report...")
            
            # Calculate summary stats
            summary = self._calculate_summary_stats()
            
            # Build mode banner
            mode_banner = ""
            if self.scan_metadata['mode'] == 'offline':
                mode_banner = "🔒 **Run Mode: Offline** (Internet-based sources intentionally skipped)\n\n"
            
            # Build report content
            content = f"""# Reconnaissance Report

## Target: {self.target}
**Scan Date:** {self.scan_metadata['report_generated_at']}

{mode_banner}---

## Executive Summary

This report contains the results of a comprehensive reconnaissance scan performed on the target `{self.target}`.

### Summary Statistics
- **Subdomains Found**: {summary['subdomains_found']}
- **Open Ports**: {summary['open_ports']}
- **Web Technologies**: {len(summary['web_technologies'])}
- **Security Issues**: {summary['security_issues']}
- **Directories Found**: {summary['directories_found']}
- **Files Found**: {summary['files_found']}
- **Vulnerabilities**: {summary['vulnerabilities']}

---

## Detailed Findings

{self._generate_nmap_section()}

{self._generate_subdomain_section()}

{self._generate_web_section()}

{self._generate_ssl_section()}

{self._generate_security_section()}

{self._generate_osint_section()}

---

*Report generated by ReconTool - Professional Reconnaissance Framework*
"""
            
            # Save report
            filename = self._get_report_filename('report', 'md')
            report_file = self.reports_dir / filename
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            self.logger.info(f"Markdown report saved to {report_file}")
            return str(report_file)
            
        except Exception as e:
            self.logger.error(f"Error generating Markdown report: {str(e)}")
            raise ScanError(f"Failed to generate Markdown report: {str(e)}")
    
    def _generate_nmap_section(self) -> str:
        """Generate Nmap scan section"""
        try:
            content = "### 🔍 Port Scan Results\n\n"
            
            # Check for port scan results
            nmap_results = self.results.get('nmap_scan', {})
            port_scan_results = self.results.get('port_scan', {})
            
            if not nmap_results and not port_scan_results:
                return content + "No port scan results available.\n\n"
            
            # Process nmap results
            if nmap_results:
                for host, data in nmap_results.items():
                    if isinstance(data, dict) and 'tcp' in data:
                        content += f"#### Host: {host}\n\n"
                        content += "| Port | State | Service | Version |\n"
                        content += "|------|-------|---------|----------|\n"
                        
                        for port, port_data in data['tcp'].items():
                            state = port_data.get('state', 'unknown')
                            service = port_data.get('name', 'unknown')
                            version = port_data.get('version', 'unknown')
                            content += f"| {port} | {state} | {service} | {version} |\n"
                        content += "\n"
            
            # Process port scanner results
            if port_scan_results and 'open_ports' in port_scan_results:
                open_ports = port_scan_results['open_ports']
                if open_ports:
                    content += "#### Open Ports Summary\n\n"
                    content += "| Port | Protocol | Service |\n"
                    content += "|------|----------|----------|\n"
                    
                    for port_info in open_ports:
                        if isinstance(port_info, dict):
                            port = port_info.get('port', 'N/A')
                            protocol = port_info.get('protocol', 'tcp')
                            service = port_info.get('service', 'unknown')
                            content += f"| {port} | {protocol} | {service} |\n"
                    content += "\n"
            
            return content if content != "### 🔍 Port Scan Results\n\n" else content + "No open ports found.\n\n"
            
        except Exception as e:
            self.logger.error(f"Error generating Nmap section: {str(e)}")
            return "### 🔍 Port Scan Results\n\nError generating port scan section.\n\n"
    
    def _generate_subdomain_section(self) -> str:
        """Generate subdomain enumeration section"""
        try:
            content = "### 🌐 Subdomain Enumeration\n\n"
            
            subdomains = self.results.get('subdomains', [])
            subdomain_results = self.results.get('subdomain_enumeration', {})
            
            if not subdomains and not subdomain_results:
                return content + "No subdomains found.\n\n"
            
            # Process basic subdomain list
            if subdomains:
                content += f"Total subdomains found: **{len(subdomains)}**\n\n"
                content += "| Subdomain | Status |\n"
                content += "|-----------|--------|\n"
                
                for subdomain in subdomains[:50]:  # Limit to first 50
                    if isinstance(subdomain, dict):
                        domain = subdomain.get('domain', 'unknown')
                        status = 'Live' if subdomain.get('live', False) else 'Unknown'
                    else:
                        domain = str(subdomain)
                        status = 'Found'
                    
                    content += f"| {domain} | {status} |\n"
                
                if len(subdomains) > 50:
                    content += f"\n*... and {len(subdomains) - 50} more subdomains*\n"
                content += "\n"
            
            # Process detailed subdomain results
            if subdomain_results and 'discovered_subdomains' in subdomain_results:
                discovered = subdomain_results['discovered_subdomains']
                if discovered:
                    content += f"#### Detailed Subdomain Analysis\n\n"
                    content += f"- **Total Discovered**: {len(discovered)}\n"
                    
                    # Count by status
                    live_count = len([s for s in discovered if s.get('live', False)])
                    content += f"- **Live Subdomains**: {live_count}\n\n"
            
            return content
            
        except Exception as e:
            self.logger.error(f"Error generating subdomain section: {str(e)}")
            return "### 🌐 Subdomain Enumeration\n\nError generating subdomain section.\n\n"
    
    def _generate_web_section(self) -> str:
        """Generate web application scan section"""
        try:
            content = "### 🕷️ Web Application Scan\n\n"
            
            web_results = self.results.get('web_scan', {})
            
            if not web_results:
                return content + "No web application scan results available.\n\n"
            
            for target, data in web_results.items():
                if isinstance(data, dict):
                    content += f"#### Target: {target}\n\n"
                    
                    # Technologies
                    technologies = data.get('technologies', [])
                    if technologies:
                        content += "**Technologies Detected:**\n"
                        for tech in technologies[:10]:  # Limit to first 10
                            content += f"- {tech}\n"
                        content += "\n"
                    
                    # Directories
                    directories = data.get('directories', [])
                    if directories:
                        content += "**Directories Found:**\n"
                        for directory in directories[:20]:  # Limit to first 20
                            content += f"- {directory}\n"
                        content += "\n"
                    
                    # Files
                    files = data.get('files', [])
                    if files:
                        content += "**Interesting Files:**\n"
                        for file in files[:15]:  # Limit to first 15
                            content += f"- {file}\n"
                        content += "\n"
            
            return content if content != "### 🕷️ Web Application Scan\n\n" else content + "No web application findings.\n\n"
            
        except Exception as e:
            self.logger.error(f"Error generating web section: {str(e)}")
            return "### 🕷️ Web Application Scan\n\nError generating web application section.\n\n"
    
    def _generate_ssl_section(self) -> str:
        """Generate SSL/TLS analysis section"""
        try:
            content = "### 🔒 SSL/TLS Analysis\n\n"
            
            ssl_results = self.results.get('security_analysis', {}).get('ssl_analysis', {})
            ssl_scan = self.results.get('ssl_scan', {})
            
            if not ssl_results and not ssl_scan:
                return content + "No SSL/TLS analysis results available.\n\n"
            
            # Process SSL scan results
            if ssl_scan:
                vulnerabilities = ssl_scan.get('vulnerabilities', [])
                if vulnerabilities:
                    content += "**SSL/TLS Vulnerabilities:**\n"
                    for vuln in vulnerabilities:
                        if isinstance(vuln, dict):
                            name = vuln.get('name', 'Unknown')
                            severity = vuln.get('severity', 'unknown').upper()
                            content += f"- **{severity}**: {name}\n"
                        else:
                            content += f"- {vuln}\n"
                    content += "\n"
            
            # Process detailed SSL analysis
            if ssl_results:
                for port_key, port_data in ssl_results.items():
                    port = port_key.replace('port_', '')
                    content += f"#### Port {port}\n\n"
                    
                    # Certificate info
                    cert_info = port_data.get('certificate')
                    if cert_info:
                        subject = cert_info.get('subject', {})
                        issuer = cert_info.get('issuer', {})
                        
                        content += "**Certificate Information:**\n"
                        content += f"- Subject: {subject.get('commonName', 'N/A')}\n"
                        content += f"- Issuer: {issuer.get('commonName', 'N/A')}\n"
                        content += f"- Valid Until: {cert_info.get('not_after', 'N/A')}\n\n"
                    
                    # Vulnerabilities for this port
                    vulnerabilities = port_data.get('vulnerabilities', [])
                    if vulnerabilities:
                        content += "**SSL/TLS Vulnerabilities:**\n"
                        for vuln in vulnerabilities:
                            severity = vuln.get('severity', 'unknown').upper()
                            name = vuln.get('name', 'unknown')
                            content += f"- **{severity}**: {name}\n"
                        content += "\n"
            
            return content if content != "### 🔒 SSL/TLS Analysis\n\n" else content + "No SSL/TLS issues found.\n\n"
            
        except Exception as e:
            self.logger.error(f"Error generating SSL section: {str(e)}")
            return "### 🔒 SSL/TLS Analysis\n\nError generating SSL/TLS section.\n\n"
    
    def _generate_security_section(self) -> str:
        """Generate security analysis section"""
        try:
            content = "### 🛡️ Security Analysis\n\n"
            
            security_results = self.results.get('security_analysis', {})
            vulnerability_results = self.results.get('vulnerability_scan', {})
            
            if not security_results and not vulnerability_results:
                return content + "No security analysis results available.\n\n"
            
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
            
            content += f"**Security Summary:**\n"
            content += f"- Total Vulnerabilities: {total_vulns}\n"
            content += f"- Critical Vulnerabilities: {critical_vulns}\n\n"
            
            if total_vulns > 0:
                content += "**Recommendations:**\n"
                if critical_vulns > 0:
                    content += "- Address critical vulnerabilities immediately\n"
                content += "- Implement SSL/TLS best practices\n"
                content += "- Regular security assessments recommended\n\n"
            
            return content
            
        except Exception as e:
            self.logger.error(f"Error generating security section: {str(e)}")
            return "### 🛡️ Security Analysis\n\nError generating security analysis section.\n\n"
    
    def _generate_osint_section(self) -> str:
        """Generate OSINT findings section"""
        try:
            content = "### 🔍 OSINT Findings\n\n"
            
            osint_results = self.results.get('osint', {})
            
            if not osint_results:
                return content + "No OSINT findings available.\n\n"
            
            # DNS records
            dns_records = osint_results.get('dns_records', {})
            if dns_records:
                content += "**DNS Records:**\n"
                for record_type, records in dns_records.items():
                    if records:
                        content += f"- {record_type.upper()}: {len(records)} records\n"
                content += "\n"
            
            # WHOIS information
            whois_data = osint_results.get('whois', {})
            if whois_data:
                content += "**WHOIS Information:**\n"
                if 'registrar' in whois_data:
                    content += f"- Registrar: {whois_data['registrar']}\n"
                if 'creation_date' in whois_data:
                    content += f"- Created: {whois_data['creation_date']}\n"
                if 'expiration_date' in whois_data:
                    content += f"- Expires: {whois_data['expiration_date']}\n"
                content += "\n"
            
            # Wayback Machine
            wayback_data = osint_results.get('wayback_machine', {})
            if wayback_data:
                urls = wayback_data.get('urls', [])
                if urls:
                    content += f"**Wayback Machine:** {len(urls)} historical URLs found\n\n"
            
            # Shodan results
            shodan_data = osint_results.get('shodan', {})
            if shodan_data:
                results = shodan_data.get('results', [])
                if results:
                    content += f"**Shodan Intelligence:** {len(results)} entries found\n\n"
            
            return content if content != "### 🔍 OSINT Findings\n\n" else content + "No OSINT findings available.\n\n"
            
        except Exception as e:
            self.logger.error(f"Error generating OSINT section: {str(e)}")
            return "### 🔍 OSINT Findings\n\nError generating OSINT section.\n\n"
