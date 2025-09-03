"""
Enhanced Result Processing System v2.0
Comprehensive result processing with normalization, correlation, aggregation, and risk scoring
"""

import json
import logging
import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, List, Optional, Set, Tuple, Union
from collections import defaultdict, Counter
from pathlib import Path

from .exceptions import ResultProcessingError
from .logger import setup_logger


class SeverityLevel(Enum):
    """Severity level enumeration"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class FindingType(Enum):
    """Finding type enumeration"""
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    INFORMATION_DISCLOSURE = "information_disclosure"
    WEAK_CONFIGURATION = "weak_configuration"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    OPEN_SERVICE = "open_service"
    SSL_ISSUE = "ssl_issue"
    DNS_ISSUE = "dns_issue"
    WEB_ISSUE = "web_issue"
    UNKNOWN = "unknown"


class ConfidenceLevel(Enum):
    """Confidence level for findings"""
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"
    UNLIKELY = "unlikely"
    FALSE_POSITIVE = "false_positive"


@dataclass
class NormalizedFinding:
    """Normalized finding across all tools"""
    # Identification
    finding_id: str = field(default_factory=lambda: hashlib.md5(str(time.time()).encode()).hexdigest()[:8])
    title: str = ""
    description: str = ""
    
    # Classification
    finding_type: FindingType = FindingType.UNKNOWN
    severity: SeverityLevel = SeverityLevel.UNKNOWN
    confidence: ConfidenceLevel = ConfidenceLevel.POSSIBLE
    
    # Target information
    target: str = ""
    port: Optional[int] = None
    service: Optional[str] = None
    protocol: Optional[str] = None
    
    # Source information
    source_tool: str = ""
    source_scan: str = ""
    raw_output: Dict[str, Any] = field(default_factory=dict)
    
    # Risk assessment
    risk_score: float = 0.0
    risk_factors: List[str] = field(default_factory=list)
    
    # Correlation data
    related_findings: List[str] = field(default_factory=list)
    correlation_score: float = 0.0
    
    # Metadata
    created_at: float = field(default_factory=time.time)
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    remediation: Optional[str] = None
    
    # False positive detection
    fp_indicators: List[str] = field(default_factory=list)
    is_false_positive: bool = False
    fp_reason: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'finding_id': self.finding_id,
            'title': self.title,
            'description': self.description,
            'finding_type': self.finding_type.value,
            'severity': self.severity.value,
            'confidence': self.confidence.value,
            'target': self.target,
            'port': self.port,
            'service': self.service,
            'protocol': self.protocol,
            'source_tool': self.source_tool,
            'source_scan': self.source_scan,
            'raw_output': self.raw_output,
            'risk_score': self.risk_score,
            'risk_factors': self.risk_factors,
            'related_findings': self.related_findings,
            'correlation_score': self.correlation_score,
            'created_at': self.created_at,
            'tags': self.tags,
            'references': self.references,
            'remediation': self.remediation,
            'fp_indicators': self.fp_indicators,
            'is_false_positive': self.is_false_positive,
            'fp_reason': self.fp_reason
        }


@dataclass
class ProcessingStats:
    """Statistics for result processing"""
    total_raw_results: int = 0
    total_normalized_findings: int = 0
    false_positives_filtered: int = 0
    correlations_found: int = 0
    
    # By severity
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0
    
    # By tool
    tool_contributions: Dict[str, int] = field(default_factory=dict)
    
    # Processing time
    processing_start: float = field(default_factory=time.time)
    processing_end: Optional[float] = None
    
    def processing_duration(self) -> float:
        """Get processing duration in seconds"""
        end_time = self.processing_end or time.time()
        return end_time - self.processing_start
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'total_raw_results': self.total_raw_results,
            'total_normalized_findings': self.total_normalized_findings,
            'false_positives_filtered': self.false_positives_filtered,
            'correlations_found': self.correlations_found,
            'critical_findings': self.critical_findings,
            'high_findings': self.high_findings,
            'medium_findings': self.medium_findings,
            'low_findings': self.low_findings,
            'info_findings': self.info_findings,
            'tool_contributions': self.tool_contributions,
            'processing_duration': self.processing_duration()
        }


class ResultProcessor:
    """Enhanced result processor with comprehensive capabilities"""
    
    def __init__(self,
                 enable_correlation: bool = True,
                 enable_fp_filtering: bool = True,
                 enable_risk_scoring: bool = True,
                 correlation_threshold: float = 0.7,
                 fp_threshold: float = 0.8):
        """
        Initialize result processor
        
        Args:
            enable_correlation: Whether to correlate findings across tools
            enable_fp_filtering: Whether to filter false positives
            enable_risk_scoring: Whether to calculate risk scores
            correlation_threshold: Minimum score for correlation
            fp_threshold: Minimum score for false positive classification
        """
        self.enable_correlation = enable_correlation
        self.enable_fp_filtering = enable_fp_filtering
        self.enable_risk_scoring = enable_risk_scoring
        self.correlation_threshold = correlation_threshold
        self.fp_threshold = fp_threshold
        
        # Setup logging
        self.logger = setup_logger('result_processor', logging.INFO)
        
        # Processing state
        self.normalized_findings: List[NormalizedFinding] = []
        self.stats = ProcessingStats()
        
        # Load processing rules
        self.normalization_rules = self._load_normalization_rules()
        self.correlation_rules = self._load_correlation_rules()
        self.fp_patterns = self._load_fp_patterns()
        self.risk_scoring_rules = self._load_risk_scoring_rules()
    
    def _add_tool_contribution(self, tool_name: str) -> None:
        """Add a contribution to tool statistics"""
        if tool_name not in self.stats.tool_contributions:
            self.stats.tool_contributions[tool_name] = 0
        self.stats.tool_contributions[tool_name] += 1
    
    def process_scan_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process comprehensive scan results
        
        Args:
            scan_results: Raw scan results from orchestrator
            
        Returns:
            Dict with processed results and statistics
        """
        self.stats = ProcessingStats()
        self.normalized_findings.clear()
        
        self.logger.info("🔄 Processing scan results...")
        
        # Step 1: Normalize results from different tools
        self.logger.info("1️⃣  Normalizing results across tools...")
        self._normalize_tool_results(scan_results)
        
        # Step 2: Filter false positives
        if self.enable_fp_filtering:
            self.logger.info("2️⃣  Filtering false positives...")
            self._filter_false_positives()
        
        # Step 3: Calculate risk scores
        if self.enable_risk_scoring:
            self.logger.info("3️⃣  Calculating risk scores...")
            self._calculate_risk_scores()
        
        # Step 4: Correlate findings across tools
        if self.enable_correlation:
            self.logger.info("4️⃣  Correlating findings across tools...")
            self._correlate_findings()
        
        # Step 5: Aggregate and summarize
        self.logger.info("5️⃣  Aggregating results...")
        aggregated_results = self._aggregate_results()
        
        # Update statistics
        self._update_final_statistics()
        self.stats.processing_end = time.time()
        
        # Return comprehensive results
        return {
            'findings': [f.to_dict() for f in self.normalized_findings],
            'aggregated_results': aggregated_results,
            'statistics': self.stats.to_dict(),
            'summary': self._generate_summary(),
            'recommendations': self._generate_recommendations(),
            'correlation_matrix': self._build_correlation_matrix()
        }
    
    def _normalize_tool_results(self, scan_results: Dict[str, Any]) -> None:
        """Normalize results from different tools into common format"""
        tool_results = scan_results.get('results', {})
        self.stats.total_raw_results = len(tool_results)
        
        for tool_name, tool_result in tool_results.items():
            if not tool_result or tool_result.get('error'):
                continue
                
            # Normalize based on tool type
            if tool_name == 'port':
                self._normalize_port_scan_results(tool_result, tool_name)
            elif tool_name == 'subdomain':
                self._normalize_subdomain_results(tool_result, tool_name)
            elif tool_name == 'web':
                self._normalize_web_scan_results(tool_result, tool_name)
            elif tool_name == 'ssl':
                self._normalize_ssl_results(tool_result, tool_name)
            elif tool_name == 'dns':
                self._normalize_dns_results(tool_result, tool_name)
            elif tool_name == 'directory':
                self._normalize_directory_results(tool_result, tool_name)
            elif tool_name == 'vulnerability':
                self._normalize_vulnerability_results(tool_result, tool_name)
            elif tool_name == 'osint':
                self._normalize_osint_results(tool_result, tool_name)
            
            # Update tool contribution stats
            if tool_name not in self.stats.tool_contributions:
                self.stats.tool_contributions[tool_name] = 0
    
    def _normalize_port_scan_results(self, results: Dict[str, Any], tool_name: str) -> None:
        """Normalize port scan results"""
        hosts = results.get('hosts', [])
        target = results.get('target', 'unknown')
        
        for host in hosts:
            host_address = host.get('address', host.get('ip', 'unknown'))
            ports = host.get('ports', [])
            
            for port_info in ports:
                port_num = port_info.get('port')
                service = port_info.get('service', {})
                state = port_info.get('state', 'unknown')
                
                if state == 'open':
                    finding = NormalizedFinding(
                        title=f"Open Port {port_num}",
                        description=f"Port {port_num} is open on {host_address}",
                        finding_type=FindingType.OPEN_SERVICE,
                        severity=self._assess_port_severity(port_num, service),
                        confidence=ConfidenceLevel.CONFIRMED,
                        target=host_address,
                        port=int(port_num) if port_num else None,
                        service=service.get('name', 'unknown'),
                        protocol=port_info.get('protocol', 'tcp'),
                        source_tool=tool_name,
                        raw_output=port_info
                    )
                    
                    # Add service-specific tags
                    if service.get('name'):
                        finding.tags.append(f"service:{service['name']}")
                    if service.get('version'):
                        finding.tags.append(f"version:{service['version']}")
                    
                    self.normalized_findings.append(finding)
                    self._add_tool_contribution(tool_name)
    
    def _normalize_subdomain_results(self, results: Dict[str, Any], tool_name: str) -> None:
        """Normalize subdomain enumeration results"""
        subdomains = results.get('subdomains', [])
        target = results.get('target', 'unknown')
        
        for subdomain in subdomains:
            if isinstance(subdomain, str):
                subdomain_name = subdomain
                subdomain_info = {}
            else:
                subdomain_name = subdomain.get('name', subdomain.get('subdomain', 'unknown'))
                subdomain_info = subdomain
            
            finding = NormalizedFinding(
                title=f"Subdomain Discovered: {subdomain_name}",
                description=f"Subdomain {subdomain_name} discovered for {target}",
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                severity=SeverityLevel.INFO,
                confidence=ConfidenceLevel.CONFIRMED,
                target=subdomain_name,
                source_tool=tool_name,
                raw_output=subdomain_info
            )
            
            finding.tags.append('subdomain')
            if 'admin' in subdomain_name or 'api' in subdomain_name:
                finding.severity = SeverityLevel.MEDIUM
                finding.tags.append('high-value')
            
            self.normalized_findings.append(finding)
            self._add_tool_contribution(tool_name)
    
    def _normalize_web_scan_results(self, results: Dict[str, Any], tool_name: str) -> None:
        """Normalize web scan results"""
        target = results.get('target', 'unknown')
        status_code = results.get('status_code')
        headers = results.get('headers', {})
        technologies = results.get('technologies', [])
        
        # HTTP status finding
        if status_code:
            severity = SeverityLevel.INFO
            if status_code in [500, 502, 503]:
                severity = SeverityLevel.LOW
            elif status_code in [403, 401]:
                severity = SeverityLevel.MEDIUM
            
            finding = NormalizedFinding(
                title=f"HTTP Response: {status_code}",
                description=f"HTTP response code {status_code} for {target}",
                finding_type=FindingType.WEB_ISSUE,
                severity=severity,
                confidence=ConfidenceLevel.CONFIRMED,
                target=target,
                source_tool=tool_name,
                raw_output={'status_code': status_code, 'headers': headers}
            )
            
            finding.tags.append(f"http-{status_code}")
            self.normalized_findings.append(finding)
            self._add_tool_contribution(tool_name)
        
        # Technology findings
        for tech in technologies:
            finding = NormalizedFinding(
                title=f"Technology Detected: {tech}",
                description=f"Web technology {tech} detected on {target}",
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                severity=SeverityLevel.INFO,
                confidence=ConfidenceLevel.LIKELY,
                target=target,
                source_tool=tool_name,
                raw_output={'technology': tech}
            )
            
            finding.tags.append('technology')
            finding.tags.append(f"tech:{tech.lower()}")
            self.normalized_findings.append(finding)
            self._add_tool_contribution(tool_name)
    
    def _normalize_ssl_results(self, results: Dict[str, Any], tool_name: str) -> None:
        """Normalize SSL scan results"""
        target = results.get('target', 'unknown')
        certificate = results.get('certificate', {})
        vulnerabilities = results.get('vulnerabilities', [])
        
        # Certificate findings
        if certificate:
            # Check for expired certificates
            if certificate.get('expired', False):
                finding = NormalizedFinding(
                    title="Expired SSL Certificate",
                    description=f"SSL certificate for {target} has expired",
                    finding_type=FindingType.SSL_ISSUE,
                    severity=SeverityLevel.HIGH,
                    confidence=ConfidenceLevel.CONFIRMED,
                    target=target,
                    source_tool=tool_name,
                    raw_output=certificate
                )
                
                finding.tags.extend(['ssl', 'certificate', 'expired'])
                self.normalized_findings.append(finding)
                self._add_tool_contribution(tool_name)
            
            # Check for weak ciphers
            weak_ciphers = certificate.get('weak_ciphers', [])
            for cipher in weak_ciphers:
                finding = NormalizedFinding(
                    title=f"Weak SSL Cipher: {cipher}",
                    description=f"Weak SSL cipher {cipher} detected on {target}",
                    finding_type=FindingType.WEAK_CONFIGURATION,
                    severity=SeverityLevel.MEDIUM,
                    confidence=ConfidenceLevel.CONFIRMED,
                    target=target,
                    source_tool=tool_name,
                    raw_output={'cipher': cipher}
                )
                
                finding.tags.extend(['ssl', 'weak-cipher'])
                self.normalized_findings.append(finding)
                self._add_tool_contribution(tool_name)
        
        # SSL vulnerabilities
        for vuln in vulnerabilities:
            severity = self._map_vulnerability_severity(vuln.get('severity', 'unknown'))
            
            finding = NormalizedFinding(
                title=f"SSL Vulnerability: {vuln.get('name', 'Unknown')}",
                description=vuln.get('description', f"SSL vulnerability detected on {target}"),
                finding_type=FindingType.VULNERABILITY,
                severity=severity,
                confidence=ConfidenceLevel.CONFIRMED,
                target=target,
                source_tool=tool_name,
                raw_output=vuln
            )
            
            finding.tags.extend(['ssl', 'vulnerability'])
            if vuln.get('cve'):
                finding.references.append(f"CVE: {vuln['cve']}")
            
            self.normalized_findings.append(finding)
            self._add_tool_contribution(tool_name)
    
    def _normalize_dns_results(self, results: Dict[str, Any], tool_name: str) -> None:
        """Normalize DNS scan results"""
        target = results.get('target', 'unknown')
        records = results.get('records', {})
        
        for record_type, record_values in records.items():
            if not record_values:
                continue
                
            for record_value in record_values:
                finding = NormalizedFinding(
                    title=f"DNS Record: {record_type}",
                    description=f"DNS {record_type} record found for {target}: {record_value}",
                    finding_type=FindingType.INFORMATION_DISCLOSURE,
                    severity=SeverityLevel.INFO,
                    confidence=ConfidenceLevel.CONFIRMED,
                    target=target,
                    source_tool=tool_name,
                    raw_output={'record_type': record_type, 'value': record_value}
                )
                
                finding.tags.extend(['dns', f"record-{record_type.lower()}"])
                
                # Highlight sensitive records
                if record_type.upper() in ['TXT', 'SPF', 'DMARC']:
                    finding.severity = SeverityLevel.LOW
                    finding.tags.append('sensitive')
                
                self.normalized_findings.append(finding)
                self._add_tool_contribution(tool_name)
    
    def _normalize_directory_results(self, results: Dict[str, Any], tool_name: str) -> None:
        """Normalize directory scan results"""
        target = results.get('target', 'unknown')
        directories = results.get('directories', [])
        
        for directory in directories:
            if isinstance(directory, str):
                dir_path = directory
                status_code = None
            else:
                dir_path = directory.get('path', directory.get('url', 'unknown'))
                status_code = directory.get('status_code')
            
            # Assess severity based on directory name
            severity = SeverityLevel.INFO
            if any(sensitive in dir_path.lower() for sensitive in ['admin', 'config', 'backup', '.git', '.env']):
                severity = SeverityLevel.MEDIUM
            elif any(critical in dir_path.lower() for critical in ['database', 'db', 'sql', 'password']):
                severity = SeverityLevel.HIGH
            
            finding = NormalizedFinding(
                title=f"Directory Found: {dir_path}",
                description=f"Directory {dir_path} discovered on {target}",
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                severity=severity,
                confidence=ConfidenceLevel.CONFIRMED,
                target=target,
                source_tool=tool_name,
                raw_output={'path': dir_path, 'status_code': status_code}
            )
            
            finding.tags.append('directory')
            if severity != SeverityLevel.INFO:
                finding.tags.append('sensitive')
            
            self.normalized_findings.append(finding)
            self._add_tool_contribution(tool_name)
    
    def _normalize_vulnerability_results(self, results: Dict[str, Any], tool_name: str) -> None:
        """Normalize vulnerability scan results"""
        target = results.get('target', 'unknown')
        vulnerabilities = results.get('vulnerabilities', [])
        
        for vuln in vulnerabilities:
            severity = self._map_vulnerability_severity(vuln.get('severity', 'unknown'))
            
            finding = NormalizedFinding(
                title=f"Vulnerability: {vuln.get('name', 'Unknown')}",
                description=vuln.get('description', f"Vulnerability detected on {target}"),
                finding_type=FindingType.VULNERABILITY,
                severity=severity,
                confidence=ConfidenceLevel.CONFIRMED,
                target=target,
                port=vuln.get('port'),
                service=vuln.get('service'),
                source_tool=tool_name,
                raw_output=vuln
            )
            
            finding.tags.append('vulnerability')
            if vuln.get('cve'):
                finding.references.append(f"CVE: {vuln['cve']}")
                finding.tags.append(f"cve:{vuln['cve']}")
            if vuln.get('cvss'):
                finding.tags.append(f"cvss:{vuln['cvss']}")
            
            self.normalized_findings.append(finding)
            self._add_tool_contribution(tool_name)
    
    def _normalize_osint_results(self, results: Dict[str, Any], tool_name: str) -> None:
        """Normalize OSINT results"""
        target = results.get('target', 'unknown')
        information = results.get('information', [])
        
        for info in information:
            if isinstance(info, str):
                info_value = info
                info_type = 'general'
            else:
                info_value = info.get('value', info.get('data', 'unknown'))
                info_type = info.get('type', 'general')
            
            finding = NormalizedFinding(
                title=f"OSINT Information: {info_type}",
                description=f"OSINT information discovered for {target}: {info_value}",
                finding_type=FindingType.INFORMATION_DISCLOSURE,
                severity=SeverityLevel.INFO,
                confidence=ConfidenceLevel.LIKELY,
                target=target,
                source_tool=tool_name,
                raw_output={'type': info_type, 'value': info_value}
            )
            
            finding.tags.extend(['osint', f"type:{info_type}"])
            
            # Assess sensitivity
            if any(sensitive in info_value.lower() for sensitive in ['email', 'phone', 'address', 'personal']):
                finding.severity = SeverityLevel.LOW
                finding.tags.append('pii')
            
            self.normalized_findings.append(finding)
            self._add_tool_contribution(tool_name)
    
    def _filter_false_positives(self) -> None:
        """Filter likely false positives"""
        filtered_findings = []
        
        for finding in self.normalized_findings:
            fp_score = self._calculate_fp_score(finding)
            
            if fp_score >= self.fp_threshold:
                finding.is_false_positive = True
                finding.fp_reason = self._get_fp_reason(finding)
                self.stats.false_positives_filtered += 1
            else:
                filtered_findings.append(finding)
        
        self.normalized_findings = filtered_findings
    
    def _calculate_fp_score(self, finding: NormalizedFinding) -> float:
        """Calculate false positive probability score (0-1)"""
        fp_score = 0.0
        
        # Check against known FP patterns
        for pattern in self.fp_patterns:
            if pattern['type'] == finding.finding_type.value:
                if any(keyword in finding.description.lower() for keyword in pattern.get('keywords', [])):
                    fp_score += pattern.get('weight', 0.1)
        
        # Port-based FP detection
        if finding.port:
            # Common false positives for certain ports
            if finding.port in [80, 443] and 'closed' in finding.description.lower():
                fp_score += 0.3
        
        # Service-based FP detection
        if finding.service:
            # Common false positives for certain services
            if finding.service in ['http', 'https'] and finding.severity == SeverityLevel.CRITICAL:
                fp_score += 0.2
        
        return min(fp_score, 1.0)
    
    def _get_fp_reason(self, finding: NormalizedFinding) -> str:
        """Get reason for false positive classification"""
        reasons = []
        
        if finding.port in [80, 443] and 'closed' in finding.description.lower():
            reasons.append("Common port status report")
        
        if finding.service in ['http', 'https'] and finding.severity == SeverityLevel.CRITICAL:
            reasons.append("Unlikely critical severity for common web service")
        
        return "; ".join(reasons) if reasons else "Pattern-based classification"
    
    def _calculate_risk_scores(self) -> None:
        """Calculate risk scores for findings"""
        for finding in self.normalized_findings:
            risk_score = 0.0
            risk_factors = []
            
            # Base severity scoring
            severity_scores = {
                SeverityLevel.CRITICAL: 9.0,
                SeverityLevel.HIGH: 7.0,
                SeverityLevel.MEDIUM: 5.0,
                SeverityLevel.LOW: 3.0,
                SeverityLevel.INFO: 1.0
            }
            risk_score += severity_scores.get(finding.severity, 0.0)
            
            # Confidence adjustment
            confidence_multipliers = {
                ConfidenceLevel.CONFIRMED: 1.0,
                ConfidenceLevel.LIKELY: 0.8,
                ConfidenceLevel.POSSIBLE: 0.6,
                ConfidenceLevel.UNLIKELY: 0.4
            }
            risk_score *= confidence_multipliers.get(finding.confidence, 0.5)
            
            # Port-based risk adjustment
            if finding.port:
                if finding.port in [22, 23, 21, 3389]:  # High-risk ports
                    risk_score += 1.0
                    risk_factors.append("High-risk port")
                elif finding.port in [80, 443, 8080, 8443]:  # Web ports
                    risk_score += 0.5
                    risk_factors.append("Web service port")
            
            # Service-based risk adjustment
            if finding.service:
                if finding.service in ['ssh', 'telnet', 'ftp', 'rdp']:
                    risk_score += 1.0
                    risk_factors.append("Remote access service")
                elif finding.service in ['mysql', 'postgresql', 'mongodb']:
                    risk_score += 1.5
                    risk_factors.append("Database service")
            
            # Finding type adjustment
            if finding.finding_type == FindingType.VULNERABILITY:
                risk_score += 2.0
                risk_factors.append("Security vulnerability")
            elif finding.finding_type == FindingType.MISCONFIGURATION:
                risk_score += 1.0
                risk_factors.append("Configuration issue")
            
            # Tag-based adjustments
            for tag in finding.tags:
                if tag in ['admin', 'api', 'database', 'sensitive']:
                    risk_score += 0.5
                    risk_factors.append(f"Sensitive component: {tag}")
                elif tag.startswith('cve:'):
                    risk_score += 1.5
                    risk_factors.append("CVE vulnerability")
            
            finding.risk_score = min(risk_score, 10.0)  # Cap at 10.0
            finding.risk_factors = risk_factors
    
    def _correlate_findings(self) -> None:
        """Correlate findings across different tools"""
        correlations_found = 0
        
        for i, finding1 in enumerate(self.normalized_findings):
            for j, finding2 in enumerate(self.normalized_findings[i+1:], i+1):
                correlation_score = self._calculate_correlation_score(finding1, finding2)
                
                if correlation_score >= self.correlation_threshold:
                    # Add cross-references
                    finding1.related_findings.append(finding2.finding_id)
                    finding2.related_findings.append(finding1.finding_id)
                    
                    finding1.correlation_score = max(finding1.correlation_score, correlation_score)
                    finding2.correlation_score = max(finding2.correlation_score, correlation_score)
                    
                    correlations_found += 1
        
        self.stats.correlations_found = correlations_found
    
    def _calculate_correlation_score(self, finding1: NormalizedFinding, finding2: NormalizedFinding) -> float:
        """Calculate correlation score between two findings"""
        score = 0.0
        
        # Same target correlation
        if finding1.target == finding2.target:
            score += 0.3
        
        # Same port correlation
        if finding1.port and finding2.port and finding1.port == finding2.port:
            score += 0.2
        
        # Same service correlation
        if finding1.service and finding2.service and finding1.service == finding2.service:
            score += 0.2
        
        # Related finding types
        related_types = {
            (FindingType.OPEN_SERVICE, FindingType.VULNERABILITY): 0.4,
            (FindingType.OPEN_SERVICE, FindingType.WEAK_CONFIGURATION): 0.3,
            (FindingType.WEB_ISSUE, FindingType.INFORMATION_DISCLOSURE): 0.3,
            (FindingType.SSL_ISSUE, FindingType.WEAK_CONFIGURATION): 0.4
        }
        
        type_pair = (finding1.finding_type, finding2.finding_type)
        reverse_pair = (finding2.finding_type, finding1.finding_type)
        
        if type_pair in related_types:
            score += related_types[type_pair]
        elif reverse_pair in related_types:
            score += related_types[reverse_pair]
        
        # Tag overlap
        common_tags = set(finding1.tags) & set(finding2.tags)
        if common_tags:
            score += len(common_tags) * 0.1
        
        return min(score, 1.0)
    
    def _aggregate_results(self) -> Dict[str, Any]:
        """Aggregate results by various dimensions"""
        aggregated = {
            'by_severity': defaultdict(list),
            'by_type': defaultdict(list),
            'by_target': defaultdict(list),
            'by_tool': defaultdict(list),
            'by_port': defaultdict(list),
            'by_service': defaultdict(list)
        }
        
        for finding in self.normalized_findings:
            # Aggregate by severity
            aggregated['by_severity'][finding.severity.value].append(finding.to_dict())
            
            # Aggregate by type
            aggregated['by_type'][finding.finding_type.value].append(finding.to_dict())
            
            # Aggregate by target
            aggregated['by_target'][finding.target].append(finding.to_dict())
            
            # Aggregate by tool
            aggregated['by_tool'][finding.source_tool].append(finding.to_dict())
            
            # Aggregate by port
            if finding.port:
                aggregated['by_port'][str(finding.port)].append(finding.to_dict())
            
            # Aggregate by service
            if finding.service:
                aggregated['by_service'][finding.service].append(finding.to_dict())
        
        # Convert defaultdicts to regular dicts
        return {k: dict(v) for k, v in aggregated.items()}
    
    def _update_final_statistics(self) -> None:
        """Update final processing statistics"""
        self.stats.total_normalized_findings = len(self.normalized_findings)
        
        # Count by severity
        for finding in self.normalized_findings:
            if finding.severity == SeverityLevel.CRITICAL:
                self.stats.critical_findings += 1
            elif finding.severity == SeverityLevel.HIGH:
                self.stats.high_findings += 1
            elif finding.severity == SeverityLevel.MEDIUM:
                self.stats.medium_findings += 1
            elif finding.severity == SeverityLevel.LOW:
                self.stats.low_findings += 1
            elif finding.severity == SeverityLevel.INFO:
                self.stats.info_findings += 1
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate processing summary"""
        total_findings = len(self.normalized_findings)
        high_risk_findings = self.stats.critical_findings + self.stats.high_findings
        
        return {
            'total_findings': total_findings,
            'high_risk_findings': high_risk_findings,
            'false_positives_filtered': self.stats.false_positives_filtered,
            'correlations_found': self.stats.correlations_found,
            'processing_duration': self.stats.processing_duration(),
            'top_risk_findings': self._get_top_risk_findings(5),
            'most_active_tool': max(self.stats.tool_contributions.items(), key=lambda x: x[1])[0] if self.stats.tool_contributions else None,
            'findings_by_severity': {
                'critical': self.stats.critical_findings,
                'high': self.stats.high_findings,
                'medium': self.stats.medium_findings,
                'low': self.stats.low_findings,
                'info': self.stats.info_findings
            }
        }
    
    def _get_top_risk_findings(self, limit: int) -> List[Dict[str, Any]]:
        """Get top risk findings"""
        sorted_findings = sorted(self.normalized_findings, key=lambda f: f.risk_score, reverse=True)
        return [f.to_dict() for f in sorted_findings[:limit]]
    
    def _generate_recommendations(self) -> List[str]:
        """Generate processing recommendations"""
        recommendations = []
        
        if self.stats.critical_findings > 0:
            recommendations.append(f"URGENT: {self.stats.critical_findings} critical findings require immediate attention")
        
        if self.stats.high_findings > 0:
            recommendations.append(f"HIGH PRIORITY: {self.stats.high_findings} high-severity findings need prompt remediation")
        
        if self.stats.false_positives_filtered > 0:
            recommendations.append(f"Filtered {self.stats.false_positives_filtered} likely false positives - review if necessary")
        
        if self.stats.correlations_found > 0:
            recommendations.append(f"Found {self.stats.correlations_found} correlated findings - review for attack chains")
        
        # Tool-specific recommendations
        most_findings_tool = max(self.stats.tool_contributions.items(), key=lambda x: x[1])[0] if self.stats.tool_contributions else None
        if most_findings_tool:
            recommendations.append(f"Tool '{most_findings_tool}' produced the most findings - focus on those results")
        
        return recommendations
    
    def _build_correlation_matrix(self) -> Dict[str, Any]:
        """Build correlation matrix for visualization"""
        matrix = {}
        
        for finding in self.normalized_findings:
            if finding.related_findings:
                matrix[finding.finding_id] = {
                    'title': finding.title,
                    'severity': finding.severity.value,
                    'related_to': finding.related_findings,
                    'correlation_score': finding.correlation_score
                }
        
        return matrix
    
    def _assess_port_severity(self, port: int, service: Dict[str, Any]) -> SeverityLevel:
        """Assess severity based on port and service"""
        if port in [22, 23, 21, 3389, 5900]:  # Remote access ports
            return SeverityLevel.MEDIUM
        elif port in [1433, 3306, 5432, 6379, 27017]:  # Database ports
            return SeverityLevel.HIGH
        elif port in [80, 443, 8080, 8443]:  # Web ports
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO
    
    def _map_vulnerability_severity(self, severity_str: str) -> SeverityLevel:
        """Map vulnerability severity string to enum"""
        severity_map = {
            'critical': SeverityLevel.CRITICAL,
            'high': SeverityLevel.HIGH,
            'medium': SeverityLevel.MEDIUM,
            'low': SeverityLevel.LOW,
            'info': SeverityLevel.INFO,
            'informational': SeverityLevel.INFO
        }
        
        return severity_map.get(severity_str.lower(), SeverityLevel.UNKNOWN)
    
    def _load_normalization_rules(self) -> Dict[str, Any]:
        """Load normalization rules"""
        return {
            'port_severity_map': {
                'remote_access': [22, 23, 21, 3389, 5900],
                'database': [1433, 3306, 5432, 6379, 27017],
                'web': [80, 443, 8080, 8443],
                'mail': [25, 110, 143, 993, 995]
            },
            'service_risk_map': {
                'high': ['ssh', 'telnet', 'ftp', 'rdp', 'vnc'],
                'medium': ['mysql', 'postgresql', 'mongodb', 'redis'],
                'low': ['http', 'https', 'smtp', 'pop3', 'imap']
            }
        }
    
    def _load_correlation_rules(self) -> Dict[str, Any]:
        """Load correlation rules"""
        return {
            'same_target_weight': 0.3,
            'same_port_weight': 0.2,
            'same_service_weight': 0.2,
            'related_types': {
                'open_service_vulnerability': 0.4,
                'web_information_disclosure': 0.3,
                'ssl_weak_configuration': 0.4
            }
        }
    
    def _load_fp_patterns(self) -> List[Dict[str, Any]]:
        """Load false positive patterns"""
        return [
            {
                'type': 'open_service',
                'keywords': ['closed', 'filtered', 'timeout'],
                'weight': 0.5
            },
            {
                'type': 'web_issue',
                'keywords': ['normal response', 'expected behavior'],
                'weight': 0.3
            },
            {
                'type': 'information_disclosure',
                'keywords': ['common directory', 'standard response'],
                'weight': 0.2
            }
        ]
    
    def _load_risk_scoring_rules(self) -> Dict[str, Any]:
        """Load risk scoring rules"""
        return {
            'severity_base_scores': {
                'critical': 9.0,
                'high': 7.0,
                'medium': 5.0,
                'low': 3.0,
                'info': 1.0
            },
            'confidence_multipliers': {
                'confirmed': 1.0,
                'likely': 0.8,
                'possible': 0.6,
                'unlikely': 0.4
            },
            'port_risk_bonus': {
                'remote_access': 1.0,
                'database': 1.5,
                'web': 0.5
            },
            'tag_risk_bonus': {
                'vulnerability': 2.0,
                'misconfiguration': 1.0,
                'sensitive': 0.5,
                'cve': 1.5
            }
        }
    
    def export_results(self, file_path: str, format: str = 'json') -> None:
        """Export processing results to file"""
        results = {
            'findings': [f.to_dict() for f in self.normalized_findings],
            'statistics': self.stats.to_dict(),
            'summary': self._generate_summary(),
            'recommendations': self._generate_recommendations(),
            'correlation_matrix': self._build_correlation_matrix(),
            'metadata': {
                'processor_version': '2.0',
                'export_timestamp': time.time(),
                'export_format': format,
                'processing_config': {
                    'correlation_enabled': self.enable_correlation,
                    'fp_filtering_enabled': self.enable_fp_filtering,
                    'risk_scoring_enabled': self.enable_risk_scoring,
                    'correlation_threshold': self.correlation_threshold,
                    'fp_threshold': self.fp_threshold
                }
            }
        }
        
        if format.lower() == 'json':
            with open(file_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
        else:
            raise ValueError(f"Unsupported export format: {format}")


# Convenience functions
def process_scan_results_simple(scan_results: Dict[str, Any],
                               enable_correlation: bool = True,
                               enable_fp_filtering: bool = True) -> Dict[str, Any]:
    """Simple result processing function"""
    processor = ResultProcessor(
        enable_correlation=enable_correlation,
        enable_fp_filtering=enable_fp_filtering
    )
    return processor.process_scan_results(scan_results)


def normalize_results_only(scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get only normalized results without correlation or filtering"""
    processor = ResultProcessor(
        enable_correlation=False,
        enable_fp_filtering=False,
        enable_risk_scoring=False
    )
    results = processor.process_scan_results(scan_results)
    return results['findings']


def get_high_risk_findings(scan_results: Dict[str, Any], risk_threshold: float = 7.0) -> List[Dict[str, Any]]:
    """Get only high-risk findings"""
    processor = ResultProcessor()
    results = processor.process_scan_results(scan_results)
    
    high_risk = []
    for finding in results['findings']:
        if finding.get('risk_score', 0) >= risk_threshold:
            high_risk.append(finding)
    
    return high_risk
