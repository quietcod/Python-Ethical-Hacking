"""
Enhanced Target Processing System v2.0
Comprehensive target processing with deduplication, categorization, validation, and reachability checking
"""

import ipaddress
import socket
import asyncio
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple, Union
from urllib.parse import urlparse
from pathlib import Path
import json
import hashlib

from .exceptions import ValidationError, TargetProcessingError
from .enhanced_validators import EnhancedInputValidator


class TargetType(Enum):
    """Target type enumeration"""
    DOMAIN = "domain"
    IP = "ip" 
    CIDR = "cidr"
    URL = "url"
    UNKNOWN = "unknown"


class TargetStatus(Enum):
    """Target status enumeration"""
    PENDING = "pending"
    VALIDATED = "validated"
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    INVALID = "invalid"
    DUPLICATE = "duplicate"
    FILTERED = "filtered"


class RiskLevel(Enum):
    """Risk level for target prioritization"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class ProcessedTarget:
    """Processed target with comprehensive metadata"""
    original_input: str
    normalized_value: str
    target_type: TargetType
    status: TargetStatus
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    validation_info: Dict[str, Any] = field(default_factory=dict)
    reachability_info: Dict[str, Any] = field(default_factory=dict)
    
    # Processing timestamps
    created_at: float = field(default_factory=time.time)
    validated_at: Optional[float] = None
    reachability_checked_at: Optional[float] = None
    
    # Relationships
    parent_target: Optional[str] = None  # For targets derived from CIDR expansion
    child_targets: List[str] = field(default_factory=list)  # For CIDR -> IPs
    
    # Processing flags
    is_duplicate: bool = False
    duplicate_of: Optional[str] = None
    is_filtered: bool = False
    filter_reason: Optional[str] = None
    
    def __hash__(self):
        """Make target hashable for deduplication"""
        return hash(self.normalized_value)
    
    def __eq__(self, other):
        """Equality comparison for deduplication"""
        if not isinstance(other, ProcessedTarget):
            return False
        return self.normalized_value == other.normalized_value
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'original_input': self.original_input,
            'normalized_value': self.normalized_value,
            'target_type': self.target_type.value,
            'status': self.status.value,
            'risk_level': self.risk_level.value,
            'metadata': self.metadata,
            'validation_info': self.validation_info,
            'reachability_info': self.reachability_info,
            'created_at': self.created_at,
            'validated_at': self.validated_at,
            'reachability_checked_at': self.reachability_checked_at,
            'parent_target': self.parent_target,
            'child_targets': self.child_targets,
            'is_duplicate': self.is_duplicate,
            'duplicate_of': self.duplicate_of,
            'is_filtered': self.is_filtered,
            'filter_reason': self.filter_reason
        }


@dataclass
class ProcessingStats:
    """Statistics for target processing"""
    total_input: int = 0
    total_processed: int = 0
    duplicates_removed: int = 0
    invalid_filtered: int = 0
    reachable_targets: int = 0
    unreachable_targets: int = 0
    
    # By type
    domains: int = 0
    ips: int = 0
    cidrs: int = 0
    urls: int = 0
    
    # By risk level
    critical_risk: int = 0
    high_risk: int = 0
    medium_risk: int = 0
    low_risk: int = 0
    
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
            'total_input': self.total_input,
            'total_processed': self.total_processed,
            'duplicates_removed': self.duplicates_removed,
            'invalid_filtered': self.invalid_filtered,
            'reachable_targets': self.reachable_targets,
            'unreachable_targets': self.unreachable_targets,
            'domains': self.domains,
            'ips': self.ips,
            'cidrs': self.cidrs,
            'urls': self.urls,
            'critical_risk': self.critical_risk,
            'high_risk': self.high_risk,
            'medium_risk': self.medium_risk,
            'low_risk': self.low_risk,
            'processing_duration': self.processing_duration()
        }


class TargetProcessor:
    """Enhanced target processor with comprehensive processing capabilities"""
    
    def __init__(self, 
                 enable_reachability_check: bool = True,
                 enable_deduplication: bool = True,
                 enable_risk_assessment: bool = True,
                 reachability_timeout: int = 5,
                 max_concurrent_checks: int = 50,
                 cidr_expansion_limit: int = 1000):
        """
        Initialize target processor
        
        Args:
            enable_reachability_check: Whether to check target reachability
            enable_deduplication: Whether to remove duplicate targets
            enable_risk_assessment: Whether to assess target risk levels
            reachability_timeout: Timeout for reachability checks (seconds)
            max_concurrent_checks: Maximum concurrent reachability checks
            cidr_expansion_limit: Maximum IPs to expand from CIDR (safety limit)
        """
        self.enable_reachability_check = enable_reachability_check
        self.enable_deduplication = enable_deduplication
        self.enable_risk_assessment = enable_risk_assessment
        self.reachability_timeout = reachability_timeout
        self.max_concurrent_checks = max_concurrent_checks
        self.cidr_expansion_limit = cidr_expansion_limit
        
        # Initialize validator
        self.validator = EnhancedInputValidator()
        
        # Processing state
        self.processed_targets: Dict[str, ProcessedTarget] = {}
        self.stats = ProcessingStats()
        
        # Deduplication tracking
        self.normalized_targets: Set[str] = set()
        self.target_hashes: Dict[str, str] = {}
        
        # Risk assessment rules
        self.risk_rules = self._load_risk_rules()
    
    def process_targets(self, targets: List[str], 
                       filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Comprehensive target processing pipeline
        
        Args:
            targets: List of target strings to process
            filters: Optional filtering configuration
            
        Returns:
            Dict with processed targets and statistics
        """
        self.stats = ProcessingStats()
        self.stats.total_input = len(targets)
        self.processed_targets.clear()
        self.normalized_targets.clear()
        self.target_hashes.clear()
        
        print(f"🎯 Processing {len(targets)} targets...")
        
        # Step 1: Validate and categorize targets
        print("1️⃣  Validating and categorizing targets...")
        validated_targets = self._validate_and_categorize(targets)
        
        # Step 2: Deduplicate targets
        if self.enable_deduplication:
            print("2️⃣  Removing duplicate targets...")
            validated_targets = self._deduplicate_targets(validated_targets)
        
        # Step 3: Expand CIDR ranges
        print("3️⃣  Expanding CIDR ranges...")
        expanded_targets = self._expand_cidr_targets(validated_targets)
        
        # Step 4: Apply filters
        if filters:
            print("4️⃣  Applying target filters...")
            filtered_targets = self._apply_filters(expanded_targets, filters)
        else:
            filtered_targets = expanded_targets
        
        # Step 5: Check reachability
        if self.enable_reachability_check:
            print("5️⃣  Checking target reachability...")
            self._check_reachability(filtered_targets)
        
        # Step 6: Assess risk levels
        if self.enable_risk_assessment:
            print("6️⃣  Assessing target risk levels...")
            self._assess_risk_levels(filtered_targets)
        
        # Step 7: Prioritize targets
        print("7️⃣  Prioritizing targets...")
        prioritized_targets = self._prioritize_targets(filtered_targets)
        
        # Update statistics
        self._update_final_statistics()
        self.stats.processing_end = time.time()
        
        # Return comprehensive results
        prioritized_dicts = [target.to_dict() for target in prioritized_targets]
        
        return {
            'targets': prioritized_dicts,
            'statistics': self.stats.to_dict(),
            'summary': self._generate_summary(),
            'recommendations': self._generate_recommendations()
        }
    
    def _validate_and_categorize(self, targets: List[str]) -> List[ProcessedTarget]:
        """Validate and categorize input targets"""
        processed = []
        
        for target_input in targets:
            try:
                # Validate target
                validation_result = self.validator.validate_target(target_input.strip())
                
                # Create processed target
                processed_target = ProcessedTarget(
                    original_input=target_input,
                    normalized_value=validation_result['value'],
                    target_type=TargetType(validation_result['type']),
                    status=TargetStatus.VALIDATED,
                    validation_info=validation_result,
                    validated_at=time.time()
                )
                
                # Add type-specific metadata
                processed_target.metadata.update(self._extract_metadata(validation_result))
                
                processed.append(processed_target)
                
            except ValidationError as e:
                # Create invalid target entry
                processed_target = ProcessedTarget(
                    original_input=target_input,
                    normalized_value=target_input.strip(),
                    target_type=TargetType.UNKNOWN,
                    status=TargetStatus.INVALID,
                    validation_info={'error': str(e)},
                    validated_at=time.time()
                )
                processed.append(processed_target)
                self.stats.invalid_filtered += 1
        
        return processed
    
    def _deduplicate_targets(self, targets: List[ProcessedTarget]) -> List[ProcessedTarget]:
        """Remove duplicate targets"""
        unique_targets = []
        seen_normalized = {}
        
        for target in targets:
            # Skip invalid targets for deduplication
            if target.status == TargetStatus.INVALID:
                unique_targets.append(target)
                continue
            
            normalized = target.normalized_value.lower()
            
            if normalized in seen_normalized:
                # Mark as duplicate
                target.is_duplicate = True
                target.duplicate_of = seen_normalized[normalized].normalized_value
                target.status = TargetStatus.DUPLICATE
                self.stats.duplicates_removed += 1
            else:
                # Add to unique targets
                seen_normalized[normalized] = target
                unique_targets.append(target)
                self.normalized_targets.add(normalized)
        
        return unique_targets
    
    def _expand_cidr_targets(self, targets: List[ProcessedTarget]) -> List[ProcessedTarget]:
        """Expand CIDR ranges to individual IP addresses"""
        expanded = []
        
        for target in targets:
            if target.target_type == TargetType.CIDR and target.status == TargetStatus.VALIDATED:
                try:
                    network = ipaddress.ip_network(target.normalized_value, strict=False)
                    
                    # Safety check for network size
                    if network.num_addresses > self.cidr_expansion_limit:
                        target.status = TargetStatus.FILTERED
                        target.is_filtered = True
                        target.filter_reason = f"CIDR too large ({network.num_addresses:,} addresses > {self.cidr_expansion_limit:,} limit)"
                        expanded.append(target)
                        continue
                    
                    # Expand to individual IPs
                    child_targets = []
                    for ip in network.hosts():
                        ip_target = ProcessedTarget(
                            original_input=f"{ip} (from {target.original_input})",
                            normalized_value=str(ip),
                            target_type=TargetType.IP,
                            status=TargetStatus.VALIDATED,
                            parent_target=target.normalized_value,
                            validation_info={'expanded_from_cidr': True, 'cidr_parent': target.normalized_value},
                            validated_at=time.time()
                        )
                        
                        # Copy risk assessment from parent
                        ip_target.risk_level = target.risk_level
                        
                        child_targets.append(ip_target)
                        expanded.append(ip_target)
                    
                    # Update parent with child references
                    target.child_targets = [t.normalized_value for t in child_targets]
                    target.metadata['expanded_count'] = len(child_targets)
                    
                    # Keep the original CIDR target for reference
                    expanded.append(target)
                    
                except Exception as e:
                    target.status = TargetStatus.INVALID
                    target.validation_info['expansion_error'] = str(e)
                    expanded.append(target)
            else:
                expanded.append(target)
        
        return expanded
    
    def _apply_filters(self, targets: List[ProcessedTarget], 
                      filters: Dict[str, Any]) -> List[ProcessedTarget]:
        """Apply filtering rules to targets"""
        filtered = []
        
        for target in targets:
            # Skip already invalid/duplicate targets
            if target.status in [TargetStatus.INVALID, TargetStatus.DUPLICATE]:
                filtered.append(target)
                continue
            
            should_filter = False
            filter_reasons = []
            
            # Type filters
            if 'exclude_types' in filters:
                if target.target_type.value in filters['exclude_types']:
                    should_filter = True
                    filter_reasons.append(f"Excluded type: {target.target_type.value}")
            
            # Private IP filter
            if 'exclude_private' in filters and filters['exclude_private']:
                if target.target_type == TargetType.IP:
                    try:
                        ip_obj = ipaddress.ip_address(target.normalized_value)
                        if ip_obj.is_private:
                            should_filter = True
                            filter_reasons.append("Private IP address")
                    except:
                        pass
            
            # Domain filters
            if 'exclude_domains' in filters:
                if target.target_type == TargetType.DOMAIN:
                    domain = target.normalized_value
                    for excluded_pattern in filters['exclude_domains']:
                        if excluded_pattern in domain or domain.endswith(excluded_pattern):
                            should_filter = True
                            filter_reasons.append(f"Excluded domain pattern: {excluded_pattern}")
            
            # Custom filters
            if 'custom_filters' in filters:
                for filter_func in filters['custom_filters']:
                    if callable(filter_func):
                        try:
                            if filter_func(target):
                                should_filter = True
                                filter_reasons.append("Custom filter")
                        except:
                            pass
            
            if should_filter:
                target.is_filtered = True
                target.status = TargetStatus.FILTERED
                target.filter_reason = "; ".join(filter_reasons)
                self.stats.invalid_filtered += 1
            
            filtered.append(target)
        
        return filtered
    
    def _check_reachability(self, targets: List[ProcessedTarget]) -> None:
        """Check target reachability using concurrent connections"""
        reachable_targets = [t for t in targets if t.status == TargetStatus.VALIDATED]
        
        if not reachable_targets:
            return
        
        print(f"   Checking reachability for {len(reachable_targets)} targets...")
        
        with ThreadPoolExecutor(max_workers=self.max_concurrent_checks) as executor:
            # Submit reachability checks
            future_to_target = {
                executor.submit(self._check_single_reachability, target): target 
                for target in reachable_targets
            }
            
            # Process results
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    reachability_info = future.result()
                    target.reachability_info = reachability_info
                    target.reachability_checked_at = time.time()
                    
                    if reachability_info['reachable']:
                        target.status = TargetStatus.REACHABLE
                        self.stats.reachable_targets += 1
                    else:
                        target.status = TargetStatus.UNREACHABLE
                        self.stats.unreachable_targets += 1
                        
                except Exception as e:
                    target.reachability_info = {
                        'reachable': False,
                        'error': str(e),
                        'method': 'error'
                    }
                    target.status = TargetStatus.UNREACHABLE
                    self.stats.unreachable_targets += 1
    
    def _check_single_reachability(self, target: ProcessedTarget) -> Dict[str, Any]:
        """Check reachability of a single target"""
        reachability_info = {
            'reachable': False,
            'method': None,
            'response_time': None,
            'details': {}
        }
        
        try:
            if target.target_type == TargetType.IP:
                # ICMP ping for IP addresses
                reachability_info.update(self._ping_target(target.normalized_value))
            
            elif target.target_type == TargetType.DOMAIN:
                # Try multiple methods for domains
                # 1. DNS resolution
                dns_result = self._check_dns_resolution(target.normalized_value)
                reachability_info['details']['dns'] = dns_result
                
                if dns_result['resolves']:
                    # 2. Try ping to resolved IP
                    resolved_ip = dns_result.get('resolved_ip')
                    if resolved_ip:
                        ping_result = self._ping_target(resolved_ip)
                        reachability_info['details']['ping'] = ping_result
                        
                        if ping_result['reachable']:
                            reachability_info['reachable'] = True
                            reachability_info['method'] = 'ping'
                            reachability_info['response_time'] = ping_result['response_time']
                        else:
                            # 3. Try HTTP/HTTPS connection
                            http_result = self._check_http_connection(target.normalized_value)
                            reachability_info['details']['http'] = http_result
                            
                            if http_result['reachable']:
                                reachability_info['reachable'] = True
                                reachability_info['method'] = 'http'
                                reachability_info['response_time'] = http_result['response_time']
                
            elif target.target_type == TargetType.URL:
                # HTTP connection for URLs
                parsed = urlparse(target.normalized_value)
                http_result = self._check_http_connection(target.normalized_value)
                reachability_info.update(http_result)
                reachability_info['details']['url_parsed'] = {
                    'scheme': parsed.scheme,
                    'hostname': parsed.hostname,
                    'port': parsed.port
                }
            
        except Exception as e:
            reachability_info['error'] = str(e)
        
        return reachability_info
    
    def _ping_target(self, target: str) -> Dict[str, Any]:
        """Ping a target to check reachability"""
        try:
            start_time = time.time()
            
            # Use system ping command
            cmd = ['ping', '-c', '1', '-W', str(self.reachability_timeout), target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.reachability_timeout + 2)
            
            response_time = time.time() - start_time
            
            return {
                'reachable': result.returncode == 0,
                'method': 'ping',
                'response_time': response_time,
                'output': result.stdout.strip(),
                'error': result.stderr.strip() if result.returncode != 0 else None
            }
            
        except subprocess.TimeoutExpired:
            return {
                'reachable': False,
                'method': 'ping',
                'response_time': None,
                'error': 'Ping timeout'
            }
        except Exception as e:
            return {
                'reachable': False,
                'method': 'ping',
                'response_time': None,
                'error': str(e)
            }
    
    def _check_dns_resolution(self, domain: str) -> Dict[str, Any]:
        """Check DNS resolution for a domain"""
        try:
            start_time = time.time()
            resolved_ip = socket.gethostbyname(domain)
            response_time = time.time() - start_time
            
            return {
                'resolves': True,
                'resolved_ip': resolved_ip,
                'response_time': response_time
            }
        except socket.gaierror as e:
            return {
                'resolves': False,
                'error': str(e)
            }
    
    def _check_http_connection(self, target: str) -> Dict[str, Any]:
        """Check HTTP/HTTPS connection to a target"""
        try:
            import urllib.request
            import urllib.error
            
            # Add protocol if not present
            if not target.startswith(('http://', 'https://')):
                target = f"http://{target}"
            
            start_time = time.time()
            
            req = urllib.request.Request(target)
            req.add_header('User-Agent', 'ReconTool/2.0 (Target Reachability Check)')
            
            with urllib.request.urlopen(req, timeout=self.reachability_timeout) as response:
                response_time = time.time() - start_time
                return {
                    'reachable': True,
                    'method': 'http',
                    'response_time': response_time,
                    'status_code': response.getcode(),
                    'url': response.geturl()
                }
                
        except urllib.error.URLError as e:
            return {
                'reachable': False,
                'method': 'http',
                'error': str(e)
            }
        except Exception as e:
            return {
                'reachable': False,
                'method': 'http',
                'error': str(e)
            }
    
    def _assess_risk_levels(self, targets: List[ProcessedTarget]) -> None:
        """Assess risk levels for targets"""
        for target in targets:
            if target.status not in [TargetStatus.REACHABLE, TargetStatus.VALIDATED]:
                continue
            
            risk_level = RiskLevel.LOW  # Default
            risk_factors = []
            
            # Domain-based risk assessment
            if target.target_type == TargetType.DOMAIN:
                domain = target.normalized_value
                
                # High-value domains
                if any(keyword in domain for keyword in ['admin', 'api', 'portal', 'dashboard', 'mgmt']):
                    risk_level = RiskLevel.HIGH
                    risk_factors.append("High-value domain keyword")
                
                # Internal/private domains
                elif any(keyword in domain for keyword in ['internal', 'intranet', 'corp', 'local']):
                    risk_level = RiskLevel.MEDIUM
                    risk_factors.append("Internal domain")
                
                # Development/test domains
                elif any(keyword in domain for keyword in ['dev', 'test', 'staging', 'qa']):
                    risk_level = RiskLevel.MEDIUM
                    risk_factors.append("Development environment")
            
            # IP-based risk assessment
            elif target.target_type == TargetType.IP:
                try:
                    ip_obj = ipaddress.ip_address(target.normalized_value)
                    
                    # Private networks are typically lower risk
                    if ip_obj.is_private:
                        risk_level = RiskLevel.LOW
                        risk_factors.append("Private IP address")
                    else:
                        risk_level = RiskLevel.MEDIUM
                        risk_factors.append("Public IP address")
                        
                except:
                    pass
            
            # Reachability-based risk adjustment
            if target.status == TargetStatus.REACHABLE:
                if risk_level == RiskLevel.LOW:
                    risk_level = RiskLevel.MEDIUM
                risk_factors.append("Target is reachable")
            
            # Service detection risk (if available)
            if 'open_ports' in target.metadata:
                open_ports = target.metadata['open_ports']
                if open_ports:
                    if risk_level == RiskLevel.LOW:
                        risk_level = RiskLevel.MEDIUM
                    elif risk_level == RiskLevel.MEDIUM:
                        risk_level = RiskLevel.HIGH
                    risk_factors.append(f"Open ports detected: {', '.join(map(str, open_ports))}")
            
            target.risk_level = risk_level
            target.metadata['risk_factors'] = risk_factors
    
    def _prioritize_targets(self, targets: List[ProcessedTarget]) -> List[ProcessedTarget]:
        """Prioritize targets based on risk level and reachability"""
        def priority_key(target):
            # Priority scoring
            score = 0
            
            # Risk level priority
            risk_scores = {
                RiskLevel.CRITICAL: 1000,
                RiskLevel.HIGH: 800,
                RiskLevel.MEDIUM: 600,
                RiskLevel.LOW: 400,
                RiskLevel.UNKNOWN: 200
            }
            score += risk_scores.get(target.risk_level, 0)
            
            # Reachability bonus
            if target.status == TargetStatus.REACHABLE:
                score += 100
            
            # Type priority
            type_scores = {
                TargetType.DOMAIN: 50,
                TargetType.IP: 40,
                TargetType.URL: 60,
                TargetType.CIDR: 30
            }
            score += type_scores.get(target.target_type, 0)
            
            # Response time bonus (faster = higher priority)
            if target.reachability_info.get('response_time'):
                response_time = target.reachability_info['response_time']
                if response_time < 1.0:
                    score += 20
                elif response_time < 5.0:
                    score += 10
            
            return -score  # Negative for descending sort
        
        # Sort by priority
        prioritized = sorted(targets, key=priority_key)
        
        # Add priority rank to metadata
        for i, target in enumerate(prioritized):
            target.metadata['priority_rank'] = i + 1
        
        return prioritized
    
    def _extract_metadata(self, validation_result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract metadata from validation result"""
        metadata = {}
        
        target_type = validation_result.get('type')
        
        if target_type == 'domain':
            metadata.update({
                'labels': validation_result.get('labels', []),
                'tld': validation_result.get('tld'),
                'apex_domain': validation_result.get('apex_domain'),
                'subdomain': validation_result.get('subdomain')
            })
        
        elif target_type == 'ip':
            metadata.update({
                'version': validation_result.get('version'),
                'is_private': validation_result.get('is_private'),
                'is_global': validation_result.get('is_global')
            })
        
        elif target_type == 'cidr':
            metadata.update({
                'network_address': validation_result.get('network_address'),
                'num_addresses': validation_result.get('num_addresses'),
                'prefix_length': validation_result.get('prefix_length')
            })
        
        elif target_type == 'url':
            metadata.update({
                'scheme': validation_result.get('scheme'),
                'hostname': validation_result.get('hostname'),
                'port': validation_result.get('port'),
                'is_secure': validation_result.get('is_secure')
            })
        
        return metadata
    
    def _load_risk_rules(self) -> Dict[str, Any]:
        """Load risk assessment rules"""
        return {
            'high_risk_keywords': [
                'admin', 'administrator', 'api', 'portal', 'dashboard', 'console',
                'mgmt', 'management', 'control', 'panel', 'cpanel', 'phpmyadmin'
            ],
            'medium_risk_keywords': [
                'internal', 'intranet', 'corp', 'corporate', 'dev', 'development',
                'test', 'testing', 'staging', 'qa', 'uat', 'demo'
            ],
            'high_risk_ports': [22, 23, 21, 3389, 5900, 1433, 3306, 5432, 6379, 27017],
            'medium_risk_ports': [80, 443, 8080, 8443, 8000, 9000]
        }
    
    def _update_final_statistics(self) -> None:
        """Update final processing statistics"""
        for target in self.processed_targets.values():
            # Count by type
            if target.target_type == TargetType.DOMAIN:
                self.stats.domains += 1
            elif target.target_type == TargetType.IP:
                self.stats.ips += 1
            elif target.target_type == TargetType.CIDR:
                self.stats.cidrs += 1
            elif target.target_type == TargetType.URL:
                self.stats.urls += 1
            
            # Count by risk level
            if target.risk_level == RiskLevel.CRITICAL:
                self.stats.critical_risk += 1
            elif target.risk_level == RiskLevel.HIGH:
                self.stats.high_risk += 1
            elif target.risk_level == RiskLevel.MEDIUM:
                self.stats.medium_risk += 1
            elif target.risk_level == RiskLevel.LOW:
                self.stats.low_risk += 1
        
        self.stats.total_processed = len([t for t in self.processed_targets.values() 
                                        if t.status not in [TargetStatus.INVALID, TargetStatus.DUPLICATE, TargetStatus.FILTERED]])
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate processing summary"""
        valid_targets = [t for t in self.processed_targets.values() 
                        if t.status in [TargetStatus.VALIDATED, TargetStatus.REACHABLE, TargetStatus.UNREACHABLE]]
        
        return {
            'total_targets_processed': len(valid_targets),
            'reachable_percentage': (self.stats.reachable_targets / len(valid_targets) * 100) if valid_targets else 0,
            'most_common_type': self._get_most_common_type(),
            'highest_risk_targets': self._get_highest_risk_targets(),
            'processing_duration': self.stats.processing_duration(),
            'recommendations_count': len(self._generate_recommendations())
        }
    
    def _get_most_common_type(self) -> str:
        """Get the most common target type"""
        type_counts = {
            'domains': self.stats.domains,
            'ips': self.stats.ips,
            'cidrs': self.stats.cidrs,
            'urls': self.stats.urls
        }
        return max(type_counts, key=type_counts.get) if any(type_counts.values()) else 'none'
    
    def _get_highest_risk_targets(self) -> List[str]:
        """Get list of highest risk targets"""
        high_risk = [t.normalized_value for t in self.processed_targets.values() 
                    if t.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]]
        return high_risk[:10]  # Top 10
    
    def _generate_recommendations(self) -> List[str]:
        """Generate processing recommendations"""
        recommendations = []
        
        if self.stats.duplicates_removed > 0:
            recommendations.append(f"Removed {self.stats.duplicates_removed} duplicate targets - consider using unique target lists")
        
        if self.stats.invalid_filtered > 0:
            recommendations.append(f"Filtered {self.stats.invalid_filtered} invalid targets - review input validation")
        
        unreachable_pct = (self.stats.unreachable_targets / (self.stats.reachable_targets + self.stats.unreachable_targets) * 100) if (self.stats.reachable_targets + self.stats.unreachable_targets) > 0 else 0
        if unreachable_pct > 30:
            recommendations.append(f"High percentage ({unreachable_pct:.1f}%) of unreachable targets - verify network connectivity")
        
        if self.stats.high_risk + self.stats.critical_risk > 0:
            recommendations.append(f"Found {self.stats.high_risk + self.stats.critical_risk} high/critical risk targets - prioritize these for scanning")
        
        if self.stats.cidrs > 0:
            recommendations.append("CIDR ranges detected - consider scanning approach for network ranges")
        
        return recommendations
    
    def export_results(self, file_path: str, format: str = 'json') -> None:
        """Export processing results to file"""
        results = {
            'targets': [t.to_dict() for t in self.processed_targets.values()],
            'statistics': self.stats.to_dict(),
            'summary': self._generate_summary(),
            'recommendations': self._generate_recommendations(),
            'metadata': {
                'processor_version': '2.0',
                'export_timestamp': time.time(),
                'export_format': format
            }
        }
        
        if format.lower() == 'json':
            with open(file_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
        else:
            raise ValueError(f"Unsupported export format: {format}")


# Convenience functions
def process_targets_simple(targets: List[str], 
                          enable_reachability: bool = True,
                          enable_deduplication: bool = True) -> Dict[str, Any]:
    """Simple target processing function"""
    processor = TargetProcessor(
        enable_reachability_check=enable_reachability,
        enable_deduplication=enable_deduplication
    )
    return processor.process_targets(targets)


def get_reachable_targets(targets: List[str]) -> List[str]:
    """Get only reachable targets from a list"""
    results = process_targets_simple(targets, enable_reachability=True)
    reachable = []
    for target_info in results['targets']:
        if isinstance(target_info, ProcessedTarget):
            if target_info.status == TargetStatus.REACHABLE:
                reachable.append(target_info.normalized_value)
        elif isinstance(target_info, dict) and target_info.get('status') == 'reachable':
            reachable.append(target_info['normalized_value'])
    return reachable


def deduplicate_targets(targets: List[str]) -> List[str]:
    """Simple target deduplication"""
    results = process_targets_simple(targets, enable_reachability=False, enable_deduplication=True)
    unique = []
    for target_info in results['targets']:
        if isinstance(target_info, ProcessedTarget):
            if not target_info.is_duplicate and target_info.status != TargetStatus.INVALID:
                unique.append(target_info.normalized_value)
        elif isinstance(target_info, dict):
            if not target_info.get('is_duplicate', False) and target_info.get('status') != 'invalid':
                unique.append(target_info['normalized_value'])
    return unique
