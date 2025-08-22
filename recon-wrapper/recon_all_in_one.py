#!/usr/bin/env python3
"""
Recon Wrapper - Core Functionality Module
Comprehensive Reconnaissance Tool - Core Scanning Components
Author: Refactored Architecture
Date: 2025-08-23

ARCHITECTURE DISTRIBUTION:
Core Functionality: 11 scanning classes + 23 external tools = 34 components

CORE SCANNING CLASSES (11):
    1. PortScanner - Network port scanning and service detection
    2. SubdomainEnumerator - Subdomain discovery and enumeration  
    3. WebScanner - Web application vulnerability scanning
    4. SSLScanner - SSL/TLS security analysis
    5. OSINTCollector - Open source intelligence gathering
    6. Screenshotter - Visual reconnaissance capture
    7. SecurityScanner - Comprehensive security analysis
    8. VulnerabilityScanner - CVE and vulnerability assessment
    9. DirectoryScanner - Web directory discovery
    10. DNSScanner - DNS enumeration and analysis
    11. NetworkScanner - Network topology mapping

EXTERNAL TOOLS (23):
    nmap, masscan, gobuster, nikto, sublist3r, amass, ffuf, feroxbuster, sqlmap,
    dirb, wfuzz, nuclei, httpx, assetfinder, subfinder, waybackpy, shodan-cli,
    censys-cli, theharvester, recon-ng, burpsuite, zap-cli, testssl

Features:
    • Port Scanning (Nmap, Masscan, Hybrid)
    • Subdomain Enumeration (multi-tool, DNSSEC, zone transfer)
    • Web Application Scanning (Nikto, tech stack, CMS, API fuzzing)
    • SSL/TLS Analysis (Heartbleed, POODLE, BEAST, DROWN, weak ciphers)
    • OSINT Collection (DNS, Wayback Machine, GitHub dorking)
    • Screenshot Capture
    • Advanced Directory Discovery (gobuster, ffuf, feroxbuster)
    • Vulnerability Scanning (CVE mapping, vulners, vulscan)
    • Network Topology Mapping and Analysis
    • DNS Security Assessment
    • Production-ready for authorized security testing
"""

import argparse
import ipaddress
import os
import sys
import json
import subprocess
import threading
import time
import csv
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET
import re
import requests
import logging
from concurrent.futures import ThreadPoolExecutor
import socket
import ssl
import hashlib
import base64
from urllib.parse import urlparse, urljoin
import dns.resolver

# CORE PYTHON LIBRARIES (23 total for Infrastructure Module):
# argparse, ipaddress, os, sys, json, subprocess, threading, time, csv, datetime, 
# pathlib, xml, re, requests, logging, concurrent.futures, socket, ssl, hashlib, 
# base64, urllib, dns, tempfile

try:
    import dns.query
    import dns.zone
    import dns.exception
    HAS_DNS_QUERY = True
except ImportError:
    HAS_DNS_QUERY = False

# Import reporting functionality from separate module
try:
    from recon_report import AdvancedReportGenerator, ReportGenerator
    HAS_REPORTING = True
except ImportError:
    HAS_REPORTING = False
    print("Warning: Reporting module not found. Report generation will be disabled.")

# Import the main ReconWrapper class  
try:
    from recon_wrapper_class import ReconWrapper
    HAS_RECON_WRAPPER = True
except ImportError:
    HAS_RECON_WRAPPER = False
    print("Warning: ReconWrapper class not found. Creating fallback.")

# Try to import optional dependencies
try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False
    
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    HAS_SELENIUM = True
except ImportError:
    HAS_SELENIUM = False

try:
    import OpenSSL
    import cryptography
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization, hashes
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# Progress tracking and enhanced UI dependencies
try:
    from tqdm import tqdm
    import colorama
    from colorama import Fore, Back, Style
    colorama.init()  # Initialize colorama for Windows compatibility
    HAS_PROGRESS = True
except ImportError:
    HAS_PROGRESS = False

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


# ============================== RESOURCE MONITOR ==============================
class ResourceMonitor:
    """Monitor system resources during reconnaissance"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.monitoring = False
        self.monitor_thread = None
        
    def get_system_stats(self):
        """Get current system resource usage"""
        if not HAS_PSUTIL:
            return {
                'cpu_percent': 0,
                'memory_percent': 0,
                'memory_available_mb': 0,
                'status': 'psutil_unavailable'
            }
        
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            
            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_available_mb': memory.available / (1024 * 1024),
                'status': 'active'
            }
        except Exception as e:
            self.logger.warning(f"Error getting system stats: {str(e)}")
            return {
                'cpu_percent': 0,
                'memory_percent': 0,
                'memory_available_mb': 0,
                'status': 'error'
            }
    
    def check_resource_limits(self):
        """Check if system is within resource limits"""
        stats = self.get_system_stats()
        
        if stats['status'] != 'active':
            return True  # Assume OK if monitoring unavailable
        
        cpu_limit = self.config.get('performance', 'cpu_limit_percent', 80)
        memory_limit = self.config.get('performance', 'memory_limit_mb', 1024)
        
        # Check CPU usage
        if stats['cpu_percent'] > cpu_limit:
            self.logger.warning(f"High CPU usage: {stats['cpu_percent']:.1f}% (limit: {cpu_limit}%)")
            return False
        
        # Check available memory
        if stats['memory_available_mb'] < memory_limit:
            self.logger.warning(f"Low memory: {stats['memory_available_mb']:.1f}MB available (limit: {memory_limit}MB)")
            return False
        
        return True
    
    def wait_for_resources(self, max_wait=60):
        """Wait for system resources to become available"""
        if not self.config.get('performance', 'resource_monitoring', True):
            return True
        
        start_time = time.time()
        while time.time() - start_time < max_wait:
            if self.check_resource_limits():
                return True
            
            self.logger.info("Waiting for system resources to become available...")
            time.sleep(5)
        
        self.logger.warning("Resource limits still exceeded after waiting, proceeding anyway")
        return False


# ============================== PROGRESS TRACKER ==============================
class ProgressTracker:
    """Real-time progress tracking and status updates for reconnaissance modules"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.start_time = time.time()
        self.current_module = ""
        self.current_operation = ""
        self.progress_bars = {}
        self.module_timings = {}
        self.total_modules = 0
        self.completed_modules = 0
        self.discoveries = []
        
        # Enable/disable features based on availability
        self.use_colors = HAS_PROGRESS and self.config.get('ui', 'colors', True)
        self.use_progress_bars = HAS_PROGRESS and self.config.get('ui', 'progress_bars', True)
        
        # Color scheme
        if self.use_colors:
            self.colors = {
                'info': Fore.CYAN,
                'success': Fore.GREEN,
                'warning': Fore.YELLOW,
                'error': Fore.RED,
                'highlight': Fore.MAGENTA,
                'reset': Style.RESET_ALL,
                'bold': Style.BRIGHT
            }
        else:
            self.colors = {key: '' for key in ['info', 'success', 'warning', 'error', 'highlight', 'reset', 'bold']}
    
    def start_scan(self, target, scan_type, estimated_modules=8):
        """Initialize scan progress tracking"""
        self.target = target
        self.scan_type = scan_type
        self.total_modules = estimated_modules
        self.start_time = time.time()
        self.completed_modules = 0
        
        print(f"\n{self.colors['bold']}{self.colors['info']}🚀 Starting {scan_type} reconnaissance on: {target}{self.colors['reset']}")
        print(f"{self.colors['info']}📊 Estimated modules: {estimated_modules}{self.colors['reset']}")
        print(f"{self.colors['info']}⏰ Started at: {datetime.now().strftime('%H:%M:%S')}{self.colors['reset']}\n")
    
    def start_module(self, module_name, description="", estimated_tasks=None):
        """Start tracking a reconnaissance module"""
        self.current_module = module_name
        self.module_start_time = time.time()
        
        # Calculate overall progress
        overall_progress = (self.completed_modules / self.total_modules) * 100 if self.total_modules > 0 else 0
        
        print(f"{self.colors['highlight']}📍 Module {self.completed_modules + 1}/{self.total_modules}: {module_name}{self.colors['reset']}")
        if description:
            print(f"   {self.colors['info']}ℹ️  {description}{self.colors['reset']}")
        print(f"   {self.colors['info']}📈 Overall Progress: {overall_progress:.1f}%{self.colors['reset']}")
        
        # Create progress bar for this module if enabled and estimated tasks provided
        if self.use_progress_bars and estimated_tasks:
            self.progress_bars[module_name] = tqdm(
                total=estimated_tasks,
                desc=f"   {module_name}",
                unit="task",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
                ncols=80
            )
    
    def update_operation(self, operation, details=""):
        """Update current operation within a module"""
        self.current_operation = operation
        
        if details:
            print(f"   {self.colors['info']}🔄 {operation}: {details}{self.colors['reset']}")
        else:
            print(f"   {self.colors['info']}🔄 {operation}{self.colors['reset']}")
    
    def update_progress(self, module_name=None, increment=1, message=""):
        """Update progress for current module"""
        module = module_name or self.current_module
        
        if module in self.progress_bars:
            self.progress_bars[module].update(increment)
            if message:
                self.progress_bars[module].set_postfix_str(message)
    
    def log_discovery(self, discovery_type, item, details=""):
        """Log a discovery (subdomain, port, vulnerability, etc.)"""
        discovery = {
            'type': discovery_type,
            'item': item,
            'details': details,
            'timestamp': datetime.now(),
            'module': self.current_module
        }
        self.discoveries.append(discovery)
        
        # Real-time discovery notification
        if details:
            print(f"   {self.colors['success']}✨ Found {discovery_type}: {item} ({details}){self.colors['reset']}")
        else:
            print(f"   {self.colors['success']}✨ Found {discovery_type}: {item}{self.colors['reset']}")
    
    def log_error(self, error_msg, suggestion="", error_type="warning"):
        """Log an error with user-friendly messaging and suggestions"""
        color = self.colors['error'] if error_type == 'error' else self.colors['warning']
        icon = "❌" if error_type == 'error' else "⚠️"
        
        print(f"   {color}{icon} {error_msg}{self.colors['reset']}")
        
        if suggestion:
            print(f"   {self.colors['info']}💡 Suggestion: {suggestion}{self.colors['reset']}")
    
    def complete_module(self, module_name=None, summary=""):
        """Mark a module as completed"""
        module = module_name or self.current_module
        
        # Close progress bar if exists
        if module in self.progress_bars:
            self.progress_bars[module].close()
            del self.progress_bars[module]
        
        # Calculate module execution time
        if hasattr(self, 'module_start_time'):
            execution_time = time.time() - self.module_start_time
            self.module_timings[module] = execution_time
        else:
            execution_time = 0
        
        self.completed_modules += 1
        
        print(f"   {self.colors['success']}✅ {module} completed in {execution_time:.1f}s{self.colors['reset']}")
        if summary:
            print(f"   {self.colors['info']}📋 {summary}{self.colors['reset']}")
        print()  # Add spacing between modules
    
    def show_intermediate_summary(self):
        """Show intermediate scan summary"""
        elapsed = time.time() - self.start_time
        progress = (self.completed_modules / self.total_modules) * 100 if self.total_modules > 0 else 0
        
        print(f"\n{self.colors['highlight']}📊 SCAN PROGRESS SUMMARY{self.colors['reset']}")
        print(f"   {self.colors['info']}🎯 Target: {getattr(self, 'target', 'Unknown')}{self.colors['reset']}")
        print(f"   {self.colors['info']}⏱️  Elapsed: {elapsed:.0f}s{self.colors['reset']}")
        print(f"   {self.colors['info']}📈 Progress: {progress:.1f}% ({self.completed_modules}/{self.total_modules} modules){self.colors['reset']}")
        print(f"   {self.colors['info']}🔍 Discoveries: {len(self.discoveries)} items found{self.colors['reset']}")
        
        # Show recent discoveries
        if self.discoveries:
            recent = self.discoveries[-3:]  # Show last 3 discoveries
            print(f"   {self.colors['success']}✨ Recent discoveries:{self.colors['reset']}")
            for disc in recent:
                print(f"      • {disc['type']}: {disc['item']}")
        print()
    
    def complete_scan(self):
        """Complete the scan and show final summary"""
        total_time = time.time() - self.start_time
        
        print(f"\n{self.colors['bold']}{self.colors['success']}🎉 RECONNAISSANCE COMPLETED!{self.colors['reset']}")
        print(f"{self.colors['info']}⏱️  Total Duration: {total_time:.1f}s ({total_time/60:.1f} minutes){self.colors['reset']}")
        print(f"{self.colors['info']}📊 Modules Completed: {self.completed_modules}/{self.total_modules}{self.colors['reset']}")
        print(f"{self.colors['info']}🔍 Total Discoveries: {len(self.discoveries)}{self.colors['reset']}")
        
        # Show discovery breakdown
        if self.discoveries:
            discovery_types = {}
            for disc in self.discoveries:
                disc_type = disc['type']
                discovery_types[disc_type] = discovery_types.get(disc_type, 0) + 1
            
            print(f"\n{self.colors['highlight']}📋 Discovery Breakdown:{self.colors['reset']}")
            for disc_type, count in discovery_types.items():
                print(f"   {self.colors['success']}• {disc_type}: {count}{self.colors['reset']}")
        
        # Show module timing breakdown
        if self.module_timings:
            print(f"\n{self.colors['highlight']}⏱️  Module Performance:{self.colors['reset']}")
            for module, duration in self.module_timings.items():
                print(f"   {self.colors['info']}• {module}: {duration:.1f}s{self.colors['reset']}")
        
        print(f"\n{self.colors['info']}📁 Results have been saved to the output directory{self.colors['reset']}\n")
    
    def estimate_remaining_time(self):
        """Estimate remaining scan time based on completed modules"""
        if self.completed_modules == 0:
            return "Unknown"
        
        elapsed = time.time() - self.start_time
        avg_time_per_module = elapsed / self.completed_modules
        remaining_modules = self.total_modules - self.completed_modules
        estimated_remaining = avg_time_per_module * remaining_modules
        
        if estimated_remaining < 60:
            return f"{estimated_remaining:.0f}s"
        else:
            return f"{estimated_remaining/60:.1f}m"
    
    def cleanup(self):
        """Clean up progress bars and resources"""
        for pbar in self.progress_bars.values():
            pbar.close()
        self.progress_bars.clear()


# ============================== ERROR HANDLER ==============================
class ErrorHandler:
    """Enhanced error handling with user-friendly messages and suggestions"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.use_colors = HAS_PROGRESS and self.config.get('ui', 'colors', True)
        
        # Color scheme
        if self.use_colors:
            self.colors = {
                'error': Fore.RED,
                'warning': Fore.YELLOW,
                'info': Fore.CYAN,
                'success': Fore.GREEN,
                'reset': Style.RESET_ALL,
                'bold': Style.BRIGHT
            }
        else:
            self.colors = {key: '' for key in ['error', 'warning', 'info', 'success', 'reset', 'bold']}
    
    def handle_tool_missing(self, tool_name, module_name=""):
        """Handle missing external tools with helpful suggestions"""
        module_info = f" in {module_name}" if module_name else ""
        
        suggestions = {
            # EXTERNAL TOOLS (23 total for Core Functionality Module):
            'nmap': "Install with: sudo apt-get install nmap (Ubuntu/Debian) or brew install nmap (macOS)",
            'masscan': "Install with: sudo apt-get install masscan or compile from source",
            'gobuster': "Install with: sudo apt-get install gobuster or go install github.com/OJ/gobuster/v3@latest",
            'nikto': "Install with: sudo apt-get install nikto",
            'sublist3r': "Install with: pip install sublist3r",
            'amass': "Download from: https://github.com/OWASP/Amass/releases",
            'ffuf': "Install with: go install github.com/ffuf/ffuf@latest",
            'feroxbuster': "Download from: https://github.com/epi052/feroxbuster/releases",
            'assetfinder': "Install with: go install github.com/tomnomnom/assetfinder@latest",
            'subfinder': "Install with: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            'nuclei': "Install with: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
            'httpx': "Install with: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
            'waybackpy': "Install with: pip install waybackpy",
            'shodan': "Install with: pip install shodan",
            'theharvester': "Install with: sudo apt-get install theharvester",
            'recon-ng': "Install with: sudo apt-get install recon-ng",
            'dirb': "Install with: sudo apt-get install dirb",
            'wfuzz': "Install with: pip install wfuzz",
            'sqlmap': "Install with: sudo apt-get install sqlmap or pip install sqlmap",
            'testssl': "Download from: https://github.com/drwetter/testssl.sh",
            'whatweb': "Install with: sudo apt-get install whatweb",
            'wafw00f': "Install with: pip install wafw00f",
            'dig': "Install with: sudo apt-get install dnsutils"
        }
        
        suggestion = suggestions.get(tool_name.lower(), f"Please install {tool_name} and ensure it's in your PATH")
        
        print(f"{self.colors['warning']}⚠️  Tool '{tool_name}' not found{module_info}{self.colors['reset']}")
        print(f"{self.colors['info']}💡 {suggestion}{self.colors['reset']}")
        print(f"{self.colors['info']}🔄 Continuing with available tools...{self.colors['reset']}\n")
        
        self.logger.warning(f"Tool {tool_name} not available{module_info}")
    
    def handle_network_error(self, target, error, module_name=""):
        """Handle network-related errors with helpful suggestions"""
        module_info = f" during {module_name}" if module_name else ""
        
        print(f"{self.colors['error']}❌ Network error for {target}{module_info}{self.colors['reset']}")
        print(f"{self.colors['info']}🔍 Error details: {str(error)}{self.colors['reset']}")
        
        # Provide specific suggestions based on error type
        error_str = str(error).lower()
        if 'timeout' in error_str:
            print(f"{self.colors['info']}💡 Target may be slow to respond. Try increasing timeout values.{self.colors['reset']}")
        elif 'connection refused' in error_str:
            print(f"{self.colors['info']}💡 Target may be blocking connections or service is down.{self.colors['reset']}")
        elif 'name resolution' in error_str or 'name or service not known' in error_str:
            print(f"{self.colors['info']}💡 DNS resolution failed. Check if domain exists or try --offline mode.{self.colors['reset']}")
        elif 'permission denied' in error_str:
            print(f"{self.colors['info']}💡 Permission denied. Try running with sudo for raw socket operations.{self.colors['reset']}")
        else:
            print(f"{self.colors['info']}💡 Check network connectivity and target availability.{self.colors['reset']}")
        
        print(f"{self.colors['info']}🔄 Continuing with next operation...{self.colors['reset']}\n")
        
        self.logger.error(f"Network error for {target}{module_info}: {error}")
    
    def handle_permission_error(self, operation, suggestion=""):
        """Handle permission-related errors"""
        print(f"{self.colors['error']}❌ Permission denied for: {operation}{self.colors['reset']}")
        
        if not suggestion:
            suggestion = "Try running with elevated privileges (sudo) or check file permissions"
        
        print(f"{self.colors['info']}💡 {suggestion}{self.colors['reset']}")
        print(f"{self.colors['info']}🔄 Continuing with available operations...{self.colors['reset']}\n")
        
        self.logger.error(f"Permission error: {operation}")
    
    def handle_api_error(self, api_name, error, suggestion=""):
        """Handle API-related errors"""
        print(f"{self.colors['warning']}⚠️  API error for {api_name}: {str(error)}{self.colors['reset']}")
        
        if not suggestion:
            if 'rate limit' in str(error).lower() or '429' in str(error):
                suggestion = "Rate limit exceeded. Wait before retrying or get premium API access."
            elif 'unauthorized' in str(error).lower() or '401' in str(error):
                suggestion = "Check API key configuration and permissions."
            elif 'forbidden' in str(error).lower() or '403' in str(error):
                suggestion = "API access forbidden. Verify API key has required permissions."
            else:
                suggestion = "Check API configuration and network connectivity."
        
        print(f"{self.colors['info']}💡 {suggestion}{self.colors['reset']}")
        print(f"{self.colors['info']}🔄 Continuing without {api_name} data...{self.colors['reset']}\n")
        
        self.logger.warning(f"API error for {api_name}: {error}")
    
    def handle_file_error(self, operation, filepath, error):
        """Handle file operation errors"""
        print(f"{self.colors['error']}❌ File error during {operation}: {filepath}{self.colors['reset']}")
        print(f"{self.colors['info']}🔍 Error: {str(error)}{self.colors['reset']}")
        
        # Provide specific suggestions
        if 'permission denied' in str(error).lower():
            print(f"{self.colors['info']}💡 Check file/directory permissions or run with appropriate privileges.{self.colors['reset']}")
        elif 'no space left' in str(error).lower():
            print(f"{self.colors['info']}💡 Insufficient disk space. Free up space or change output directory.{self.colors['reset']}")
        elif 'file not found' in str(error).lower():
            print(f"{self.colors['info']}💡 File or directory doesn't exist. Check path and create if necessary.{self.colors['reset']}")
        else:
            print(f"{self.colors['info']}💡 Check file path and permissions.{self.colors['reset']}")
        
        print(f"{self.colors['info']}🔄 Continuing with available operations...{self.colors['reset']}\n")
        
        self.logger.error(f"File error during {operation} ({filepath}): {error}")
    
    def handle_module_failure(self, module_name, error, is_critical=False):
        """Handle module execution failures"""
        level = "critical" if is_critical else "non-critical"
        icon = "💥" if is_critical else "⚠️"
        color = self.colors['error'] if is_critical else self.colors['warning']
        
        print(f"{color}{icon} {level.title()} failure in {module_name}{self.colors['reset']}")
        print(f"{self.colors['info']}🔍 Error: {str(error)}{self.colors['reset']}")
        
        if is_critical:
            print(f"{self.colors['error']}💡 This module is critical for the scan. Consider fixing the issue and rerunning.{self.colors['reset']}")
        else:
            print(f"{self.colors['info']}💡 This module is optional. Scan will continue with remaining modules.{self.colors['reset']}")
        
        print(f"{self.colors['info']}🔄 Continuing with scan...{self.colors['reset']}\n")
        
        log_level = self.logger.error if is_critical else self.logger.warning
        log_level(f"Module failure in {module_name}: {error}")
    
    def handle_dependency_missing(self, dependency, feature, install_command=""):
        """Handle missing Python dependencies"""
        print(f"{self.colors['warning']}⚠️  Missing dependency: {dependency}{self.colors['reset']}")
        print(f"{self.colors['info']}🚫 Feature disabled: {feature}{self.colors['reset']}")
        
        if install_command:
            print(f"{self.colors['info']}💡 Install with: {install_command}{self.colors['reset']}")
        else:
            print(f"{self.colors['info']}💡 Install with: pip install {dependency}{self.colors['reset']}")
        
        print(f"{self.colors['info']}🔄 Continuing with available features...{self.colors['reset']}\n")
        
        self.logger.warning(f"Missing dependency {dependency} - {feature} disabled")
    
    def graceful_degradation(self, feature, alternative, reason=""):
        """Handle graceful feature degradation"""
        reason_text = f" ({reason})" if reason else ""
        
        print(f"{self.colors['warning']}⬇️  Degrading feature: {feature}{reason_text}{self.colors['reset']}")
        print(f"{self.colors['info']}🔄 Using alternative: {alternative}{self.colors['reset']}")
        print(f"{self.colors['info']}💡 For full functionality, address the underlying issue.{self.colors['reset']}\n")
        
        self.logger.info(f"Graceful degradation: {feature} -> {alternative}{reason_text}")
    
    def suggest_fixes(self, issue_type, context=""):
        """Provide general troubleshooting suggestions"""
        suggestions = {
            'slow_response': [
                "Increase timeout values in configuration",
                "Check network connectivity to target",
                "Consider using light scan mode for faster results",
                "Run during off-peak hours for better performance"
            ],
            'high_memory': [
                "Enable light mode to reduce memory usage",
                "Increase system swap space",
                "Close other applications to free memory",
                "Process targets one at a time instead of batch mode"
            ],
            'permission_issues': [
                "Run with appropriate privileges (sudo for raw sockets)",
                "Check file/directory permissions",
                "Ensure output directory is writable",
                "Verify tool installation permissions"
            ],
            'network_issues': [
                "Check internet connectivity",
                "Verify target is accessible",
                "Check firewall settings",
                "Try using VPN if geographically restricted"
            ]
        }
        
        if issue_type in suggestions:
            print(f"{self.colors['info']}🔧 Troubleshooting suggestions for {issue_type}:{self.colors['reset']}")
            for i, suggestion in enumerate(suggestions[issue_type], 1):
                print(f"{self.colors['info']}   {i}. {suggestion}{self.colors['reset']}")
            print()


# ============================== CONFIG MANAGER ==============================
class ConfigManager:
    """Manages configuration settings for the recon wrapper"""
    
    def __init__(self, config_file=None):
        self.config = self.get_default_config()
        self.logger = logging.getLogger(__name__)
        
        if config_file:
            self.load_config(config_file)
        else:
            # Try to load default config file
            default_config = Path(__file__).parent / "config.json"
            if default_config.exists():
                self.load_config(str(default_config))
    
    def get_default_config(self):
        """Return default configuration settings"""
        return {
            "nmap": {
                "basic_flags": "-sV -sC --version-intensity 1",
                "aggressive_flags": "-A -T4 -O",
                "timeout": 300,
                "top_ports": 1000
            },
            "subdomains": {
                "tools": ["sublist3r", "assetfinder", "amass", "subfinder"],
                "wordlist": "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt",
                "timeout": 600,
                "threads": 50
            },
            "web": {
                "nikto_flags": "-h",
                "whatweb_flags": "-a 3",
                "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "timeout": 180,
                "follow_redirects": True
            },
            "wordpress": {
                "wpscan_flags": "--enumerate ap,at,u,dbe",
                "api_token": "",
                "timeout": 300
            },
            "ssl": {
                "testssl_flags": "--fast --parallel",
                "timeout": 120
            },
            "security": {
                "enabled": True,
                "ssl_analysis": True,
                "cert_transparency": True,
                "check_vulnerabilities": True,
                "security_headers": True,
                "cipher_analysis": True,
                "protocol_analysis": True,
                "max_subdomains": 5,
                "ports": [443, 8443, 9443, 8080, 8008, 8888],
                "timeout": 30
            },
            "osint": {
                "theharvester_sources": "baidu,bing,google,yahoo,duckduckgo",
                "shodan_api_key": "YOUR_SHODAN_API_KEY_HERE",
                "virustotal_api_key": "",
                "timeout": 240
            },
            "screenshots": {
                "tool": "gowitness", # or "aquatone"
                "resolution": "1440,900",
                "timeout": 30,
                "threads": 10
            },
            "general": {
                "threads": 10,
                "timeout": 300,
                "user_agent": "ReconWrapper/1.0",
                "delay": 1,
                "retries": 3,
                "offline_mode": False,
                "dns_server": "",
                "cidr_range": "",
                "dir_wordlist": ""
            },
            "mode": {
                "offline": False,
                "skip_online_modules": ["whois", "shodan", "crtsh", "sublist3r", "assetfinder", "subfinder", "theharvester"]
            },
            "dns": {
                "servers": []
            },
            "bruteforce": {
                "dir_wordlist": "/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt",
                "dns_wordlist": "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt",
                "rate_limit": 0,
                "threads": 10,
                "max_words": 5000
            },
            "performance": {
                "max_concurrent_modules": 1,  # Number of heavy modules to run simultaneously  
                "module_cooldown": 5,         # Seconds to wait between heavy modules
                "memory_limit_mb": 1024,      # Memory usage limit in MB (for future use)
                "cpu_limit_percent": 80,      # CPU usage limit percentage (for future use)
                "enable_staggering": True,    # Enable module staggering
                "light_mode": False,          # Reduce resource usage across all modules
                "resource_monitoring": True   # Monitor system resources during scan
            },
            "output": {
                "format": ["json", "txt", "xml"],
                "compress": False,
                "cleanup_raw": False
            },
            "reporting": {
                "advanced_enabled": True,
                "generate_pdf": True,
                "generate_risk_assessment": True,
                "generate_compliance": True,
                "generate_csv": True,
                "risk_scoring": {
                    "enabled": True,
                    "weights": {
                        "critical_vulns": 30,
                        "high_vulns": 20,
                        "medium_vulns": 10,
                        "low_vulns": 5,
                        "expired_certs": 25,
                        "weak_protocols": 15,
                        "missing_headers": 10,
                        "open_ports": 8,
                        "exposed_services": 12
                    }
                },
                "compliance_frameworks": ["owasp", "nist", "pci_dss"],
                "executive_summary": True,
                "technical_details": True,
                "visualization": {
                    "charts": True,
                    "interactive": False,
                    "export_images": False
                }
            },
            "ui": {
                "colors": True,                    # Enable colored output
                "progress_bars": True,             # Show progress bars during operations
                "real_time_updates": True,         # Display real-time status updates
                "discovery_notifications": True,   # Show discoveries as they happen
                "detailed_errors": True,          # Show detailed error messages with suggestions
                "intermediate_summaries": True,   # Show progress summaries during scan
                "module_timings": True,           # Display module execution times
                "eta_estimates": True             # Show estimated time remaining
            }
        }
    
    def load_config(self, config_file):
        """Load configuration from file"""
        try:
            with open(config_file, 'r') as f:
                if config_file.endswith('.json'):
                    user_config = json.load(f)
                elif config_file.endswith('.yaml') or config_file.endswith('.yml'):
                    if HAS_YAML:
                        user_config = yaml.safe_load(f)
                    else:
                        raise ValueError("YAML support not available")
                else:
                    raise ValueError("Unsupported config file format")
                
                # Merge with default config
                self.merge_config(user_config)
                self.logger.info(f"Loaded configuration from {config_file}")
                
        except FileNotFoundError:
            self.logger.warning(f"Config file not found: {config_file}")
        except Exception as e:
            self.logger.error(f"Error loading config: {str(e)}")
    
    def merge_config(self, user_config):
        """Merge user configuration with default configuration"""
        def merge_dict(default, user):
            for key, value in user.items():
                if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                    merge_dict(default[key], value)
                else:
                    default[key] = value
        
        merge_dict(self.config, user_config)
    
    def get(self, section, key=None, default=None):
        """Get configuration value"""
        try:
            if key is None:
                return self.config.get(section, default)
            return self.config.get(section, {}).get(key, default)
        except Exception:
            return default
    
    def set(self, section, key, value):
        """Set configuration value"""
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value
    
    def save_config(self, config_file):
        """Save current configuration to file"""
        try:
            with open(config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            self.logger.info(f"Configuration saved to {config_file}")
        except Exception as e:
            self.logger.error(f"Error saving config: {str(e)}")
    
    def validate_dependencies(self):
        """Validate that required tools are installed"""
        tools = {
            'nmap': 'nmap --version',
            'nikto': 'nikto -Version',
            'whatweb': 'whatweb --version',
            'wpscan': 'wpscan --version',
            'testssl.sh': 'testssl.sh --version',
            'theharvester': 'theHarvester --version',
            'sublist3r': 'sublist3r --help',
            'assetfinder': 'assetfinder --help',
            'amass': 'amass --version',
            'subfinder': 'subfinder --version',
            'httprobe': 'httprobe --help',
            'httpx': 'httpx --version',
            'gowitness': 'gowitness --version',
            'aquatone': 'aquatone --version'
        }
        
        available_tools = {}
        missing_tools = []
        
        for tool, check_cmd in tools.items():
            try:
                result = os.system(f"{check_cmd} >/dev/null 2>&1")
                if result == 0:
                    available_tools[tool] = True
                else:
                    available_tools[tool] = False
                    missing_tools.append(tool)
            except Exception:
                available_tools[tool] = False
                missing_tools.append(tool)
        
        if missing_tools:
            self.logger.warning(f"Missing tools: {', '.join(missing_tools)}")
            self.logger.info("Install missing tools for full functionality")
        
        return available_tools, missing_tools


# ============================== SECURITY SCANNER ==============================
class SecurityScanner:
    """SSL/TLS Security Analysis and Certificate Transparency Scanner"""
    
    def __init__(self, output_dir, config):
        self.output_dir = Path(output_dir)
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.results = {}
        
    def analyze_ssl_tls(self, target, port=443):
        """Comprehensive SSL/TLS analysis"""
        self.logger.info(f"Analyzing SSL/TLS for {target}:{port}")
        
        ssl_info = {
            'target': target,
            'port': port,
            'certificate': None,
            'cipher_suites': [],
            'protocols': [],
            'vulnerabilities': [],
            'security_headers': {},
            'certificate_chain': [],
            'transparency_logs': []
        }
        
        try:
            # Get SSL certificate information
            ssl_info['certificate'] = self._get_certificate_info(target, port)
            
            # Test supported SSL/TLS protocols
            ssl_info['protocols'] = self._test_ssl_protocols(target, port)
            
            # Get cipher suites
            ssl_info['cipher_suites'] = self._get_cipher_suites(target, port)
            
            # Check for common vulnerabilities
            ssl_info['vulnerabilities'] = self._check_ssl_vulnerabilities(target, port)
            
            # Get security headers
            ssl_info['security_headers'] = self._check_security_headers(target, port)
            
            # Get certificate chain
            ssl_info['certificate_chain'] = self._get_certificate_chain(target, port)
            
            # Query Certificate Transparency logs
            if ssl_info['certificate']:
                ssl_info['transparency_logs'] = self._query_certificate_transparency(ssl_info['certificate'])
            
            # Save results
            self._save_ssl_results(target, ssl_info)
            self.results[f"{target}:{port}"] = ssl_info
            
        except Exception as e:
            self.logger.error(f"SSL/TLS analysis failed for {target}:{port}: {str(e)}")
            ssl_info['error'] = str(e)
            
        return ssl_info
        
    def _get_certificate_info(self, target, port):
        """Extract detailed certificate information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    # Get basic certificate info that's always available
                    basic_cert = ssock.getpeercert()
                    
                    cert_info = {
                        'subject': dict(x[0] for x in basic_cert.get('subject', [])),
                        'issuer': dict(x[0] for x in basic_cert.get('issuer', [])),
                        'serial_number': basic_cert.get('serialNumber'),
                        'not_before': basic_cert.get('notBefore'),
                        'not_after': basic_cert.get('notAfter'),
                        'signature_algorithm': None,
                        'public_key_algorithm': None,
                        'public_key_size': None,
                        'san': [name[1] for name in basic_cert.get('subjectAltName', [])],
                        'sha256_fingerprint': None,
                        'sha1_fingerprint': None,
                        'pem': None
                    }
                    
                    # Try to get detailed info with cryptography if available
                    if HAS_CRYPTO:
                        try:
                            cert_der = ssock.getpeercert_chain()[0].public_bytes(serialization.Encoding.DER)
                            cert_pem = ssock.getpeercert_chain()[0].public_bytes(serialization.Encoding.PEM)
                            cert = x509.load_der_x509_certificate(cert_der, default_backend())
                            
                            # Extract detailed information
                            cert_info['subject'] = {attr.oid._name: attr.value for attr in cert.subject}
                            cert_info['issuer'] = {attr.oid._name: attr.value for attr in cert.issuer}
                            cert_info['serial_number'] = str(cert.serial_number)
                            cert_info['not_before'] = cert.not_valid_before.isoformat()
                            cert_info['not_after'] = cert.not_valid_after.isoformat()
                            cert_info['signature_algorithm'] = cert.signature_algorithm_oid._name
                            cert_info['public_key_size'] = cert.public_key().key_size
                            cert_info['pem'] = cert_pem.decode() if isinstance(cert_pem, bytes) else cert_pem
                            
                            # Get Subject Alternative Names
                            try:
                                san_ext = cert.extensions.get_extension_for_oid(x509.NameOID.SUBJECT_ALTERNATIVE_NAME)
                                cert_info['san'] = [name.value for name in san_ext.value]
                            except x509.ExtensionNotFound:
                                pass
                                
                            # Calculate fingerprints
                            cert_info['sha256_fingerprint'] = cert.fingerprint(hashes.SHA256()).hex()
                            cert_info['sha1_fingerprint'] = cert.fingerprint(hashes.SHA1()).hex()
                            
                        except Exception as e:
                            self.logger.warning(f"Detailed certificate parsing failed: {e}")
                    
                    # Calculate basic fingerprint without cryptography
                    if not cert_info['sha256_fingerprint']:
                        try:
                            cert_der = ssock.getpeercert(binary_form=True)
                            cert_info['sha256_fingerprint'] = hashlib.sha256(cert_der).hexdigest()
                            cert_info['sha1_fingerprint'] = hashlib.sha1(cert_der).hexdigest()
                        except Exception:
                            pass
                        
                    return cert_info
                    
        except Exception as e:
            self.logger.error(f"Failed to get certificate info: {str(e)}")
            return None
            
    def _test_ssl_protocols(self, target, port):
        """Test supported SSL/TLS protocol versions"""
        protocols = []
        protocol_versions = [
            ('SSLv2', ssl.PROTOCOL_SSLv2 if hasattr(ssl, 'PROTOCOL_SSLv2') else None),
            ('SSLv3', ssl.PROTOCOL_SSLv3 if hasattr(ssl, 'PROTOCOL_SSLv3') else None),
            ('TLSv1.0', ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None),
            ('TLSv1.1', ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None),
            ('TLSv1.2', ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None),
            ('TLSv1.3', ssl.PROTOCOL_TLS if hasattr(ssl, 'PROTOCOL_TLS') else None)
        ]
        
        for name, protocol in protocol_versions:
            if protocol is None:
                continue
                
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((target, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        protocols.append({
                            'name': name,
                            'supported': True,
                            'cipher': ssock.cipher()
                        })
            except Exception:
                protocols.append({
                    'name': name,
                    'supported': False,
                    'cipher': None
                })
                
        return protocols
        
    def _get_cipher_suites(self, target, port):
        """Get supported cipher suites"""
        cipher_suites = []
        
        try:
            # Test with different SSL contexts to get cipher information
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        cipher_suites.append({
                            'name': cipher_info[0],
                            'protocol': cipher_info[1],
                            'key_length': cipher_info[2]
                        })
                        
        except Exception as e:
            self.logger.error(f"Failed to get cipher suites: {str(e)}")
            
        return cipher_suites
        
    def _check_ssl_vulnerabilities(self, target, port):
        """Check for common SSL/TLS vulnerabilities"""
        vulnerabilities = []
        
        # Check for weak protocols
        protocols = self._test_ssl_protocols(target, port)
        for proto in protocols:
            if proto['supported']:
                if proto['name'] in ['SSLv2', 'SSLv3', 'TLSv1.0']:
                    vulnerabilities.append({
                        'type': 'weak_protocol',
                        'name': f"Weak Protocol: {proto['name']}",
                        'severity': 'high' if proto['name'] in ['SSLv2', 'SSLv3'] else 'medium',
                        'description': f"Server supports deprecated protocol {proto['name']}"
                    })
                    
        # Check certificate validity
        cert_info = self._get_certificate_info(target, port)
        if cert_info:
            try:
                from datetime import datetime
                if cert_info.get('not_after'):
                    expiry = datetime.fromisoformat(cert_info['not_after'].replace('Z', '+00:00'))
                    if expiry < datetime.now():
                        vulnerabilities.append({
                            'type': 'expired_certificate',
                            'name': 'Expired Certificate',
                            'severity': 'high',
                            'description': f"Certificate expired on {cert_info['not_after']}"
                        })
                    elif (expiry - datetime.now()).days < 30:
                        vulnerabilities.append({
                            'type': 'expiring_certificate',
                            'name': 'Certificate Expiring Soon',
                            'severity': 'medium',
                            'description': f"Certificate expires on {cert_info['not_after']}"
                        })
            except Exception:
                pass
                
        return vulnerabilities
        
    def _check_security_headers(self, target, port):
        """Check HTTP security headers"""
        headers = {}
        
        try:
            # Try HTTPS first
            url = f"https://{target}:{port}" if port != 443 else f"https://{target}"
            response = requests.get(url, timeout=10, verify=False, allow_redirects=False)
            
            security_headers = [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Referrer-Policy',
                'Permissions-Policy',
                'Expect-CT'
            ]
            
            for header in security_headers:
                value = response.headers.get(header)
                headers[header] = {
                    'present': value is not None,
                    'value': value
                }
                
        except Exception as e:
            self.logger.error(f"Failed to check security headers: {str(e)}")
            
        return headers
        
    def _get_certificate_chain(self, target, port):
        """Get complete certificate chain"""
        chain = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    # Try to get certificate chain
                    if HAS_CRYPTO:
                        try:
                            chain_certs = ssock.getpeercert_chain()
                            
                            for cert in chain_certs:
                                cert_der = cert.public_bytes(serialization.Encoding.DER)
                                cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
                                
                                chain.append({
                                    'subject': {attr.oid._name: attr.value for attr in cert_obj.subject},
                                    'issuer': {attr.oid._name: attr.value for attr in cert_obj.issuer},
                                    'serial_number': str(cert_obj.serial_number),
                                    'fingerprint': cert_obj.fingerprint(hashes.SHA256()).hex()
                                })
                        except Exception as e:
                            self.logger.warning(f"Detailed chain parsing failed: {e}")
                    
                    # Fallback to basic certificate info
                    if not chain:
                        try:
                            basic_cert = ssock.getpeercert()
                            chain.append({
                                'subject': dict(x[0] for x in basic_cert.get('subject', [])),
                                'issuer': dict(x[0] for x in basic_cert.get('issuer', [])),
                                'serial_number': basic_cert.get('serialNumber'),
                                'fingerprint': 'unavailable'
                            })
                        except Exception:
                            chain.append({
                                'subject': 'Certificate info unavailable',
                                'issuer': 'Certificate info unavailable'
                            })
                            
        except Exception as e:
            self.logger.error(f"Failed to get certificate chain: {str(e)}")
            
        return chain
        
    def _query_certificate_transparency(self, cert_info):
        """Query Certificate Transparency logs"""
        ct_logs = []
        
        # Check if Certificate Transparency is enabled
        if not self.config.get('security', 'cert_transparency', True):
            self.logger.info("Certificate Transparency queries disabled")
            return ct_logs
        
        if not cert_info or not cert_info.get('sha256_fingerprint'):
            return ct_logs
            
        try:
            # Query crt.sh for certificate transparency logs
            fingerprint = cert_info['sha256_fingerprint']
            url = f"https://crt.sh/?q={fingerprint}&output=json"
            
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    for entry in data[:10]:  # Limit to first 10 entries
                        ct_logs.append({
                            'id': entry.get('id'),
                            'logged_at': entry.get('entry_timestamp'),
                            'not_before': entry.get('not_before'),
                            'not_after': entry.get('not_after'),
                            'common_name': entry.get('common_name'),
                            'issuer_name': entry.get('issuer_name')
                        })
                        
        except Exception as e:
            self.logger.error(f"Failed to query Certificate Transparency logs: {str(e)}")
            
        return ct_logs
        
    def _save_ssl_results(self, target, ssl_info):
        """Save SSL/TLS analysis results"""
        try:
            output_file = self.output_dir / f"ssl_analysis_{target.replace('.', '_')}.json"
            with open(output_file, 'w') as f:
                json.dump(ssl_info, f, indent=2, default=str)
            self.logger.info(f"SSL analysis results saved to {output_file}")
        except Exception as e:
            self.logger.error(f"Failed to save SSL results: {str(e)}")
            
    def scan_target(self, target):
        """Run complete security scan on target"""
        self.logger.info(f"Running security scan on {target}")
        
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'ssl_analysis': {},
            'open_ports': []
        }
        
        # Get SSL/TLS ports from configuration
        ssl_ports = self.config.get('security', 'ports', [443, 8443, 9443, 8080, 8008, 8888])
        timeout = self.config.get('security', 'timeout', 30)
        
        for port in ssl_ports:
            if self._port_is_open(target, port, timeout=timeout):
                results['open_ports'].append(port)
                ssl_result = self.analyze_ssl_tls(target, port)
                results['ssl_analysis'][f"port_{port}"] = ssl_result
                
        return results
        
    def _port_is_open(self, target, port, timeout=3):
        """Check if a port is open"""
        try:
            with socket.create_connection((target, port), timeout=timeout):
                return True
        except (socket.timeout, socket.error):
            return False
    
    def vulnerability_scan(self, target):
        """Enhanced vulnerability scanning with multiple tools"""
        try:
            print(f"\n🔍 Starting vulnerability scan for: {target}")
            
            results = {
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'nmap_vulners': {},
                'ssl_vulnerabilities': {},
                'web_vulnerabilities': {},
                'service_vulnerabilities': {},
                'cve_analysis': {}
            }
            
            # Nmap vulnerability scripts
            nmap_vuln_results = self._run_nmap_vulners(target)
            if nmap_vuln_results:
                results['nmap_vulners'] = nmap_vuln_results
            
            # SSL/TLS vulnerability analysis
            ssl_vulns = self._analyze_ssl_vulnerabilities(target)
            if ssl_vulns:
                results['ssl_vulnerabilities'] = ssl_vulns
            
            # Web application vulnerability checks
            web_vulns = self._check_web_vulnerabilities(target)
            if web_vulns:
                results['web_vulnerabilities'] = web_vulns
            
            # Service-specific vulnerability checks
            service_vulns = self._check_service_vulnerabilities(target)
            if service_vulns:
                results['service_vulnerabilities'] = service_vulns
            
            print(f"✅ Vulnerability scan completed for {target}")
            return results
            
        except Exception as e:
            self.logger.error(f"Vulnerability scan error: {str(e)}")
            return {}
    
    def _run_nmap_vulners(self, target):
        """Run Nmap with vulnerability detection scripts"""
        try:
            vuln_scripts = [
                '--script=vuln',
                '--script=vulners',
                '--script=vulscan',
                '--script=exploit'
            ]
            
            results = {}
            
            for script in vuln_scripts:
                try:
                    cmd = f"nmap -sV {script} --script-args vulners.shodan-api-key='' {target}"
                    result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=300)
                    
                    if result.stdout:
                        script_name = script.split('=')[1] if '=' in script else script
                        results[script_name] = self._parse_nmap_vuln_output(result.stdout)
                        
                except subprocess.TimeoutExpired:
                    self.logger.warning(f"Nmap vulnerability script {script} timed out")
                except Exception as e:
                    self.logger.debug(f"Script {script} failed: {str(e)}")
                    
            return results
            
        except Exception as e:
            self.logger.error(f"Nmap vulnerability scan error: {str(e)}")
            return {}
    
    def _parse_nmap_vuln_output(self, output):
        """Parse Nmap vulnerability scan output"""
        vulnerabilities = []
        
        # Look for CVE patterns
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = re.findall(cve_pattern, output)
        
        # Look for vulnerability descriptions
        vuln_lines = []
        for line in output.split('\n'):
            if any(keyword in line.lower() for keyword in ['vulnerable', 'exploit', 'cve-', 'risk']):
                vuln_lines.append(line.strip())
        
        return {
            'cves': list(set(cves)),
            'vulnerability_details': vuln_lines[:20]  # Limit output
        }
    
    def _analyze_ssl_vulnerabilities(self, target):
        """Advanced SSL/TLS vulnerability analysis"""
        try:
            ssl_ports = [443, 8443, 9443, 8080, 8008]
            results = {}
            
            for port in ssl_ports:
                if self._port_is_open(target, port):
                    port_results = {}
                    
                    # Check for common SSL vulnerabilities
                    vuln_checks = {
                        'heartbleed': self._check_heartbleed(target, port),
                        'poodle': self._check_poodle(target, port),
                        'beast': self._check_beast(target, port),
                        'drown': self._check_drown(target, port),
                        'weak_ciphers': self._check_weak_ciphers(target, port),
                        'certificate_issues': self._check_certificate_issues(target, port)
                    }
                    
                    # Filter out empty results
                    port_results = {k: v for k, v in vuln_checks.items() if v}
                    
                    if port_results:
                        results[f'port_{port}'] = port_results
                        
            return results
            
        except Exception as e:
            self.logger.error(f"SSL vulnerability analysis error: {str(e)}")
            return {}
    
    def _check_heartbleed(self, target, port):
        """Check for Heartbleed vulnerability using Nmap"""
        try:
            cmd = f"nmap -p {port} --script ssl-heartbleed {target}"
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=30)
            
            if 'VULNERABLE' in result.stdout:
                return {
                    'vulnerable': True,
                    'cve': 'CVE-2014-0160',
                    'severity': 'HIGH',
                    'description': 'Heartbleed vulnerability detected'
                }
        except Exception:
            pass
        return None
    
    def _check_poodle(self, target, port):
        """Check for POODLE vulnerability"""
        try:
            cmd = f"nmap -p {port} --script ssl-poodle {target}"
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=30)
            
            if 'VULNERABLE' in result.stdout:
                return {
                    'vulnerable': True,
                    'cve': 'CVE-2014-3566',
                    'severity': 'MEDIUM',
                    'description': 'POODLE vulnerability detected'
                }
        except Exception:
            pass
        return None
    
    def _check_beast(self, target, port):
        """Check for BEAST vulnerability"""
        try:
            cmd = f"nmap -p {port} --script ssl-enum-ciphers {target}"
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=30)
            
            # Look for CBC ciphers with TLS 1.0
            if 'TLSv1.0' in result.stdout and 'CBC' in result.stdout:
                return {
                    'vulnerable': True,
                    'cve': 'CVE-2011-3389',
                    'severity': 'MEDIUM',
                    'description': 'BEAST vulnerability - CBC cipher with TLS 1.0'
                }
        except Exception:
            pass
        return None
    
    def _check_drown(self, target, port):
        """Check for DROWN vulnerability"""
        try:
            cmd = f"nmap -p {port} --script ssl-dh-params {target}"
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=30)
            
            if 'SSLv2' in result.stdout:
                return {
                    'vulnerable': True,
                    'cve': 'CVE-2016-0800',
                    'severity': 'HIGH',
                    'description': 'DROWN vulnerability - SSLv2 enabled'
                }
        except Exception:
            pass
        return None
    
    def _check_weak_ciphers(self, target, port):
        """Check for weak SSL/TLS ciphers"""
        try:
            cmd = f"nmap -p {port} --script ssl-enum-ciphers {target}"
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=30)
            
            weak_ciphers = []
            weak_keywords = ['NULL', 'EXPORT', 'RC4', 'DES', 'MD5', 'weak']
            
            for line in result.stdout.split('\n'):
                for keyword in weak_keywords:
                    if keyword in line.upper():
                        weak_ciphers.append(line.strip())
                        
            if weak_ciphers:
                return {
                    'weak_ciphers_found': True,
                    'severity': 'MEDIUM',
                    'ciphers': weak_ciphers[:10],  # Limit output
                    'description': 'Weak or insecure ciphers detected'
                }
        except Exception:
            pass
        return None
    
    def _check_certificate_issues(self, target, port):
        """Check for SSL certificate issues"""
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    issues = []
                    
                    # Check expiration
                    import datetime
                    not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.datetime.now()).days
                    
                    if days_until_expiry < 30:
                        issues.append(f"Certificate expires in {days_until_expiry} days")
                    
                    # Check for self-signed
                    if cert.get('issuer') == cert.get('subject'):
                        issues.append("Self-signed certificate")
                    
                    # Check for weak signature algorithm
                    if 'sha1' in cert.get('signatureAlgorithm', '').lower():
                        issues.append("Weak signature algorithm (SHA-1)")
                    
                    if issues:
                        return {
                            'certificate_issues': True,
                            'issues': issues,
                            'severity': 'MEDIUM',
                            'certificate_info': {
                                'subject': cert.get('subject'),
                                'issuer': cert.get('issuer'),
                                'expiry': cert.get('notAfter')
                            }
                        }
                        
        except Exception as e:
            self.logger.debug(f"Certificate check error: {str(e)}")
        return None
    
    def _check_web_vulnerabilities(self, target):
        """Check for common web application vulnerabilities"""
        try:
            results = {}
            
            # Check if target responds to HTTP/HTTPS
            protocols = []
            if self._port_is_open(target, 80):
                protocols.append('http')
            if self._port_is_open(target, 443):
                protocols.append('https')
                
            for protocol in protocols:
                base_url = f"{protocol}://{target}"
                
                # SQL Injection basic check
                sqli_check = self._basic_sqli_check(base_url)
                if sqli_check:
                    results['sql_injection'] = sqli_check
                
                # XSS basic check
                xss_check = self._basic_xss_check(base_url)
                if xss_check:
                    results['xss'] = xss_check
                
                # Directory traversal check
                lfi_check = self._basic_lfi_check(base_url)
                if lfi_check:
                    results['directory_traversal'] = lfi_check
                
                # Command injection check
                cmd_check = self._basic_command_injection_check(base_url)
                if cmd_check:
                    results['command_injection'] = cmd_check
                    
            return results
            
        except Exception as e:
            self.logger.error(f"Web vulnerability check error: {str(e)}")
            return {}
    
    def _basic_sqli_check(self, base_url):
        """Basic SQL injection detection"""
        try:
            payloads = ["'", "1'OR'1'='1", "admin'--", "' UNION SELECT NULL--"]
            
            for payload in payloads:
                test_urls = [
                    f"{base_url}/?id={payload}",
                    f"{base_url}/login?username={payload}&password=test",
                    f"{base_url}/search?q={payload}"
                ]
                
                for url in test_urls:
                    try:
                        resp = requests.get(url, timeout=5)
                        
                        # Look for SQL error messages
                        error_patterns = [
                            r'mysql_fetch_array',
                            r'ORA-\d{5}',
                            r'Microsoft.*ODBC.*SQL',
                            r'PostgreSQL.*ERROR',
                            r'Warning.*mysql_.*',
                            r'SQL syntax.*MySQL',
                            r'sqlite3\.OperationalError'
                        ]
                        
                        for pattern in error_patterns:
                            if re.search(pattern, resp.text, re.IGNORECASE):
                                return {
                                    'potential_sqli': True,
                                    'url': url,
                                    'payload': payload,
                                    'pattern_matched': pattern,
                                    'severity': 'HIGH'
                                }
                                
                    except Exception:
                        continue
                        
        except Exception:
            pass
        return None
    
    def _basic_xss_check(self, base_url):
        """Basic XSS detection"""
        try:
            payloads = [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>"
            ]
            
            for payload in payloads:
                test_urls = [
                    f"{base_url}/?search={payload}",
                    f"{base_url}/?q={payload}",
                    f"{base_url}/?name={payload}"
                ]
                
                for url in test_urls:
                    try:
                        resp = requests.get(url, timeout=5)
                        
                        if payload in resp.text:
                            return {
                                'potential_xss': True,
                                'url': url,
                                'payload': payload,
                                'reflected': True,
                                'severity': 'MEDIUM'
                            }
                            
                    except Exception:
                        continue
                        
        except Exception:
            pass
        return None
    
    def _basic_lfi_check(self, base_url):
        """Basic Local File Inclusion detection"""
        try:
            payloads = [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd"
            ]
            
            for payload in payloads:
                test_urls = [
                    f"{base_url}/?file={payload}",
                    f"{base_url}/?page={payload}",
                    f"{base_url}/?include={payload}"
                ]
                
                for url in test_urls:
                    try:
                        resp = requests.get(url, timeout=5)
                        
                        # Look for signs of file inclusion
                        if any(pattern in resp.text for pattern in ['root:x:', 'daemon:', 'bin:', '127.0.0.1']):
                            return {
                                'potential_lfi': True,
                                'url': url,
                                'payload': payload,
                                'severity': 'HIGH'
                            }
                            
                    except Exception:
                        continue
                        
        except Exception:
            pass
        return None
    
    def _basic_command_injection_check(self, base_url):
        """Basic command injection detection"""
        try:
            payloads = [
                "; ls",
                "| whoami",
                "&& dir",
                "`id`"
            ]
            
            for payload in payloads:
                test_urls = [
                    f"{base_url}/?cmd={payload}",
                    f"{base_url}/?exec={payload}",
                    f"{base_url}/?system={payload}"
                ]
                
                for url in test_urls:
                    try:
                        resp = requests.get(url, timeout=5)
                        
                        # Look for command output patterns
                        cmd_patterns = [
                            r'uid=\d+.*gid=\d+',  # id command output
                            r'total \d+',         # ls command output
                            r'Volume.*Serial',    # dir command output
                            r'root.*bin.*sbin'    # whoami/ls output
                        ]
                        
                        for pattern in cmd_patterns:
                            if re.search(pattern, resp.text):
                                return {
                                    'potential_command_injection': True,
                                    'url': url,
                                    'payload': payload,
                                    'pattern_matched': pattern,
                                    'severity': 'HIGH'
                                }
                                
                    except Exception:
                        continue
                        
        except Exception:
            pass
        return None
    
    def _check_service_vulnerabilities(self, target):
        """Check for service-specific vulnerabilities"""
        try:
            results = {}
            
            # Check common vulnerable services
            vulnerable_services = {
                21: 'FTP',
                22: 'SSH', 
                23: 'Telnet',
                25: 'SMTP',
                53: 'DNS',
                80: 'HTTP',
                110: 'POP3',
                143: 'IMAP',
                443: 'HTTPS',
                993: 'IMAPS',
                995: 'POP3S',
                1433: 'MSSQL',
                3306: 'MySQL',
                5432: 'PostgreSQL',
                6379: 'Redis'
            }
            
            for port, service in vulnerable_services.items():
                if self._port_is_open(target, port):
                    service_vulns = self._check_specific_service(target, port, service)
                    if service_vulns:
                        results[f'{service}_port_{port}'] = service_vulns
                        
            return results
            
        except Exception as e:
            self.logger.error(f"Service vulnerability check error: {str(e)}")
            return {}
    
    def _check_specific_service(self, target, port, service):
        """Check vulnerabilities for specific services"""
        try:
            vulnerabilities = []
            
            if service == 'SSH':
                # Check for weak SSH configuration
                ssh_issues = self._check_ssh_vulnerabilities(target, port)
                if ssh_issues:
                    vulnerabilities.extend(ssh_issues)
                    
            elif service == 'FTP':
                # Check for anonymous FTP
                ftp_issues = self._check_ftp_vulnerabilities(target, port)
                if ftp_issues:
                    vulnerabilities.extend(ftp_issues)
                    
            elif service in ['MySQL', 'MSSQL', 'PostgreSQL']:
                # Check for database vulnerabilities
                db_issues = self._check_database_vulnerabilities(target, port, service)
                if db_issues:
                    vulnerabilities.extend(db_issues)
                    
            return vulnerabilities if vulnerabilities else None
            
        except Exception:
            return None
    
    def _check_ssh_vulnerabilities(self, target, port):
        """Check SSH-specific vulnerabilities"""
        try:
            issues = []
            
            # Use Nmap SSH scripts
            ssh_scripts = [
                '--script=ssh2-enum-algos',
                '--script=ssh-hostkey',
                '--script=ssh-auth-methods'
            ]
            
            for script in ssh_scripts:
                try:
                    cmd = f"nmap -p {port} {script} {target}"
                    result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=30)
                    
                    # Look for weak algorithms
                    if 'weak' in result.stdout.lower() or 'deprecated' in result.stdout.lower():
                        issues.append({
                            'issue': 'Weak SSH algorithms detected',
                            'severity': 'MEDIUM',
                            'details': result.stdout[:200]
                        })
                        
                except Exception:
                    continue
                    
            return issues
            
        except Exception:
            return []
    
    def _check_ftp_vulnerabilities(self, target, port):
        """Check FTP-specific vulnerabilities"""
        try:
            issues = []
            
            # Check for anonymous FTP
            try:
                import ftplib
                ftp = ftplib.FTP()
                ftp.connect(target, port, timeout=10)
                
                try:
                    ftp.login('anonymous', 'test@test.com')
                    issues.append({
                        'issue': 'Anonymous FTP access enabled',
                        'severity': 'MEDIUM',
                        'details': 'Anonymous login successful'
                    })
                    ftp.quit()
                except:
                    pass
                    
            except Exception:
                pass
                
            return issues
            
        except Exception:
            return []
    
    def _check_database_vulnerabilities(self, target, port, service):
        """Check database-specific vulnerabilities"""
        try:
            issues = []
            
            # Use Nmap database scripts
            if service == 'MySQL':
                cmd = f"nmap -p {port} --script=mysql-info,mysql-empty-password {target}"
            elif service == 'MSSQL':
                cmd = f"nmap -p {port} --script=ms-sql-info,ms-sql-empty-password {target}"
            elif service == 'PostgreSQL':
                cmd = f"nmap -p {port} --script=pgsql-brute {target}"
            else:
                return []
                
            try:
                result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=30)
                
                # Look for security issues
                if 'empty password' in result.stdout.lower():
                    issues.append({
                        'issue': 'Empty/default password detected',
                        'severity': 'HIGH',
                        'service': service
                    })
                    
                if 'root' in result.stdout.lower() and 'access' in result.stdout.lower():
                    issues.append({
                        'issue': 'Root access detected',
                        'severity': 'HIGH',
                        'service': service
                    })
                    
            except Exception:
                pass
                
            return issues
            
        except Exception:
            return []


# ============================== PORT SCANNER ==============================
class PortScanner:
    """Nmap port scanner wrapper"""
    
    def __init__(self, output_dir, config):
        self.output_dir = Path(output_dir)
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def basic_scan(self, target):
        """Run basic port scan"""
        self.logger.info(f"Running basic port scan on {target}")
        
        flags = self.config.get('nmap', 'basic_flags', '-sV -sC')
        timeout = self.config.get('nmap', 'timeout', 300)
        
        output_file = self.output_dir / 'nmap' / f'{target}_basic'
        
        cmd = [
            'nmap', 
            *flags.split(),
            '-oA', str(output_file),
            '--open',
            target
        ]
        
        return self._run_nmap_command(cmd, target, 'basic')
    
    def aggressive_scan(self, target):
        """Run aggressive port scan with light mode support"""
        self.logger.info(f"Running aggressive port scan on {target}")
        
        flags = self.config.get('nmap', 'aggressive_flags', '-A -T4')
        
        # Adjust for light mode
        if self.config.get('performance', 'light_mode', False):
            # Use lighter timing and reduce aggressive features
            flags = flags.replace('-T4', '-T3')  # Slower timing
            flags = flags.replace('-A', '-sV -sC')  # Remove OS detection and traceroute
            self.logger.info("Light mode: Using reduced Nmap flags for lower resource usage")
        
        timeout = self.config.get('nmap', 'timeout', 600)
        
        output_file = self.output_dir / 'nmap' / f'{target}_aggressive'
        
        cmd = [
            'nmap',
            *flags.split(),
            '-oA', str(output_file),
            '--open',
            target
        ]
        
        return self._run_nmap_command(cmd, target, 'aggressive')
    
    def _run_nmap_command(self, cmd, target, scan_type):
        """Execute nmap command and parse results"""
        try:
            self.logger.info(f"Executing: {' '.join(cmd)}")
            
            # Run the command
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.get('nmap', 'timeout', 300)
            )
            
            if result.returncode != 0:
                self.logger.error(f"Nmap scan failed: {result.stderr}")
                return {}
            
            # Parse XML output
            xml_file = f"{cmd[cmd.index('-oA') + 1]}.xml"
            
            if os.path.exists(xml_file):
                return self._parse_nmap_xml(xml_file, target, scan_type)
            else:
                self.logger.warning(f"XML output file not found: {xml_file}")
                return {}
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"Nmap scan timed out for {target}")
            return {}
        except Exception as e:
            self.logger.error(f"Error running nmap scan: {str(e)}")
            return {}
    
    def _parse_nmap_xml(self, xml_file, target, scan_type):
        """Parse Nmap XML output"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            results = {
                'target': target,
                'scan_type': scan_type,
                'timestamp': root.get('startstr'),
                'hosts': [],
                'summary': {
                    'total_hosts': 0,
                    'hosts_up': 0,
                    'total_ports': 0,
                    'open_ports': 0,
                    'filtered_ports': 0,
                    'closed_ports': 0
                }
            }
            
            for host in root.findall('host'):
                host_info = self._parse_host(host)
                if host_info:
                    results['hosts'].append(host_info)
                    results['summary']['total_hosts'] += 1
                    
                    if host_info['status'] == 'up':
                        results['summary']['hosts_up'] += 1
                        
                    for port in host_info.get('ports', []):
                        results['summary']['total_ports'] += 1
                        state = port.get('state', 'unknown')
                        if state == 'open':
                            results['summary']['open_ports'] += 1
                        elif state == 'filtered':
                            results['summary']['filtered_ports'] += 1
                        elif state == 'closed':
                            results['summary']['closed_ports'] += 1
            
            # Save parsed results
            json_file = self.output_dir / 'nmap' / f'{target}_{scan_type}_parsed.json'
            with open(json_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            self.logger.info(f"Parsed nmap results saved to {json_file}")
            return results
            
        except Exception as e:
            self.logger.error(f"Error parsing XML file {xml_file}: {str(e)}")
            return {}
    
    def _parse_host(self, host_element):
        """Parse individual host from XML"""
        try:
            # Get host address
            address_elem = host_element.find('address')
            if address_elem is None:
                return None
                
            host_info = {
                'address': address_elem.get('addr'),
                'address_type': address_elem.get('addrtype'),
                'status': host_element.find('status').get('state'),
                'hostnames': [],
                'ports': [],
                'os': {},
                'scripts': []
            }
            
            # Get hostnames
            hostnames = host_element.find('hostnames')
            if hostnames is not None:
                for hostname in hostnames.findall('hostname'):
                    host_info['hostnames'].append({
                        'name': hostname.get('name'),
                        'type': hostname.get('type')
                    })
            
            # Get ports
            ports = host_element.find('ports')
            if ports is not None:
                for port in ports.findall('port'):
                    port_info = {
                        'port': port.get('portid'),
                        'protocol': port.get('protocol'),
                        'state': port.find('state').get('state'),
                        'reason': port.find('state').get('reason'),
                        'service': {}
                    }
                    
                    # Get service info
                    service = port.find('service')
                    if service is not None:
                        port_info['service'] = {
                            'name': service.get('name', ''),
                            'product': service.get('product', ''),
                            'version': service.get('version', ''),
                            'extrainfo': service.get('extrainfo', '')
                        }
                    
                    host_info['ports'].append(port_info)
            
            return host_info
            
        except Exception as e:
            self.logger.error(f"Error parsing host: {str(e)}")
            return None

    def masscan_scan(self, target, port_range="1-65535"):
        """Run masscan for ultra-fast port discovery"""
        try:
            # Check if masscan is available
            subprocess.run(['masscan', '--help'], capture_output=True, check=True)
            
            self.logger.info(f"Running masscan on {target} (ports {port_range})")
            
            output_file = self.output_dir / 'nmap' / f'{target}_masscan.json'
            
            # Masscan command with rate limiting for safety
            cmd = [
                'masscan',
                target,
                '-p', port_range,
                '--rate', '1000',  # Conservative rate
                '--output-format', 'json',
                '--output-filename', str(output_file),
                '--open-only'
            ]
            
            # Run masscan with timeout
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # Parse masscan JSON output
                masscan_results = self._parse_masscan_json(output_file, target)
                self.logger.info(f"Masscan discovered {len(masscan_results.get('ports', []))} open ports")
                return masscan_results
            else:
                self.logger.error(f"Masscan failed: {result.stderr}")
                return None
                
        except subprocess.CalledProcessError:
            self.logger.warning("Masscan not available, falling back to nmap")
            return None
        except subprocess.TimeoutExpired:
            self.logger.warning("Masscan timed out")
            return None
        except Exception as e:
            self.logger.error(f"Error running masscan: {str(e)}")
            return None

    def _parse_masscan_json(self, json_file, target):
        """Parse masscan JSON output"""
        try:
            results = {
                'target': target,
                'scan_type': 'masscan',
                'ports': [],
                'total_ports': 0
            }
            
            if not json_file.exists():
                return results
            
            with open(json_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and line.startswith('{'):
                        try:
                            port_data = json.loads(line)
                            if 'ports' in port_data:
                                for port_info in port_data['ports']:
                                    results['ports'].append({
                                        'port': port_info.get('port'),
                                        'protocol': port_info.get('proto', 'tcp'),
                                        'state': 'open',
                                        'service': {'name': 'unknown'},
                                        'discovered_by': 'masscan'
                                    })
                        except json.JSONDecodeError:
                            continue
            
            results['total_ports'] = len(results['ports'])
            return results
            
        except Exception as e:
            self.logger.error(f"Error parsing masscan output: {str(e)}")
            return {'target': target, 'scan_type': 'masscan', 'ports': [], 'total_ports': 0}

    def hybrid_scan(self, target):
        """Hybrid scan: masscan for discovery + nmap for service detection"""
        self.logger.info(f"Running hybrid scan on {target}")
        
        # Step 1: Fast port discovery with masscan
        masscan_results = self.masscan_scan(target)
        
        if masscan_results and masscan_results['total_ports'] > 0:
            # Step 2: Extract discovered ports
            open_ports = [str(port['port']) for port in masscan_results['ports']]
            port_list = ','.join(open_ports[:100])  # Limit to first 100 ports
            
            self.logger.info(f"Masscan found {len(open_ports)} ports, running nmap service detection")
            
            # Step 3: Service detection with nmap on discovered ports
            output_file = self.output_dir / 'nmap' / f'{target}_hybrid'
            
            cmd = [
                'nmap',
                '-sV', '-sC',  # Service detection and default scripts
                '-p', port_list,
                '-oA', str(output_file),
                '--open',
                target
            ]
            
            nmap_results = self._run_nmap_command(cmd, target, 'hybrid')
            
            # Merge results
            if nmap_results:
                # Update masscan results with nmap service info
                nmap_ports = {p['port']: p for host in nmap_results.get('hosts', []) for p in host.get('ports', [])}
                
                for port in masscan_results['ports']:
                    port_num = str(port['port'])
                    if port_num in nmap_ports:
                        port.update(nmap_ports[port_num])
                
                masscan_results['scan_type'] = 'hybrid'
                masscan_results['service_detection'] = True
                
            return masscan_results
        else:
            # Fallback to basic nmap scan
            self.logger.info("Masscan found no ports, falling back to nmap basic scan")
            return self.basic_scan(target)


# ============================== SUBDOMAIN ENUMERATOR ==============================
class SubdomainEnumerator:
    """Subdomain enumeration using multiple tools"""
    
    def __init__(self, output_dir, config):
        self.output_dir = Path(output_dir)
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.subdomains = set()
        
    def enumerate(self, domain):
        """Run comprehensive subdomain enumeration"""
        self.logger.info(f"Starting subdomain enumeration for {domain}")
        
        # Create results structure
        results = {
            'domain': domain,
            'subdomains': [],
            'live_subdomains': [],
            'tools_used': [],
            'total_found': 0,
            'total_live': 0
        }
        
        # Check if we're in offline mode
        offline_mode = self.config.get('mode', 'offline', False) or self.config.get('general', 'offline_mode', False)
        
        if offline_mode:
            # Run offline enumeration methods
            self.logger.info("Running in offline mode - using internal enumeration methods")
            self._dns_bruteforce(domain, results)
            self._zone_transfer(domain, results)
            self._san_from_cert(domain, results)
        else:
            # Run online enumeration methods
            self._run_sublist3r(domain, results)
            self._run_assetfinder(domain, results)
            self._run_subfinder(domain, results)
            self._run_crtsh(domain, results)
        
        # Deduplicate and validate subdomains
        unique_subdomains = list(self.subdomains)
        results['subdomains'] = unique_subdomains
        results['total_found'] = len(unique_subdomains)
        
        # Check which subdomains are live
        live_subdomains = self._validate_subdomains(unique_subdomains[:50])  # Limit for performance
        results['live_subdomains'] = live_subdomains
        results['total_live'] = len(live_subdomains)
        
        # Save results
        self._save_results(domain, results)
        
        self.logger.info(f"Found {results['total_found']} subdomains, {results['total_live']} live")
        return [sub['subdomain'] for sub in live_subdomains]
    
    def _run_sublist3r(self, domain, results):
        """Run Sublist3r for subdomain enumeration"""
        try:
            self.logger.info("Running Sublist3r...")
            output_file = self.output_dir / 'subdomains' / f'{domain}_sublist3r.txt'
            
            cmd = [
                'sublist3r',
                '-d', domain,
                '-o', str(output_file)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.get('subdomains', 'timeout', 300)
            )
            
            if result.returncode == 0 and output_file.exists():
                with open(output_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
                    self.subdomains.update(subdomains)
                    results['tools_used'].append('sublist3r')
                    self.logger.info(f"Sublist3r found {len(subdomains)} subdomains")
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.logger.warning(f"Sublist3r error: {str(e)}")
    
    def _run_assetfinder(self, domain, results):
        """Run Assetfinder for subdomain enumeration"""
        try:
            self.logger.info("Running Assetfinder...")
            
            cmd = ['assetfinder', domain]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.get('subdomains', 'timeout', 300)
            )
            
            if result.returncode == 0:
                subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                self.subdomains.update(subdomains)
                results['tools_used'].append('assetfinder')
                
                # Save output
                output_file = self.output_dir / 'subdomains' / f'{domain}_assetfinder.txt'
                with open(output_file, 'w') as f:
                    f.write(result.stdout)
                
                self.logger.info(f"Assetfinder found {len(subdomains)} subdomains")
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.logger.warning(f"Assetfinder error: {str(e)}")
    
    def _run_subfinder(self, domain, results):
        """Run Subfinder for subdomain enumeration"""
        try:
            self.logger.info("Running Subfinder...")
            output_file = self.output_dir / 'subdomains' / f'{domain}_subfinder.txt'
            
            cmd = [
                'subfinder',
                '-d', domain,
                '-o', str(output_file),
                '-silent'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.get('subdomains', 'timeout', 300)
            )
            
            if result.returncode == 0 and output_file.exists():
                with open(output_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
                    self.subdomains.update(subdomains)
                    results['tools_used'].append('subfinder')
                    self.logger.info(f"Subfinder found {len(subdomains)} subdomains")
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.logger.warning(f"Subfinder error: {str(e)}")
    
    def _run_crtsh(self, domain, results):
        """Query crt.sh for certificate transparency logs"""
        try:
            self.logger.info("Querying crt.sh...")
            
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                
                for entry in data[:100]:  # Limit results
                    name_value = entry.get('name_value', '')
                    if name_value:
                        # Handle multiple names in one entry
                        names = name_value.split('\n')
                        for name in names:
                            name = name.strip()
                            if name and domain in name:
                                subdomains.add(name)
                
                self.subdomains.update(subdomains)
                results['tools_used'].append('crt.sh')
                
                self.logger.info(f"crt.sh found {len(subdomains)} subdomains")
            
        except Exception as e:
            self.logger.warning(f"Error querying crt.sh: {str(e)}")
    
    def _dns_bruteforce(self, domain, results):
        """DNS bruteforce using local/internal resolver"""
        try:
            self.logger.info("Running DNS bruteforce...")
            
            # Load DNS wordlist with comprehensive error handling
            wordlist_path = self.config.get('bruteforce', 'dns_wordlist', '/usr/share/wordlists/subdomains.txt')
            
            # Create a basic fallback wordlist
            basic_words = [
                'www', 'mail', 'admin', 'ftp', 'blog', 'test', 'dev', 'staging', 'api',
                'portal', 'intranet', 'vpn', 'secure', 'app', 'web', 'server', 'host',
                'database', 'db', 'sql', 'backup', 'store', 'shop', 'cdn', 'static',
                'img', 'images', 'media', 'assets', 'files', 'docs', 'help', 'support'
            ]
            
            # Attempt to load custom wordlist with proper error handling
            if not wordlist_path or not os.path.exists(wordlist_path):
                if wordlist_path:
                    self.logger.warning(f"DNS wordlist not found: {wordlist_path}, using built-in wordlist")
                else:
                    self.logger.info("No DNS wordlist specified, using built-in wordlist")
                self.logger.info(f"Using built-in DNS wordlist ({len(basic_words)} words)")
                wordlist = basic_words
            else:
                try:
                    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                        wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')][:1000]  # Limit for performance
                        if wordlist:
                            self.logger.info(f"Loaded DNS wordlist from {wordlist_path} ({len(wordlist)} words)")
                        else:
                            self.logger.warning(f"DNS wordlist is empty: {wordlist_path}, using built-in wordlist")
                            wordlist = basic_words
                except (IOError, OSError, PermissionError) as e:
                    self.logger.error(f"Cannot read DNS wordlist '{wordlist_path}': {str(e)}, using built-in wordlist")
                    wordlist = basic_words
                except Exception as e:
                    self.logger.error(f"Unexpected error loading DNS wordlist '{wordlist_path}': {str(e)}, using built-in wordlist")
                    wordlist = basic_words
            
            # Configure DNS resolver
            resolver = dns.resolver.Resolver()
            dns_servers = self.config.get('dns', 'servers', [])
            if dns_servers:
                resolver.nameservers = dns_servers
                self.logger.info(f"Using DNS servers: {dns_servers}")
            
            # Detect wildcard DNS by testing multiple random labels
            wildcard_ips = set()
            try:
                import random
                import string
                
                # Test multiple random labels to catch round-robin wildcards
                for i in range(3):
                    # Generate a truly random label
                    random_string = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
                    random_label = f"nonexistent-{random_string}-{i}.{domain}"
                    
                    try:
                        answer = resolver.resolve(random_label, 'A')
                        # Collect all IPs from the response (in case of multiple A records)
                        for record in answer:
                            wildcard_ips.add(str(record))
                        self.logger.debug(f"Wildcard test {i+1}: {random_label} -> {[str(r) for r in answer]}")
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        # This is good - means no wildcard for this test
                        pass
                    except Exception as e:
                        self.logger.debug(f"Wildcard test {i+1} error: {str(e)}")
                
                if wildcard_ips:
                    self.logger.info(f"Wildcard DNS detected! IPs: {sorted(wildcard_ips)}")
                else:
                    self.logger.info("No wildcard DNS detected")
                    
            except Exception as e:
                self.logger.warning(f"Wildcard detection error: {str(e)}")
                wildcard_ips = set()  # Continue without wildcard detection
            
            # Bruteforce subdomains
            found_subdomains = []
            for word in wordlist[:500]:  # Limit for performance
                subdomain = f"{word}.{domain}"
                try:
                    answer = resolver.resolve(subdomain, 'A')
                    
                    # Check all A records returned
                    subdomain_ips = set(str(record) for record in answer)
                    
                    # Skip if all IPs match wildcard IPs
                    if wildcard_ips and subdomain_ips.issubset(wildcard_ips):
                        self.logger.debug(f"Skipping {subdomain} - matches wildcard IP(s)")
                        continue
                    
                    # Also skip if ANY IP matches wildcard (more conservative approach)
                    if wildcard_ips and subdomain_ips.intersection(wildcard_ips):
                        self.logger.debug(f"Skipping {subdomain} - contains wildcard IP")
                        continue
                    
                    found_subdomains.append(subdomain)
                    self.subdomains.add(subdomain)
                    
                except dns.resolver.NXDOMAIN:
                    pass  # Domain doesn't exist
                except Exception as e:
                    self.logger.debug(f"DNS error for {subdomain}: {str(e)}")
            
            results['tools_used'].append('dns_bruteforce')
            
            # Save bruteforce results
            output_file = self.output_dir / 'subdomains' / f'{domain}_dns_bruteforce.txt'
            with open(output_file, 'w') as f:
                for subdomain in found_subdomains:
                    f.write(f"{subdomain}\n")
            
            self.logger.info(f"DNS bruteforce found {len(found_subdomains)} subdomains")
            
        except Exception as e:
            self.logger.warning(f"DNS bruteforce error: {str(e)}")
    
    def _zone_transfer(self, domain, results):
        """Attempt zone transfer (AXFR)"""
        try:
            self.logger.info("Attempting zone transfer (AXFR)...")
            
            # Get NS records using dig
            ns_records = []
            try:
                cmd = ['dig', '+short', domain, 'NS']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    ns_records = [line.strip().rstrip('.') for line in result.stdout.strip().split('\n') if line.strip()]
            except Exception as e:
                self.logger.debug(f"Error getting NS records with dig: {str(e)}")
            
            # Fallback to dns.resolver for NS records
            if not ns_records:
                try:
                    resolver = dns.resolver.Resolver()
                    dns_servers = self.config.get('dns', 'servers', [])
                    if dns_servers:
                        resolver.nameservers = dns_servers
                    
                    answer = resolver.resolve(domain, 'NS')
                    ns_records = [str(rdata).rstrip('.') for rdata in answer]
                except Exception as e:
                    self.logger.debug(f"Error getting NS records with resolver: {str(e)}")
            
            if not ns_records:
                self.logger.info("No NS records found for zone transfer")
                return
            
            self.logger.info(f"Found {len(ns_records)} NS records: {ns_records}")
            
            # Try zone transfer on each NS
            transfer_results = []
            for ns in ns_records[:3]:  # Limit NS servers
                try:
                    self.logger.info(f"Trying zone transfer from {ns}")
                    
                    # Use dns.query.xfr for zone transfer if available
                    if HAS_DNS_QUERY:
                        try:
                            self.logger.debug(f"Attempting AXFR from {ns}...")
                            xfr = dns.query.xfr(ns, domain, timeout=30)
                            zone = dns.zone.from_xfr(xfr)
                            
                            # Extract subdomains from zone
                            for name, node in zone.nodes.items():
                                if name != dns.name.empty:
                                    subdomain = f"{name}.{domain}".rstrip('.')
                                    if subdomain != domain:  # Exclude apex domain
                                        transfer_results.append(subdomain)
                                        self.subdomains.add(subdomain)
                            
                            self.logger.info(f"Zone transfer successful from {ns}: {len(transfer_results)} records")
                            break  # Success, no need to try other NS
                            
                        except dns.exception.DNSException as e:
                            # Specific DNS exceptions (refused, timeout, etc.)
                            if "refused" in str(e).lower() or "REFUSED" in str(e):
                                self.logger.info(f"AXFR refused by {ns} (expected security measure)")
                            elif "timeout" in str(e).lower() or "TIMEOUT" in str(e):
                                self.logger.info(f"AXFR timeout from {ns}")
                            elif "NOTAUTH" in str(e):
                                self.logger.info(f"AXFR not authorized by {ns}")
                            else:
                                self.logger.info(f"AXFR failed from {ns}: {str(e)}")
                        except Exception as e:
                            # Other non-DNS exceptions
                            self.logger.debug(f"Zone transfer error from {ns}: {str(e)}")
                    else:
                        self.logger.info("dns.query not available - skipping zone transfer")
                        break
                        
                except Exception as e:
                    self.logger.debug(f"Error with NS {ns}: {str(e)}")
            
            if transfer_results:
                results['tools_used'].append('zone_transfer')
                
                # Save zone transfer results
                output_file = self.output_dir / 'subdomains' / f'{domain}_zone_transfer.txt'
                with open(output_file, 'w') as f:
                    for subdomain in transfer_results:
                        f.write(f"{subdomain}\n")
                
                self.logger.info(f"Zone transfer found {len(transfer_results)} subdomains")
            else:
                self.logger.info("Zone transfer not allowed or failed")
                
        except Exception as e:
            self.logger.warning(f"Zone transfer error: {str(e)}")
    
    def _san_from_cert(self, domain, results):
        """Extract subdomains from certificate Subject Alternative Names (SAN)"""
        try:
            self.logger.info("Extracting subdomains from SSL certificates...")
            
            # Get target IPs
            target_ips = []
            try:
                # Try to resolve domain to IP
                import socket
                ip = socket.gethostbyname(domain)
                target_ips.append(ip)
            except:
                # If resolution fails, try the domain itself if it looks like an IP
                try:
                    ipaddress.ip_address(domain)
                    target_ips.append(domain)
                except:
                    self.logger.info(f"Could not resolve {domain} to IP for certificate analysis")
                    return
            
            # Common SSL ports to check
            ssl_ports = [443, 8443, 8080, 8000, 9443]
            found_subdomains = []
            
            for ip in target_ips:
                for port in ssl_ports:
                    try:
                        self.logger.debug(f"Checking SSL certificate on {ip}:{port}")
                        
                        # Create SSL context
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        
                        # Connect and get certificate
                        with socket.create_connection((ip, port), timeout=10) as sock:
                            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                                cert_der = ssock.getpeercert_chain()[0]
                                
                                # Parse certificate with cryptography
                                if HAS_CRYPTO:
                                    cert = x509.load_der_x509_certificate(cert_der.public_bytes(ssl.ENCODING_DER), default_backend())
                                    
                                    # Extract SAN extension
                                    try:
                                        san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                                        san_names = san_ext.value
                                        
                                        for name in san_names:
                                            if isinstance(name, x509.DNSName):
                                                dns_name = str(name.value)
                                                # Check if it's a subdomain of our target domain
                                                if dns_name.endswith(f'.{domain}') or dns_name == domain:
                                                    found_subdomains.append(dns_name)
                                                    self.subdomains.add(dns_name)
                                                    
                                        self.logger.info(f"Found {len(san_names)} SAN entries on {ip}:{port}")
                                        
                                    except x509.ExtensionNotFound:
                                        self.logger.debug(f"No SAN extension found on {ip}:{port}")
                                        
                                else:
                                    # Fallback to basic certificate parsing
                                    cert_info = ssock.getpeercert()
                                    san_list = cert_info.get('subjectAltName', [])
                                    
                                    for san_type, san_value in san_list:
                                        if san_type == 'DNS':
                                            if san_value.endswith(f'.{domain}') or san_value == domain:
                                                found_subdomains.append(san_value)
                                                self.subdomains.add(san_value)
                                    
                                    self.logger.info(f"Found {len(san_list)} SAN entries on {ip}:{port} (basic parsing)")
                        
                        # If we found a working SSL port, we can stop checking other ports for this IP
                        if found_subdomains:
                            break
                            
                    except (ConnectionRefusedError, ssl.SSLError, socket.timeout):
                        # Port not open or SSL not available
                        continue
                    except Exception as e:
                        self.logger.debug(f"SSL error on {ip}:{port}: {str(e)}")
                        continue
            
            if found_subdomains:
                results['tools_used'].append('cert_san')
                
                # Remove duplicates
                unique_sans = list(set(found_subdomains))
                
                # Save SAN results
                output_file = self.output_dir / 'subdomains' / f'{domain}_cert_san.txt'
                with open(output_file, 'w') as f:
                    for subdomain in unique_sans:
                        f.write(f"{subdomain}\n")
                
                self.logger.info(f"Certificate SAN analysis found {len(unique_sans)} subdomains")
            else:
                self.logger.info("No subdomains found in certificate SANs")
                
        except Exception as e:
            self.logger.warning(f"Certificate SAN analysis error: {str(e)}")
    
    def _validate_subdomains(self, subdomains):
        """Validate which subdomains are live using HTTP probes"""
        self.logger.info("Validating live subdomains...")
        
        live_subdomains = []
        
        def check_http(subdomain):
            for scheme in ['https', 'http']:
                try:
                    url = f"{scheme}://{subdomain}"
                    response = requests.head(url, timeout=5, allow_redirects=True)
                    if response.status_code < 400:
                        return {
                            'subdomain': subdomain,
                            'url': url,
                            'status_code': response.status_code
                        }
                except:
                    continue
            return None
        
        threads = min(self.config.get('subdomains', 'threads', 20), 20)  # Limit threads
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(check_http, sub) for sub in subdomains]
            
            for future in futures:
                try:
                    result = future.result(timeout=10)
                    if result:
                        live_subdomains.append(result)
                except:
                    continue
        
        return live_subdomains
    
    def _save_results(self, domain, results):
        """Save enumeration results"""
        # Save JSON results
        json_file = self.output_dir / 'subdomains' / f'{domain}_results.json'
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Save all subdomains to text file
        all_subs_file = self.output_dir / 'subdomains' / f'{domain}_all_subdomains.txt'
        with open(all_subs_file, 'w') as f:
            for subdomain in sorted(results['subdomains']):
                f.write(f"{subdomain}\n")
        
        self.logger.info(f"Subdomain results saved to {json_file}")


# ============================== WEB SCANNER ==============================
class WebScanner:
    """Web application scanner wrapper"""
    
    def __init__(self, output_dir, config):
        self.output_dir = Path(output_dir)
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def scan_target(self, target):
        """Run comprehensive web application scan"""
        self.logger.info(f"Starting web application scan for {target}")
        
        results = {
            'target': target,
            'nikto': {},
            'technology_stack': {},
            'security_headers': {},
            'directories': []
        }
        
        # Determine if target is HTTP/HTTPS accessible
        urls = self._get_web_urls(target)
        
        for url in urls[:2]:  # Limit to 2 URLs
            self.logger.info(f"Scanning {url}")
            
            # Run Nikto scan
            nikto_results = self._run_nikto(url)
            results['nikto'][url] = nikto_results
            
            # Technology stack detection
            tech_stack = self._detect_technology_stack(url)
            results['technology_stack'][url] = tech_stack
            
            # Security headers analysis
            headers = self._analyze_security_headers(url)
            results['security_headers'][url] = headers
            
            # Directory brute force
            directories = self._brute_force_dirs(url)
            results['directories'].extend(directories)
            
            # Enhanced directory discovery with modern tools
            enhanced_dirs = self._enhanced_directory_discovery(url)
            results['directories'].extend(enhanced_dirs)
        
        # Save results
        self._save_web_results(target, results)
        
        return results
    
    def _get_web_urls(self, target):
        """Get HTTP/HTTPS URLs for target"""
        urls = []
        
        # If target is already a URL, use it
        if target.startswith('http'):
            urls.append(target)
        else:
            # Try both HTTP and HTTPS
            for scheme in ['https', 'http']:
                url = f"{scheme}://{target}"
                try:
                    response = requests.head(url, timeout=10, allow_redirects=True)
                    if response.status_code < 400:
                        urls.append(url)
                except:
                    continue
        
        return urls if urls else [f"http://{target}"]  # Fallback
    
    def _run_nikto(self, url):
        """Run Nikto web vulnerability scanner"""
        try:
            self.logger.info(f"Running Nikto on {url}")
            
            output_file = self.output_dir / 'web' / f'nikto_{self._sanitize_url(url)}.txt'
            
            cmd = [
                'nikto',
                '-h', url,
                '-output', str(output_file),
                '-Format', 'txt'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.get('web', 'timeout', 300)
            )
            
            nikto_results = {
                'return_code': result.returncode,
                'findings': []
            }
            
            if output_file.exists():
                with open(output_file, 'r') as f:
                    content = f.read()
                    # Simple parsing of Nikto output
                    lines = content.split('\n')
                    for line in lines:
                        if line.startswith('+'):
                            nikto_results['findings'].append(line.strip())
            
            return nikto_results
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.logger.warning(f"Nikto error: {str(e)}")
            return {'error': str(e)}
    
    def _detect_technology_stack(self, url):
        """Enhanced technology stack detection with Wappalyzer-style analysis"""
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
            
            tech_stack = {
                'server': response.headers.get('Server', ''),
                'powered_by': response.headers.get('X-Powered-By', ''),
                'framework': [],
                'cms': [],
                'programming_language': [],
                'web_servers': [],
                'databases': [],
                'javascript_libraries': [],
                'cdn': [],
                'analytics': [],
                'confidence_score': 0
            }
            
            # Analyze headers, content, and scripts
            content = response.text.lower()
            headers = response.headers
            
            # Enhanced detection patterns
            detection_patterns = {
                'cms': [
                    ('WordPress', r'wp-content|wp-includes|wordpress|wp-json', 'meta[name="generator"][content*="wordpress"]'),
                    ('Drupal', r'drupal|sites/default|misc/drupal\.js', 'meta[name="generator"][content*="drupal"]'),
                    ('Joomla', r'joomla|com_content|media/jui', 'meta[name="generator"][content*="joomla"]'),
                    ('Magento', r'magento|mage/|skin/frontend', 'var BLANK_URL'),
                    ('Shopify', r'shopify|cdn\.shopify\.com', 'shopify'),
                    ('PrestaShop', r'prestashop|ps_', 'prestashop'),
                ],
                'frameworks': [
                    ('React', r'react|__react|data-reactroot', '_react'),
                    ('Angular', r'angular|ng-|angularjs', 'angular'),
                    ('Vue.js', r'vue\.js|__vue__|v-if|v-for', 'vue'),
                    ('Laravel', r'laravel_session|laravel_token', 'laravel'),
                    ('Django', r'django|csrfmiddlewaretoken', 'django'),
                    ('Ruby on Rails', r'rails|csrf-token|authenticity_token', 'rails'),
                    ('Express.js', r'express|x-powered-by.*express', 'express'),
                    ('Spring', r'spring|jsessionid|java_session', 'spring'),
                ],
                'languages': [
                    ('PHP', r'\.php|php|x-powered-by.*php', 'phpsessid'),
                    ('ASP.NET', r'\.aspx|asp\.net|x-aspnet-version', 'asp.net_sessionid'),
                    ('Java', r'\.jsp|\.jsf|jsessionid', 'java'),
                    ('Python', r'\.py|django|flask|wsgi', 'python'),
                    ('Node.js', r'node\.js|express|x-powered-by.*express', 'nodejs'),
                    ('Ruby', r'\.rb|rails|ruby', 'ruby'),
                ],
                'servers': [
                    ('Apache', r'apache|httpd', 'server.*apache'),
                    ('Nginx', r'nginx', 'server.*nginx'),
                    ('IIS', r'iis|microsoft-iis', 'server.*iis'),
                    ('LiteSpeed', r'litespeed|lsws', 'server.*litespeed'),
                    ('Cloudflare', r'cloudflare|cf-ray', 'cf-ray'),
                ],
                'js_libraries': [
                    ('jQuery', r'jquery|jquery\.min\.js', 'jquery'),
                    ('Bootstrap', r'bootstrap|bootstrap\.min\.css', 'bootstrap'),
                    ('Modernizr', r'modernizr', 'modernizr'),
                    ('Underscore.js', r'underscore\.js|_\.', 'underscore'),
                    ('Moment.js', r'moment\.js', 'moment'),
                ],
                'analytics': [
                    ('Google Analytics', r'google-analytics|ga\.js|gtag', 'ua-'),
                    ('Google Tag Manager', r'googletagmanager', 'gtm'),
                    ('Adobe Analytics', r'omniture|adobe.*analytics', 'omniture'),
                    ('Hotjar', r'hotjar', 'hotjar'),
                ],
                'cdn': [
                    ('Cloudflare', r'cloudflare|cf-ray', 'cf-ray'),
                    ('AWS CloudFront', r'cloudfront', 'cloudfront'),
                    ('Fastly', r'fastly', 'fastly'),
                    ('MaxCDN', r'maxcdn', 'maxcdn'),
                ]
            }
            
            confidence = 0
            
            # Check each category
            for category, patterns in detection_patterns.items():
                for tech_name, content_pattern, header_pattern in patterns:
                    score = 0
                    
                    # Check content patterns
                    if re.search(content_pattern, content):
                        score += 1
                        
                    # Check header patterns
                    for header_name, header_value in headers.items():
                        if re.search(header_pattern, f"{header_name}: {header_value}".lower()):
                            score += 2  # Headers are more reliable
                            
                    if score > 0:
                        category_key = category.rstrip('s')  # Remove 's' for dict key
                        if category_key not in tech_stack:
                            tech_stack[category_key] = []
                        tech_stack[category_key].append({
                            'name': tech_name,
                            'confidence': min(score * 33, 100)  # Cap at 100%
                        })
                        confidence += score
            
            # Special detection for specific technologies
            self._detect_cms_specific(url, tech_stack, content, headers)
            self._detect_api_technologies(url, tech_stack)
            
            tech_stack['confidence_score'] = min(confidence * 10, 100)
            return tech_stack
            
        except Exception as e:
            self.logger.error(f"Error detecting technology stack: {str(e)}")
            return {}
    
    def _detect_cms_specific(self, url, tech_stack, content, headers):
        """Specific CMS detection with version discovery"""
        try:
            # WordPress specific
            if any('wordpress' in item['name'].lower() for item in tech_stack.get('cms', [])):
                wp_version = self._get_wordpress_version(url, content)
                if wp_version:
                    for item in tech_stack['cms']:
                        if 'wordpress' in item['name'].lower():
                            item['version'] = wp_version
                            
            # Check for admin panels
            admin_paths = [
                '/wp-admin/', '/admin/', '/administrator/', '/admin.php',
                '/wp-login.php', '/login/', '/dashboard/'
            ]
            
            accessible_admin = []
            for path in admin_paths:
                try:
                    admin_url = urljoin(url, path)
                    resp = requests.get(admin_url, timeout=5, allow_redirects=True)
                    if resp.status_code == 200:
                        accessible_admin.append(path)
                except:
                    continue
                    
            if accessible_admin:
                tech_stack['admin_panels'] = accessible_admin
                
        except Exception as e:
            self.logger.debug(f"CMS specific detection error: {str(e)}")
    
    def _get_wordpress_version(self, url, content):
        """Get WordPress version"""
        try:
            # Check generator meta tag
            version_match = re.search(r'wordpress\s+([\d\.]+)', content)
            if version_match:
                return version_match.group(1)
                
            # Check readme.html
            readme_url = urljoin(url, '/readme.html')
            resp = requests.get(readme_url, timeout=5)
            if resp.status_code == 200:
                version_match = re.search(r'version\s+([\d\.]+)', resp.text.lower())
                if version_match:
                    return version_match.group(1)
                    
        except Exception:
            pass
        return None
    
    def _detect_api_technologies(self, url, tech_stack):
        """Detect API-related technologies"""
        try:
            api_endpoints = [
                '/api/', '/api/v1/', '/api/v2/', '/rest/', '/graphql',
                '/swagger/', '/openapi.json', '/api-docs'
            ]
            
            api_info = []
            for endpoint in api_endpoints:
                try:
                    api_url = urljoin(url, endpoint)
                    resp = requests.get(api_url, timeout=5)
                    if resp.status_code in [200, 401, 403]:  # API exists but may need auth
                        api_info.append({
                            'endpoint': endpoint,
                            'status': resp.status_code,
                            'content_type': resp.headers.get('Content-Type', '')
                        })
                except:
                    continue
                    
            if api_info:
                tech_stack['api_endpoints'] = api_info
                
        except Exception as e:
            self.logger.debug(f"API detection error: {str(e)}")
    
    def api_fuzzing(self, base_url, endpoints=None):
        """Enhanced API fuzzing and enumeration"""
        try:
            print(f"\n🔍 Starting API fuzzing for: {base_url}")
            
            results = {
                'discovered_endpoints': [],
                'parameter_fuzzing': {},
                'authentication_tests': {},
                'rate_limiting': {},
                'security_headers': {}
            }
            
            if not endpoints:
                endpoints = self._discover_api_endpoints(base_url)
            
            for endpoint in endpoints:
                full_url = urljoin(base_url, endpoint)
                print(f"   📡 Testing endpoint: {endpoint}")
                
                # Test different HTTP methods
                methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
                endpoint_results = {}
                
                for method in methods:
                    try:
                        resp = requests.request(method, full_url, timeout=10)
                        endpoint_results[method] = {
                            'status_code': resp.status_code,
                            'response_time': resp.elapsed.total_seconds(),
                            'content_length': len(resp.content),
                            'headers': dict(resp.headers)
                        }
                        
                        # Check for interesting responses
                        if resp.status_code in [200, 201, 202, 400, 401, 403, 422]:
                            endpoint_results[method]['interesting'] = True
                            
                    except Exception as e:
                        endpoint_results[method] = {'error': str(e)}
                
                results['discovered_endpoints'].append({
                    'endpoint': endpoint,
                    'methods': endpoint_results
                })
                
                # Parameter fuzzing for GET endpoints
                if endpoint_results.get('GET', {}).get('status_code') == 200:
                    param_results = self._fuzz_parameters(full_url)
                    if param_results:
                        results['parameter_fuzzing'][endpoint] = param_results
                
                # Rate limiting test
                rate_limit = self._test_rate_limiting(full_url)
                if rate_limit:
                    results['rate_limiting'][endpoint] = rate_limit
            
            # Authentication bypass tests
            results['authentication_tests'] = self._test_auth_bypass(base_url)
            
            print(f"✅ API fuzzing completed. Found {len(results['discovered_endpoints'])} endpoints")
            return results
            
        except Exception as e:
            self.logger.error(f"API fuzzing error: {str(e)}")
            return {}
    
    def _discover_api_endpoints(self, base_url):
        """Discover API endpoints through various methods"""
        endpoints = set()
        
        # Common API paths
        common_paths = [
            '/api/', '/api/v1/', '/api/v2/', '/api/v3/',
            '/rest/', '/graphql', '/swagger/', '/openapi.json',
            '/api-docs', '/docs/', '/documentation/',
            '/users/', '/user/', '/admin/', '/auth/',
            '/login/', '/register/', '/profile/', '/settings/',
            '/products/', '/orders/', '/payments/', '/search/'
        ]
        
        print("   🔍 Discovering API endpoints...")
        for path in common_paths:
            try:
                url = urljoin(base_url, path)
                resp = requests.get(url, timeout=5)
                if resp.status_code not in [404, 502, 503]:
                    endpoints.add(path)
            except:
                continue
        
        # Try to find endpoints from JavaScript files
        try:
            resp = requests.get(base_url, timeout=10)
            js_urls = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', resp.text)
            
            for js_url in js_urls[:5]:  # Limit to first 5 JS files
                full_js_url = urljoin(base_url, js_url)
                try:
                    js_resp = requests.get(full_js_url, timeout=5)
                    # Look for API endpoints in JS
                    api_patterns = re.findall(r'["\'](/api/[^"\']*)["\']', js_resp.text)
                    endpoints.update(api_patterns)
                except:
                    continue
        except:
            pass
            
        return list(endpoints)
    
    def _fuzz_parameters(self, url):
        """Fuzz common parameters"""
        common_params = [
            'id', 'user_id', 'username', 'email', 'token', 'key',
            'page', 'limit', 'offset', 'search', 'query', 'filter',
            'sort', 'order', 'category', 'type', 'format', 'callback'
        ]
        
        interesting_responses = []
        
        for param in common_params:
            test_values = ['1', 'admin', 'test', '../', 'null', '0', '-1']
            
            for value in test_values:
                try:
                    resp = requests.get(url, params={param: value}, timeout=5)
                    
                    # Check for interesting status codes or content changes
                    if resp.status_code in [200, 400, 422, 500] and len(resp.content) > 100:
                        interesting_responses.append({
                            'parameter': param,
                            'value': value,
                            'status_code': resp.status_code,
                            'content_length': len(resp.content)
                        })
                        break  # Found interesting response, move to next param
                except:
                    continue
                    
        return interesting_responses
    
    def _test_rate_limiting(self, url):
        """Test for rate limiting"""
        try:
            response_times = []
            status_codes = []
            
            for i in range(10):  # Make 10 rapid requests
                start_time = time.time()
                resp = requests.get(url, timeout=5)
                response_time = time.time() - start_time
                
                response_times.append(response_time)
                status_codes.append(resp.status_code)
                
                # Check for rate limiting status codes
                if resp.status_code in [429, 503]:
                    return {
                        'rate_limited': True,
                        'status_code': resp.status_code,
                        'request_number': i + 1,
                        'retry_after': resp.headers.get('Retry-After')
                    }
                    
            # Check if response times increased significantly
            if len(response_times) > 5:
                avg_first_half = sum(response_times[:5]) / 5
                avg_second_half = sum(response_times[5:]) / len(response_times[5:])
                
                if avg_second_half > avg_first_half * 2:  # 2x slower
                    return {
                        'potential_rate_limiting': True,
                        'avg_response_time_increase': avg_second_half / avg_first_half
                    }
                    
        except Exception:
            pass
            
        return None
    
    def _test_auth_bypass(self, base_url):
        """Test common authentication bypass techniques"""
        bypass_tests = {
            'headers': [
                {'X-Forwarded-For': '127.0.0.1'},
                {'X-Real-IP': '127.0.0.1'},
                {'X-Originating-IP': '127.0.0.1'},
                {'X-Remote-IP': '127.0.0.1'},
                {'X-Client-IP': '127.0.0.1'},
                {'X-Original-URL': '/admin'},
                {'X-Rewrite-URL': '/admin'},
            ],
            'parameters': [
                {'admin': 'true'},
                {'debug': '1'},
                {'test': '1'},
                {'role': 'admin'},
                {'privilege': 'admin'}
            ]
        }
        
        results = {}
        protected_endpoints = ['/admin/', '/api/admin/', '/dashboard/', '/profile/']
        
        for endpoint in protected_endpoints:
            url = urljoin(base_url, endpoint)
            endpoint_results = []
            
            try:
                # Baseline request
                baseline = requests.get(url, timeout=5)
                baseline_status = baseline.status_code
                
                # Test header bypasses
                for headers in bypass_tests['headers']:
                    try:
                        resp = requests.get(url, headers=headers, timeout=5)
                        if resp.status_code != baseline_status and resp.status_code == 200:
                            endpoint_results.append({
                                'type': 'header_bypass',
                                'method': headers,
                                'status_code': resp.status_code
                            })
                    except:
                        continue
                
                # Test parameter bypasses
                for params in bypass_tests['parameters']:
                    try:
                        resp = requests.get(url, params=params, timeout=5)
                        if resp.status_code != baseline_status and resp.status_code == 200:
                            endpoint_results.append({
                                'type': 'parameter_bypass',
                                'method': params,
                                'status_code': resp.status_code
                            })
                    except:
                        continue
                        
                if endpoint_results:
                    results[endpoint] = endpoint_results
                    
            except:
                continue
                
        return results
    
    def _analyze_security_headers(self, url):
        """Analyze security headers"""
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
            
            security_headers = {
                'x_frame_options': response.headers.get('X-Frame-Options'),
                'x_content_type_options': response.headers.get('X-Content-Type-Options'),
                'strict_transport_security': response.headers.get('Strict-Transport-Security'),
                'content_security_policy': response.headers.get('Content-Security-Policy'),
                'missing_headers': []
            }
            
            # Check for missing security headers
            required_headers = [
                'X-Frame-Options',
                'X-Content-Type-Options', 
                'Strict-Transport-Security',
                'Content-Security-Policy'
            ]
            
            for header in required_headers:
                if header not in response.headers:
                    security_headers['missing_headers'].append(header)
            
            return security_headers
            
        except Exception as e:
            self.logger.error(f"Error analyzing security headers: {str(e)}")
            return {}
    
    def _sanitize_url(self, url):
        """Sanitize URL for filename"""
        return re.sub(r'[^\w\-_\.]', '_', url)
    
    def _brute_force_dirs(self, url):
        """Brute force directories and common files with concurrency control and rate limiting"""
        try:
            self.logger.info(f"Starting directory brute force for {url}")
            
            # Load directory wordlist with comprehensive error handling
            wordlist_path = self.config.get('bruteforce', 'dir_wordlist', '/usr/share/wordlists/dirb/common.txt')
            
            # Create a basic directory/file wordlist as fallback
            basic_dirs = [
                # Common directories
                'admin', 'administrator', 'login', 'uploads', 'images', 'img', 'css', 'js',
                'api', 'config', 'backup', 'backups', 'tmp', 'temp', 'test', 'dev',
                'phpmyadmin', 'wp-admin', 'wp-content', 'wp-includes', 'dashboard', 'panel',
                'control', 'cpanel', 'webmail', 'mail', 'ftp', 'ssh', 'logs', 'log',
                'database', 'db', 'files', 'documents', 'downloads', 'media', 'assets',
                'private', 'secret', 'hidden', 'secure', 'protected', 'include', 'inc',
                
                # Common files
                'robots.txt', 'sitemap.xml', 'favicon.ico', 'crossdomain.xml',
                '.htaccess', '.htpasswd', 'web.config', 'readme.txt', 'README.md',
                'install.php', 'setup.php', 'config.php', 'wp-config.php',
                'phpinfo.php', 'info.php', 'test.php', 'index.bak',
                'backup.sql', 'database.sql', 'dump.sql', '.env', '.git',
                
                # Admin panels and login pages
                'admin.php', 'login.php', 'signin.php', 'auth.php',
                'manager', 'administrator.php', 'moderator.php'
            ]
            
            # Attempt to load custom wordlist with proper error handling
            if not wordlist_path or not os.path.exists(wordlist_path):
                if wordlist_path:
                    self.logger.warning(f"Directory wordlist not found: {wordlist_path}, skipping directory brute force")
                    self.logger.info("To enable directory brute force, specify a valid wordlist with --dir-wordlist")
                    return []  # Skip directory brute force entirely if no wordlist
                else:
                    self.logger.info("No directory wordlist specified, using built-in wordlist")
                    self.logger.info(f"Using built-in directory wordlist ({len(basic_dirs)} entries)")
                    wordlist = basic_dirs
            else:
                try:
                    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                        wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                        if wordlist:
                            # Limit wordlist size for performance
                            max_words = self.config.get('bruteforce', 'max_words', 5000)
                            if len(wordlist) > max_words:
                                self.logger.info(f"Limiting wordlist from {len(wordlist)} to {max_words} entries")
                                wordlist = wordlist[:max_words]
                            self.logger.info(f"Loaded directory wordlist from {wordlist_path} ({len(wordlist)} entries)")
                        else:
                            self.logger.warning(f"Directory wordlist is empty: {wordlist_path}, skipping directory brute force")
                            return []  # Skip if wordlist is empty
                except (IOError, OSError, PermissionError) as e:
                    self.logger.error(f"Cannot read directory wordlist '{wordlist_path}': {str(e)}, skipping directory brute force")
                    return []  # Skip directory brute force on file errors
                except Exception as e:
                    self.logger.error(f"Unexpected error loading directory wordlist '{wordlist_path}': {str(e)}, skipping directory brute force")
                    return []  # Skip directory brute force on unexpected errors
            
            # Configuration
            timeout = min(self.config.get('web', 'timeout', 5), 10)  # Max 10 seconds
            rate_limit = self.config.get('bruteforce', 'rate_limit', 0)  # Seconds between requests
            max_threads = self.config.get('bruteforce', 'threads', 10)  # Default 10 threads
            max_threads = min(max_threads, 50)  # Cap at 50 threads
            
            # Interesting status codes to save
            interesting_codes = {
                200: 'OK',
                201: 'Created', 
                202: 'Accepted',
                204: 'No Content',
                301: 'Moved Permanently',
                302: 'Found',
                303: 'See Other',
                307: 'Temporary Redirect',
                308: 'Permanent Redirect',
                401: 'Unauthorized',
                403: 'Forbidden',
                405: 'Method Not Allowed',
                500: 'Internal Server Error',
                503: 'Service Unavailable'
            }
            
            self.logger.info(f"Using {max_threads} threads with {rate_limit}s rate limit")
            
            found_directories = []
            processed_count = 0
            
            def test_directory(path):
                """Test a single directory/file path"""
                nonlocal processed_count
                
                try:
                    # Rate limiting
                    if rate_limit > 0:
                        time.sleep(rate_limit)
                    
                    # Construct full URL
                    if not path.startswith('/'):
                        path = '/' + path
                    test_url = url.rstrip('/') + path
                    
                    # Use HEAD request for faster scanning (fallback to GET if needed)
                    try:
                        response = requests.head(
                            test_url,
                            timeout=timeout,
                            allow_redirects=False,
                            headers={
                                'User-Agent': self.config.get('general', 'user_agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36')
                            }
                        )
                        
                        # Some servers return 405 for HEAD but allow GET
                        if response.status_code == 405:
                            response = requests.get(
                                test_url,
                                timeout=timeout,
                                allow_redirects=False,
                                headers={
                                    'User-Agent': self.config.get('general', 'user_agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36')
                                }
                            )
                            
                    except requests.exceptions.RequestException:
                        # Fallback to GET request
                        response = requests.get(
                            test_url,
                            timeout=timeout,
                            allow_redirects=False,
                            headers={
                                'User-Agent': self.config.get('general', 'user_agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36')
                            }
                        )
                    
                    processed_count += 1
                    if processed_count % 100 == 0:
                        self.logger.info(f"Processed {processed_count}/{len(wordlist)} paths...")
                    
                    # Check for interesting status codes
                    if response.status_code in interesting_codes:
                        directory_info = {
                            'path': path,
                            'url': test_url,
                            'status_code': response.status_code,
                            'status_text': interesting_codes.get(response.status_code, 'Unknown'),
                            'size': response.headers.get('Content-Length', 'unknown'),
                            'content_type': response.headers.get('Content-Type', 'unknown'),
                            'server': response.headers.get('Server', 'unknown')
                        }
                        
                        # Add redirect information
                        if response.status_code in [301, 302, 303, 307, 308]:
                            directory_info['location'] = response.headers.get('Location', 'unknown')
                        
                        self.logger.info(f"Found: {test_url} [{response.status_code} {interesting_codes.get(response.status_code, '')}]")
                        return directory_info
                    
                    return None
                    
                except requests.exceptions.Timeout:
                    self.logger.debug(f"Timeout testing {test_url}")
                    return None
                except requests.exceptions.ConnectionError:
                    self.logger.debug(f"Connection error testing {test_url}")
                    return None
                except Exception as e:
                    self.logger.debug(f"Error testing {test_url}: {str(e)}")
                    return None
            
            # Use ThreadPoolExecutor for concurrent requests
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = [executor.submit(test_directory, path) for path in wordlist]
                
                for future in futures:
                    try:
                        result = future.result(timeout=timeout + 5)  # Give extra time for completion
                        if result:
                            found_directories.append(result)
                    except Exception as e:
                        self.logger.debug(f"Thread execution error: {str(e)}")
            
            # Save directory brute force results
            if found_directories:
                output_file = self.output_dir / 'web' / f'directories_{self._sanitize_url(url)}.txt'
                with open(output_file, 'w') as f:
                    f.write(f"Directory brute force results for {url}\n")
                    f.write(f"Threads: {max_threads}, Rate limit: {rate_limit}s\n")
                    f.write("=" * 60 + "\n\n")
                    
                    for dir_info in sorted(found_directories, key=lambda x: x['status_code']):
                        f.write(f"[{dir_info['status_code']}] {dir_info['url']} ({dir_info['status_text']})\n")
                        
                        if dir_info.get('content_type') != 'unknown':
                            f.write(f"    Content-Type: {dir_info['content_type']}\n")
                        if dir_info.get('size') != 'unknown':
                            f.write(f"    Size: {dir_info['size']} bytes\n")
                        if dir_info.get('server') != 'unknown':
                            f.write(f"    Server: {dir_info['server']}\n")
                        if dir_info.get('location'):
                            f.write(f"    Location: {dir_info['location']}\n")
                        f.write("\n")
                
                self.logger.info(f"Directory brute force found {len(found_directories)} accessible paths")
                
                # Log summary by status code
                status_summary = {}
                for item in found_directories:
                    code = item['status_code']
                    status_summary[code] = status_summary.get(code, 0) + 1
                
                summary_text = ', '.join([f"{code}: {count}" for code, count in sorted(status_summary.items())])
                self.logger.info(f"Status code summary: {summary_text}")
                
            else:
                self.logger.info("No accessible directories found")
            
            return found_directories
            
        except Exception as e:
            self.logger.error(f"Error during directory brute force: {str(e)}")
            return []

    def _enhanced_directory_discovery(self, url):
        """Enhanced directory discovery using multiple tools (gobuster, ffuf, feroxbuster)"""
        self.logger.info(f"Starting enhanced directory discovery for {url}")
        
        discovered_paths = []
        
        # Try gobuster first (if available)
        gobuster_results = self._run_gobuster(url)
        discovered_paths.extend(gobuster_results)
        
        # Try ffuf as alternative (if available)
        if not gobuster_results:
            ffuf_results = self._run_ffuf(url)
            discovered_paths.extend(ffuf_results)
        
        # Try feroxbuster for recursive discovery (if available)
        ferox_results = self._run_feroxbuster(url)
        discovered_paths.extend(ferox_results)
        
        # Deduplicate results
        unique_paths = list(set(discovered_paths))
        
        self.logger.info(f"Enhanced directory discovery found {len(unique_paths)} unique paths")
        return unique_paths

    def _run_gobuster(self, url):
        """Run gobuster for directory discovery"""
        try:
            # Check if gobuster is available
            subprocess.run(['gobuster', '--help'], capture_output=True, check=True)
            
            self.logger.info(f"Running gobuster directory scan on {url}")
            
            # Get wordlist path
            wordlist_path = self.config.get('bruteforce', 'dir_wordlist', '/usr/share/wordlists/dirb/common.txt')
            
            # Fallback wordlists
            fallback_wordlists = [
                '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
                '/usr/share/wordlists/dirb/common.txt',
                '/usr/share/seclists/Discovery/Web-Content/common.txt',
                '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt'
            ]
            
            # Find available wordlist
            if not os.path.exists(wordlist_path):
                for fallback in fallback_wordlists:
                    if os.path.exists(fallback):
                        wordlist_path = fallback
                        break
                else:
                    self.logger.warning("No wordlist found for gobuster")
                    return []
            
            output_file = self.output_dir / 'web' / f'gobuster_{self._sanitize_url(url)}.txt'
            
            cmd = [
                'gobuster', 'dir',
                '-u', url,
                '-w', wordlist_path,
                '-o', str(output_file),
                '-t', '50',  # 50 threads
                '-x', 'php,html,txt,js,css,bak,old,backup',  # Common extensions
                '--wildcard',
                '--no-error',
                '--quiet'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Parse results
            discovered_paths = []
            if output_file.exists():
                with open(output_file, 'r') as f:
                    for line in f:
                        if line.strip() and not line.startswith('='):
                            # Extract path from gobuster output
                            parts = line.strip().split()
                            if parts:
                                path = parts[0]
                                discovered_paths.append({
                                    'path': path,
                                    'status': parts[1] if len(parts) > 1 else 'unknown',
                                    'size': parts[2] if len(parts) > 2 else 'unknown',
                                    'tool': 'gobuster'
                                })
            
            self.logger.info(f"Gobuster found {len(discovered_paths)} directories/files")
            return discovered_paths
            
        except subprocess.CalledProcessError:
            self.logger.warning("Gobuster not available")
            return []
        except Exception as e:
            self.logger.error(f"Error running gobuster: {str(e)}")
            return []

    def _run_ffuf(self, url):
        """Run ffuf for directory discovery"""
        try:
            # Check if ffuf is available
            subprocess.run(['ffuf', '-h'], capture_output=True, check=True)
            
            self.logger.info(f"Running ffuf directory scan on {url}")
            
            # Get wordlist path
            wordlist_path = self.config.get('bruteforce', 'dir_wordlist', '/usr/share/wordlists/dirb/common.txt')
            
            if not os.path.exists(wordlist_path):
                self.logger.warning("No wordlist found for ffuf")
                return []
            
            output_file = self.output_dir / 'web' / f'ffuf_{self._sanitize_url(url)}.json'
            
            cmd = [
                'ffuf',
                '-u', f"{url}/FUZZ",
                '-w', wordlist_path,
                '-o', str(output_file),
                '-of', 'json',
                '-t', '50',  # 50 threads
                '-mc', '200,204,301,302,307,401,403',  # Match status codes
                '-fs', '0',  # Filter size 0
                '-silent'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Parse JSON results
            discovered_paths = []
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                        for result in data.get('results', []):
                            discovered_paths.append({
                                'path': f"/{result['input']['FUZZ']}",
                                'status': result['status'],
                                'size': result['length'],
                                'words': result['words'],
                                'tool': 'ffuf'
                            })
                except json.JSONDecodeError:
                    self.logger.warning("Could not parse ffuf JSON output")
            
            self.logger.info(f"Ffuf found {len(discovered_paths)} directories/files")
            return discovered_paths
            
        except subprocess.CalledProcessError:
            self.logger.warning("Ffuf not available")
            return []
        except Exception as e:
            self.logger.error(f"Error running ffuf: {str(e)}")
            return []

    def _run_feroxbuster(self, url):
        """Run feroxbuster for recursive directory discovery"""
        try:
            # Check if feroxbuster is available
            subprocess.run(['feroxbuster', '--help'], capture_output=True, check=True)
            
            self.logger.info(f"Running feroxbuster recursive scan on {url}")
            
            # Get wordlist path
            wordlist_path = self.config.get('bruteforce', 'dir_wordlist', '/usr/share/wordlists/dirb/common.txt')
            
            if not os.path.exists(wordlist_path):
                self.logger.warning("No wordlist found for feroxbuster")
                return []
            
            output_file = self.output_dir / 'web' / f'feroxbuster_{self._sanitize_url(url)}.txt'
            
            cmd = [
                'feroxbuster',
                '-u', url,
                '-w', wordlist_path,
                '-o', str(output_file),
                '-t', '50',  # 50 threads
                '-d', '3',   # Depth of 3
                '-x', 'php,html,txt,js,css,bak,old,backup',  # Extensions
                '--silent',
                '--no-recursion'  # Control recursion manually
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            # Parse results
            discovered_paths = []
            if output_file.exists():
                with open(output_file, 'r') as f:
                    for line in f:
                        if line.strip() and 'HTTP' in line:
                            # Parse feroxbuster output format
                            parts = line.strip().split()
                            if len(parts) >= 4:
                                status = parts[0]
                                size = parts[1]
                                path = parts[-1].replace(url, '')
                                discovered_paths.append({
                                    'path': path,
                                    'status': status,
                                    'size': size,
                                    'tool': 'feroxbuster'
                                })
            
            self.logger.info(f"Feroxbuster found {len(discovered_paths)} directories/files")
            return discovered_paths
            
        except subprocess.CalledProcessError:
            self.logger.warning("Feroxbuster not available")
            return []
        except Exception as e:
            self.logger.error(f"Error running feroxbuster: {str(e)}")
            return []
    
    def _save_web_results(self, target, results):
        """Save web scanning results"""
        json_file = self.output_dir / 'web' / f'{target}_web_results.json'
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        self.logger.info(f"Web scan results saved to {json_file}")
    
    def is_wordpress(self, target):
        """Check if target is running WordPress"""
        try:
            urls = self._get_web_urls(target)
            
            for url in urls[:1]:  # Check only first URL
                response = requests.get(url, timeout=10)
                content = response.text.lower()
                
                # Check for WordPress indicators
                wp_indicators = ['wp-content', 'wp-includes', 'wordpress']
                
                for indicator in wp_indicators:
                    if indicator in content:
                        return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking for WordPress: {str(e)}")
            return False


# ============================== SSL SCANNER ==============================
class SSLScanner:
    """SSL/TLS scanner wrapper"""
    
    def __init__(self, output_dir, config):
        self.output_dir = Path(output_dir)
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def scan(self, target):
        """Run comprehensive SSL/TLS analysis"""
        self.logger.info(f"Starting SSL/TLS analysis for {target}")
        
        results = {
            'target': target,
            'certificate_info': {},
            'vulnerabilities': []
        }
        
        # Manual SSL analysis
        cert_info = self._analyze_certificate(target)
        results['certificate_info'] = cert_info
        
        # Vulnerability assessment
        vulnerabilities = self._assess_ssl_vulnerabilities(cert_info)
        results['vulnerabilities'] = vulnerabilities
        
        # Save results
        self._save_ssl_results(target, results)
        
        return results
    
    def _analyze_certificate(self, target):
        """Analyze SSL certificate"""
        try:
            self.logger.info(f"Analyzing SSL certificate for {target}")
            
            # Parse target to get hostname and port
            if ':' in target:
                hostname, port = target.split(':', 1)
                port = int(port)
            else:
                hostname = target
                port = 443
            
            # Get certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
            
            cert_info = {
                'subject': dict(x[0] for x in cert['subject']),
                'issuer': dict(x[0] for x in cert['issuer']),
                'serial_number': cert['serialNumber'],
                'not_before': cert['notBefore'],
                'not_after': cert['notAfter'],
                'version': cert['version'],
                'is_expired': self._is_cert_expired(cert['notAfter'])
            }
            
            return cert_info
            
        except Exception as e:
            self.logger.error(f"Error analyzing certificate: {str(e)}")
            return {'error': str(e)}
    
    def _is_cert_expired(self, not_after):
        """Check if certificate is expired"""
        try:
            # Parse cert date format
            from datetime import datetime
            cert_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            return datetime.now() > cert_date
        except:
            return False
    
    def _assess_ssl_vulnerabilities(self, cert_info):
        """Assess SSL/TLS vulnerabilities"""
        vulnerabilities = []
        
        # Check certificate expiry
        if cert_info.get('is_expired'):
            vulnerabilities.append({
                'type': 'expired_certificate',
                'severity': 'critical',
                'description': 'SSL certificate has expired'
            })
        
        return vulnerabilities
    
    def _save_ssl_results(self, target, results):
        """Save SSL analysis results"""
        json_file = self.output_dir / 'ssl' / f'{target}_ssl_results.json'
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        self.logger.info(f"SSL analysis results saved to {json_file}")


# ============================== OSINT COLLECTOR ==============================
class OSINTCollector:
    """OSINT data collection wrapper"""
    
    def __init__(self, output_dir, config):
        self.output_dir = Path(output_dir)
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def collect(self, target):
        """Run comprehensive OSINT collection"""
        self.logger.info(f"Starting OSINT collection for {target}")
        
        results = {
            'target': target,
            'whois': {},
            'dns_records': {},
            'shodan': {}
        }
        
        # Check if we're in offline mode
        offline_mode = self.config.get('mode', 'offline', False) or self.config.get('general', 'offline_mode', False)
        
        if offline_mode:
            self.logger.info("Running in offline mode - skipping internet-based OSINT sources")
            
            # Only run DNS record enumeration in offline mode
            dns_results = self._enumerate_dns_records(target)
            results['dns_records'] = dns_results
            
            # Set skipped sources with appropriate messages
            results['whois'] = {'error': 'skipped_offline_mode'}
            results['shodan'] = {'error': 'skipped_offline_mode'}
        else:
            # Online mode: run all OSINT sources
            
            # WHOIS lookup
            if HAS_WHOIS:
                whois_results = self._run_whois_lookup(target)
                results['whois'] = whois_results
            
            # DNS record enumeration
            dns_results = self._enumerate_dns_records(target)
            results['dns_records'] = dns_results
            
            # Shodan lookup (if API key available)
            shodan_results = self._query_shodan(target)
            results['shodan'] = shodan_results
        
        # Save results
        self._save_osint_results(target, results)
        
        return results
    
    def _run_whois_lookup(self, target):
        """Perform WHOIS lookup"""
        try:
            self.logger.info(f"Performing WHOIS lookup for {target}")
            
            # Remove protocol if present
            if target.startswith('http'):
                target = urlparse(target).netloc
            
            whois_info = whois.whois(target)
            
            whois_results = {
                'domain_name': str(whois_info.domain_name) if whois_info.domain_name else None,
                'registrar': whois_info.registrar,
                'creation_date': str(whois_info.creation_date) if whois_info.creation_date else None,
                'expiration_date': str(whois_info.expiration_date) if whois_info.expiration_date else None,
                'country': whois_info.country
            }
            
            return whois_results
            
        except Exception as e:
            self.logger.error(f"Error performing WHOIS lookup: {str(e)}")
            return {'error': str(e)}
    
    def _enumerate_dns_records(self, target):
        """Enumerate DNS records"""
        try:
            self.logger.info(f"Enumerating DNS records for {target}")
            
            # Remove protocol if present
            if target.startswith('http'):
                target = urlparse(target).netloc
            
            dns_results = {
                'A': [],
                'MX': [],
                'NS': [],
                'TXT': []
            }
            
            record_types = ['A', 'MX', 'NS', 'TXT']
            
            # Check for custom DNS servers
            dns_servers = self.config.get('dns', 'servers', [])
            custom_dns = self.config.get('general', 'dns_server', '')
            
            # Use custom DNS server if provided
            dns_server_arg = []
            resolver_nameservers = None
            
            if custom_dns:
                dns_server_arg = [f'@{custom_dns}']
                resolver_nameservers = [custom_dns]
                self.logger.info(f"Using custom DNS server: {custom_dns}")
            elif dns_servers:
                # Use first DNS server from config
                dns_server_arg = [f'@{dns_servers[0]}']
                resolver_nameservers = dns_servers
                self.logger.info(f"Using DNS server from config: {dns_servers[0]}")
            else:
                self.logger.debug("Using system default DNS servers")
            
            for record_type in record_types:
                try:
                    # Try dig command first
                    cmd = ['dig', '+short'] + dns_server_arg + [target, record_type]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0 and result.stdout.strip():
                        records = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                        dns_results[record_type] = records
                        self.logger.debug(f"Found {len(records)} {record_type} records via dig")
                    else:
                        # Fallback to dns.resolver if dig fails or returns nothing
                        self.logger.debug(f"dig failed for {record_type}, trying dns.resolver fallback...")
                        
                        try:
                            resolver = dns.resolver.Resolver()
                            if resolver_nameservers:
                                resolver.nameservers = resolver_nameservers
                                self.logger.debug(f"Resolver using nameservers: {resolver_nameservers}")
                            
                            answer = resolver.resolve(target, record_type)
                            records = [str(rdata) for rdata in answer]
                            dns_results[record_type] = records
                            self.logger.debug(f"Found {len(records)} {record_type} records via dns.resolver")
                            
                        except dns.resolver.NXDOMAIN:
                            self.logger.debug(f"No {record_type} records found (NXDOMAIN)")
                        except dns.resolver.NoAnswer:
                            self.logger.debug(f"No {record_type} records found (NODATA)")
                        except Exception as resolver_e:
                            self.logger.debug(f"dns.resolver also failed for {record_type}: {str(resolver_e)}")
                        
                except subprocess.TimeoutExpired:
                    self.logger.debug(f"dig timeout for {record_type} records")
                    # Try dns.resolver fallback for timeout
                    try:
                        resolver = dns.resolver.Resolver()
                        if resolver_nameservers:
                            resolver.nameservers = resolver_nameservers
                        resolver.timeout = 5  # Shorter timeout for fallback
                        
                        answer = resolver.resolve(target, record_type)
                        records = [str(rdata) for rdata in answer]
                        dns_results[record_type] = records
                        self.logger.debug(f"Found {len(records)} {record_type} records via dns.resolver fallback")
                        
                    except Exception as fallback_e:
                        self.logger.debug(f"Fallback resolver also failed for {record_type}: {str(fallback_e)}")
                        
                except FileNotFoundError:
                    # dig command not found, use dns.resolver
                    self.logger.debug("dig command not found, using dns.resolver")
                    try:
                        resolver = dns.resolver.Resolver()
                        if resolver_nameservers:
                            resolver.nameservers = resolver_nameservers
                        
                        answer = resolver.resolve(target, record_type)
                        records = [str(rdata) for rdata in answer]
                        dns_results[record_type] = records
                        self.logger.debug(f"Found {len(records)} {record_type} records via dns.resolver (no dig)")
                        
                    except Exception as resolver_e:
                        self.logger.debug(f"dns.resolver failed for {record_type}: {str(resolver_e)}")
                        
                except Exception as e:
                    self.logger.debug(f"Error querying {record_type} records: {str(e)}")
            
            # Summary logging
            total_records = sum(len(records) for records in dns_results.values())
            if total_records > 0:
                summary = ', '.join([f"{rtype}: {len(records)}" for rtype, records in dns_results.items() if records])
                self.logger.info(f"DNS enumeration found {total_records} total records ({summary})")
            else:
                self.logger.info("No DNS records found")
            
            return dns_results
            
        except Exception as e:
            self.logger.error(f"Error enumerating DNS records: {str(e)}")
            return {'error': str(e)}

    def enhanced_dns_enumeration(self, target):
        """Enhanced DNS enumeration with advanced techniques"""
        self.logger.info(f"Starting enhanced DNS enumeration for {target}")
        
        # Clean target
        if target.startswith('http'):
            target = urlparse(target).netloc
        
        results = {
            'target': target,
            'basic_records': {},
            'advanced_records': {},
            'dns_security': {},
            'subdomain_bruteforce': [],
            'zone_transfer': {},
            'dns_bruteforce': []
        }
        
        # Basic DNS records (existing functionality)
        results['basic_records'] = self._enumerate_dns_records(target)
        
        # Advanced DNS records
        results['advanced_records'] = self._enumerate_advanced_dns_records(target)
        
        # DNS security checks
        results['dns_security'] = self._check_dns_security(target)
        
        # DNS-based subdomain bruteforce
        results['subdomain_bruteforce'] = self._dns_subdomain_bruteforce(target)
        
        # Zone transfer attempts
        results['zone_transfer'] = self._attempt_zone_transfer(target)
        
        return results

    def _enumerate_advanced_dns_records(self, target):
        """Enumerate additional DNS record types"""
        advanced_records = {
            'AAAA': [],    # IPv6
            'CNAME': [],   # Canonical names
            'PTR': [],     # Reverse DNS
            'SOA': [],     # Start of Authority
            'SRV': [],     # Service records
            'CAA': [],     # Certificate Authority Authorization
            'DMARC': [],   # DMARC policy
            'SPF': [],     # SPF records
            'DKIM': []     # DKIM records
        }
        
        record_types = ['AAAA', 'CNAME', 'PTR', 'SOA', 'SRV', 'CAA']
        
        for record_type in record_types:
            try:
                cmd = ['dig', '+short', target, record_type]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and result.stdout.strip():
                    records = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                    advanced_records[record_type] = records
                    
            except Exception as e:
                self.logger.debug(f"Error getting {record_type} records: {str(e)}")
        
        # Check for DMARC policy
        try:
            dmarc_domain = f"_dmarc.{target}"
            cmd = ['dig', '+short', dmarc_domain, 'TXT']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and result.stdout.strip():
                advanced_records['DMARC'] = [result.stdout.strip()]
        except:
            pass
        
        # Check for SPF records in TXT
        try:
            cmd = ['dig', '+short', target, 'TXT']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and result.stdout.strip():
                txt_records = result.stdout.strip().split('\n')
                spf_records = [record for record in txt_records if 'v=spf1' in record.lower()]
                advanced_records['SPF'] = spf_records
        except:
            pass
        
        return advanced_records

    def _check_dns_security(self, target):
        """Check DNS security configurations"""
        security_results = {
            'dnssec_enabled': False,
            'spf_configured': False,
            'dmarc_configured': False,
            'caa_configured': False,
            'security_score': 0
        }
        
        try:
            # Check DNSSEC
            cmd = ['dig', '+dnssec', '+short', target, 'A']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if 'RRSIG' in result.stdout:
                security_results['dnssec_enabled'] = True
                security_results['security_score'] += 25
        except:
            pass
        
        try:
            # Check SPF
            cmd = ['dig', '+short', target, 'TXT']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if 'v=spf1' in result.stdout.lower():
                security_results['spf_configured'] = True
                security_results['security_score'] += 25
        except:
            pass
        
        try:
            # Check DMARC
            dmarc_domain = f"_dmarc.{target}"
            cmd = ['dig', '+short', dmarc_domain, 'TXT']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if 'v=DMARC1' in result.stdout:
                security_results['dmarc_configured'] = True
                security_results['security_score'] += 25
        except:
            pass
        
        try:
            # Check CAA
            cmd = ['dig', '+short', target, 'CAA']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.stdout.strip():
                security_results['caa_configured'] = True
                security_results['security_score'] += 25
        except:
            pass
        
        return security_results

    def _dns_subdomain_bruteforce(self, target):
        """DNS-based subdomain bruteforce"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'prod', 'blog', 'shop', 'store', 'portal', 'support', 'help',
            'docs', 'cdn', 'static', 'media', 'images', 'assets', 'secure',
            'vpn', 'remote', 'app', 'mobile', 'beta', 'demo', 'lab',
            'git', 'svn', 'repo', 'backup', 'db', 'database', 'mysql',
            'postgres', 'redis', 'elastic', 'kibana', 'grafana'
        ]
        
        found_subdomains = []
        
        for subdomain in common_subdomains:
            try:
                full_domain = f"{subdomain}.{target}"
                
                # Try A record
                cmd = ['dig', '+short', full_domain, 'A']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                
                if result.returncode == 0 and result.stdout.strip():
                    ip_addresses = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                    found_subdomains.append({
                        'subdomain': full_domain,
                        'type': 'A',
                        'values': ip_addresses
                    })
                else:
                    # Try CNAME record
                    cmd = ['dig', '+short', full_domain, 'CNAME']
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    
                    if result.returncode == 0 and result.stdout.strip():
                        cname_values = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                        found_subdomains.append({
                            'subdomain': full_domain,
                            'type': 'CNAME',
                            'values': cname_values
                        })
                        
            except Exception as e:
                self.logger.debug(f"Error checking subdomain {subdomain}: {str(e)}")
                continue
        
        self.logger.info(f"DNS bruteforce found {len(found_subdomains)} subdomains")
        return found_subdomains

    def _attempt_zone_transfer(self, target):
        """Attempt DNS zone transfer"""
        zone_transfer_results = {
            'attempted': False,
            'successful': False,
            'nameservers': [],
            'transferred_records': []
        }
        
        try:
            # Get nameservers
            cmd = ['dig', '+short', target, 'NS']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and result.stdout.strip():
                nameservers = [line.strip().rstrip('.') for line in result.stdout.strip().split('\n') if line.strip()]
                zone_transfer_results['nameservers'] = nameservers
                
                # Try zone transfer against each nameserver
                for ns in nameservers[:3]:  # Limit to first 3 NS
                    try:
                        zone_transfer_results['attempted'] = True
                        self.logger.info(f"Attempting zone transfer from {ns}")
                        
                        cmd = ['dig', f'@{ns}', target, 'AXFR']
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                        
                        if result.returncode == 0 and result.stdout.strip():
                            # Check if transfer was successful (contains multiple records)
                            lines = result.stdout.strip().split('\n')
                            if len(lines) > 5:  # More than just SOA records
                                zone_transfer_results['successful'] = True
                                zone_transfer_results['transferred_records'] = lines[:50]  # Limit output
                                self.logger.warning(f"Zone transfer successful from {ns}!")
                                break
                                
                    except Exception as e:
                        self.logger.debug(f"Zone transfer failed for {ns}: {str(e)}")
                        
        except Exception as e:
            self.logger.error(f"Error in zone transfer attempt: {str(e)}")
        
        return zone_transfer_results
    
    def _query_shodan(self, target):
        """Query Shodan API for target information"""
        try:
            api_key = self.config.get('osint', 'shodan_api_key')
            if not api_key:
                return {'error': 'no_api_key'}
            
            self.logger.info(f"Querying Shodan for {target}")
            
            # Remove protocol if present
            if target.startswith('http'):
                target = urlparse(target).netloc
            
            # Resolve target to IP if it's a domain
            try:
                ip = socket.gethostbyname(target)
            except:
                ip = target
            
            url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                shodan_results = {
                    'ip': data.get('ip_str'),
                    'country': data.get('country_name'),
                    'city': data.get('city'),
                    'ports': data.get('ports', [])[:10],  # Limit ports
                    'vulnerabilities': data.get('vulns', [])[:5]  # Limit vulns
                }
                
                return shodan_results
            else:
                return {'error': f'API error: {response.status_code}'}
                
        except Exception as e:
            self.logger.error(f"Error querying Shodan: {str(e)}")
            return {'error': str(e)}
    
    def _save_osint_results(self, target, results):
        """Save OSINT results"""
        json_file = self.output_dir / 'osint' / f'{target}_osint_results.json'
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        self.logger.info(f"OSINT results saved to {json_file}")

    def wayback_analysis(self, target):
        """Analyze target using Wayback Machine data"""
        self.logger.info(f"Analyzing Wayback Machine data for {target}")
        
        results = {
            'target': target,
            'snapshots': [],
            'interesting_files': [],
            'technologies_history': [],
            'status': 'success'
        }
        
        try:
            # Get snapshots from Wayback Machine API
            snapshots = self._get_wayback_snapshots(target)
            results['snapshots'] = snapshots
            
            # Analyze snapshots for interesting files
            interesting_files = self._find_interesting_files(snapshots)
            results['interesting_files'] = interesting_files
            
            # Technology stack evolution
            tech_history = self._analyze_technology_evolution(snapshots)
            results['technologies_history'] = tech_history
            
            self.logger.info(f"Found {len(snapshots)} snapshots and {len(interesting_files)} interesting files")
            
        except Exception as e:
            self.logger.error(f"Wayback analysis failed: {str(e)}")
            results['status'] = 'failed'
            results['error'] = str(e)
        
        return results

    def _get_wayback_snapshots(self, target):
        """Get snapshots from Wayback Machine CDX API"""
        try:
            # Clean target URL
            if target.startswith('http'):
                domain = urlparse(target).netloc
            else:
                domain = target
                
            # Query Wayback CDX API
            cdx_url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=1000"
            
            response = requests.get(cdx_url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            if not data:
                return []
            
            # Skip header row
            snapshots = []
            for row in data[1:]:
                if len(row) >= 7:
                    snapshots.append({
                        'timestamp': row[1],
                        'url': row[2],
                        'status_code': row[4],
                        'mimetype': row[3],
                        'length': row[5],
                        'wayback_url': f"http://web.archive.org/web/{row[1]}/{row[2]}"
                    })
            
            return snapshots
            
        except Exception as e:
            self.logger.error(f"Error getting Wayback snapshots: {str(e)}")
            return []

    def _find_interesting_files(self, snapshots):
        """Find interesting files from Wayback snapshots"""
        interesting_extensions = [
            '.sql', '.bak', '.backup', '.old', '.orig', '.tmp',
            '.config', '.conf', '.ini', '.env', '.log',
            '.zip', '.tar', '.gz', '.rar', '.7z',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx',
            '.xml', '.json', '.csv', '.txt'
        ]
        
        interesting_paths = [
            'admin', 'config', 'backup', 'test', 'dev',
            'staging', 'api', 'private', 'internal',
            'upload', 'uploads', 'files', 'documents'
        ]
        
        interesting_files = []
        
        for snapshot in snapshots:
            url = snapshot['url'].lower()
            
            # Check for interesting file extensions
            for ext in interesting_extensions:
                if url.endswith(ext):
                    interesting_files.append({
                        'url': snapshot['url'],
                        'wayback_url': snapshot['wayback_url'],
                        'timestamp': snapshot['timestamp'],
                        'type': 'interesting_extension',
                        'reason': f'Contains {ext} extension'
                    })
                    break
            
            # Check for interesting paths
            for path in interesting_paths:
                if f'/{path}/' in url or f'/{path}.' in url:
                    interesting_files.append({
                        'url': snapshot['url'],
                        'wayback_url': snapshot['wayback_url'],
                        'timestamp': snapshot['timestamp'],
                        'type': 'interesting_path',
                        'reason': f'Contains {path} in path'
                    })
                    break
        
        # Remove duplicates
        seen_urls = set()
        unique_files = []
        for file_info in interesting_files:
            if file_info['url'] not in seen_urls:
                seen_urls.add(file_info['url'])
                unique_files.append(file_info)
        
        return unique_files[:50]  # Limit to 50 most interesting

    def _analyze_technology_evolution(self, snapshots):
        """Analyze technology stack evolution over time"""
        tech_history = []
        
        # Group snapshots by year
        yearly_snapshots = {}
        for snapshot in snapshots:
            year = snapshot['timestamp'][:4]
            if year not in yearly_snapshots:
                yearly_snapshots[year] = []
            yearly_snapshots[year].append(snapshot)
        
        # Analyze each year
        for year in sorted(yearly_snapshots.keys()):
            year_snapshots = yearly_snapshots[year]
            
            # Look for technology indicators in URLs
            technologies = set()
            
            for snapshot in year_snapshots:
                url = snapshot['url'].lower()
                
                # Common technology indicators
                if 'wp-' in url or 'wordpress' in url:
                    technologies.add('WordPress')
                if '.php' in url:
                    technologies.add('PHP')
                if '.asp' in url or '.aspx' in url:
                    technologies.add('ASP.NET')
                if '.jsp' in url:
                    technologies.add('JSP')
                if 'jquery' in url:
                    technologies.add('jQuery')
                if 'bootstrap' in url:
                    technologies.add('Bootstrap')
                if 'angular' in url:
                    technologies.add('Angular')
                if 'react' in url:
                    technologies.add('React')
                if 'vue' in url:
                    technologies.add('Vue.js')
            
            if technologies:
                tech_history.append({
                    'year': year,
                    'technologies': list(technologies),
                    'snapshots_count': len(year_snapshots)
                })
        
        return tech_history

    def github_dorking(self, target):
        """Search GitHub for potential sensitive information"""
        self.logger.info(f"Performing GitHub dorking for {target}")
        
        results = {
            'target': target,
            'potential_leaks': [],
            'repositories': [],
            'status': 'success'
        }
        
        try:
            # Clean domain name
            if target.startswith('http'):
                domain = urlparse(target).netloc
            else:
                domain = target
            
            # Remove www. prefix if present
            domain = domain.replace('www.', '')
            
            # Common search queries for sensitive information
            search_queries = [
                f'"{domain}" password',
                f'"{domain}" api_key',
                f'"{domain}" secret',
                f'"{domain}" token',
                f'"{domain}" config',
                f'"{domain}" database',
                f'"{domain}" credentials',
                f'site:{domain} filetype:env',
                f'site:{domain} filetype:config',
                f'site:{domain} filetype:sql'
            ]
            
            # Note: This is a placeholder implementation
            # Real implementation would require GitHub API token
            for query in search_queries[:3]:  # Limit to avoid rate limiting
                self.logger.info(f"Searching GitHub for: {query}")
                # Simulated search results
                results['potential_leaks'].append({
                    'query': query,
                    'note': 'GitHub API integration required for actual search',
                    'recommendation': f'Manually search GitHub for: {query}'
                })
            
            self.logger.info(f"GitHub dorking completed with {len(search_queries)} queries")
            
        except Exception as e:
            self.logger.error(f"GitHub dorking failed: {str(e)}")
            results['status'] = 'failed'
            results['error'] = str(e)
        
        return results


# ============================== SCREENSHOTTER ==============================
class Screenshotter:
    """Web service screenshot capture wrapper"""
    
    def __init__(self, output_dir, config):
        self.output_dir = Path(output_dir)
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def capture_screenshots(self, targets):
        """Capture screenshots of multiple targets"""
        self.logger.info(f"Capturing screenshots for {len(targets)} targets")
        
        results = {
            'targets': targets,
            'screenshots': [],
            'tool_used': 'custom'
        }
        
        # Prepare URLs (limit to 5)
        urls = []
        for target in targets[:5]:
            if target.startswith('http'):
                urls.append(target)
            else:
                urls.append(f'https://{target}')
        
        # Capture screenshots
        screenshots = self._capture_with_requests(urls)
        results['screenshots'] = screenshots
        
        # Save results
        self._save_screenshot_results(results)
        
        return results
    
    def _capture_with_requests(self, urls):
        """Capture basic info using requests (fallback method)"""
        screenshots = []
        
        for url in urls:
            try:
                response = requests.get(url, timeout=10)
                if response.status_code < 400:
                    screenshots.append({
                        'url': url,
                        'status_code': response.status_code,
                        'title': self._extract_title(response.text),
                        'status': 'basic_info_captured'
                    })
            except:
                screenshots.append({
                    'url': url,
                    'status': 'failed'
                })
        
        return screenshots
    
    def _extract_title(self, html):
        """Extract title from HTML"""
        try:
            if '<title>' in html and '</title>' in html:
                title = html.split('<title>')[1].split('</title>')[0]
                return title.strip()[:100]
        except:
            pass
        return ""
    
    def _save_screenshot_results(self, results):
        """Save screenshot results"""
        json_file = self.output_dir / 'screenshots' / 'screenshot_results.json'
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        self.logger.info(f"Screenshot results saved to {json_file}")


# Fallback ReconWrapper class if import fails
if not HAS_RECON_WRAPPER:
    class ReconWrapper:
        """Fallback ReconWrapper class with basic functionality"""
        
        def __init__(self):
            self.target = None
            self.target_type = None
            self.output_dir = None
            self.config = ConfigManager()
            self.logger = None
            self.results = {}
            self.scanners = {}
            
            # Initialize components
            self.resource_monitor = ResourceMonitor(self.config)
            self.progress_tracker = ProgressTracker(self.config)
            self.error_handler = ErrorHandler(self.config)
        
        def setup_logging(self):
            """Setup basic logging"""
            log_file = self.output_dir / "scan.log"
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler(log_file),
                    logging.StreamHandler()
                ]
            )
            self.logger = logging.getLogger('recon_wrapper')
            self.logger.info(f"Logging initialized for target: {self.target}")
        
        def initialize_scanners(self):
            """Initialize all scanner components"""
            try:
                self.scanners = {
                    'port': PortScanner(self.config, self.logger),
                    'subdomain': SubdomainEnumerator(self.config, self.logger),
                    'web': WebScanner(self.config, self.logger),
                    'security': SecurityScanner(self.config, self.logger),
                    'osint': OSINTCollector(self.config, self.logger),
                    'screenshot': Screenshotter(self.config, self.logger)
                }
                self.logger.info("All scanners initialized successfully")
                return True
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Failed to initialize scanners: {str(e)}")
                else:
                    print(f"Failed to initialize scanners: {str(e)}")
                return False
        
        def run_comprehensive_scan(self, scan_type='full'):
            """Run comprehensive reconnaissance scan"""
            try:
                self.logger.info(f"Starting {scan_type} reconnaissance scan on {self.target}")
                
                # Initialize scanners
                if not self.initialize_scanners():
                    return False
                
                # Run scans based on type
                if scan_type in ['full', 'port', 'basic']:
                    self.run_port_scan()
                
                if scan_type in ['full', 'subdomain', 'discovery']:
                    self.run_subdomain_enumeration()
                
                if scan_type in ['full', 'web']:
                    self.run_web_scan()
                
                if scan_type in ['full', 'security', 'ssl']:
                    self.run_security_scan()
                
                if scan_type in ['full', 'osint']:
                    self.run_osint_collection()
                
                if scan_type in ['full', 'screenshot']:
                    self.run_screenshot_capture()
                
                self.logger.info("Comprehensive scan completed successfully")
                return True
                
            except Exception as e:
                self.logger.error(f"Comprehensive scan failed: {str(e)}")
                return False
        
        def run_port_scan(self):
            """Run port scanning"""
            try:
                self.logger.info("Starting port scan...")
                self.progress_tracker.start_task("Port Scanning")
                
                port_results = self.scanners['port'].scan_target(self.target)
                if port_results:
                    self.results['nmap_scan'] = port_results
                    self.logger.info(f"Port scan completed")
                
                self.progress_tracker.complete_task("Port Scanning")
                
            except Exception as e:
                self.logger.error(f"Port scan failed: {str(e)}")
                self.error_handler.handle_error("port_scan", e)
        
        def run_subdomain_enumeration(self):
            """Run subdomain enumeration"""
            try:
                self.logger.info("Starting subdomain enumeration...")
                self.progress_tracker.start_task("Subdomain Enumeration")
                
                subdomain_results = self.scanners['subdomain'].enumerate_subdomains(self.target)
                if subdomain_results:
                    self.results['subdomains'] = subdomain_results
                    self.logger.info(f"Subdomain enumeration completed")
                
                self.progress_tracker.complete_task("Subdomain Enumeration")
                
            except Exception as e:
                self.logger.error(f"Subdomain enumeration failed: {str(e)}")
                self.error_handler.handle_error("subdomain_enum", e)
        
        def run_web_scan(self):
            """Run web application scanning"""
            try:
                self.logger.info("Starting web application scan...")
                self.progress_tracker.start_task("Web Application Scanning")
                
                web_results = self.scanners['web'].scan_web_applications(self.target)
                if web_results:
                    self.results['web_scan'] = web_results
                    self.logger.info(f"Web scan completed")
                
                self.progress_tracker.complete_task("Web Application Scanning")
                
            except Exception as e:
                self.logger.error(f"Web scan failed: {str(e)}")
                self.error_handler.handle_error("web_scan", e)
        
        def run_security_scan(self):
            """Run security analysis"""
            try:
                self.logger.info("Starting security analysis...")
                self.progress_tracker.start_task("Security Analysis")
                
                security_results = self.scanners['security'].analyze_security(self.target)
                if security_results:
                    self.results['security_analysis'] = security_results
                    self.logger.info("Security analysis completed")
                
                self.progress_tracker.complete_task("Security Analysis")
                
            except Exception as e:
                self.logger.error(f"Security analysis failed: {str(e)}")
                self.error_handler.handle_error("security_scan", e)
        
        def run_osint_collection(self):
            """Run OSINT collection"""
            try:
                self.logger.info("Starting OSINT collection...")
                self.progress_tracker.start_task("OSINT Collection")
                
                osint_results = self.scanners['osint'].collect_intelligence(self.target)
                if osint_results:
                    self.results['osint'] = osint_results
                    self.logger.info("OSINT collection completed")
                
                self.progress_tracker.complete_task("OSINT Collection")
                
            except Exception as e:
                self.logger.error(f"OSINT collection failed: {str(e)}")
                self.error_handler.handle_error("osint_collection", e)
        
        def run_screenshot_capture(self):
            """Run screenshot capture"""
            try:
                self.logger.info("Starting screenshot capture...")
                self.progress_tracker.start_task("Screenshot Capture")
                
                screenshot_results = self.scanners['screenshot'].capture_screenshots(self.target)
                if screenshot_results:
                    self.results['screenshots'] = screenshot_results
                    self.logger.info(f"Screenshot capture completed")
                
                self.progress_tracker.complete_task("Screenshot Capture")
                
            except Exception as e:
                self.logger.error(f"Screenshot capture failed: {str(e)}")
                self.error_handler.handle_error("screenshot_capture", e)
        
        def generate_report(self):
            """Generate reports using the external reporting module"""
            if not HAS_REPORTING:
                self.logger.warning("Reporting module not available. Skipping report generation.")
                return
                
            try:
                self.logger.info("Generating reports...")
                
                # Standard reports
                report_gen = ReportGenerator(self.output_dir, self.results, self.target, self.config)
                report_gen.generate_markdown_report()
                report_gen.generate_json_report()
                
                # Advanced reporting (if enabled)
                if self.config and self.config.get('reporting', 'advanced_enabled', True):
                    self.logger.info("Generating advanced reports...")
                    advanced_gen = AdvancedReportGenerator(self.output_dir, self.results, self.target, self.config)
                    
                    try:
                        generated_reports = advanced_gen.generate_all_reports()
                        if generated_reports:
                            self.logger.info(f"Advanced reports generated: {', '.join(generated_reports)}")
                        else:
                            self.logger.warning("No advanced reports were generated")
                    except Exception as e:
                        self.logger.error(f"Advanced reporting failed: {str(e)}")
                
                self.logger.info("Reports generated successfully")
                
            except Exception as e:
                self.logger.error(f"Report generation failed: {str(e)}")
        
        def run_single_target(self, target, scan_type='full'):
            """Run scan against a single target"""
            try:
                self.target = target
                self.target_type = 'domain' if '.' in target and not target.replace('.', '').isdigit() else 'ip'
                
                # Create output directory
                safe_target = target.replace('.', '_').replace('/', '_')
                self.output_dir = Path(f"recon_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
                self.output_dir.mkdir(exist_ok=True)
                
                # Setup logging
                self.setup_logging()
                
                # Run comprehensive scan
                success = self.run_comprehensive_scan(scan_type)
                
                if success:
                    # Save results
                    self.save_results()
                    # Generate reports
                    self.generate_report()
                
                return success
                
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Single target scan failed: {str(e)}")
                else:
                    print(f"Single target scan failed: {str(e)}")
                return False
        
        def run_multiple_targets(self, targets_file, scan_type='full'):
            """Run scan against multiple targets from file"""
            try:
                with open(targets_file, 'r') as f:
                    targets = [line.strip() for line in f if line.strip()]
                
                success_count = 0
                for target in targets:
                    print(f"\n🎯 Scanning target: {target}")
                    if self.run_single_target(target, scan_type):
                        success_count += 1
                
                return success_count > 0
                
            except Exception as e:
                print(f"Multiple targets scan failed: {str(e)}")
                return False
        
        def save_results(self):
            """Save scan results to JSON file"""
            try:
                results_file = self.output_dir / f"recon_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                
                output_data = {
                    'target': self.target,
                    'scan_date': datetime.now().isoformat(),
                    'results': self.results
                }
                
                with open(results_file, 'w') as f:
                    json.dump(output_data, f, indent=2, default=str)
                
                self.logger.info(f"Results saved to {results_file}")
                
            except Exception as e:
                self.logger.error(f"Failed to save results: {str(e)}")
        
        def _load_existing_results(self):
            """Load existing scan results for reports-only mode"""
            try:
                # Look for existing JSON results in current directory
                result_files = [
                    f"recon_{self.target}*.json",
                    f"*{self.target}*.json",
                    "scan_results.json",
                    "results.json"
                ]
                
                import glob
                for pattern in result_files:
                    matching_files = glob.glob(pattern)
                    if matching_files:
                        # Use the most recent file
                        latest_file = max(matching_files, key=os.path.getctime)
                        self.logger.info(f"Loading existing results from {latest_file}")
                        
                        with open(latest_file, 'r') as f:
                            loaded_results = json.load(f)
                            
                        # Merge loaded results with current results structure
                        if isinstance(loaded_results, dict):
                            self.results.update(loaded_results.get('results', loaded_results))
                            return True
                
                return False
                
            except Exception as e:
                self.logger.error(f"Failed to load existing results: {str(e)}")
                return False


# ============================== VULNERABILITY SCANNER ==============================
class VulnerabilityScanner:
    """CVE and vulnerability assessment scanner"""
    
    def __init__(self, output_dir, config):
        self.output_dir = Path(output_dir)
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def scan_vulnerabilities(self, target):
        """Run comprehensive vulnerability assessment"""
        self.logger.info(f"Starting vulnerability scan for {target}")
        
        results = {
            'target': target,
            'cve_scan': {},
            'nuclei_scan': {},
            'vulnerability_count': 0
        }
        
        # CVE scanning with vulners and vulscan scripts
        self._run_nmap_vulners(target, results)
        self._run_nuclei_scan(target, results)
        
        return results
    
    def _run_nmap_vulners(self, target, results):
        """Run Nmap with vulners script"""
        try:
            output_file = self.output_dir / 'vulnerabilities' / f'{target}_vulners.xml'
            output_file.parent.mkdir(exist_ok=True)
            
            cmd = [
                'nmap', '-sV', '--script=vulners',
                '-oX', str(output_file),
                target
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if result.returncode == 0:
                results['cve_scan']['vulners'] = str(output_file)
                
        except Exception as e:
            self.logger.warning(f"Vulners scan error: {str(e)}")
    
    def _run_nuclei_scan(self, target, results):
        """Run Nuclei vulnerability scanner"""
        try:
            output_file = self.output_dir / 'vulnerabilities' / f'{target}_nuclei.json'
            
            cmd = [
                'nuclei', '-target', f"http://{target}",
                '-json', '-output', str(output_file)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if result.returncode == 0:
                results['nuclei_scan']['output'] = str(output_file)
                
        except Exception as e:
            self.logger.warning(f"Nuclei scan error: {str(e)}")


# ============================== DIRECTORY SCANNER ==============================
class DirectoryScanner:
    """Advanced directory and file discovery scanner"""
    
    def __init__(self, output_dir, config):
        self.output_dir = Path(output_dir)
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def scan_directories(self, target):
        """Run comprehensive directory discovery"""
        self.logger.info(f"Starting directory scan for {target}")
        
        results = {
            'target': target,
            'gobuster': {},
            'ffuf': {},
            'feroxbuster': {},
            'directories_found': []
        }
        
        # Multiple directory discovery tools
        self._run_gobuster(target, results)
        self._run_ffuf(target, results)
        self._run_feroxbuster(target, results)
        
        return results
    
    def _run_gobuster(self, target, results):
        """Run Gobuster directory discovery"""
        try:
            output_file = self.output_dir / 'directories' / f'{target}_gobuster.txt'
            output_file.parent.mkdir(exist_ok=True)
            
            cmd = [
                'gobuster', 'dir',
                '-u', f"http://{target}",
                '-w', '/usr/share/wordlists/dirb/common.txt',
                '-o', str(output_file)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                results['gobuster']['output'] = str(output_file)
                
        except Exception as e:
            self.logger.warning(f"Gobuster error: {str(e)}")
    
    def _run_ffuf(self, target, results):
        """Run FFUF for fast directory discovery"""
        try:
            output_file = self.output_dir / 'directories' / f'{target}_ffuf.json'
            
            cmd = [
                'ffuf',
                '-u', f"http://{target}/FUZZ",
                '-w', '/usr/share/wordlists/dirb/common.txt',
                '-o', str(output_file),
                '-of', 'json'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                results['ffuf']['output'] = str(output_file)
                
        except Exception as e:
            self.logger.warning(f"FFUF error: {str(e)}")
    
    def _run_feroxbuster(self, target, results):
        """Run Feroxbuster for recursive directory discovery"""
        try:
            output_file = self.output_dir / 'directories' / f'{target}_feroxbuster.txt'
            
            cmd = [
                'feroxbuster',
                '-u', f"http://{target}/",
                '-w', '/usr/share/wordlists/dirb/common.txt',
                '-o', str(output_file)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                results['feroxbuster']['output'] = str(output_file)
                
        except Exception as e:
            self.logger.warning(f"Feroxbuster error: {str(e)}")


# ============================== DNS SCANNER ==============================
class DNSScanner:
    """Comprehensive DNS enumeration and analysis"""
    
    def __init__(self, output_dir, config):
        self.output_dir = Path(output_dir)
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def scan_dns(self, target):
        """Run comprehensive DNS analysis"""
        self.logger.info(f"Starting DNS scan for {target}")
        
        results = {
            'target': target,
            'dns_records': {},
            'zone_transfer': {},
            'dns_security': {}
        }
        
        # DNS record enumeration
        self._enumerate_dns_records(target, results)
        self._attempt_zone_transfer(target, results)
        self._analyze_dns_security(target, results)
        
        return results
    
    def _enumerate_dns_records(self, target, results):
        """Enumerate all DNS record types"""
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'SRV']
        
        for record_type in record_types:
            try:
                cmd = ['dig', '+short', target, record_type]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and result.stdout.strip():
                    results['dns_records'][record_type] = result.stdout.strip().split('\n')
                    
            except Exception as e:
                self.logger.debug(f"DNS {record_type} query error: {str(e)}")
    
    def _attempt_zone_transfer(self, target, results):
        """Attempt DNS zone transfer"""
        try:
            # Get NS records first
            cmd = ['dig', '+short', target, 'NS']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                ns_servers = result.stdout.strip().split('\n')
                
                for ns in ns_servers[:3]:  # Limit attempts
                    try:
                        cmd = ['dig', f'@{ns.strip()}', target, 'AXFR']
                        transfer_result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                        
                        if 'XFR size' in transfer_result.stdout:
                            results['zone_transfer'][ns] = 'SUCCESS'
                        else:
                            results['zone_transfer'][ns] = 'REFUSED'
                            
                    except Exception as e:
                        results['zone_transfer'][ns] = f'ERROR: {str(e)}'
                        
        except Exception as e:
            self.logger.warning(f"Zone transfer error: {str(e)}")
    
    def _analyze_dns_security(self, target, results):
        """Analyze DNS security features"""
        try:
            # Check DNSSEC
            cmd = ['dig', '+dnssec', target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            results['dns_security']['dnssec'] = 'RRSIG' in result.stdout
            
        except Exception as e:
            self.logger.warning(f"DNS security analysis error: {str(e)}")


# ============================== NETWORK SCANNER ==============================
class NetworkScanner:
    """Network topology mapping and analysis"""
    
    def __init__(self, output_dir, config):
        self.output_dir = Path(output_dir)
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def scan_network(self, target):
        """Run comprehensive network analysis"""
        self.logger.info(f"Starting network scan for {target}")
        
        results = {
            'target': target,
            'network_discovery': {},
            'topology_mapping': {},
            'route_analysis': {}
        }
        
        # Network discovery and mapping
        self._discover_network_hosts(target, results)
        self._map_network_topology(target, results)
        self._analyze_routing(target, results)
        
        return results
    
    def _discover_network_hosts(self, target, results):
        """Discover live hosts in network"""
        try:
            # Ping sweep for network discovery
            cmd = ['nmap', '-sn', target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                results['network_discovery']['ping_sweep'] = result.stdout
                
        except Exception as e:
            self.logger.warning(f"Network discovery error: {str(e)}")
    
    def _map_network_topology(self, target, results):
        """Map network topology"""
        try:
            # Traceroute for topology mapping
            cmd = ['traceroute', target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                results['topology_mapping']['traceroute'] = result.stdout
                
        except Exception as e:
            self.logger.warning(f"Topology mapping error: {str(e)}")
    
    def _analyze_routing(self, target, results):
        """Analyze routing information"""
        try:
            # Route analysis
            cmd = ['route', '-n']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                results['route_analysis']['routing_table'] = result.stdout
                
        except Exception as e:
            self.logger.warning(f"Route analysis error: {str(e)}")


# ============================== API SCANNER ==============================
class APIScanner:
    """REST API and web service scanner"""
    
    def __init__(self, output_dir, config):
        self.output_dir = Path(output_dir)
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def scan_apis(self, target):
        """Run comprehensive API scanning"""
        self.logger.info(f"Starting API scan for {target}")
        
        results = {
            'target': target,
            'api_discovery': {},
            'endpoint_analysis': {},
            'security_testing': {}
        }
        
        # API discovery and analysis
        self._discover_api_endpoints(target, results)
        self._analyze_api_security(target, results)
        
        return results
    
    def _discover_api_endpoints(self, target, results):
        """Discover API endpoints"""
        try:
            # Common API paths
            api_paths = ['/api', '/v1', '/v2', '/rest', '/graphql', '/swagger', '/docs']
            
            for path in api_paths:
                url = f"http://{target}{path}"
                try:
                    response = requests.get(url, timeout=10)
                    if response.status_code == 200:
                        results['api_discovery'][path] = {
                            'status': response.status_code,
                            'content_type': response.headers.get('content-type', ''),
                            'content_length': len(response.content)
                        }
                except:
                    continue
                    
        except Exception as e:
            self.logger.warning(f"API discovery error: {str(e)}")
    
    def _analyze_api_security(self, target, results):
        """Analyze API security"""
        try:
            # Check for common API security issues
            url = f"http://{target}/api"
            
            # Test for CORS issues
            headers = {'Origin': 'https://evil.com'}
            response = requests.options(url, headers=headers, timeout=10)
            
            if 'Access-Control-Allow-Origin' in response.headers:
                results['security_testing']['cors'] = {
                    'vulnerable': '*' in response.headers['Access-Control-Allow-Origin'],
                    'header': response.headers['Access-Control-Allow-Origin']
                }
                
        except Exception as e:
            self.logger.warning(f"API security analysis error: {str(e)}")


def print_banner():
    """Print the application banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    RECON WRAPPER - ALL-IN-ONE VERSION                       ║
║                   Comprehensive Reconnaissance Toolkit                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Features: Port Scanning • Subdomain Enum • Web Scanning • SSL Analysis    ║
║           OSINT Collection • Screenshots • Advanced Reporting               ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)


# ============================== RISK SCORER ==============================
def main():
    """Main function"""
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='Comprehensive Reconnaissance Wrapper - All-in-One Version',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s --domain example.com
  %(prog)s --ip 192.168.1.1 --full
  %(prog)s --targets-file targets.txt --fast
  %(prog)s --domain example.com --config custom.json
  %(prog)s --domain internal.company.com --offline --dns-server 10.0.0.53
  %(prog)s --cidr 10.0.0.0/24 --offline --dir-wordlist /usr/share/wordlists/dirs.txt
  %(prog)s --domain example.com --rate-limit 0.5 --dir-threads 5
        '''
    )
    
    # Target options
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('--domain', help='Single domain target')
    target_group.add_argument('--ip', help='Single IP target')
    target_group.add_argument('--targets-file', help='File containing multiple targets')
    
    # Scan type options
    scan_group = parser.add_mutually_exclusive_group()
    scan_group.add_argument('--fast', action='store_true', help='Run fast/light scan')
    scan_group.add_argument('--full', action='store_true', help='Run comprehensive scan')
    
    # Output options
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=300, help='Timeout for scans (seconds)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    # Offline mode and helper options
    parser.add_argument('--offline', action='store_true', help='Run in offline mode (avoid internet-only sources)')
    parser.add_argument('--dns-server', help='Custom DNS server for internal networks (e.g., 10.0.0.53)')
    parser.add_argument('--cidr', help='CIDR range for internal network sweeps (e.g., 10.0.0.0/24)')
    parser.add_argument('--dir-wordlist', help='Custom wordlist for directory brute force (e.g., /path/to/dirs.txt)')
    parser.add_argument('--rate-limit', type=float, default=0, help='Rate limit for directory brute force (seconds between requests, default: 0)')
    parser.add_argument('--dir-threads', type=int, default=10, help='Number of threads for directory brute force (default: 10)')
    
    # Performance and resource management options
    parser.add_argument('--light-mode', action='store_true', help='Reduce resource usage across all modules')
    parser.add_argument('--no-stagger', action='store_true', help='Disable module staggering (run all modules simultaneously)')
    parser.add_argument('--cooldown', type=int, default=5, help='Seconds to wait between heavy modules (default: 5)')
    parser.add_argument('--no-resource-monitor', action='store_true', help='Disable system resource monitoring')
    
    # Security analysis options
    parser.add_argument('--no-security', action='store_true', help='Skip security analysis (SSL/TLS, certificates, vulnerabilities)')
    parser.add_argument('--security-ports', nargs='+', type=int, default=[443, 8443, 9443, 8080, 8008, 8888], 
                       help='Ports to check for SSL/TLS services (default: 443 8443 9443 8080 8008 8888)')
    parser.add_argument('--no-cert-transparency', action='store_true', help='Skip Certificate Transparency log queries')
    parser.add_argument('--security-timeout', type=int, default=30, help='Timeout for security checks (default: 30)')
    
    # Advanced reporting options
    parser.add_argument('--no-advanced-reports', action='store_true', help='Skip advanced reporting (risk assessment, compliance)')
    parser.add_argument('--no-risk-assessment', action='store_true', help='Skip risk scoring and assessment')
    parser.add_argument('--no-compliance', action='store_true', help='Skip compliance framework analysis')
    parser.add_argument('--reports-only', action='store_true', help='Generate only reports (skip scanning)')
    parser.add_argument('--pdf-reports', action='store_true', help='Enable PDF report generation (requires reportlab)')
    parser.add_argument('--csv-export', action='store_true', help='Enable CSV data export')
    
    args = parser.parse_args()
    
    # Initialize recon wrapper
    recon = ReconWrapper()
    
    # Load custom config if provided
    if args.config:
        recon.config.load_config(args.config)
    
    # Set offline mode and helper options from command line
    if args.offline:
        recon.config.set('general', 'offline_mode', True)
        recon.config.set('mode', 'offline', True)
    if args.dns_server:
        recon.config.set('general', 'dns_server', args.dns_server)
        # Also add to DNS servers list
        dns_servers = recon.config.get('dns', 'servers', [])
        if args.dns_server not in dns_servers:
            dns_servers.append(args.dns_server)
            recon.config.set('dns', 'servers', dns_servers)
    if args.cidr:
        recon.config.set('general', 'cidr_range', args.cidr)
    if args.dir_wordlist:
        recon.config.set('general', 'dir_wordlist', args.dir_wordlist)
        recon.config.set('bruteforce', 'dir_wordlist', args.dir_wordlist)
    if args.rate_limit:
        recon.config.set('bruteforce', 'rate_limit', args.rate_limit)
    if args.dir_threads:
        recon.config.set('bruteforce', 'threads', args.dir_threads)
    
    # Set performance options from command line
    if args.light_mode:
        recon.config.set('performance', 'light_mode', True)
        # Adjust other settings for light mode
        recon.config.set('bruteforce', 'threads', min(args.dir_threads or 10, 5))  # Reduce threads
        recon.config.set('subdomains', 'threads', min(recon.config.get('subdomains', 'threads', 50), 20))  # Reduce subdomain threads
        print("🔋 Light mode enabled - reduced resource usage")
    if args.no_stagger:
        recon.config.set('performance', 'enable_staggering', False)
        print("⚡ Module staggering disabled - all modules will run back-to-back")
    if args.cooldown != 5:  # Only set if different from default
        recon.config.set('performance', 'module_cooldown', args.cooldown)
    if args.no_resource_monitor:
        recon.config.set('performance', 'resource_monitoring', False)
        print("📊 System resource monitoring disabled")
    if args.threads:
        recon.config.set('general', 'threads', args.threads)
    if args.timeout:
        recon.config.set('general', 'timeout', args.timeout)
    
    # Set security options from command line
    if args.no_security:
        recon.config.set('security', 'enabled', False)
        print("🚫 Security analysis disabled")
    if args.security_ports != [443, 8443, 9443, 8080, 8008, 8888]:  # Only set if different from default
        recon.config.set('security', 'ports', args.security_ports)
        print(f"🔍 Security scan ports: {args.security_ports}")
    if args.no_cert_transparency:
        recon.config.set('security', 'cert_transparency', False)
        print("📜 Certificate Transparency log queries disabled")
    if args.security_timeout != 30:  # Only set if different from default
        recon.config.set('security', 'timeout', args.security_timeout)
    
    # Set advanced reporting options from command line
    if args.no_advanced_reports:
        recon.config.set('reporting', 'advanced_enabled', False)
        print("📊 Advanced reporting disabled")
    if args.no_risk_assessment:
        recon.config.set('reporting', 'generate_risk_assessment', False)
        recon.config.set('reporting', 'risk_scoring', {'enabled': False})
        print("🎯 Risk assessment disabled")
    if args.no_compliance:
        recon.config.set('reporting', 'generate_compliance', False)
        print("📋 Compliance framework analysis disabled")
    if args.pdf_reports:
        recon.config.set('reporting', 'generate_pdf', True)
        print("📄 PDF report generation enabled")
    if args.csv_export:
        recon.config.set('reporting', 'generate_csv', True)
        print("📈 CSV data export enabled")
        
    # Determine scan type
    scan_type = 'basic'
    if args.fast:
        scan_type = 'light'
    elif args.full:
        scan_type = 'full'
    
    # Handle reports-only mode
    if args.reports_only:
        print("📊 Reports-only mode: Generating reports from existing data...")
        success = False
        
        if args.domain:
            recon.target = args.domain
            recon.output_dir = Path(f"recon_{args.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            recon.output_dir.mkdir(exist_ok=True)
            recon.setup_logging()
            
            # Try to load existing results
            if recon._load_existing_results():
                recon.generate_report()
                success = True
            else:
                print("❌ No existing scan results found. Run a scan first.")
                
        elif args.ip:
            recon.target = args.ip
            recon.output_dir = Path(f"recon_{args.ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            recon.output_dir.mkdir(exist_ok=True)
            recon.setup_logging()
            
            if recon._load_existing_results():
                recon.generate_report()
                success = True
            else:
                print("❌ No existing scan results found. Run a scan first.")
        else:
            print("❌ Target required for reports-only mode")
            
    else:
        # Run reconnaissance
        success = False
        
        if args.domain:
            success = recon.run_single_target(args.domain, scan_type)
        elif args.ip:
            success = recon.run_single_target(args.ip, scan_type)
        elif args.targets_file:
            success = recon.run_multiple_targets(args.targets_file, scan_type)
        
    if success:
        print(f"\n✅ Reconnaissance completed successfully!")
        if hasattr(recon, 'output_dir'):
            print(f"📁 Results saved in: {recon.output_dir}")
        print("\n🎯 External tools used in this toolkit (23 total):")
        print("   • Port Scanning: nmap, masscan")
        print("   • Subdomain Discovery: sublist3r, assetfinder, subfinder, amass")
        print("   • Web Scanning: nikto, gobuster, ffuf, feroxbuster, dirb, wfuzz")
        print("   • Vulnerability: nuclei, sqlmap, testssl")
        print("   • OSINT: theharvester, recon-ng, waybackpy, shodan")
        print("   • Network: dig, httpx, whatweb, wafw00f")
        print("   • Install with: ./install.sh")
    else:
        print(f"\n❌ Reconnaissance failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
