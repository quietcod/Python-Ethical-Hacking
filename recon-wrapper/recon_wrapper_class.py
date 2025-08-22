"""
ReconWrapper - Infrastructure Module
Main reconnaissance orchestration and infrastructure management
Author: Refactored Architecture
Date: 2025-08-23

ARCHITECTURE DISTRIBUTION:
Infrastructure: 1 wrapper class + 23 core Python libraries = 24 components

WRAPPER CLASS (1):
    ReconWrapper - Main orchestration and coordination class

CORE PYTHON LIBRARIES (23):
    argparse, ipaddress, os, sys, json, subprocess, threading, time, csv, datetime,
    pathlib, xml, re, requests, logging, concurrent.futures, socket, ssl, hashlib,
    base64, urllib, dns, tempfile

Features:
- Central orchestration of all scanning components
- Configuration management and validation
- Resource monitoring and optimization
- Progress tracking and status reporting
- Error handling and recovery mechanisms
- Result consolidation and coordination
- Multi-target and batch processing
- Logging and audit trail management
"""

import json
import logging
from datetime import datetime
from pathlib import Path
import os

# Import all scanner classes
from recon_all_in_one import (
    ConfigManager, ResourceMonitor, ProgressTracker, ErrorHandler,
    PortScanner, SubdomainEnumerator, WebScanner, SecurityScanner,
    OSINTCollector, Screenshotter
)

# Import reporting classes
try:
    from recon_report import AdvancedReportGenerator, ReportGenerator
    HAS_REPORTING = True
except ImportError:
    HAS_REPORTING = False


class ReconWrapper:
    """Main reconnaissance wrapper class"""
    
    def __init__(self):
            self.target = None
            self.target_type = None
            self.output_dir = None
            self.config = ConfigManager()
            self.logger = None
            self.results = {}
            self.scanners = {}
            
            # Initialize components with config
            self.resource_monitor = ResourceMonitor(self.config)
            self.progress_tracker = ProgressTracker(self.config)
            self.error_handler = ErrorHandler(self.config)
        
    def setup_logging(self):
        """Setup logging configuration"""
        log_file = self.output_dir / "scan.log"
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Setup file handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)
        
        # Setup console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(logging.INFO)
        
        # Configure logger
        self.logger = logging.getLogger('recon_wrapper')
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
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
            self.logger.error(f"Failed to initialize scanners: {str(e)}")
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
                self.logger.info(f"Port scan completed: {len(port_results)} hosts scanned")
            
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
                self.logger.info(f"Subdomain enumeration completed: {len(subdomain_results)} subdomains found")
            
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
                self.logger.info(f"Web scan completed: {len(web_results)} targets scanned")
            
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
                self.logger.info(f"Screenshot capture completed: {len(screenshot_results)} screenshots taken")
            
            self.progress_tracker.complete_task("Screenshot Capture")
            
        except Exception as e:
            self.logger.error(f"Screenshot capture failed: {str(e)}")
            self.error_handler.handle_error("screenshot_capture", e)
    
    def generate_report(self):
        """Generate comprehensive report"""
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
            
            for pattern in result_files:
                import glob
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
