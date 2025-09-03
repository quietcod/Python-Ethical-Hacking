"""
Real Orchestrator - Actual Tool Execution
Replaces SimpleOrchestrator's simulation with real tool execution
"""

import json
import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List

from .logger import setup_logger
from .exceptions import ScanError, ToolNotFoundError
from .utils import check_tool_installed, get_missing_tools, generate_scan_id
from .tool_loader import load_all_tools, get_tool_class, get_tool_status

# Import ReportManager with fallback handling
try:
    from ..reporting.report_manager import ReportManager
    REPORTING_AVAILABLE = True
except ImportError:
    try:
        from recon_tool.reporting.report_manager import ReportManager
        REPORTING_AVAILABLE = True
    except ImportError:
        REPORTING_AVAILABLE = False
        ReportManager = None

# Load all tool classes using the robust tool loader
print("🔧 Initializing tool integration...")
AVAILABLE_TOOLS = load_all_tools()
TOOLS_STATUS = get_tool_status()

# Extract individual tool classes
PortScanner = AVAILABLE_TOOLS.get('PortScanner')
SubdomainEnumerator = AVAILABLE_TOOLS.get('SubdomainEnumerator')
WebScanner = AVAILABLE_TOOLS.get('WebScanner')
SSLScanner = AVAILABLE_TOOLS.get('SSLScanner')
DNSScanner = AVAILABLE_TOOLS.get('DNSScanner')
DirectoryScanner = AVAILABLE_TOOLS.get('DirectoryScanner')
VulnerabilityScanner = AVAILABLE_TOOLS.get('VulnerabilityScanner')
OSINTCollector = AVAILABLE_TOOLS.get('OSINTCollector')

# Check if we have any tools available
TOOLS_AVAILABLE = any(TOOLS_STATUS.values())

if TOOLS_AVAILABLE:
    successful_tools = [name for name, status in TOOLS_STATUS.items() if status]
    print(f"✅ Tool integration successful: {len(successful_tools)}/8 tools loaded")
    print(f"   Available tools: {', '.join(successful_tools)}")
else:
    print("❌ Tool integration failed: No tools could be loaded")


class RealOrchestrator:
    """Real orchestrator that executes actual reconnaissance tools"""
    
    def __init__(self, config_manager=None, output_dir: Optional[Path] = None):
        self.config = config_manager
        self.output_dir = Path(output_dir) if output_dir else Path('./recon_results')
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup logging
        self.logger = setup_logger('orchestrator', logging.INFO)
        
        # Initialize results storage
        self.results = {}
        
        # Tool configuration
        self.tool_config = self._get_tool_config()
        
        # Track scan progress
        self.scan_id = generate_scan_id()
        
    def setup(self, output_dir: Optional[Path] = None):
        """Setup orchestrator with output directory"""
        if output_dir:
            self.output_dir = Path(output_dir)
            self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger.info(f"Real orchestrator initialized with output directory: {self.output_dir}")
    
    def check_dependencies(self) -> Dict[str, Any]:
        """Check which tools are available"""
        self.logger.info("Checking tool dependencies...")
        
        # First check if tool classes were imported successfully
        if not TOOLS_AVAILABLE:
            self.logger.error("Tool classes could not be imported - check Python path configuration")
            self.logger.info("Tool class status:")
            for tool_name, status in TOOLS_STATUS.items():
                status_str = "✅ Loaded" if status else "❌ Failed"
                self.logger.info(f"  {tool_name}: {status_str}")
            raise ToolNotFoundError("Tool classes not available - import failed")
        
        # Report tool class integration status
        self.logger.info("Tool class integration status:")
        for tool_name, status in TOOLS_STATUS.items():
            status_str = "✅ Available" if status else "❌ Missing"
            self.logger.info(f"  {tool_name}: {status_str}")
        
        # Define required external tools by category
        tool_requirements = {
            'network': ['nmap'],
            'subdomain': ['subfinder', 'assetfinder'],  # Optional tools
            'web': ['curl', 'wget'],  # Basic tools
            'ssl': ['openssl'],
            'dns': ['dig', 'nslookup'],
            'directory': ['gobuster', 'dirb'],  # Optional
            'vulnerability': ['nuclei'],  # Optional
        }
        
        # Check external tool availability
        self.logger.info("External tool availability:")
        tool_status = {}
        missing_critical = []
        
        for category, tools in tool_requirements.items():
            tool_status[category] = {}
            for tool in tools:
                available = check_tool_installed(tool)
                tool_status[category][tool] = available
                
                # Mark critical missing tools
                if not available and tool in ['nmap', 'curl', 'dig']:
                    missing_critical.append(tool)
        
        # Log results
        for category, tools in tool_status.items():
            available_tools = [tool for tool, status in tools.items() if status]
            missing_tools = [tool for tool, status in tools.items() if not status]
            
            if available_tools:
                self.logger.info(f"  {category.title()} tools available: {', '.join(available_tools)}")
            if missing_tools:
                self.logger.warning(f"  {category.title()} tools missing: {', '.join(missing_tools)}")
        
        if missing_critical:
            raise ToolNotFoundError(f"Critical external tools missing: {', '.join(missing_critical)}")
        
        # Combine tool class and external tool status
        combined_status = {
            'tool_classes': TOOLS_STATUS,
            'external_tools': tool_status
        }
        
        return combined_status
    
    def run_scan(self, target: str, **scan_options) -> bool:
        """Run real scan for target"""
        try:
            self.logger.info(f"Starting REAL scan for target: {target}")
            
            # Check if this is a dry run
            if scan_options.get('dry_run', False):
                self.logger.info("DRY RUN MODE - No actual scanning will be performed")
                return self._handle_dry_run(target, scan_options)
            
            # Check tool dependencies
            tool_status = self.check_dependencies()
            
            # Initialize scan results
            scan_results = {
                'target': target,
                'scan_id': self.scan_id,
                'start_time': datetime.now().isoformat(),
                'scan_options': scan_options,
                'status': 'running',
                'tool_availability': tool_status,
                'results': {}
            }
            
            # Create target-specific output directory
            target_dir = self.output_dir / self._sanitize_filename(target)
            target_dir.mkdir(exist_ok=True)
            
            # Determine which tools to run
            tools_to_run = self._determine_tools_to_run(scan_options)
            scan_results['tools_planned'] = tools_to_run
            
            self.logger.info(f"Running tools: {', '.join(tools_to_run)}")
            
            # Execute tools in sequence
            for tool_name in tools_to_run:
                try:
                    self.logger.info(f"Executing {tool_name} scan...")
                    tool_result = self._execute_tool(tool_name, target, target_dir, scan_options)
                    scan_results['results'][tool_name] = tool_result
                    self.logger.info(f"✅ {tool_name} scan completed")
                    
                except Exception as e:
                    self.logger.error(f"❌ {tool_name} scan failed: {str(e)}")
                    scan_results['results'][tool_name] = {
                        'status': 'failed',
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    }
                    # Continue with other tools even if one fails
            
            scan_results['status'] = 'completed'
            scan_results['end_time'] = datetime.now().isoformat()
            
            # Save results
            self._save_results(target, scan_results)
            
            # Generate summary
            self._generate_scan_summary(target, scan_results)
            
            # Generate reports if requested
            if scan_options.get('generate_reports', False):
                self._generate_reports(target, scan_results, scan_options)
            
            self.logger.info(f"✅ Real scan completed successfully for {target}")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Real scan failed for {target}: {str(e)}")
            # Save error state
            error_results = {
                'target': target,
                'scan_id': self.scan_id,
                'start_time': scan_results.get('start_time', datetime.now().isoformat()),
                'status': 'failed',
                'error': str(e),
                'end_time': datetime.now().isoformat()
            }
            self._save_results(target, error_results)
            return False
    
    def _handle_dry_run(self, target: str, scan_options: Dict[str, Any]) -> bool:
        """Handle dry run mode"""
        tools_to_run = self._determine_tools_to_run(scan_options)
        
        dry_run_results = {
            'target': target,
            'scan_id': self.scan_id,
            'start_time': datetime.now().isoformat(),
            'status': 'dry_run_completed',
            'scan_options': scan_options,
            'tools_that_would_run': tools_to_run,
            'note': 'Dry run mode - no actual scanning performed',
            'end_time': datetime.now().isoformat()
        }
        
        # Save dry run results
        self._save_results(target, dry_run_results)
        return True
    
    def _determine_tools_to_run(self, scan_options: Dict[str, Any]) -> List[str]:
        """Determine which tools to run based on scan options"""
        scan_mode = scan_options.get('scan_mode', 'normal')
        enabled_tools = scan_options.get('enabled_tools', [])
        disabled_tools = scan_options.get('disabled_tools', [])
        
        # Define tool sets by scan mode
        tool_sets = {
            'passive': ['osint', 'dns'],
            'quick': ['subdomain', 'port', 'web'],
            'normal': ['subdomain', 'port', 'web', 'ssl', 'dns'],
            'full': ['subdomain', 'port', 'web', 'ssl', 'dns', 'directory', 'vulnerability', 'osint']
        }
        
        if enabled_tools:
            # If specific tools are enabled, only run those
            tools_to_run = enabled_tools.copy()
        else:
            # Use scan mode to determine tools
            tools_to_run = tool_sets.get(scan_mode, tool_sets['normal']).copy()
        
        # Remove disabled tools
        if disabled_tools:
            tools_to_run = [tool for tool in tools_to_run if tool not in disabled_tools]
        
        return tools_to_run
    
    def _execute_tool(self, tool_name: str, target: str, output_dir: Path, scan_options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a specific tool"""
        tool_start_time = datetime.now()
        
        try:
            if not TOOLS_AVAILABLE:
                raise ScanError(f"Tool classes not imported - cannot execute {tool_name}")
            
            if tool_name == 'subdomain':
                if SubdomainEnumerator is None:
                    raise ScanError("SubdomainEnumerator class not available")
                return self._run_subdomain_enumeration(target, output_dir, scan_options)
            elif tool_name == 'port':
                if PortScanner is None:
                    raise ScanError("PortScanner class not available")
                return self._run_port_scanning(target, output_dir, scan_options)
            elif tool_name == 'web':
                if WebScanner is None:
                    raise ScanError("WebScanner class not available")
                return self._run_web_scanning(target, output_dir, scan_options)
            elif tool_name == 'ssl':
                if SSLScanner is None:
                    raise ScanError("SSLScanner class not available")
                return self._run_ssl_scanning(target, output_dir, scan_options)
            elif tool_name == 'dns':
                if DNSScanner is None:
                    raise ScanError("DNSScanner class not available")
                return self._run_dns_scanning(target, output_dir, scan_options)
            elif tool_name == 'directory':
                if DirectoryScanner is None:
                    raise ScanError("DirectoryScanner class not available")
                return self._run_directory_scanning(target, output_dir, scan_options)
            elif tool_name == 'vulnerability':
                if VulnerabilityScanner is None:
                    raise ScanError("VulnerabilityScanner class not available")
                return self._run_vulnerability_scanning(target, output_dir, scan_options)
            elif tool_name == 'osint':
                if OSINTCollector is None:
                    raise ScanError("OSINTCollector class not available")
                return self._run_osint_collection(target, output_dir, scan_options)
            else:
                raise ScanError(f"Unknown tool: {tool_name}")
                
        except Exception as e:
            # Return error result with timing info
            duration = (datetime.now() - tool_start_time).total_seconds()
            return {
                'status': 'failed',
                'error': str(e),
                'duration': duration,
                'timestamp': datetime.now().isoformat()
            }
    
    def _run_subdomain_enumeration(self, target: str, output_dir: Path, scan_options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute subdomain enumeration"""
        tool_start_time = datetime.now()
        
        try:
            enumerator = SubdomainEnumerator(output_dir, self.tool_config, self.logger)
            subdomains = enumerator.enumerate(target)
            
            duration = (datetime.now() - tool_start_time).total_seconds()
            
            return {
                'status': 'completed',
                'subdomains_found': len(subdomains),
                'subdomains': subdomains[:50],  # Limit output size
                'duration': duration,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            duration = (datetime.now() - tool_start_time).total_seconds()
            raise ScanError(f"Subdomain enumeration failed: {str(e)}")
    
    def _run_port_scanning(self, target: str, output_dir: Path, scan_options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute port scanning"""
        tool_start_time = datetime.now()
        
        try:
            scanner = PortScanner(output_dir, self.tool_config, self.logger)
            
            # Choose scan type based on options
            if scan_options.get('scan_mode') == 'quick':
                results = scanner.basic_scan(target)
            elif scan_options.get('scan_mode') == 'full':
                results = scanner.aggressive_scan(target)
            else:
                # Try hybrid scan if masscan is available
                if check_tool_installed('masscan'):
                    results = scanner.hybrid_scan(target)
                else:
                    results = scanner.basic_scan(target)
            
            duration = (datetime.now() - tool_start_time).total_seconds()
            
            # Extract summary information
            summary = results.get('summary', {})
            
            return {
                'status': 'completed',
                'scan_type': results.get('scan_type', 'basic'),
                'hosts_found': summary.get('hosts_up', 0),
                'open_ports': summary.get('open_ports', 0),
                'total_ports': summary.get('total_ports', 0),
                'duration': duration,
                'timestamp': datetime.now().isoformat(),
                'detailed_results': results  # Full results
            }
            
        except Exception as e:
            duration = (datetime.now() - tool_start_time).total_seconds()
            raise ScanError(f"Port scanning failed: {str(e)}")
    
    def _run_web_scanning(self, target: str, output_dir: Path, scan_options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute web scanning"""
        tool_start_time = datetime.now()
        
        try:
            scanner = WebScanner(output_dir, self.tool_config, self.logger)
            results = scanner.scan_target(target)  # Use correct method name
            
            duration = (datetime.now() - tool_start_time).total_seconds()
            
            return {
                'status': 'completed',
                'technologies': results.get('technology_stack', {}),
                'security_headers': results.get('security_headers', {}),
                'directories': results.get('directories', []),
                'duration': duration,
                'timestamp': datetime.now().isoformat(),
                'detailed_results': results
            }
            
        except Exception as e:
            duration = (datetime.now() - tool_start_time).total_seconds()
            raise ScanError(f"Web scanning failed: {str(e)}")
    
    def _run_ssl_scanning(self, target: str, output_dir: Path, scan_options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute SSL scanning"""
        tool_start_time = datetime.now()
        
        try:
            scanner = SSLScanner(output_dir, self.tool_config, self.logger)
            results = scanner.scan(target)  # Use correct method name
            
            duration = (datetime.now() - tool_start_time).total_seconds()
            
            return {
                'status': 'completed',
                'ssl_enabled': results.get('ssl_enabled', False),
                'certificate_info': results.get('certificate', {}),
                'vulnerabilities': results.get('vulnerabilities', []),
                'duration': duration,
                'timestamp': datetime.now().isoformat(),
                'detailed_results': results
            }
            
        except Exception as e:
            duration = (datetime.now() - tool_start_time).total_seconds()
            raise ScanError(f"SSL scanning failed: {str(e)}")
    
    def _run_dns_scanning(self, target: str, output_dir: Path, scan_options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute DNS scanning"""
        tool_start_time = datetime.now()
        
        try:
            scanner = DNSScanner(output_dir, self.tool_config, self.logger)
            results = scanner.scan_dns(target)  # Use correct method name
            
            duration = (datetime.now() - tool_start_time).total_seconds()
            
            return {
                'status': 'completed',
                'dns_records': results.get('records', {}),
                'nameservers': results.get('nameservers', []),
                'duration': duration,
                'timestamp': datetime.now().isoformat(),
                'detailed_results': results
            }
            
        except Exception as e:
            duration = (datetime.now() - tool_start_time).total_seconds()
            raise ScanError(f"DNS scanning failed: {str(e)}")
    
    def _run_directory_scanning(self, target: str, output_dir: Path, scan_options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute directory scanning"""
        tool_start_time = datetime.now()
        
        try:
            scanner = DirectoryScanner(output_dir, self.tool_config, self.logger)
            results = scanner.scan_directories(target)
            
            duration = (datetime.now() - tool_start_time).total_seconds()
            
            return {
                'status': 'completed',
                'directories_found': len(results.get('directories', [])),
                'files_found': len(results.get('files', [])),
                'duration': duration,
                'timestamp': datetime.now().isoformat(),
                'detailed_results': results
            }
            
        except Exception as e:
            duration = (datetime.now() - tool_start_time).total_seconds()
            raise ScanError(f"Directory scanning failed: {str(e)}")
    
    def _run_vulnerability_scanning(self, target: str, output_dir: Path, scan_options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute vulnerability scanning"""
        tool_start_time = datetime.now()
        
        try:
            scanner = VulnerabilityScanner(output_dir, self.tool_config, self.logger)
            results = scanner.scan_vulnerabilities(target)
            
            duration = (datetime.now() - tool_start_time).total_seconds()
            
            return {
                'status': 'completed',
                'vulnerabilities_found': len(results.get('vulnerabilities', [])),
                'high_risk': len([v for v in results.get('vulnerabilities', []) if v.get('severity') == 'high']),
                'duration': duration,
                'timestamp': datetime.now().isoformat(),
                'detailed_results': results
            }
            
        except Exception as e:
            duration = (datetime.now() - tool_start_time).total_seconds()
            raise ScanError(f"Vulnerability scanning failed: {str(e)}")
    
    def _run_osint_collection(self, target: str, output_dir: Path, scan_options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute OSINT collection"""
        tool_start_time = datetime.now()
        
        try:
            collector = OSINTCollector(output_dir, self.tool_config, self.logger)
            results = collector.collect(target)  # Use correct method name
            
            duration = (datetime.now() - tool_start_time).total_seconds()
            
            return {
                'status': 'completed',
                'sources_checked': len(results.get('sources', [])),
                'information_gathered': len(results.get('information', [])),
                'duration': duration,
                'timestamp': datetime.now().isoformat(),
                'detailed_results': results
            }
            
        except Exception as e:
            duration = (datetime.now() - tool_start_time).total_seconds()
            raise ScanError(f"OSINT collection failed: {str(e)}")
    
    def _get_tool_config(self) -> Dict[str, Any]:
        """Get tool configuration"""
        default_config = {
            'timeout': 300,
            'threads': 10,
            'light_mode': False,
            'offline_mode': False,
            'basic_flags': '-sV -sC',
            'aggressive_flags': '-A -T4'
        }
        
        if self.config and hasattr(self.config, 'get_tool_config'):
            return self.config.get_tool_config()
        return default_config
    
    def _generate_scan_summary(self, target: str, scan_results: Dict[str, Any]) -> None:
        """Generate a summary of scan results"""
        summary = {
            'target': target,
            'scan_id': scan_results['scan_id'],
            'status': scan_results['status'],
            'start_time': scan_results['start_time'],
            'end_time': scan_results['end_time'],
            'tools_executed': len(scan_results.get('results', {})),
            'successful_tools': len([r for r in scan_results.get('results', {}).values() if r.get('status') == 'completed']),
            'failed_tools': len([r for r in scan_results.get('results', {}).values() if r.get('status') == 'failed']),
            'highlights': {}
        }
        
        # Extract key findings
        results = scan_results.get('results', {})
        
        if 'subdomain' in results and results['subdomain'].get('status') == 'completed':
            summary['highlights']['subdomains'] = results['subdomain'].get('subdomains_found', 0)
        
        if 'port' in results and results['port'].get('status') == 'completed':
            summary['highlights']['open_ports'] = results['port'].get('open_ports', 0)
        
        if 'vulnerability' in results and results['vulnerability'].get('status') == 'completed':
            summary['highlights']['vulnerabilities'] = results['vulnerability'].get('vulnerabilities_found', 0)
        
        # Save summary
        target_dir = self.output_dir / self._sanitize_filename(target)
        summary_file = target_dir / 'scan_summary.json'
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        self.logger.info(f"Scan summary saved to {summary_file}")
    
    def _generate_reports(self, target: str, scan_results: Dict[str, Any], scan_options: Dict[str, Any]) -> None:
        """Generate multi-format reports"""
        try:
            if not REPORTING_AVAILABLE or ReportManager is None:
                self.logger.warning("⚠️ Reporting system not available - skipping report generation")
                return
                
            self.logger.info("📊 Generating reports...")
            
            # Get report formats from options
            report_formats = scan_options.get('report_formats', ['json', 'markdown'])
            
            # Initialize report manager
            config = getattr(self, 'config', None)
            report_manager = ReportManager(self.output_dir, config)
            
            # Generate reports
            generated_reports = report_manager.generate_reports(
                results=scan_results,
                target=target,
                formats=report_formats
            )
            
            if generated_reports:
                self.logger.info(f"✅ Generated {len(generated_reports)} reports:")
                for format_name, file_path in generated_reports.items():
                    self.logger.info(f"  • {format_name.upper()}: {file_path}")
                
                # Get and log summary
                summary = report_manager.get_report_summary(generated_reports)
                self.logger.info(f"📁 Total report size: {summary['total_size_human']}")
            else:
                self.logger.warning("⚠️ No reports were generated")
                
        except Exception as e:
            self.logger.error(f"❌ Report generation failed: {str(e)}")
            # Don't fail the entire scan if report generation fails
    
    def _save_results(self, target: str, results: Dict[str, Any]):
        """Save scan results to file"""
        try:
            # Create target-specific output directory
            target_dir = self.output_dir / self._sanitize_filename(target)
            target_dir.mkdir(exist_ok=True)
            
            # Save results as JSON
            results_file = target_dir / 'scan_results.json'
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            # Also save to main results
            self.results[target] = results
            
            self.logger.info(f"Results saved to {results_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to save results: {str(e)}")
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for safe file creation"""
        invalid_chars = '<>:"/\\|?*'
        for char in invalid_chars:
            filename = filename.replace(char, '_')
        return filename.strip(' .')
    
    def resume_scan(self, state_file: str, target: str, **scan_options) -> bool:
        """Resume scan from previous state"""
        self.logger.info(f"Resume functionality implementation in progress")
        # For now, just run a normal scan
        return self.run_scan(target, **scan_options)


# Export the real orchestrator
ReconOrchestrator = RealOrchestrator
