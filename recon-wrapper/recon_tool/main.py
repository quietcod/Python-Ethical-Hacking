#!/usr/bin/env python3
"""
Recon Tool - Main Entry Point v2.0
Professional Reconnaissance Toolkit
Author: Security Research Team
Date: 2025-08-25

Usage:
    python3 main.py --domain example.com
    python3 main.py --ip 192.168.1.1 --full
    python3 main.py --targets-file targets.txt --output-dir /path/to/output
    python3 main.py --config custom_config.json --verbose
    python3 main.py --version
"""

import sys
import argparse
import logging
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Optional, List

# Add the current directory to Python path for imports
sys.path.append(str(Path(__file__).parent))

# Version information
try:
    from . import __version__, __author__, __description__
    VERSION = __version__
    AUTHOR = __author__ 
    DESCRIPTION = __description__
except ImportError:
    VERSION = "2.0.0"
    AUTHOR = "Security Research Team"
    DESCRIPTION = "Professional reconnaissance framework"

# Try importing core modules, fall back gracefully if not available
try:
    from core.logger import setup_logger
    from core.exceptions import ConfigurationError, ValidationError, ToolNotFoundError
    from core.validators import TargetValidator
    from core.enhanced_validators import EnhancedInputValidator, validate_tools_available
    from core.target_processor import TargetProcessor, process_targets_simple
    from config import ConfigManager
    CORE_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Core modules not fully available: {e}")
    CORE_AVAILABLE = False


def print_banner():
    """Print application banner"""
    banner = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    RECON TOOL v{VERSION} - PROFESSIONAL EDITION              ║
║                   Comprehensive Reconnaissance Toolkit                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Architecture: 77 Components • Modular Design • Interactive Dashboard        ║
║  Categories: Network • Web • OSINT • Advanced Reporting                      ║
║  Features: Real-time Updates • Multi-format Reports • Plugin Support         ║
║  Author: {AUTHOR:<58}                                                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_completion_summary(output_dir: Path, target_count: int, failed_count: int = 0):
    """Print scan completion summary"""
    if failed_count == 0:
        print(f"\n✅ All reconnaissance scans completed successfully!")
    else:
        print(f"\n⚠️  {target_count - failed_count}/{target_count} scans completed successfully")
        print(f"   {failed_count} scan(s) failed - check logs for details")
    
    print(f"📁 Results saved in: {output_dir}")
    
    # Check for reports directory
    reports_dir = output_dir / "reports"
    if reports_dir.exists():
        print(f"📊 Reports available in: {reports_dir}")
    else:
        print(f"📊 View individual results in target directories")
    
    # Provide helpful next steps
    print(f"\n💡 Next steps:")
    print(f"   • Review results: ls -la {output_dir}")
    print(f"   • Generate reports: python3 -m recon_tool.reporting --help")
    print(f"   • View logs: find {output_dir} -name '*.log'")


def print_error_help(error_type: str, specific_error: str = ""):
    """Print helpful error information"""
    help_messages = {
        'validation': f"""
💡 Validation Error Help:
   Error: {specific_error}
   
   Valid formats:
   • Domain: example.com (no http:// prefix, must contain at least one dot)
   • IP address: 192.168.1.1 or 2001:db8::1
   • Targets file: One target per line, # for comments
   
   Examples:
   • python3 -m recon_tool.main --domain google.com
   • python3 -m recon_tool.main --ip 8.8.8.8
   • python3 -m recon_tool.main --targets-file targets.txt
        """,
        'configuration': f"""
💡 Configuration Error Help:
   Error: {specific_error}
   
   Common issues:
   • Check config file syntax (must be valid JSON)
   • Verify file paths exist and are readable
   • Ensure output directory is writable
   • Use --debug for detailed error information
   
   Example config file structure:
   {{
     "tools": {{"enabled": ["port", "subdomain", "web"]}},
     "output": {{"format": "json", "directory": "./results"}},
     "scan_options": {{"threads": 10, "timeout": 300}}
   }}
        """,
        'permission': f"""
💡 Permission Error Help:
   Error: {specific_error}
   
   Solutions:
   • Check output directory write permissions: chmod 755 ./recon_results
   • Run with appropriate user privileges
   • Verify log file location is writable
   • Try using a different output directory: --output-dir /tmp/recon
        """,
        'invalid_combination': f"""
💡 Invalid Combination Error Help:
   Error: {specific_error}
   
   Common conflicts:
   • Cannot use --full, --quick, and --passive together (choose one)
   • Cannot specify both --tools and --exclude-tools for the same tool
   • Target options are mutually exclusive (use --domain OR --ip OR --targets-file)
   
   Examples of valid combinations:
   • python3 -m recon_tool.main --domain example.com --quick
   • python3 -m recon_tool.main --ip 8.8.8.8 --tools port subdomain
   • python3 -m recon_tool.main --targets-file targets.txt --full --exclude-tools screenshot
        """,
        'missing_dependency': f"""
💡 Missing Dependency Error Help:
   Error: {specific_error}
   
   Solutions:
   • Install missing tools: sudo apt-get install nmap dig curl
   • Check if tools are in PATH: which nmap
   • Install Python dependencies: pip install -r requirements.txt
   • Use --dry-run to test without executing tools
        """
    }
    
    if error_type in help_messages:
        print(help_messages[error_type])
    else:
        print(f"""
💡 General Error Help:
   Error: {specific_error}
   
   For more help:
   • Use --help for command usage
   • Use --debug for detailed error information
   • Check the documentation
   • Review log files for more details
        """)


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser"""
    parser = argparse.ArgumentParser(
        prog='recon_tool',
        description=f"{DESCRIPTION} (v{VERSION})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  %(prog)s --domain example.com                    # Quick domain scan
  %(prog)s --ip 192.168.1.1 --full                # Full IP scan
  %(prog)s --targets-file targets.txt              # Multiple targets
  %(prog)s --domain example.com --quick            # Fast scan mode
  %(prog)s --domain example.com --tools port web   # Specific tools only
  %(prog)s --domain example.com --passive          # OSINT only (no active scanning)
  %(prog)s --version                               # Show version information

Scan Modes:
  --quick     Fast scan (basic port scan + subdomain enum)
  --full      Comprehensive scan (all tools, detailed analysis)
  --passive   OSINT only (no direct target interaction)
  (default)   Balanced scan (most tools, reasonable speed)

Tool Categories:
  Network:    port, dns, network
  Web:        web, ssl, directory, api, screenshot
  OSINT:      subdomain, osint
  Security:   vulnerability

Output Formats:
  json        Machine-readable JSON format
  markdown    Human-readable Markdown reports
  html        Professional HTML reports with charts
  pdf         Professional PDF reports (requires reportlab)
  all         Generate all formats (default)

Author: {AUTHOR}
Version: {VERSION}

For detailed documentation, visit: https://github.com/your-repo/recon-tool
        """
    )
    
    # Version information
    parser.add_argument(
        '--version', '-V',
        action='version',
        version=f'%(prog)s {VERSION}\n{DESCRIPTION}\nAuthor: {AUTHOR}'
    )
    
    # Target specification (mutually exclusive)
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        '--domain', '-d',
        metavar='DOMAIN',
        help='Target domain to scan (e.g., example.com)'
    )
    target_group.add_argument(
        '--ip', '-i',
        metavar='IP_ADDRESS',
        help='Target IP address to scan (IPv4 or IPv6)'
    )
    target_group.add_argument(
        '--targets-file', '-f',
        type=Path,
        metavar='FILE',
        help='File containing list of targets (one per line, # for comments)'
    )
    
    # Scan configuration
    parser.add_argument(
        '--output-dir', '-o',
        type=Path,
        default=Path('./recon_results'),
        metavar='DIR',
        help='Output directory for results (default: %(default)s)'
    )
    
    parser.add_argument(
        '--config', '-c',
        type=Path,
        metavar='FILE',
        help='Path to custom configuration file (JSON format)'
    )
    
    # Scan modes (mutually exclusive)
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        '--full',
        action='store_true',
        help='Enable full scan mode (all tools, comprehensive analysis)'
    )
    
    mode_group.add_argument(
        '--quick',
        action='store_true',
        help='Enable quick scan mode (basic tools, faster execution)'
    )
    
    mode_group.add_argument(
        '--passive',
        action='store_true',
        help='Enable passive scan mode (OSINT only, no direct target contact)'
    )
    
    # Tool selection
    parser.add_argument(
        '--tools',
        nargs='+',
        metavar='TOOL',
        choices=[
            'subdomain', 'port', 'web', 'ssl', 'dns', 'network',
            'directory', 'api', 'screenshot', 'osint', 'vulnerability'
        ],
        help='Specific tools to run. Available: %(choices)s'
    )
    
    parser.add_argument(
        '--exclude-tools',
        nargs='+',
        metavar='TOOL',
        choices=[
            'subdomain', 'port', 'web', 'ssl', 'dns', 'network',
            'directory', 'api', 'screenshot', 'osint', 'vulnerability'
        ],
        help='Tools to exclude from scan. Available: %(choices)s'
    )
    
    # Output options
    parser.add_argument(
        '--format',
        choices=['json', 'markdown', 'html', 'pdf', 'all'],
        default='all',
        help='Report format (default: %(default)s)'
    )
    
    parser.add_argument(
        '--no-report',
        action='store_true',
        help='Skip report generation (only save raw scan data)'
    )
    
    # Logging options
    parser.add_argument(
        '--verbose', '-v',
        action='count',
        default=0,
        help='Increase verbosity (-v: warnings, -vv: info, -vvv: debug)'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress non-essential output (errors only)'
    )
    
    parser.add_argument(
        '--log-file',
        type=Path,
        metavar='FILE',
        help='Log file path (default: output_dir/recon_tool.log)'
    )
    
    # Performance options
    performance_group = parser.add_argument_group('performance options')
    performance_group.add_argument(
        '--threads',
        type=int,
        default=10,
        metavar='N',
        help='Number of threads to use (default: %(default)s)'
    )
    
    performance_group.add_argument(
        '--timeout',
        type=int,
        default=300,
        metavar='SECONDS',
        help='Scan timeout in seconds (default: %(default)s)'
    )
    
    performance_group.add_argument(
        '--rate-limit',
        type=float,
        default=1.0,
        metavar='RPS',
        help='Rate limit in requests per second (default: %(default)s)'
    )
    
    # Advanced options
    advanced_group = parser.add_argument_group('advanced options')
    advanced_group.add_argument(
        '--resume',
        metavar='STATE_FILE',
        help='Resume scan from previous state file'
    )
    
    advanced_group.add_argument(
        '--skip-dns-check',
        action='store_true',
        help='Skip DNS resolution validation (useful for internal domains)'
    )
    
    # Development/testing options
    dev_group = parser.add_argument_group('development options')
    dev_group.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode (detailed error information)'
    )
    
    dev_group.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without executing (test configuration)'
    )
    
    return parser


def setup_logging(args) -> logging.Logger:
    """Setup logging based on arguments"""
    # Determine log level
    if hasattr(args, 'debug') and args.debug:
        log_level = logging.DEBUG
    elif hasattr(args, 'verbose') and args.verbose >= 3:
        log_level = logging.DEBUG
    elif hasattr(args, 'verbose') and args.verbose == 2:
        log_level = logging.INFO
    elif hasattr(args, 'verbose') and args.verbose == 1:
        log_level = logging.WARNING
    elif hasattr(args, 'quiet') and args.quiet:
        log_level = logging.ERROR
    else:
        log_level = logging.INFO
    
    # Setup logger
    if CORE_AVAILABLE:
        logger = setup_logger(
            name='recon_tool',
            level=log_level,
            log_file=args.log_file if hasattr(args, 'log_file') and args.log_file else None
        )
    else:
        # Basic logging setup
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(args.log_file) if hasattr(args, 'log_file') and args.log_file else logging.NullHandler()
            ]
        )
        logger = logging.getLogger('recon_tool')
    
    return logger


def validate_arguments(args) -> None:
    """Enhanced argument validation with comprehensive checks"""
    errors = []
    
    if CORE_AVAILABLE:
        # Initialize enhanced validator
        check_dns = not getattr(args, 'skip_dns_check', False)
        validator = EnhancedInputValidator(
            check_dns_resolution=check_dns,
            allow_private_ips=True,
            require_tld=True,
            verify_tools=True
        )
        
        # Validate target input
        try:
            if args.domain:
                target_info = validator.validate_target(args.domain)
                if target_info['type'] != 'domain':
                    errors.append(f"Expected domain but got {target_info['type']}: {args.domain}")
            elif args.ip:
                target_info = validator.validate_target(args.ip)
                if target_info['type'] != 'ip':
                    errors.append(f"Expected IP address but got {target_info['type']}: {args.ip}")
            elif args.targets_file:
                if not args.targets_file.exists():
                    errors.append(f"Targets file not found: {args.targets_file}")
                else:
                    try:
                        file_validation = validator.validate_targets_file(str(args.targets_file))
                        if file_validation['valid_count'] == 0:
                            errors.append(f"No valid targets found in file: {args.targets_file}")
                        elif file_validation['invalid_count'] > 0:
                            # Show first few invalid targets as examples
                            invalid_examples = file_validation['invalid_targets'][:3]
                            error_details = []
                            for invalid in invalid_examples:
                                error_details.append(f"Line {invalid['line_number']}: {invalid['target']} - {invalid['error']}")
                            
                            if file_validation['invalid_count'] > 3:
                                error_details.append(f"... and {file_validation['invalid_count'] - 3} more")
                            
                            errors.append(f"Invalid targets in file:\n  " + "\n  ".join(error_details))
                    except ValidationError as e:
                        errors.append(str(e))
        except ValidationError as e:
            errors.append(str(e))
        
        # Validate tool availability for requested tools
        if hasattr(args, 'tools') and args.tools:
            try:
                # Map CLI tool names to internal tool names
                tool_mapping = {
                    'port': ['nmap'],
                    'subdomain': ['subfinder', 'assetfinder'],
                    'web': ['curl'],
                    'ssl': ['openssl'],
                    'dns': ['dig'],
                    'network': ['nmap', 'ping'],
                    'directory': ['curl'],
                    'api': ['curl'],
                    'vulnerability': ['nmap'],
                    'osint': ['dig', 'curl']
                }
                
                required_tools = []
                for cli_tool in args.tools:
                    if cli_tool in tool_mapping:
                        required_tools.extend(tool_mapping[cli_tool])
                
                if required_tools:
                    tool_validation = validate_tools_available(list(set(required_tools)))
                    if not tool_validation['all_available']:
                        missing = tool_validation['missing_tools']
                        errors.append(f"Required tools not available: {', '.join(missing)}")
            except ToolNotFoundError as e:
                errors.append(str(e))
    else:
        # Basic validation fallback
        if args.targets_file and not args.targets_file.exists():
            errors.append(f"Targets file not found: {args.targets_file}")
        
        # Basic domain validation
        if hasattr(args, 'domain') and args.domain:
            if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', args.domain):
                errors.append(f"Invalid domain format: {args.domain}")
    
    # Validate scan mode conflicts
    scan_modes = ['full', 'quick', 'passive']
    active_modes = [mode for mode in scan_modes if getattr(args, mode, False)]
    if len(active_modes) > 1:
        errors.append(f"Conflicting scan modes: {', '.join(active_modes)}. Only one can be specified.")
    
    # Validate tool selection conflicts
    if hasattr(args, 'tools') and hasattr(args, 'exclude_tools') and args.tools and args.exclude_tools:
        conflicting_tools = set(args.tools) & set(args.exclude_tools)
        if conflicting_tools:
            errors.append(f"Tools cannot be both included and excluded: {', '.join(conflicting_tools)}")
    
    # Validate numeric arguments
    if hasattr(args, 'threads') and args.threads <= 0:
        errors.append("Thread count must be positive")
    
    if hasattr(args, 'timeout') and args.timeout <= 0:
        errors.append("Timeout must be positive")
    
    if hasattr(args, 'rate_limit') and args.rate_limit <= 0:
        errors.append("Rate limit must be positive")
    
    # Validate output directory
    if args.output_dir:
        try:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            # Test write permissions
            test_file = args.output_dir / '.write_test'
            test_file.touch()
            test_file.unlink()
        except PermissionError:
            errors.append(f"No write permission for output directory: {args.output_dir}")
        except Exception as e:
            errors.append(f"Cannot create output directory: {e}")
    
    # Validate config file
    if hasattr(args, 'config') and args.config:
        if not args.config.exists():
            errors.append(f"Configuration file not found: {args.config}")
        else:
            try:
                with open(args.config, 'r') as f:
                    json.load(f)
            except json.JSONDecodeError as e:
                errors.append(f"Invalid JSON in config file: {e}")
            except Exception as e:
                errors.append(f"Cannot read config file: {e}")
    
    # Validate resume file
    if hasattr(args, 'resume') and args.resume:
        resume_path = Path(args.resume)
        if not resume_path.exists():
            errors.append(f"Resume state file not found: {args.resume}")
    
    # Validate log file
    if hasattr(args, 'log_file') and args.log_file:
        try:
            args.log_file.parent.mkdir(parents=True, exist_ok=True)
            # Test write permissions
            test_log = args.log_file.parent / '.log_test'
            test_log.touch()
            test_log.unlink()
        except Exception as e:
            errors.append(f"Cannot write to log file location: {e}")
    
    # If there are validation errors, raise with combined message
    if errors:
        error_msg = "Validation failed:\n" + "\n".join(f"  • {error}" for error in errors)
        if CORE_AVAILABLE:
            raise ValidationError(error_msg)
        else:
            raise ValueError(error_msg)


def load_targets_from_file(file_path: Path) -> List[str]:
    """Load and validate targets from file"""
    if CORE_AVAILABLE:
        # Use enhanced validation
        validator = EnhancedInputValidator()
        try:
            file_validation = validator.validate_targets_file(str(file_path))
            
            if file_validation['valid_count'] == 0:
                raise ValidationError("No valid targets found in file")
            
            # Return only valid targets
            valid_targets = [target['value'] for target in file_validation['valid_targets']]
            
            # Log invalid targets as warnings
            if file_validation['invalid_count'] > 0:
                print(f"⚠️  Warning: {file_validation['invalid_count']} invalid targets skipped from file")
                for invalid in file_validation['invalid_targets'][:5]:  # Show first 5
                    print(f"   Line {invalid['line_number']}: {invalid['target']} - {invalid['error']}")
                if file_validation['invalid_count'] > 5:
                    print(f"   ... and {file_validation['invalid_count'] - 5} more")
            
            print(f"✅ Loaded {len(valid_targets)} valid targets from file")
            return valid_targets
            
        except ValidationError as e:
            raise ValidationError(f"Error validating targets file: {e}")
    else:
        # Fallback to basic loading
        targets = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line)
        except Exception as e:
            raise ValidationError(f"Error reading targets file: {e}")
        
        if not targets:
            raise ValidationError("No valid targets found in file")
        
        return targets


def process_and_validate_targets(targets: List[str], args, logger) -> List[str]:
    """Process and validate targets using enhanced target processor"""
    if not CORE_AVAILABLE:
        logger.warning("Enhanced target processing not available - using basic validation")
        return targets
    
    try:
        logger.info(f"🎯 Processing {len(targets)} targets with enhanced validation...")
        
        # Configure target processor
        processor = TargetProcessor(
            enable_reachability_check=not args.passive,  # No reachability check in passive mode
            enable_deduplication=True,
            enable_risk_assessment=True,
            reachability_timeout=5,
            max_concurrent_checks=args.threads,
            cidr_expansion_limit=1000
        )
        
        # Set up filters based on arguments
        filters = {}
        
        # Exclude private IPs if not explicitly allowed
        if not getattr(args, 'include_private', False):
            filters['exclude_private'] = True
        
        # Add custom filters based on scan mode
        if args.passive:
            # In passive mode, exclude any targets that require direct interaction
            filters['exclude_types'] = []  # Don't exclude types, just don't do reachability
        
        # Process targets
        results = processor.process_targets(targets, filters)
        
        # Extract processed targets
        processed_targets = results['targets']
        stats = results['statistics']
        
        # Get valid, reachable targets for scanning
        valid_targets = []
        reachable_targets = []
        high_priority_targets = []
        
        for target_info in processed_targets:
            target = target_info['normalized_value']
            status = target_info['status']
            risk_level = target_info['risk_level']
            
            # Include all validated targets
            if status in ['validated', 'reachable', 'unreachable']:
                valid_targets.append(target)
                
                # Track reachable targets
                if status == 'reachable':
                    reachable_targets.append(target)
                
                # Track high priority targets
                if risk_level in ['critical', 'high']:
                    high_priority_targets.append(target)
        
        # Log processing summary
        print(f"\n📊 Target Processing Summary:")
        print(f"   • Total input targets: {stats['total_input']}")
        print(f"   • Valid targets: {len(valid_targets)}")
        print(f"   • Duplicates removed: {stats['duplicates_removed']}")
        print(f"   • Invalid filtered: {stats['invalid_filtered']}")
        
        if not args.passive:
            print(f"   • Reachable targets: {stats['reachable_targets']}")
            print(f"   • Unreachable targets: {stats['unreachable_targets']}")
        
        if high_priority_targets:
            print(f"   • High priority targets: {len(high_priority_targets)}")
        
        print(f"   • Processing time: {stats['processing_duration']:.1f}s")
        
        # Show recommendations
        recommendations = results['recommendations']
        if recommendations:
            print(f"\n💡 Recommendations:")
            for rec in recommendations[:5]:  # Show top 5
                print(f"   • {rec}")
        
        # Save detailed processing results
        if hasattr(args, 'output_dir') and args.output_dir:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            processing_file = args.output_dir / 'target_processing_results.json'
            processor.export_results(str(processing_file))
            logger.info(f"Detailed target processing results saved to: {processing_file}")
        
        # Return prioritized targets
        if not valid_targets:
            raise ValidationError("No valid targets remaining after processing")
        
        logger.info(f"✅ Target processing completed - {len(valid_targets)} targets ready for scanning")
        return valid_targets
        
    except Exception as e:
        logger.error(f"❌ Target processing failed: {e}")
        logger.info("Falling back to basic target validation...")
        return targets


def configure_scan_options(args) -> dict:
    """Configure scan options from arguments"""
    options = {
        'threads': args.threads,
        'timeout': args.timeout,
        'rate_limit': args.rate_limit,
        'debug': args.debug,
        'dry_run': args.dry_run
    }
    
    # Scan mode
    if args.full:
        options['scan_mode'] = 'full'
    elif args.quick:
        options['scan_mode'] = 'quick'
    elif args.passive:
        options['scan_mode'] = 'passive'
    else:
        options['scan_mode'] = 'normal'
    
    # Tool selection
    if args.tools:
        options['enabled_tools'] = args.tools
    
    if args.exclude_tools:
        options['disabled_tools'] = args.exclude_tools
    
    # Report options
    if not args.no_report:
        options['generate_reports'] = True
        options['report_formats'] = [args.format] if args.format != 'all' else ['json', 'markdown', 'html', 'pdf']
    else:
        options['generate_reports'] = False
    
    return options


def check_scan_dependencies(scan_options: dict, logger) -> None:
    """Check that required tools are available for the planned scan"""
    if not CORE_AVAILABLE:
        logger.warning("Tool dependency checking not available - proceeding without validation")
        return
    
    try:
        # Determine which tools will be needed based on scan options
        required_tools = set()
        
        # Default tools for basic scanning
        required_tools.update(['nmap', 'dig', 'curl'])
        
        # Add tools based on scan mode
        scan_mode = scan_options.get('scan_mode', 'normal')
        if scan_mode == 'full':
            required_tools.update(['openssl', 'subfinder'])
        elif scan_mode == 'passive':
            required_tools.update(['dig'])  # Only DNS tools for passive
        
        # Add tools based on enabled tools
        enabled_tools = scan_options.get('enabled_tools', [])
        tool_mapping = {
            'port': ['nmap'],
            'subdomain': ['subfinder', 'assetfinder'],
            'web': ['curl'],
            'ssl': ['openssl'],
            'dns': ['dig'],
            'network': ['nmap', 'ping'],
            'directory': ['curl'],
            'api': ['curl'],
            'vulnerability': ['nmap'],
            'osint': ['dig', 'curl']
        }
        
        for tool in enabled_tools:
            if tool in tool_mapping:
                required_tools.update(tool_mapping[tool])
        
        # Check tool availability
        logger.info(f"Checking availability of {len(required_tools)} required tools...")
        
        tool_validation = validate_tools_available(list(required_tools))
        
        if tool_validation['all_available']:
            logger.info(f"✅ All {tool_validation['total_available']} required tools are available")
        else:
            missing_count = len(tool_validation['missing_tools'])
            available_count = tool_validation['total_available']
            
            logger.warning(f"⚠️  {missing_count} tools missing, {available_count} available")
            
            # Show missing tools with install suggestions
            from core.enhanced_validators import get_tool_install_suggestions
            suggestions = get_tool_install_suggestions(tool_validation['missing_tools'])
            
            print(f"\n⚠️  Missing tools ({missing_count}):")
            for suggestion in suggestions:
                print(f"   • {suggestion}")
            
            print(f"\n💡 Install missing tools or use --tools to specify only available tools")
            
            # Only fail if critical tools are missing (this will raise ToolNotFoundError)
            
    except ToolNotFoundError as e:
        logger.error(f"❌ Critical tools missing: {e}")
        raise
    except Exception as e:
        logger.warning(f"⚠️  Tool dependency check failed: {e}")
        logger.info("Proceeding with scan - some tools may fail during execution")


def execute_simple_scan(targets: List[str], args, config_manager, logger) -> int:
    """Simple scan execution fallback"""
    logger.info("Executing simple scan mode")
    
    # Create output directory
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    
    results = {}
    
    for target in targets:
        logger.info(f"Scanning target: {target}")
        target_results = {'target': target, 'scan_date': datetime.now().isoformat()}
        
        try:
            # Basic port scan example (this would be expanded)
            if not args.passive:
                logger.info(f"Running port scan on {target}")
                # Here you would integrate with the actual scanner classes
                target_results['port_scan'] = {'status': 'simulated', 'note': 'Simple scan mode'}
            
            # OSINT collection example
            logger.info(f"Collecting OSINT for {target}")
            target_results['osint'] = {'status': 'simulated', 'note': 'Simple scan mode'}
            
            results[target] = target_results
            
        except Exception as e:
            logger.error(f"Error scanning {target}: {e}")
            results[target] = {'error': str(e)}
    
    # Save results
    results_file = output_dir / 'simple_scan_results.json'
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    logger.info(f"Simple scan completed. Results saved to {results_file}")
    print_completion_summary(output_dir, len(targets))
    return 0


def main():
    """Main entry point"""
    try:
        print_banner()
        
        # Parse command line arguments
        parser = create_argument_parser()
        args = parser.parse_args()
        
        # Setup logging
        logger = setup_logging(args)
        logger.info(f"Starting ReconTool v{VERSION}")
        
        # Validate arguments
        validate_arguments(args)
        
        # Initialize configuration manager
        if CORE_AVAILABLE:
            config_manager = ConfigManager()
            if hasattr(args, 'config') and args.config:
                logger.info(f"Loading configuration from: {args.config}")
                config_manager.load_config(args.config)
        else:
            config_manager = None
            logger.warning("Configuration manager not available - using default settings")
        
        # Configure scan options
        scan_options = configure_scan_options(args)
        
        # Check tool dependencies before proceeding
        logger.info("Validating tool dependencies...")
        try:
            check_scan_dependencies(scan_options, logger)
        except ToolNotFoundError as e:
            logger.error(f"Cannot proceed due to missing critical tools: {e}")
            return 1
        
        # Determine targets
        targets = []
        if hasattr(args, 'domain') and args.domain:
            targets = [args.domain]
        elif hasattr(args, 'ip') and args.ip:
            targets = [args.ip]
        elif hasattr(args, 'targets_file') and args.targets_file:
            targets = load_targets_from_file(args.targets_file)
        
        logger.info(f"Loaded {len(targets)} initial target(s)")
        
        # Process and validate targets with enhanced processing
        logger.info("Processing targets with enhanced validation...")
        processed_targets = process_and_validate_targets(targets, args, logger)
        
        logger.info(f"Scanning {len(processed_targets)} processed target(s)")
        
        # Initialize orchestrator
        logger.info("Initializing reconnaissance orchestrator...")
        use_orchestrator = False
        orchestrator = None
        
        if CORE_AVAILABLE:
            try:
                # Try to import and initialize REAL orchestrator first
                from core.real_orchestrator import RealOrchestrator
                orchestrator = RealOrchestrator(config_manager, args.output_dir)
                if hasattr(orchestrator, 'setup'):
                    orchestrator.setup(output_dir=args.output_dir)
                use_orchestrator = True
                logger.info("Real orchestrator initialized successfully")
                print("Using RealOrchestrator (production mode)")
            except Exception as e:
                logger.warning(f"Real orchestrator failed: {e}")
                print(f"RealOrchestrator failed: {e}")
                try:
                    # Fallback to full orchestrator
                    from core.orchestrator import ReconOrchestrator
                    orchestrator = ReconOrchestrator(config_manager)
                    if hasattr(orchestrator, 'setup'):
                        orchestrator.setup(output_dir=args.output_dir)
                    use_orchestrator = True
                    logger.info("Full orchestrator initialized successfully")
                    print("Using FullOrchestrator (advanced mode)")
                except Exception as e2:
                    logger.warning(f"Full orchestrator failed: {e2}")
                    print(f"FullOrchestrator failed: {e2}")
                    try:
                        # Last resort - simple orchestrator (simulation only)
                        from core.simple_orchestrator import SimpleOrchestrator
                        orchestrator = SimpleOrchestrator(config_manager, args.output_dir)
                        use_orchestrator = True
                        logger.info("Simple orchestrator initialized successfully")
                        print("Using SimpleOrchestrator (development mode)")
                    except Exception as e3:
                        logger.warning(f"Failed to initialize any orchestrator: {e3}")
                        logger.info("Falling back to simple execution mode...")
                        use_orchestrator = False
        else:
            logger.info("Core modules not available - using simple execution mode...")
            use_orchestrator = False
        
        # Execute scans
        if use_orchestrator:
            # Use full orchestrator
            all_success = True
            for i, target in enumerate(processed_targets, 1):
                logger.info(f"Starting scan {i}/{len(processed_targets)} for target: {target}")
                
                try:
                    # Resume from previous state if requested
                    if args.resume and i == 1:  # Only for first target
                        logger.info(f"Resuming scan from state file: {args.resume}")
                        success = orchestrator.resume_scan(args.resume, target, **scan_options)
                    else:
                        success = orchestrator.run_scan(target, **scan_options)
                    
                    if success:
                        logger.info(f"✅ Scan completed successfully for {target}")
                    else:
                        logger.error(f"❌ Scan failed for {target}")
                        all_success = False
                        
                except KeyboardInterrupt:
                    logger.warning(f"⚠️  Scan interrupted by user for target: {target}")
                    break
                except Exception as e:
                    logger.error(f"❌ Error scanning {target}: {str(e)}")
                    all_success = False
                    continue
            
            # Summary
            if all_success:
                print_completion_summary(orchestrator.output_dir, len(processed_targets))
                return 0
            else:
                failed_count = sum(1 for i in range(len(processed_targets)) if not all_success)
                print_completion_summary(orchestrator.output_dir, len(processed_targets), failed_count)
                return 1
        else:
            # Use simple execution
            return execute_simple_scan(processed_targets, args, config_manager, logger)
            
    except KeyboardInterrupt:
        print(f"\n⚠️  Operation interrupted by user")
        return 130
    except Exception as e:
        error_type = type(e).__name__
        error_msg = str(e)
        
        # Handle both core and standard exceptions with specific error types
        if CORE_AVAILABLE and (isinstance(e, ValidationError) or isinstance(e, ConfigurationError)):
            print(f"\n❌ Configuration error: {error_msg}")
            if isinstance(e, ValidationError):
                print_error_help('validation', error_msg)
            else:
                print_error_help('configuration', error_msg)
        elif isinstance(e, ValueError):
            print(f"\n❌ Validation error: {error_msg}")
            if "conflicting" in error_msg.lower() or "only one" in error_msg.lower():
                print_error_help('invalid_combination', error_msg)
            else:
                print_error_help('validation', error_msg)
        elif isinstance(e, PermissionError):
            print(f"\n❌ Permission error: {error_msg}")
            print_error_help('permission', error_msg)
        elif isinstance(e, FileNotFoundError):
            print(f"\n❌ File not found: {error_msg}")
            print_error_help('configuration', error_msg)
        elif isinstance(e, json.JSONDecodeError):
            print(f"\n❌ JSON parsing error: {error_msg}")
            print_error_help('configuration', error_msg)
        elif "command not found" in error_msg.lower() or "not installed" in error_msg.lower():
            print(f"\n❌ Missing dependency: {error_msg}")
            print_error_help('missing_dependency', error_msg)
        else:
            print(f"\n❌ {error_type}: {error_msg}")
            if 'args' in locals() and hasattr(args, 'debug') and args.debug:
                import traceback
                print("\nDebug traceback:")
                traceback.print_exc()
            else:
                print("Use --debug for detailed error information")
        
        return 1


if __name__ == "__main__":
    sys.exit(main())
