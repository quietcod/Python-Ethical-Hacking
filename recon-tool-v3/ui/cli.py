#!/usr/bin/env python3
"""
CLI Interface - Clean Architecture
Command-line interface for recon tool
"""

import argparse
import sys
from pathlib import Path

def create_parser():
    """Create and configure argument parser"""
    parser = argparse.ArgumentParser(
        prog='recon-tool-v3',
        description='Professional reconnaissance toolkit with modular design',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t example.com --profile quick
  %(prog)s -t example.com --tools nmap,subfinder
  %(prog)s -t example.com --interactive
  %(prog)s --list-tools
        """
    )
    
    # Target specification
    parser.add_argument('-t', '--target', 
                       help='Target domain, IP, or URL to scan')
    
    # Scan configuration
    parser.add_argument('-p', '--profile', 
                       choices=['quick', 'full', 'passive', 'web_focused', 
                               'network_focused', 'osint_focused'],
                       help='Predefined scan profile')
    
    parser.add_argument('--tools',
                       help='Comma-separated list of specific tools to run')
    
    # Output options
    parser.add_argument('-o', '--output',
                       help='Output directory for results')
    
    parser.add_argument('--format',
                       choices=['json', 'html', 'markdown', 'pdf'],
                       default='json',
                       help='Output format (default: json)')
    
    # Mode options
    parser.add_argument('-I', '--interactive',
                       action='store_true',
                       help='Run in interactive mode')
    
    parser.add_argument('--list-tools',
                       action='store_true', 
                       help='List all available tools')
    
    parser.add_argument('--list-profiles',
                       action='store_true',
                       help='List all scan profiles')
    
    # Verbosity and logging
    parser.add_argument('-v', '--verbose',
                       action='store_true',
                       help='Enable verbose output')
    
    parser.add_argument('--debug',
                       action='store_true',
                       help='Enable debug logging')
    
    return parser

def run_cli_mode(args):
    """Run in CLI mode with command line arguments"""
    parser = create_parser()
    parsed_args = parser.parse_args(args)
    
    # Handle informational commands
    if parsed_args.list_tools:
        return list_tools()
    
    if parsed_args.list_profiles:
        return list_profiles()
    
    # Switch to interactive mode if requested
    if parsed_args.interactive:
        from ui.interactive import run_interactive_mode
        return run_interactive_mode()
    
    # Validate required arguments
    if not parsed_args.target:
        print("❌ Error: Target is required for CLI mode")
        print("Use --help for usage information or --interactive for interactive mode")
        return 1
    
    # Execute scan
    return execute_scan(parsed_args)

def list_tools():
    """List all available tools"""
    try:
        from tools import TOOL_REGISTRY
        
        print("🔧 Available Tools:")
        print("=" * 50)
        
        for category, tools in TOOL_REGISTRY.items():
            print(f"\n📁 {category.upper()}:")
            for tool_name, tool_info in tools.items():
                print(f"  • {tool_name:<12} - {tool_info['description']}")
        
        return 0
    except Exception as e:
        print(f"❌ Error listing tools: {e}")
        return 1

def list_profiles():
    """List all scan profiles"""
    try:
        from tools import SCAN_PROFILES
        
        print("🎯 Available Scan Profiles:")
        print("=" * 50)
        
        for profile_name, profile_info in SCAN_PROFILES.items():
            print(f"\n📋 {profile_name.upper()}:")
            print(f"   Description: {profile_info['description']}")
            print(f"   Tools: {', '.join(profile_info['tools'])}")
        
        return 0
    except Exception as e:
        print(f"❌ Error listing profiles: {e}")
        return 1

def execute_scan(args):
    """Execute reconnaissance scan with given arguments"""
    try:
        from core.orchestrator import ReconOrchestrator
        from core.config import load_config
        from core.logger import setup_logger
        
        # Setup logging
        log_level = 'DEBUG' if args.debug else ('INFO' if args.verbose else 'WARNING')
        logger = setup_logger(level=log_level)
        
        # Load configuration
        config = load_config()
        
        # Create orchestrator
        orchestrator = ReconOrchestrator(config, logger)
        
        # Execute scan
        print(f"🎯 Starting reconnaissance of: {args.target}")
        
        scan_params = {
            'target': args.target,
            'profile': args.profile,
            'tools': args.tools.split(',') if args.tools else None,
            'output_dir': args.output,
            'output_format': args.format,
            'verbose': args.verbose
        }
        
        results = orchestrator.execute_scan(scan_params)
        
        print("✅ Reconnaissance completed successfully!")
        return 0
        
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        return 1
