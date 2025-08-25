"""
ReconTool Reporting CLI
Command-line interface for generating reports from scan results
"""

import argparse
import json
import sys
from pathlib import Path

from .report_manager import ReportManager
from ..core.exceptions import ScanError


def main():
    """Main entry point for the reporting CLI"""
    parser = argparse.ArgumentParser(
        description='Generate reports from ReconTool scan results',
        prog='python3 -m recon_tool.reporting'
    )
    
    parser.add_argument(
        'results_file',
        nargs='?',  # Make optional
        help='Path to scan results JSON file'
    )
    
    parser.add_argument(
        '--target',
        help='Target name for the report'
    )
    
    parser.add_argument(
        '--output-dir',
        default='.',
        help='Output directory for reports (default: current directory)'
    )
    
    parser.add_argument(
        '--formats',
        nargs='+',
        choices=['json', 'markdown', 'html', 'pdf'],
        default=['json', 'markdown', 'html'],
        help='Report formats to generate (default: json markdown html)'
    )
    
    parser.add_argument(
        '--config',
        help='Configuration file path'
    )
    
    parser.add_argument(
        '--list-formats',
        action='store_true',
        help='List available report formats and exit'
    )
    
    parser.add_argument(
        '--cleanup',
        type=int,
        metavar='DAYS',
        help='Clean up old reports older than specified days'
    )
    
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress non-error output'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Set up logging
    import logging
    log_level = logging.ERROR if args.quiet else logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        # Initialize report manager
        config = {}
        if args.config:
            config_path = Path(args.config)
            if config_path.exists():
                with open(config_path, 'r') as f:
                    config = json.load(f)
        
        output_dir = Path(args.output_dir)
        report_manager = ReportManager(output_dir, config)
        
        # Handle list formats option
        if args.list_formats:
            available_formats = report_manager.get_available_formats()
            print("Available report formats:")
            for fmt in available_formats:
                print(f"  • {fmt}")
            return 0
        
        # Handle cleanup option
        if args.cleanup is not None:
            if not args.quiet:
                print(f"Cleaning up reports older than {args.cleanup} days...")
            removed_count = report_manager.cleanup_old_reports(args.cleanup)
            if not args.quiet:
                print(f"Removed {removed_count} old report files")
            return 0
        
        # Validate required arguments for normal operation
        if not args.results_file:
            print("Error: results_file is required", file=sys.stderr)
            return 1
        
        if not args.target:
            print("Error: --target is required", file=sys.stderr)
            return 1
        
        # Validate results file
        results_file = Path(args.results_file)
        if not results_file.exists():
            print(f"Error: Results file not found: {results_file}", file=sys.stderr)
            return 1
        
        if not results_file.suffix.lower() == '.json':
            print(f"Error: Results file must be a JSON file: {results_file}", file=sys.stderr)
            return 1
        
        # Filter requested formats to only available ones
        available_formats = report_manager.get_available_formats()
        requested_formats = args.formats
        valid_formats = [f for f in requested_formats if f in available_formats]
        invalid_formats = [f for f in requested_formats if f not in available_formats]
        
        if invalid_formats:
            print(f"Warning: Unavailable formats ignored: {', '.join(invalid_formats)}", file=sys.stderr)
        
        if not valid_formats:
            print("Error: No valid report formats specified", file=sys.stderr)
            return 1
        
        # Generate reports
        if not args.quiet:
            print(f"Generating reports for target: {args.target}")
            print(f"Results file: {results_file}")
            print(f"Output directory: {output_dir}")
            print(f"Formats: {', '.join(valid_formats)}")
            print()
        
        generated_reports = report_manager.generate_reports_from_file(
            results_file, args.target, valid_formats
        )
        
        # Display results
        if generated_reports:
            if not args.quiet:
                print("✅ Report generation completed successfully!")
                print()
                
                # Get and display summary
                summary = report_manager.get_report_summary(generated_reports)
                print(f"📊 Generated {summary['total_reports']} reports:")
                
                for format_name, file_info in summary['files'].items():
                    print(f"  • {format_name.upper()}: {file_info['path']} ({file_info['size_human']})")
                
                print(f"\n📁 Total size: {summary['total_size_human']}")
                print(f"📁 Reports directory: {output_dir / 'reports'}")
        else:
            print("❌ No reports were generated", file=sys.stderr)
            return 1
        
        return 0
        
    except ScanError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
