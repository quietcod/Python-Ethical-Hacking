#!/usr/bin/env python3
"""
Recon Tool v3.0 - Clean Architecture
Professional reconnaissance toolkit with modular design
Ultra-minimal entry point - just routing
"""

def main():
    """Entry point - Interactive UI by default, CLI with --cli flag"""
    import sys
    from pathlib import Path
    
    # Add project root to Python path
    project_root = Path(__file__).parent
    sys.path.insert(0, str(project_root))
    
    try:
        # Handle help requests
        if '--help' in sys.argv or '-h' in sys.argv:
            if '--cli' in sys.argv or '-c' in sys.argv:
                # CLI help
                args = [arg for arg in sys.argv[1:] if arg not in ['--cli', '-c']]
                from ui.cli import run_cli_mode
                return run_cli_mode(args)
            else:
                # Show general help with emphasis on interactive mode
                print("🔍 Recon Tool v3.0 - Professional Reconnaissance Toolkit")
                print("=" * 60)
                print()
                print("🎯 DEFAULT MODE: Interactive LinUtil-style Interface")
                print("   Simply run: python main.py")
                print()
                print("🖥️  INTERACTIVE FEATURES:")
                print("   • Two-panel visual interface")
                print("   • Real-time scan output")
                print("   • Automatic PDF report generation")
                print("   • Tool categorization and selection")
                print("   • Live progress monitoring")
                print()
                print("⌨️  NAVIGATION:")
                print("   • ↑↓ arrows: Navigate tools/options")
                print("   • ←→ arrows: Switch panels")
                print("   • Enter: Select • 't': Set target • 's': Start scan")
                print("   • 'c': Clear output • 'q': Quit")
                print()
                print("💻 COMMAND LINE MODE:")
                print("   Use --cli flag for traditional command-line interface")
                print("   Examples:")
                print("     python main.py --cli -t example.com --profile quick")
                print("     python main.py --cli --list-tools")
                print("     python main.py --cli --help  # CLI-specific help")
                print()
                print("🚀 Get started: python main.py")
                return 0
        
        # Parse basic command line to determine mode
        # Default to interactive mode, use --cli for command line
        if '--cli' in sys.argv or '-c' in sys.argv:
            # Remove the --cli flag before passing to CLI mode
            args = [arg for arg in sys.argv[1:] if arg not in ['--cli', '-c']]
            from ui.cli import run_cli_mode
            return run_cli_mode(args)
        else:
            # Default to interactive mode
            from ui.interactive import run_interactive_mode
            return run_interactive_mode()
            
    except KeyboardInterrupt:
        print("\n👋 Operation cancelled by user")
        return 130
    except Exception as e:
        print(f"❌ Error: {e}")
        print("Use --help for usage information")
        return 1

if __name__ == "__main__":
    exit(main())
