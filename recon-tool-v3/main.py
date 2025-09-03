#!/usr/bin/env python3
"""
Recon Tool v3.0 - Clean Architecture
Professional reconnaissance toolkit with modular design
Ultra-minimal entry point - just routing
"""

def main():
    """Ultra-minimal entry point - just routing"""
    import sys
    from pathlib import Path
    
    # Add project root to Python path
    project_root = Path(__file__).parent
    sys.path.insert(0, str(project_root))
    
    try:
        # Parse basic command line to determine mode
        if '--interactive' in sys.argv or '-I' in sys.argv:
            from ui.interactive import run_interactive_mode
            return run_interactive_mode()
        else:
            from ui.cli import run_cli_mode
            return run_cli_mode(sys.argv[1:])
            
    except KeyboardInterrupt:
        print("\n👋 Operation cancelled by user")
        return 130
    except Exception as e:
        print(f"❌ Error: {e}")
        print("Use --help for usage information")
        return 1

if __name__ == "__main__":
    exit(main())
