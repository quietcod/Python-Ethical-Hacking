#!/usr/bin/env python3
"""
Recon Tool Launcher
Easy launcher for the reconnaissance tool with interactive mode
"""

import sys
import os
from pathlib import Path

def main():
    """Main launcher function"""
    print("🎯 Recon Tool Launcher")
    print("=" * 40)
    
    # Add current directory to Python path
    current_dir = Path(__file__).parent
    sys.path.insert(0, str(current_dir))
    
    try:
        # Check if we should launch interactive mode by default
        if len(sys.argv) == 1:
            print("🚀 No arguments provided - launching interactive mode...")
            print("💡 Tip: Use --help to see all command-line options")
            sys.argv.append('--interactive')
        
        # Import and run the main application
        from recon_tool.main import main as recon_main
        recon_main()
        
    except KeyboardInterrupt:
        print("\n⚠️  Interrupted by user. Exiting...")
        sys.exit(130)
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Make sure all required modules are available")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
