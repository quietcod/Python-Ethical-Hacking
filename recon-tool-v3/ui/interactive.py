#!/usr/bin/env python3
"""
Interactive Menu System - Clean Architecture
Professional interactive interface for reconnaissance
"""

def run_interactive_mode():
    """Handle interactive menu mode"""
    print("🔍 Recon Tool v3.0 - Interactive Mode")
    print("=" * 50)
    
    try:
        while True:
            print("\n📋 Main Menu:")
            print("1. 🎯 Quick Scan")
            print("2. 🔧 Custom Scan")
            print("3. 📁 List Tools")
            print("4. 📊 View Profiles")
            print("5. ❓ Help")
            print("6. 🚪 Exit")
            
            choice = input("\nSelect option (1-6): ").strip()
            
            if choice == '1':
                return run_quick_scan()
            elif choice == '2':
                return run_custom_scan()
            elif choice == '3':
                list_tools_interactive()
            elif choice == '4':
                list_profiles_interactive()
            elif choice == '5':
                show_help()
            elif choice == '6':
                print("👋 Goodbye!")
                return 0
            else:
                print("❌ Invalid option. Please select 1-6.")
                
    except KeyboardInterrupt:
        print("\n👋 Interactive mode cancelled")
        return 130
    except Exception as e:
        print(f"❌ Error in interactive mode: {e}")
        return 1

def run_quick_scan():
    """Run a quick reconnaissance scan"""
    print("\n🎯 Quick Scan Mode")
    print("-" * 30)
    
    target = input("Enter target (domain/IP): ").strip()
    if not target:
        print("❌ Target cannot be empty")
        return 1
    
    try:
        from core.orchestrator import ReconOrchestrator
        from core.config import load_config
        from core.logger import setup_logger
        
        # Setup components
        logger = setup_logger(level='INFO')
        config = load_config()
        orchestrator = ReconOrchestrator(config, logger)
        
        # Execute quick scan
        print(f"🚀 Starting quick scan of: {target}")
        
        scan_params = {
            'target': target,
            'profile': 'quick',
            'output_format': 'json',
            'verbose': True
        }
        
        results = orchestrator.execute_scan(scan_params)
        print("✅ Quick scan completed!")
        return 0
        
    except Exception as e:
        print(f"❌ Quick scan failed: {e}")
        return 1

def run_custom_scan():
    """Run a custom reconnaissance scan with user choices"""
    print("\n🔧 Custom Scan Mode")
    print("-" * 30)
    
    target = input("Enter target (domain/IP): ").strip()
    if not target:
        print("❌ Target cannot be empty")
        return 1
    
    # Show available profiles
    print("\n📊 Available Profiles:")
    profiles = ['quick', 'full', 'passive', 'web_focused', 'network_focused', 'osint_focused']
    for i, profile in enumerate(profiles, 1):
        print(f"{i}. {profile}")
    
    profile_choice = input("\nSelect profile (1-6) or press Enter for custom tools: ").strip()
    
    selected_profile = None
    selected_tools = None
    
    if profile_choice and profile_choice.isdigit():
        idx = int(profile_choice) - 1
        if 0 <= idx < len(profiles):
            selected_profile = profiles[idx]
            print(f"Selected profile: {selected_profile}")
    
    if not selected_profile:
        print("\n🔧 Available Tools:")
        print("nmap, masscan, subfinder, amass, nikto, gobuster, httpx, nuclei")
        tools_input = input("Enter tools (comma-separated): ").strip()
        if tools_input:
            selected_tools = [tool.strip() for tool in tools_input.split(',')]
    
    try:
        from core.orchestrator import ReconOrchestrator
        from core.config import load_config
        from core.logger import setup_logger
        
        # Setup components
        logger = setup_logger(level='INFO')
        config = load_config()
        orchestrator = ReconOrchestrator(config, logger)
        
        # Execute custom scan
        print(f"🚀 Starting custom scan of: {target}")
        
        scan_params = {
            'target': target,
            'profile': selected_profile,
            'tools': selected_tools,
            'output_format': 'json',
            'verbose': True
        }
        
        results = orchestrator.execute_scan(scan_params)
        print("✅ Custom scan completed!")
        return 0
        
    except Exception as e:
        print(f"❌ Custom scan failed: {e}")
        return 1

def list_tools_interactive():
    """Display available tools in interactive mode"""
    try:
        from tools import TOOL_REGISTRY
        
        print("\n🔧 Available Tools:")
        print("=" * 50)
        
        for category, tools in TOOL_REGISTRY.items():
            print(f"\n📁 {category.upper()}:")
            for tool_name, tool_info in tools.items():
                print(f"  • {tool_name:<12} - {tool_info['description']}")
    
    except Exception as e:
        print(f"❌ Error displaying tools: {e}")

def list_profiles_interactive():
    """Display scan profiles in interactive mode"""
    try:
        from tools import SCAN_PROFILES
        
        print("\n🎯 Scan Profiles:")
        print("=" * 50)
        
        for profile_name, profile_info in SCAN_PROFILES.items():
            print(f"\n📋 {profile_name.upper()}:")
            print(f"   Description: {profile_info['description']}")
            print(f"   Tools: {', '.join(profile_info['tools'])}")
    
    except Exception as e:
        print(f"❌ Error displaying profiles: {e}")

def show_help():
    """Display help information"""
    print("\n❓ Help - Recon Tool v3.0")
    print("=" * 50)
    print("""
🎯 QUICK SCAN:
   Fast reconnaissance using nmap, subfinder, and httpx
   Perfect for initial target assessment (5-10 minutes)

🔧 CUSTOM SCAN:
   Choose specific scan profile or individual tools
   Flexible configuration for targeted reconnaissance

📁 TOOLS:
   20+ professional security tools across 6 categories:
   • Network: nmap, masscan
   • Web: nikto, gobuster, dirb, wfuzz, httpx, katana, aquatone
   • OSINT: subfinder, amass, theharvester, waybackurls, shodan, censys
   • DNS: dnsrecon, fierce
   • SSL: sslscan, testssl
   • Vulnerability: nuclei

📊 PROFILES:
   • quick: Fast scan (3 tools, 5-10 min)
   • full: Comprehensive scan (9 tools, 15-30 min)
   • passive: OSINT-only (no direct target contact)
   • web_focused: Web application security
   • network_focused: Infrastructure assessment
   • osint_focused: Intelligence gathering

🚀 TIPS:
   • Start with quick scan for overview
   • Use passive profile for stealth reconnaissance
   • Combine multiple tools for comprehensive assessment
   • Check output directory for detailed results
    """)

def get_user_input(prompt, default=None):
    """Get user input with optional default value"""
    # TODO: Implement enhanced input handling
    pass

class InteractiveMenu:
    """Clean interactive menu implementation"""
    
    def __init__(self):
        # TODO: Initialize menu system
        pass
    
    def display_main_menu(self):
        # TODO: Show main menu options
        pass
    
    def get_user_selection(self):
        # TODO: Handle user input
        pass
