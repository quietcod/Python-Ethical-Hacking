#!/usr/bin/env python3
"""
Interactive Menu System for Recon Tool
Provides user-friendly interface for scan type selection
"""

import os
import sys
from typing import Dict, List, Tuple, Optional
from pathlib import Path


class InteractiveMenu:
    """Interactive menu system for scan configuration"""
    
    def __init__(self):
        self.scan_categories = {
            "1": {
                "name": "🌐 Network Reconnaissance",
                "description": "Network-level scanning and discovery",
                "tools": {
                    "1": ("Port Scanning", "port", "Comprehensive port scanning with nmap/masscan"),
                    "2": ("Network Discovery", "network", "Host discovery and network topology mapping"),
                    "3": ("DNS Analysis", "dns", "DNS enumeration and zone transfer testing"),
                    "4": ("Service Detection", "service", "Service version detection and banner grabbing"),
                    "5": ("Network Security", "network_security", "Network security assessment and analysis"),
                    "all": ("Run All Network Scans", "network_all", "Execute all network reconnaissance tools")
                }
            },
            "2": {
                "name": "🕸️  Web Application Testing",
                "description": "Web application security assessment",
                "tools": {
                    "1": ("Technology Detection", "web_tech", "Technology stack and CMS identification"),
                    "2": ("Directory Discovery", "directory", "Directory and file brute-forcing"),
                    "3": ("Web Vulnerabilities", "web_vuln", "Web vulnerability scanning with nikto"),
                    "4": ("SSL/TLS Analysis", "ssl", "SSL/TLS security assessment"),
                    "5": ("API Testing", "api", "REST/GraphQL API security testing"),
                    "6": ("Security Headers", "headers", "HTTP security headers analysis"),
                    "all": ("Run All Web Scans", "web_all", "Execute all web application tests")
                }
            },
            "3": {
                "name": "🔍 OSINT & Intelligence",
                "description": "Open Source Intelligence gathering",
                "tools": {
                    "1": ("Subdomain Enumeration", "subdomain", "Comprehensive subdomain discovery"),
                    "2": ("Search Engine Intel", "search_intel", "Google dorking and search intelligence"),
                    "3": ("Social Media Intel", "social_intel", "Social media and public information gathering"),
                    "4": ("Certificate Transparency", "cert_transparency", "SSL certificate monitoring"),
                    "5": ("Breach Database", "breach_check", "Credential breach database checking"),
                    "6": ("Wayback Analysis", "wayback", "Historical website analysis"),
                    "all": ("Run All OSINT", "osint_all", "Execute all intelligence gathering tools")
                }
            },
            "4": {
                "name": "🛡️  Security Assessment",
                "description": "Comprehensive security vulnerability testing",
                "tools": {
                    "1": ("Vulnerability Scanning", "vulnerability", "Automated vulnerability detection"),
                    "2": ("Authentication Testing", "auth_test", "Authentication and authorization testing"),
                    "3": ("Input Validation", "input_validation", "Input validation and injection testing"),
                    "4": ("Configuration Analysis", "config_analysis", "Security configuration assessment"),
                    "5": ("Compliance Testing", "compliance", "OWASP/NIST compliance checking"),
                    "all": ("Run All Security Tests", "security_all", "Execute comprehensive security assessment")
                }
            },
            "5": {
                "name": "📸 Visual & Documentation",
                "description": "Visual reconnaissance and documentation",
                "tools": {
                    "1": ("Screenshot Capture", "screenshot", "Automated website screenshots"),
                    "2": ("Visual Analysis", "visual_analysis", "Visual website analysis and comparison"),
                    "3": ("Report Generation", "reporting", "Comprehensive report generation"),
                    "all": ("Run All Visual Tools", "visual_all", "Execute all visual reconnaissance tools")
                }
            }
        }
        
        self.scan_modes = {
            "1": ("🏃 Quick Scan", "quick", "Fast reconnaissance (5-10 minutes)"),
            "2": ("🔍 Full Scan", "full", "Comprehensive assessment (15-30 minutes)"),
            "3": ("🕵️  Passive Scan", "passive", "OSINT only, no direct target contact"),
            "4": ("🎯 Custom Scan", "custom", "Select specific tools and categories")
        }
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_header(self, title: str):
        """Print formatted header"""
        width = 80
        print("=" * width)
        print(f"{title:^{width}}")
        print("=" * width)
    
    def print_section_header(self, title: str):
        """Print section header"""
        print(f"\n{'='*20} {title} {'='*20}")
    
    def display_main_menu(self) -> str:
        """Display main scan mode selection menu"""
        self.clear_screen()
        self.print_header("🎯 RECON TOOL - INTERACTIVE MODE")
        
        print("""
Welcome to the interactive reconnaissance toolkit!
This guided interface will help you configure and run comprehensive security scans.

🎯 Quick Start Tips:
• Choose 'Quick Scan' for fast reconnaissance (5-10 minutes)
• Choose 'Full Scan' for comprehensive assessment (15-30 minutes)  
• Choose 'Passive Scan' for OSINT-only (no direct target contact)
• Choose 'Custom Scan' to select specific tools and categories
        """)
        
        print("\n🚀 Select Scan Mode:")
        print("-" * 50)
        
        for key, (name, mode, description) in self.scan_modes.items():
            print(f"  {key}. {name}")
            print(f"     {description}")
            print()
        
        print("  0. Exit")
        print("-" * 50)
        
        while True:
            choice = input("\n📝 Enter your choice (0-4): ").strip()
            if choice in ["0", "1", "2", "3", "4"]:
                return choice
            print("❌ Invalid choice. Please enter 0-4.")
    
    def display_category_menu(self) -> List[str]:
        """Display category selection menu for custom scan"""
        self.clear_screen()
        self.print_header("🎯 SELECT SCAN CATEGORIES")
        
        print("\n🔧 Available Scan Categories:")
        print("-" * 60)
        
        for key, category in self.scan_categories.items():
            print(f"  {key}. {category['name']}")
            print(f"     {category['description']}")
            print()
        
        print("  all. Run All Categories")
        print("  0. Back to Main Menu")
        print("-" * 60)
        
        selected_categories = []
        
        while True:
            print(f"\n📋 Selected categories: {', '.join(selected_categories) if selected_categories else 'None'}")
            choice = input("📝 Enter category number (or 'done' to continue, 'all' for everything): ").strip().lower()
            
            if choice == "0":
                return []
            elif choice == "done":
                if selected_categories:
                    return selected_categories
                else:
                    print("❌ Please select at least one category.")
            elif choice == "all":
                return list(self.scan_categories.keys())
            elif choice in self.scan_categories:
                if choice not in selected_categories:
                    selected_categories.append(choice)
                    print(f"✅ Added: {self.scan_categories[choice]['name']}")
                else:
                    print(f"⚠️  Category already selected: {self.scan_categories[choice]['name']}")
            else:
                print("❌ Invalid choice. Please enter a valid category number.")
    
    def display_tools_menu(self, category_key: str) -> List[str]:
        """Display tools menu for a specific category"""
        category = self.scan_categories[category_key]
        
        self.clear_screen()
        self.print_header(f"🔧 {category['name']} - TOOL SELECTION")
        
        print(f"\n📋 Category: {category['description']}")
        print("-" * 60)
        
        for key, (name, tool_id, description) in category['tools'].items():
            if key != "all":
                print(f"  {key}. {name}")
                print(f"     {description}")
                print()
        
        print(f"  all. {category['tools']['all'][0]}")
        print(f"       {category['tools']['all'][2]}")
        print()
        print("  0. Back to Category Selection")
        print("-" * 60)
        
        selected_tools = []
        
        while True:
            print(f"\n📋 Selected tools: {', '.join(selected_tools) if selected_tools else 'None'}")
            choice = input("📝 Enter tool number (or 'done' to continue, 'all' for everything): ").strip().lower()
            
            if choice == "0":
                return []
            elif choice == "done":
                if selected_tools:
                    return selected_tools
                else:
                    print("❌ Please select at least one tool.")
            elif choice == "all":
                return [category['tools']['all'][1]]  # Return the "all" tool identifier
            elif choice in category['tools'] and choice != "all":
                tool_id = category['tools'][choice][1]
                if tool_id not in selected_tools:
                    selected_tools.append(tool_id)
                    print(f"✅ Added: {category['tools'][choice][0]}")
                else:
                    print(f"⚠️  Tool already selected: {category['tools'][choice][0]}")
            else:
                print("❌ Invalid choice. Please enter a valid tool number.")
    
    def get_target_input(self) -> Tuple[str, str]:
        """Get target input from user"""
        self.clear_screen()
        self.print_header("🎯 TARGET SPECIFICATION")
        
        print("\n📝 Target Input Options:")
        print("-" * 40)
        print("  1. Single Domain (e.g., example.com)")
        print("  2. IP Address (e.g., 192.168.1.1)")
        print("  3. Target File (e.g., targets.txt)")
        print("-" * 40)
        
        while True:
            choice = input("\n📝 Select target type (1-3): ").strip()
            
            if choice == "1":
                target = input("🌐 Enter domain (e.g., example.com): ").strip()
                # Clean up URL if user enters full URL
                if target.startswith(('http://', 'https://')):
                    from urllib.parse import urlparse
                    parsed = urlparse(target)
                    target = parsed.netloc or parsed.path
                if target:
                    return "domain", target
                print("❌ Please enter a valid domain.")
            
            elif choice == "2":
                target = input("🖥️  Enter IP address: ").strip()
                if target:
                    return "ip", target
                print("❌ Please enter a valid IP address.")
            
            elif choice == "3":
                target = input("📁 Enter file path: ").strip()
                if target and Path(target).exists():
                    return "file", target
                print("❌ File not found. Please enter a valid file path.")
            
            else:
                print("❌ Invalid choice. Please enter 1-3.")
    
    def get_output_directory(self) -> str:
        """Get output directory from user"""
        print("\n📁 Output Directory:")
        print("-" * 30)
        default_dir = "./recon_results"
        
        output_dir = input(f"📂 Enter output directory (default: {default_dir}): ").strip()
        
        if not output_dir:
            output_dir = default_dir
        
        return output_dir
    
    def get_advanced_options(self) -> Dict[str, any]:
        """Get advanced scan options"""
        print("\n⚙️  Advanced Options:")
        print("-" * 30)
        
        options = {}
        
        # Threading
        threads = input("🧵 Number of threads (default: 10): ").strip()
        if threads.isdigit():
            options['threads'] = int(threads)
        
        # Timeout
        timeout = input("⏱️  Timeout in seconds (default: 300): ").strip()
        if timeout.isdigit():
            options['timeout'] = int(timeout)
        
        # Verbose output
        verbose = input("📢 Verbose output? (y/N): ").strip().lower()
        options['verbose'] = verbose in ['y', 'yes']
        
        # Rate limiting
        rate_limit = input("🐌 Rate limit between requests in seconds (default: 1): ").strip()
        if rate_limit.replace('.', '').isdigit():
            options['rate_limit'] = float(rate_limit)
        
        return options
    
    def display_scan_summary(self, scan_config: Dict[str, any]) -> bool:
        """Display scan configuration summary and get confirmation"""
        self.clear_screen()
        self.print_header("📋 SCAN CONFIGURATION SUMMARY")
        
        print(f"\n🎯 Target: {scan_config.get('target_value', 'N/A')}")
        print(f"📁 Output: {scan_config.get('output_dir', 'N/A')}")
        print(f"🔧 Mode: {scan_config.get('scan_mode', 'N/A')}")
        
        if scan_config.get('selected_tools'):
            print(f"\n🛠️  Selected Tools:")
            for tool in scan_config['selected_tools']:
                print(f"   • {tool}")
        
        if scan_config.get('advanced_options'):
            print(f"\n⚙️  Advanced Options:")
            for key, value in scan_config['advanced_options'].items():
                print(f"   • {key}: {value}")
        
        print("\n" + "="*60)
        
        while True:
            confirm = input("\n🚀 Start scan with this configuration? (Y/n): ").strip().lower()
            if confirm in ['', 'y', 'yes']:
                return True
            elif confirm in ['n', 'no']:
                return False
            else:
                print("❌ Please enter Y or N.")
    
    def run_interactive_mode(self) -> Optional[Dict[str, any]]:
        """Main interactive mode flow"""
        try:
            # Main menu
            main_choice = self.display_main_menu()
            
            if main_choice == "0":
                print("\n👋 Goodbye!")
                return None
            
            scan_config = {
                'interactive_mode': True,
                'selected_tools': [],
                'advanced_options': {}
            }
            
            # Handle scan mode selection
            if main_choice in ["1", "2", "3"]:  # Quick, Full, or Passive
                mode_name, mode_id, _ = self.scan_modes[main_choice]
                scan_config['scan_mode'] = mode_id
                scan_config['scan_mode_name'] = mode_name
                
            elif main_choice == "4":  # Custom scan
                scan_config['scan_mode'] = 'custom'
                scan_config['scan_mode_name'] = '🎯 Custom Scan'
                
                # Category selection
                selected_categories = self.display_category_menu()
                if not selected_categories:
                    return None
                
                # Tool selection for each category
                all_tools = []
                for category_key in selected_categories:
                    if category_key == "all":
                        # Add all tools from all categories
                        for cat_key, category in self.scan_categories.items():
                            all_tools.append(category['tools']['all'][1])
                        break
                    else:
                        tools = self.display_tools_menu(category_key)
                        if not tools:
                            return None
                        all_tools.extend(tools)
                
                scan_config['selected_tools'] = list(set(all_tools))  # Remove duplicates
            
            # Get target input
            target_type, target_value = self.get_target_input()
            scan_config['target_type'] = target_type
            scan_config['target_value'] = target_value
            
            # Get output directory
            output_dir = self.get_output_directory()
            scan_config['output_dir'] = output_dir
            
            # Get advanced options
            print("\n🔧 Would you like to configure advanced options?")
            config_advanced = input("⚙️  Configure advanced options? (y/N): ").strip().lower()
            
            if config_advanced in ['y', 'yes']:
                advanced_options = self.get_advanced_options()
                scan_config['advanced_options'] = advanced_options
            
            # Display summary and confirm
            if self.display_scan_summary(scan_config):
                return scan_config
            else:
                print("\n🔄 Scan cancelled. Returning to main menu...")
                return self.run_interactive_mode()
        
        except KeyboardInterrupt:
            print("\n\n⚠️  Interrupted by user. Exiting...")
            return None
        except Exception as e:
            print(f"\n❌ Error in interactive mode: {str(e)}")
            return None


def main():
    """Test the interactive menu"""
    menu = InteractiveMenu()
    config = menu.run_interactive_mode()
    
    if config:
        print("\n🎯 Final Configuration:")
        import json
        print(json.dumps(config, indent=2))


if __name__ == "__main__":
    main()
