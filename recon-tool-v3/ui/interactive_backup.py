#!/usr/bin/env python3
"""
Interactive Terminal UI - LinUtil Style Interface
Professional terminal-based interface for reconnaissance tools
"""

import curses
import curses.panel
import os
import sys
import threading
import time
from datetime import datetime
from typing import Dict, List, Any, Optional

def run_interactive_mode():
    """Launch the terminal-based UI"""
    try:
        # Initialize curses and run the TUI
        return curses.wrapper(main_tui)
               self.output_text.append("   PDF report generated successfully!")
            
            if pdf_reports.get('pdf'):
                self.output_text.append(f"   PDF Location: {pdf_reports['pdf']}")
                # Show relative path for easier reading
                relative_path = pdf_reports['pdf'].replace(os.getcwd() + '/', '')
                self.output_text.append(f"   Relative Path: {relative_path}")
            else:
                self.output_text.append("   PDF report generation failed")eyboardInterrupt:
        print("\n Interactive mode cancelled")
        return 130
    except Exception as e:
        print(f" Error in interactive mode: {e}")
        return 1

def main_tui(stdscr):
    """Main TUI function - LinUtil style interface"""
    # Initialize colors
    curses.start_color()
    curses.use_default_colors()
    
    # Define color pairs
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)    # Header
    curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_WHITE)   # Selected
    curses.init_pair(3, curses.COLOR_YELLOW, -1)                 # Warning
    curses.init_pair(4, curses.COLOR_GREEN, -1)                  # Success
    curses.init_pair(5, curses.COLOR_RED, -1)                    # Error
    curses.init_pair(6, curses.COLOR_CYAN, -1)                   # Info
    curses.init_pair(7, curses.COLOR_MAGENTA, -1)                # Accent
    
    # Initialize the TUI application
    app = ReconTUI(stdscr)
    return app.run()

class ReconTUI:
    """Terminal User Interface for Recon Tool - LinUtil Style"""
    
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.height, self.width = stdscr.getmaxyx()
        
        # UI State
        self.left_panel_width = 30
        self.selected_tool = None
        self.selected_scan_type = None
        self.current_panel = "tools"  # "tools" or "scans"
        self.tool_index = 0
        self.scan_index = 0
        self.target = ""
        self.output_text = []
        self.scan_running = False
        
        # Load tools and categories
        self._load_tools()
        
        # Create windows
        self._create_windows()
        
        # Hide cursor
        curses.curs_set(0)
        
    def _load_tools(self):
        """Load tools from the registry"""
        try:
            sys.path.append(os.path.dirname(os.path.dirname(__file__)))
            from tools import TOOL_REGISTRY, SCAN_PROFILES
            
            self.tool_registry = TOOL_REGISTRY
            self.scan_profiles = SCAN_PROFILES
            
            # Create tool list with categories
            self.tools_list = []
            for category, tools in TOOL_REGISTRY.items():
                if category != "legacy":  # Skip deprecated tools
                    # Add category header
                    self.tools_list.append({
                        'type': 'category',
                        'name': category.upper(),
                        'description': f'{len(tools)} tools available'
                    })
                    # Add tools in category
                    for tool_name, tool_info in tools.items():
                        self.tools_list.append({
                            'type': 'tool',
                            'name': tool_name,
                            'display_name': tool_info['name'],
                            'description': tool_info['description'],
                            'category': category,
                            'info': tool_info
                        })
            
        except ImportError as e:
            self.tools_list = [{'type': 'error', 'name': 'Error loading tools', 'description': str(e)}]
    
    def _create_windows(self):
        """Create the window layout"""
        # Header window
        self.header_win = curses.newwin(3, self.width, 0, 0)
        
        # Left panel (tools list)
        left_height = self.height - 3
        self.left_win = curses.newwin(left_height, self.left_panel_width, 3, 0)
        
        # Right panel (scan options and output)
        right_width = self.width - self.left_panel_width
        self.right_win = curses.newwin(left_height, right_width, 3, self.left_panel_width)
        
        # Footer
        self.footer_win = curses.newwin(1, self.width, self.height - 1, 0)
    
    def run(self):
        """Main event loop"""
        # Set timeout for screen refresh during scans
        self.stdscr.timeout(500)  # 500ms timeout for regular refresh
        
        while True:
            self._draw_interface()
            
            # Handle input (with timeout)
            key = self.stdscr.getch()
            
            # Handle timeout (no key pressed) - just refresh screen
            if key == -1:
                continue
            
            if key == ord('q') or key == 27:  # ESC or 'q' to quit
                break
            elif key == curses.KEY_UP:
                self._handle_up()
            elif key == curses.KEY_DOWN:
                self._handle_down()
            elif key == curses.KEY_LEFT:
                self._handle_left()
            elif key == curses.KEY_RIGHT:
                self._handle_right()
            elif key == ord('\n') or key == ord('\r'):  # Enter
                self._handle_enter()
            elif key == ord('t'):
                self._get_target()
            elif key == ord('s') and self.selected_tool and self.selected_scan_type and self.target:
                self._start_scan()
            elif key == ord('c'):
                self._clear_output()
            elif key == ord('h') or key == ord('?'):
                self._show_help()
        
        return 0
    
    def _draw_interface(self):
        """Draw the complete interface"""
        self._draw_header()
        self._draw_left_panel()
        self._draw_right_panel()
        self._draw_footer()
        self.stdscr.refresh()
    
    def _draw_header(self):
        """Draw the header section"""
        self.header_win.clear()
        self.header_win.bkgd(' ', curses.color_pair(1))
        
        # Title
        title = "************************* Recon Tool v3.0 *************************"
        self.header_win.addstr(0, 0, title[:self.width])
        
        # Subtitle
        subtitle = "Professional Reconnaissance Toolkit - Interactive Terminal Interface"
        self.header_win.addstr(1, 2, subtitle[:self.width-4])
        
        # Target display
        target_text = f"Target: {self.target if self.target else 'Not set (Press \'t\' to set)'}"
        self.header_win.addstr(2, 2, target_text[:self.width-4])
        
        self.header_win.refresh()
    
    def _draw_left_panel(self):
        """Draw the left panel with tools list"""
        self.left_win.clear()
        self.left_win.box()
        
        # Panel title
        title = " Available Tools "
        self.left_win.addstr(0, (self.left_panel_width - len(title)) // 2, title, curses.color_pair(6))
        
        # Draw tools list
        max_items = self.height - 6
        start_y = 1
        
        for i, tool in enumerate(self.tools_list[:max_items]):
            y = start_y + i
            if y >= self.height - 4:
                break
                
            # Highlight current selection
            attr = curses.color_pair(2) if i == self.tool_index and self.current_panel == "tools" else 0
            
            if tool['type'] == 'category':
                # Category header
                text = f"[{tool['name']}]"
                self.left_win.addstr(y, 2, text[:self.left_panel_width-4], curses.color_pair(7) | curses.A_BOLD)
            elif tool['type'] == 'tool':
                # Tool item
                text = f"  > {tool['display_name']}"
                self.left_win.addstr(y, 2, text[:self.left_panel_width-4], attr)
            else:
                # Error or other
                text = f"ERR {tool['name']}"
                self.left_win.addstr(y, 2, text[:self.left_panel_width-4], curses.color_pair(5))
        
        self.left_win.refresh()
    
    def _draw_right_panel(self):
        """Draw the right panel with scan options and output"""
        self.right_win.clear()
        self.right_win.box()
        
        right_width = self.width - self.left_panel_width
        
        if not self.selected_tool:
            # Welcome message
            title = " Select a Tool "
            self.right_win.addstr(0, (right_width - len(title)) // 2, title, curses.color_pair(6))
            
            welcome_lines = [
                "Welcome to Recon Tool v3.0 Interactive Interface",
                "",
                "Instructions:",
                "• Use Up/Down arrows to navigate tools",
                "• Press Enter to select a tool",
                "• Press 't' to set target",
                "• Press 's' to start scan",
                "• Press 'c' to clear output",
                "• Press 'q' or ESC to quit",
                "",
                "Select a tool from the left panel to see scan options."
            ]
            
            for i, line in enumerate(welcome_lines):
                if i + 2 < self.height - 4:
                    self.right_win.addstr(i + 2, 2, line[:right_width-4])
                    
        elif not self.scan_running and not self.output_text:
            # Show scan options for selected tool
            tool = self._get_current_tool()
            if tool:
                title = f" {tool['display_name']} Scan Options "
                self.right_win.addstr(0, 2, title, curses.color_pair(6))
                
                # Tool description
                self.right_win.addstr(2, 2, f"Description: {tool['description'][:right_width-15]}")
                self.right_win.addstr(3, 2, f"Category: {tool['category'].title()}")
                
                # Scan types
                scan_types = self._get_scan_types_for_tool(tool['name'])
                self.right_win.addstr(5, 2, "Available Scan Types:", curses.color_pair(7) | curses.A_BOLD)
                
                for i, scan_type in enumerate(scan_types):
                    y = 6 + i
                    attr = curses.color_pair(2) if i == self.scan_index and self.current_panel == "scans" else 0
                    text = f"  {i+1}. {scan_type['name']} - {scan_type['description']}"
                    if y < self.height - 4:
                        self.right_win.addstr(y, 2, text[:right_width-4], attr)
                
                # Instructions
                if self.target:
                    status_line = f"Target: {self.target} | Press 's' to start scan"
                    self.right_win.addstr(self.height - 6, 2, status_line[:right_width-4], curses.color_pair(4))
                else:
                    status_line = "Press 't' to set target first"
                    self.right_win.addstr(self.height - 6, 2, status_line[:right_width-4], curses.color_pair(3))
        else:
            # Show scan output
            title = " Scan Output "
            self.right_win.addstr(0, (right_width - len(title)) // 2, title, curses.color_pair(6))
            
            if self.scan_running:
                self.right_win.addstr(2, 2, " Scan in progress...", curses.color_pair(3))
            
            # Display output lines
            max_output_lines = self.height - 8
            start_line = max(0, len(self.output_text) - max_output_lines)
            
            for i, line in enumerate(self.output_text[start_line:]):
                y = 3 + i
                if y < self.height - 4:
                    display_line = line[:right_width-4]
                    color = curses.color_pair(4) if "completed" in line else curses.color_pair(5) if "failed" in line else 0
                    self.right_win.addstr(y, 2, display_line, color)
        
        self.right_win.refresh()
    
    def _draw_footer(self):
        """Draw the footer with key bindings"""
        self.footer_win.clear()
        
        if self.scan_running:
            footer_text = " Scan in progress... [c] Clear [q] Quit [h] Help"
        else:
            footer_text = "[Up/Down] Navigate [Enter] Select [t] Target [s] Start [c] Clear [h] Help [q] Quit"
        
        self.footer_win.addstr(0, 0, footer_text[:self.width])
        self.footer_win.refresh()
    
    def _handle_up(self):
        """Handle up arrow key"""
        if self.current_panel == "tools":
            if self.tool_index > 0:
                self.tool_index -= 1
                # Skip category headers
                while (self.tool_index > 0 and 
                       self.tools_list[self.tool_index]['type'] == 'category'):
                    self.tool_index -= 1
        elif self.current_panel == "scans" and self.selected_tool:
            scan_types = self._get_scan_types_for_tool(self.selected_tool)
            if self.scan_index > 0:
                self.scan_index -= 1
    
    def _handle_down(self):
        """Handle down arrow key"""
        if self.current_panel == "tools":
            if self.tool_index < len(self.tools_list) - 1:
                self.tool_index += 1
                # Skip category headers
                while (self.tool_index < len(self.tools_list) - 1 and 
                       self.tools_list[self.tool_index]['type'] == 'category'):
                    self.tool_index += 1
        elif self.current_panel == "scans" and self.selected_tool:
            scan_types = self._get_scan_types_for_tool(self.selected_tool)
            if self.scan_index < len(scan_types) - 1:
                self.scan_index += 1
    
    def _handle_left(self):
        """Handle left arrow key"""
        if self.current_panel == "scans":
            self.current_panel = "tools"
            self.selected_scan_type = None
    
    def _handle_right(self):
        """Handle right arrow key"""
        if self.current_panel == "tools" and self.selected_tool:
            self.current_panel = "scans"
            self.scan_index = 0
    
    def _handle_enter(self):
        """Handle Enter key"""
        if self.current_panel == "tools":
            tool = self._get_current_tool()
            if tool and tool['type'] == 'tool':
                self.selected_tool = tool['name']
                self.current_panel = "scans"
                self.scan_index = 0
        elif self.current_panel == "scans" and self.selected_tool:
            scan_types = self._get_scan_types_for_tool(self.selected_tool)
            if self.scan_index < len(scan_types):
                self.selected_scan_type = scan_types[self.scan_index]
    
    def _get_target(self):
        """Get target from user input"""
        # Create input window
        input_win = curses.newwin(5, 50, self.height // 2 - 2, self.width // 2 - 25)
        input_win.box()
        input_win.addstr(1, 2, "Enter Target (domain/IP):")
        input_win.addstr(3, 2, "> ")
        input_win.refresh()
        
        # Enable cursor and echo
        curses.curs_set(1)
        curses.echo()
        
        # Get input
        target = input_win.getstr(3, 4, 40).decode('utf-8').strip()
        
        # Disable cursor and echo
        curses.curs_set(0)
        curses.noecho()
        
        if target:
            self.target = target
        
        # Clean up
        del input_win
        self.stdscr.clear()
    
    def _start_scan(self):
        """Start the selected scan"""
        if not all([self.selected_tool, self.selected_scan_type, self.target]):
            return
        
        self.scan_running = True
        self.output_text = []
        
        # Start scan in background thread
        scan_thread = threading.Thread(target=self._run_scan)
        scan_thread.daemon = True
        scan_thread.start()
    
    def _run_scan(self):
        """Run the actual scan (in background thread)"""
        try:
            # Add initial output
            self.output_text.append(f">> Starting {self.selected_scan_type['name']} scan of {self.target}")
            self.output_text.append(f"   Tool: {self.selected_tool}")
            self.output_text.append(f"   Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            self.output_text.append("")
            
            # Setup scan components
            self.output_text.append("   Initializing scan components...")
            time.sleep(0.5)  # Brief pause for UI update
            
            sys.path.append(os.path.dirname(os.path.dirname(__file__)))
            from core.orchestrator import ReconOrchestrator
            from core.config import load_config
            from core.logger import setup_logger
            
            # Setup components
            logger = setup_logger(level='INFO')
            config = load_config()
            orchestrator = ReconOrchestrator(config, logger)
            
            self.output_text.append("   Components initialized")
            
            # Prepare scan parameters
            scan_params = {
                'target': self.target,
                'tools': [self.selected_tool],
                'output_format': 'json',
                'report_format': 'pdf',
                'verbose': True
            }
            
            self.output_text.append(">> Executing scan...")
            self.output_text.append(f"   Target: {self.target}")
            self.output_text.append(f"   Tool: {self.selected_tool}")
            time.sleep(1)  # Allow UI to update
            
            # Execute scan with progress updates
            self.output_text.append("   Launching reconnaissance tool...")
            time.sleep(1)
            
            results = orchestrator.execute_scan(scan_params)
            
            self.output_text.append("   Tool execution completed")
            self.output_text.append("   Processing results...")
            time.sleep(0.5)
            
            # Generate PDF report
            self.output_text.append("   Generating PDF report...")
            
            from reporting.report_manager import ReportManager
            report_manager = ReportManager()
            
            # Generate PDF report
            pdf_reports = report_manager.generate_all_reports(
                results, self.target, formats=['pdf']
            )
            
            self.output_text.append("✅ PDF report generated successfully!")
            
            if pdf_reports.get('pdf'):
                self.output_text.append(f"📁 PDF Location: {pdf_reports['pdf']}")
                # Show relative path for easier reading
                relative_path = pdf_reports['pdf'].replace(os.getcwd() + '/', '')
                self.output_text.append(f"� Relative Path: {relative_path}")
            else:
                self.output_text.append("❌ PDF report generation failed")
            
            # Display summary results
            self.output_text.append("")
            self.output_text.append("📊 Results Summary:")
            
            total_findings = 0
            for tool_name, tool_results in results.items():
                if isinstance(tool_results, dict):
                    if 'subdomains' in tool_results:
                        count = len(tool_results['subdomains'])
                        self.output_text.append(f"  • Subdomains found: {count}")
                        total_findings += count
                    if 'ports' in tool_results:
                        count = len(tool_results['ports'])
                        self.output_text.append(f"  • Open ports: {count}")
                        total_findings += count
                    if 'vulnerabilities' in tool_results:
                        count = len(tool_results['vulnerabilities'])
                        self.output_text.append(f"  • Vulnerabilities: {count}")
                        total_findings += count
                    if 'urls' in tool_results:
                        count = len(tool_results['urls'])
                        self.output_text.append(f"  • URLs discovered: {count}")
                        total_findings += count
            
            if total_findings == 0:
                self.output_text.append("  • No significant findings (tool may need configuration)")
            
            self.output_text.append("")
            self.output_text.append("   Scan completed successfully!")
            self.output_text.append("   Press 'c' to clear output or select another tool")
            
        except Exception as e:
            self.output_text.append(f"   Scan failed: {str(e)}")
            self.output_text.append("   Possible issues:")
            self.output_text.append("  • Tool not installed or not in PATH")
            self.output_text.append("  • Network connectivity issues") 
            self.output_text.append("  • Invalid target format")
            self.output_text.append("  • Permission restrictions")
        finally:
            self.scan_running = False
    
    def _clear_output(self):
        """Clear the output area"""
        self.output_text = []
        self.scan_running = False
    
    def _show_help(self):
        """Show help information in the output area"""
        self.output_text = [
            "🆘 Recon Tool v3.0 - Help & Instructions",
            "",
            "🎮 NAVIGATION:",
            "  ↑↓ Arrow Keys    - Navigate tools/scan options",
            "  ←→ Arrow Keys    - Switch between panels",
            "  Enter           - Select tool or scan type",
            "",
            "🔧 ACTIONS:",
            "  't'             - Set target domain/IP",
            "  's'             - Start selected scan",
            "  'c'             - Clear output area",
            "  'h' or '?'      - Show this help",
            "  'q' or ESC      - Quit application",
            "",
            "📝 WORKFLOW:",
            "  1. Press 't' to set target",
            "  2. Select a tool from left panel",
            "  3. Choose scan type from right panel", 
            "  4. Press 's' to start scan",
            "  5. Monitor progress and get PDF report",
            "",
            "💡 TIPS:",
            "  • Ensure target tools are installed",
            "  • Use valid domain/IP formats",
            "  • PDF reports saved to results/reports/",
            "  • Press 'c' to clear this help",
        ]
    
    def _get_current_tool(self):
        """Get the currently selected tool"""
        if 0 <= self.tool_index < len(self.tools_list):
            return self.tools_list[self.tool_index]
        return None
    
    def _get_scan_types_for_tool(self, tool_name):
        """Get available scan types for a tool"""
        # Define scan types based on tool category and capabilities
        tool_info = None
        for category, tools in self.tool_registry.items():
            if tool_name in tools:
                tool_info = tools[tool_name]
                break
        
        if not tool_info:
            return []
        
        category = tool_info.get('category', '')
        
        # Define scan types based on tool category
        scan_types = {
            'network_scanning': [
                {'name': 'Quick Port Scan', 'description': 'Fast scan of common ports'},
                {'name': 'Full Port Scan', 'description': 'Comprehensive scan of all ports'},
                {'name': 'Service Detection', 'description': 'Identify services and versions'},
                {'name': 'OS Detection', 'description': 'Operating system fingerprinting'}
            ],
            'web_vulnerability': [
                {'name': 'Quick Web Scan', 'description': 'Fast vulnerability assessment'},
                {'name': 'Comprehensive Scan', 'description': 'Detailed vulnerability analysis'},
                {'name': 'SSL/TLS Check', 'description': 'SSL certificate and configuration'},
            ],
            'directory_enum': [
                {'name': 'Common Directories', 'description': 'Scan for common directories'},
                {'name': 'File Extensions', 'description': 'Scan for specific file types'},
                {'name': 'Custom Wordlist', 'description': 'Use custom wordlist'},
            ],
            'subdomain_enum': [
                {'name': 'Passive Discovery', 'description': 'OSINT-based subdomain finding'},
                {'name': 'DNS Bruteforce', 'description': 'Active DNS enumeration'},
                {'name': 'Certificate Transparency', 'description': 'CT log analysis'},
            ],
            'web_discovery': [
                {'name': 'HTTP Probe', 'description': 'Basic HTTP service detection'},
                {'name': 'Technology Stack', 'description': 'Identify web technologies'},
                {'name': 'Response Analysis', 'description': 'Detailed HTTP response analysis'},
            ]
        }
        
        return scan_types.get(category, [
            {'name': 'Standard Scan', 'description': 'Default scan configuration'},
            {'name': 'Verbose Scan', 'description': 'Detailed output and analysis'}
        ])

# Legacy functions for compatibility
def run_quick_scan():
    """Legacy quick scan function"""
    print("Please use the new interactive TUI mode: python main.py --interactive")
    return 1

def run_custom_scan():
    """Legacy custom scan function"""
    print("Please use the new interactive TUI mode: python main.py --interactive")
    return 1

def list_tools_interactive():
    """Legacy tools listing function"""
    print("Please use the new interactive TUI mode: python main.py --interactive")

def list_profiles_interactive():
    """Legacy profiles listing function"""
    print("Please use the new interactive TUI mode: python main.py --interactive")

def show_help():
    """Display help information"""
    print("\n❓ Help - Recon Tool v3.0")
    print("=" * 50)
    print("""
🎯 INTERACTIVE MODE:
   Launch with: python main.py --interactive
   
   Features:
   • LinUtil-style terminal interface
   • Left panel: Tool selection
   • Right panel: Scan options and live output
   • Real-time scan execution with PDF reports
   
🔧 NAVIGATION:
   • ↑↓ arrows: Navigate tools/options
   • ←→ arrows: Switch between panels
   • Enter: Select tool/option
   • 't': Set target
   • 's': Start scan
   • 'c': Clear output
   • 'q' or ESC: Quit
   
📊 FEATURES:
   • Live scan output
   • Automatic PDF report generation
   • Professional terminal interface
   • Tool categorization
   • Multiple scan types per tool
    """)

def get_user_input(prompt, default=None):
    """Get user input with optional default value"""
    try:
        value = input(f"{prompt}: ").strip()
        return value if value else default
    except KeyboardInterrupt:
        return None

class InteractiveMenu:
    """Legacy interactive menu class"""
    
    def __init__(self):
        print("Legacy interface. Please use: python main.py --interactive")
    
    def display_main_menu(self):
        print("Please use the new TUI interface.")
    
    def get_user_selection(self):
        return None
