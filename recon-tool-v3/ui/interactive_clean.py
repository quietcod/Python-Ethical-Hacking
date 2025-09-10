#!/usr/bin/env python3
"""
Interactive Terminal UI for Recon Tool v3
LinUtil-style interface with two-panel layout
"""

import curses
import threading
import time
import os
from datetime import datetime
from core.orchestrator import ReconOrchestrator


def interactive_main():
    """Launch the interactive terminal interface"""
    try:
        return curses.wrapper(main_tui)
    except KeyboardInterrupt:
        print("\n Interactive mode cancelled")
        return 130
    except Exception as e:
        print(f" Error in interactive mode: {e}")
        return 1

def main_tui(stdscr):
    """Main TUI function - LinUtil style interface"""
    # Initialize colors
    curses.start_color()
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)    # Header
    curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_WHITE)   # Selected
    curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Scanning
    curses.init_pair(4, curses.COLOR_GREEN, curses.COLOR_BLACK)   # Success
    curses.init_pair(5, curses.COLOR_RED, curses.COLOR_BLACK)     # Error
    
    # Hide cursor
    curses.curs_set(0)
    
    # Create and run the TUI
    tui = ReconTUI(stdscr)
    return tui.run()


class ReconTUI:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.height, self.width = stdscr.getmaxyx()
        
        # Available tools - same as in config
        self.tools = [
            "nmap",
            "masscan", 
            "nuclei",
            "gobuster",
            "subfinder",
            "amass",
            "httpx",
            "nikto",
            "sslscan",
            "testssl",
            "dirb",
            "wfuzz",
            "fierce",
            "dnsrecon",
            "theharvester",
            "waybackurls",
            "katana",
            "curl_probe",
            "shodan",
            "censys",
            "aquatone"
        ]
        
        # Available scan types for selected tool
        self.scan_types = {
            "nmap": [
                {"name": "Quick Scan", "type": "quick"},
                {"name": "Full Port Scan", "type": "full"},
                {"name": "Stealth Scan", "type": "stealth"},
                {"name": "Service Detection", "type": "service"},
                {"name": "Script Scan", "type": "script"}
            ],
            "masscan": [
                {"name": "Fast Port Scan", "type": "fast"},
                {"name": "Top Ports", "type": "top"}
            ],
            "nuclei": [
                {"name": "Critical Vulns", "type": "critical"},
                {"name": "All Templates", "type": "all"}
            ],
            "gobuster": [
                {"name": "Directory Brute Force", "type": "dir"},
                {"name": "DNS Subdomain", "type": "dns"}
            ],
            "subfinder": [
                {"name": "Passive Subdomain", "type": "passive"}
            ],
            "default": [
                {"name": "Default Scan", "type": "default"}
            ]
        }
        
        self.current_selection = 0
        self.selected_tool = None
        self.selected_scan_type = None
        self.target = None
        self.output_text = []
        self.scan_running = False
        self.help_shown = False
        
        # Create windows
        self._create_windows()
    
    def _create_windows(self):
        """Create the window layout - LinUtil style"""
        # Calculate dimensions
        left_width = self.width // 3
        right_width = self.width - left_width - 1
        
        # Create left panel (tools)
        self.left_win = curses.newwin(self.height - 2, left_width, 1, 0)
        self.left_win.box()
        
        # Create right panel (scan types/output)
        self.right_win = curses.newwin(self.height - 2, right_width, 1, left_width + 1)
        self.right_win.box()
        
        # Header and footer
        self.header_win = curses.newwin(1, self.width, 0, 0)
        self.footer_win = curses.newwin(1, self.width, self.height - 1, 0)
    
    def _draw_header(self):
        """Draw the header"""
        self.header_win.clear()
        title = "Recon Tool v3 - Interactive Mode"
        target_info = f" | Target: {self.target or 'Not Set'}"
        header_text = title + target_info
        
        if len(header_text) > self.width:
            header_text = header_text[:self.width-3] + "..."
            
        self.header_win.addstr(0, 0, header_text[:self.width], curses.color_pair(1))
        self.header_win.refresh()
    
    def _draw_left_panel(self):
        """Draw the tools panel"""
        self.left_win.clear()
        self.left_win.box()
        
        # Panel title
        self.left_win.addstr(1, 2, "Available Tools", curses.A_BOLD)
        
        # Draw tools list
        for i, tool in enumerate(self.tools):
            y = i + 3
            if y >= self.height - 4:  # Leave space for box
                break
                
            if self.selected_tool is None and i == self.current_selection:
                # Highlight current selection
                self.left_win.addstr(y, 2, f"> {tool}", curses.color_pair(2))
            elif tool == self.selected_tool:
                # Show selected tool
                self.left_win.addstr(y, 2, f"* {tool}", curses.color_pair(4))
            else:
                self.left_win.addstr(y, 2, f"  {tool}")
        
        self.left_win.refresh()
    
    def _draw_right_panel(self):
        """Draw the scan types/output panel"""
        self.right_win.clear()
        self.right_win.box()
        
        if self.help_shown:
            self._draw_help()
        elif self.scan_running:
            self._draw_scan_output()
        elif self.selected_tool:
            self._draw_scan_types()
        else:
            self._draw_instructions()
            
        self.right_win.refresh()
    
    def _draw_instructions(self):
        """Draw initial instructions"""
        instructions = [
            "Instructions:",
            "",
            "• Use Up/Down arrows to navigate tools",
            "• Press Enter to select a tool",
            "• Press 't' to set target",
            "• Press 's' to start scan",
            "• Press 'c' to clear output",
            "• Press 'q' or ESC to quit",
            "• Press 'h' for help",
            "",
            "Select a tool to see available scan types"
        ]
        
        for i, line in enumerate(instructions):
            if i + 2 < self.height - 4:
                self.right_win.addstr(i + 2, 2, line)
    
    def _draw_scan_types(self):
        """Draw available scan types for selected tool"""
        self.right_win.addstr(1, 2, f"Scan Types - {self.selected_tool}", curses.A_BOLD)
        
        # Get scan types for this tool
        scan_types = self.scan_types.get(self.selected_tool, self.scan_types["default"])
        
        for i, scan_type in enumerate(scan_types):
            y = i + 3
            if y >= self.height - 4:
                break
                
            if scan_type == self.selected_scan_type:
                self.right_win.addstr(y, 2, f"* {scan_type['name']}", curses.color_pair(4))
            else:
                self.right_win.addstr(y, 2, f"  {scan_type['name']}")
        
        # Instructions
        y = len(scan_types) + 5
        if y < self.height - 4:
            self.right_win.addstr(y, 2, "Press Enter to select scan type")
            self.right_win.addstr(y + 1, 2, "Press 'b' to go back")
    
    def _draw_scan_output(self):
        """Draw scan output"""
        self.right_win.addstr(1, 2, "Scan Output", curses.A_BOLD)
        
        if self.scan_running:
            if not self.output_text:
                self.right_win.addstr(2, 2, " Scan in progress...", curses.color_pair(3))
        
        # Display output lines
        start_y = 3
        visible_lines = self.height - 6  # Leave space for borders and title
        
        # Show last N lines that fit in window
        display_lines = self.output_text[-visible_lines:] if len(self.output_text) > visible_lines else self.output_text
        
        for i, line in enumerate(display_lines):
            y = start_y + i
            if y >= self.height - 2:
                break
            
            # Color coding for different types of messages
            if line:
                try:
                    color = curses.color_pair(4) if "completed" in line else curses.color_pair(5) if "failed" in line else 0
                    # Truncate long lines
                    display_line = line[:self.width - 8] if len(line) > self.width - 8 else line
                    self.right_win.addstr(y, 2, display_line, color)
                except curses.error:
                    pass  # Skip lines that don't fit
    
    def _draw_help(self):
        """Draw help information"""
        help_text = [
            "Help - Keyboard Shortcuts:",
            "",
            "Navigation:",
            "  Up/Down  - Navigate tools/options",
            "  Enter    - Select tool/option",
            "  b        - Go back",
            "",
            "Actions:",
            "  t        - Set target",
            "  s        - Start scan",
            "  c        - Clear output",
            "  h        - Toggle this help",
            "  q/ESC    - Quit",
            "",
            "Workflow:",
            "1. Set target with 't'",
            "2. Select a tool",
            "3. Choose scan type",
            "4. Press 's' to start scan",
            "",
            "Press 'h' again to close help"
        ]
        
        for i, line in enumerate(help_text):
            if i + 2 < self.height - 4:
                self.right_win.addstr(i + 2, 2, line)
    
    def _draw_footer(self):
        """Draw the footer with shortcuts"""
        self.footer_win.clear()
        
        if self.scan_running:
            footer_text = " Scan in progress... [c] Clear [q] Quit [h] Help"
        else:
            footer_text = "[Up/Down] Navigate [Enter] Select [t] Target [s] Start [c] Clear [h] Help [q] Quit"
        
        # Truncate if too long
        if len(footer_text) > self.width:
            footer_text = footer_text[:self.width-3] + "..."
            
        self.footer_win.addstr(0, 0, footer_text[:self.width])
        self.footer_win.refresh()
    
    def _refresh_all(self):
        """Refresh all windows"""
        self._draw_header()
        self._draw_left_panel()
        self._draw_right_panel()
        self._draw_footer()
    
    def _handle_navigation(self, key):
        """Handle navigation keys"""
        if key == curses.KEY_UP:
            if self.selected_tool is None:
                # Navigate tools
                self.current_selection = max(0, self.current_selection - 1)
            else:
                # Navigate scan types
                scan_types = self.scan_types.get(self.selected_tool, self.scan_types["default"])
                if self.selected_scan_type:
                    current_idx = scan_types.index(self.selected_scan_type)
                    new_idx = max(0, current_idx - 1)
                    self.selected_scan_type = scan_types[new_idx]
                    
        elif key == curses.KEY_DOWN:
            if self.selected_tool is None:
                # Navigate tools
                self.current_selection = min(len(self.tools) - 1, self.current_selection + 1)
            else:
                # Navigate scan types
                scan_types = self.scan_types.get(self.selected_tool, self.scan_types["default"])
                if self.selected_scan_type:
                    current_idx = scan_types.index(self.selected_scan_type)
                    new_idx = min(len(scan_types) - 1, current_idx + 1)
                    self.selected_scan_type = scan_types[new_idx]
                else:
                    self.selected_scan_type = scan_types[0]
                    
        elif key == ord('\n') or key == curses.KEY_ENTER:
            if self.selected_tool is None:
                # Select tool
                self.selected_tool = self.tools[self.current_selection]
                scan_types = self.scan_types.get(self.selected_tool, self.scan_types["default"])
                self.selected_scan_type = scan_types[0]  # Auto-select first scan type
            else:
                # Tool already selected, scan type should be selected
                pass
    
    def _set_target(self):
        """Set the target for scanning"""
        curses.echo()
        curses.curs_set(1)
        
        # Create input window
        input_win = curses.newwin(3, 50, self.height // 2 - 1, self.width // 2 - 25)
        input_win.box()
        input_win.addstr(1, 2, "Enter target (IP/domain): ")
        input_win.refresh()
        
        try:
            target = input_win.getstr(1, 26, 20).decode('utf-8').strip()
            if target:
                self.target = target
        except:
            pass
        
        curses.noecho()
        curses.curs_set(0)
        del input_win
    
    def _start_scan(self):
        """Start the scan in a background thread"""
        if not self.target:
            self.output_text.append("Error: No target set. Press 't' to set target.")
            return
            
        if not self.selected_tool or not self.selected_scan_type:
            self.output_text.append("Error: No tool or scan type selected.")
            return
            
        if self.scan_running:
            self.output_text.append("Scan already in progress...")
            return
        
        # Start scan in background thread
        self.scan_running = True
        scan_thread = threading.Thread(target=self._execute_scan)
        scan_thread.daemon = True
        scan_thread.start()
    
    def _execute_scan(self):
        """Execute the actual scan"""
        try:
            from core.orchestrator import ReconOrchestrator
            
            orchestrator = ReconOrchestrator()
            
            # Prepare scan parameters
            scan_params = {
                'target': self.target,
                'tools': [self.selected_tool],
                'scan_type': self.selected_scan_type['type'],
                'output_dir': 'results',
                'verbose': True
            }
            
            # Add initial output
            self.output_text.append(f">> Starting {self.selected_scan_type['name']} scan of {self.target}")
            self.output_text.append(f"   Tool: {self.selected_tool}")
            self.output_text.append(f"   Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            self.output_text.append("")
            
            # Setup scan components
            self.output_text.append("   Initializing scan components...")
            time.sleep(0.5)  # Brief pause for UI update
            
            self.output_text.append("   Components initialized")
            
            # Execute scan
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
            
            self.output_text.append("   PDF report generated successfully!")
            
            if pdf_reports and 'pdf' in pdf_reports:
                self.output_text.append(f"   PDF Location: {pdf_reports['pdf']}")
                
                # Show relative path for user convenience  
                relative_path = os.path.relpath(pdf_reports['pdf'])
                self.output_text.append(f"   Relative Path: {relative_path}")
            else:
                self.output_text.append("   PDF report generation failed")
            
            # Display summary results
            self.output_text.append("")
            self.output_text.append("   Results Summary:")
            
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
        """Clear the output text"""
        self.output_text.clear()
        if self.scan_running:
            self.output_text.append("Scan cleared. Scan still running in background...")
    
    def _go_back(self):
        """Go back to tool selection"""
        if self.selected_tool:
            self.selected_tool = None
            self.selected_scan_type = None
    
    def run(self):
        """Main event loop"""
        self.stdscr.timeout(1000)  # 1 second timeout for auto-refresh
        
        while True:
            self._refresh_all()
            
            try:
                key = self.stdscr.getch()
                
                if key == -1:  # Timeout - auto refresh during scan
                    continue
                    
                # Handle quit
                if key == ord('q') or key == 27:  # 'q' or ESC
                    break
                    
                # Handle help
                elif key == ord('h'):
                    self.help_shown = not self.help_shown
                    
                # Handle target setting
                elif key == ord('t'):
                    self._set_target()
                    
                # Handle scan start
                elif key == ord('s'):
                    self._start_scan()
                    
                # Handle clear output
                elif key == ord('c'):
                    self._clear_output()
                    
                # Handle back
                elif key == ord('b'):
                    self._go_back()
                    
                # Handle navigation
                else:
                    self._handle_navigation(key)
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                # Log error but continue
                self.output_text.append(f"UI Error: {str(e)}")
        
        return 0


if __name__ == "__main__":
    interactive_main()
