#!/usr/bin/env python3
"""
Enhanced Terminal Interface for Recon Tool
Inspired by Chris Titus LinuxUtil design patterns
"""

import os
import sys
import time
import threading
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum


class Colors:
    """ANSI color codes for terminal formatting"""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    # Foreground colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bright colors
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'


class BoxChars:
    """Unicode box-drawing characters"""
    TOP_LEFT = '╔'
    TOP_RIGHT = '╗'
    BOTTOM_LEFT = '╚'
    BOTTOM_RIGHT = '╝'
    HORIZONTAL = '═'
    VERTICAL = '║'
    CROSS = '╬'
    T_DOWN = '╦'
    T_UP = '╩'
    T_RIGHT = '╠'
    T_LEFT = '╣'
    
    # Single line variants
    S_TOP_LEFT = '┌'
    S_TOP_RIGHT = '┐'
    S_BOTTOM_LEFT = '└'
    S_BOTTOM_RIGHT = '┘'
    S_HORIZONTAL = '─'
    S_VERTICAL = '│'
    S_CROSS = '┼'
    S_T_DOWN = '┬'
    S_T_UP = '┴'
    S_T_RIGHT = '├'
    S_T_LEFT = '┤'


class StatusIcon:
    """Status icons with colors"""
    SUCCESS = f"{Colors.BRIGHT_GREEN}✓{Colors.RESET}"
    ERROR = f"{Colors.BRIGHT_RED}✗{Colors.RESET}"
    WARNING = f"{Colors.BRIGHT_YELLOW}⚠{Colors.RESET}"
    INFO = f"{Colors.BRIGHT_BLUE}ℹ{Colors.RESET}"
    RUNNING = f"{Colors.BRIGHT_CYAN}⟳{Colors.RESET}"
    PENDING = f"{Colors.YELLOW}⏳{Colors.RESET}"
    TOOL = f"{Colors.BRIGHT_MAGENTA}🔧{Colors.RESET}"
    TARGET = f"{Colors.BRIGHT_GREEN}🎯{Colors.RESET}"
    REPORT = f"{Colors.BRIGHT_BLUE}📊{Colors.RESET}"


@dataclass
class MenuItem:
    """Menu item data structure"""
    id: str
    title: str
    description: str
    category: str
    status: str = "ready"
    enabled: bool = True
    icon: str = ""


class MenuCategory(Enum):
    """Menu categories for organization"""
    NETWORK = "network"
    WEB = "web"
    OSINT = "osint"
    SECURITY = "security"
    VISUAL = "visual"
    CONFIG = "config"


class TerminalUI:
    """Enhanced terminal user interface"""
    
    def __init__(self):
        self.width = self._get_terminal_width()
        self.height = self._get_terminal_height()
        self.running_tasks = {}
        self.status_line = ""
        
    def _get_terminal_width(self) -> int:
        """Get terminal width, default to 80"""
        try:
            return os.get_terminal_size().columns
        except:
            return 80
    
    def _get_terminal_height(self) -> int:
        """Get terminal height, default to 24"""
        try:
            return os.get_terminal_size().lines
        except:
            return 24
    
    def clear_screen(self):
        """Clear terminal screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def move_cursor(self, row: int, col: int):
        """Move cursor to specific position"""
        print(f'\033[{row};{col}H', end='')
    
    def hide_cursor(self):
        """Hide terminal cursor"""
        print('\033[?25l', end='')
    
    def show_cursor(self):
        """Show terminal cursor"""
        print('\033[?25h', end='')
    
    def draw_box(self, x: int, y: int, width: int, height: int, 
                 title: str = "", color: str = Colors.CYAN, double: bool = True) -> None:
        """Draw a box with optional title"""
        if double:
            tl, tr, bl, br = BoxChars.TOP_LEFT, BoxChars.TOP_RIGHT, BoxChars.BOTTOM_LEFT, BoxChars.BOTTOM_RIGHT
            h, v = BoxChars.HORIZONTAL, BoxChars.VERTICAL
        else:
            tl, tr, bl, br = BoxChars.S_TOP_LEFT, BoxChars.S_TOP_RIGHT, BoxChars.S_BOTTOM_LEFT, BoxChars.S_BOTTOM_RIGHT
            h, v = BoxChars.S_HORIZONTAL, BoxChars.S_VERTICAL
        
        # Top border
        self.move_cursor(y, x)
        top_line = tl + h * (width - 2) + tr
        if title:
            title_start = (width - len(title) - 2) // 2
            if title_start > 0:
                top_line = (tl + h * title_start + f" {color}{Colors.BOLD}{title}{Colors.RESET} " + 
                           h * (width - title_start - len(title) - 4) + tr)
        print(f"{color}{top_line}{Colors.RESET}")
        
        # Side borders
        for i in range(1, height - 1):
            self.move_cursor(y + i, x)
            print(f"{color}{v}{Colors.RESET}", end='')
            self.move_cursor(y + i, x + width - 1)
            print(f"{color}{v}{Colors.RESET}")
        
        # Bottom border
        self.move_cursor(y + height - 1, x)
        print(f"{color}{bl + h * (width - 2) + br}{Colors.RESET}")
    
    def draw_header(self, title: str, subtitle: str = "") -> int:
        """Draw main header with title and subtitle"""
        self.clear_screen()
        
        # Main title box
        title_width = min(self.width - 4, 80)
        title_height = 7 if subtitle else 5
        start_x = (self.width - title_width) // 2
        
        self.draw_box(start_x, 1, title_width, title_height, "", Colors.BRIGHT_CYAN, True)
        
        # Title text
        title_line = f"{Colors.BRIGHT_WHITE}{Colors.BOLD}🎯 {title} 🎯{Colors.RESET}"
        title_x = start_x + (title_width - len(title) - 6) // 2
        self.move_cursor(3, title_x)
        print(title_line)
        
        if subtitle:
            subtitle_line = f"{Colors.BRIGHT_BLUE}{subtitle}{Colors.RESET}"
            subtitle_x = start_x + (title_width - len(subtitle)) // 2
            self.move_cursor(4, subtitle_x)
            print(subtitle_line)
        
        return title_height + 2
    
    def draw_status_bar(self, status: str, progress: Optional[int] = None) -> None:
        """Draw status bar at bottom of screen"""
        self.move_cursor(self.height - 1, 1)
        
        # Clear the line
        print(' ' * (self.width - 1), end='')
        self.move_cursor(self.height - 1, 1)
        
        # Status text
        status_text = f"{Colors.BG_BLUE}{Colors.WHITE} {status} {Colors.RESET}"
        print(status_text, end='')
        
        # Progress bar if provided
        if progress is not None:
            bar_width = 20
            filled = int((progress / 100) * bar_width)
            bar = f" [{Colors.BRIGHT_GREEN}{'█' * filled}{Colors.DIM}{'░' * (bar_width - filled)}{Colors.RESET}] {progress}%"
            print(bar, end='')
        
        # Right-aligned time
        current_time = time.strftime("%H:%M:%S")
        time_text = f"{Colors.DIM}{current_time}{Colors.RESET}"
        time_x = self.width - len(current_time) - 1
        self.move_cursor(self.height - 1, time_x)
        print(time_text)
    
    def draw_menu_category(self, category: str, items: List[MenuItem], 
                          start_y: int, start_x: int, width: int) -> int:
        """Draw a menu category with items"""
        category_height = len(items) + 4
        
        # Category header
        category_icons = {
            "network": "🌐",
            "web": "🕸️",
            "osint": "🔍", 
            "security": "🛡️",
            "visual": "📸",
            "config": "⚙️"
        }
        
        icon = category_icons.get(category.lower(), "📋")
        title = f"{icon} {category.upper()}"
        
        self.draw_box(start_x, start_y, width, category_height, title, Colors.BRIGHT_MAGENTA, False)
        
        # Menu items
        for i, item in enumerate(items):
            item_y = start_y + 2 + i
            self.move_cursor(item_y, start_x + 2)
            
            # Status icon
            status_icon = {
                "ready": f"{Colors.GREEN}●{Colors.RESET}",
                "running": f"{Colors.BRIGHT_CYAN}⟳{Colors.RESET}",
                "completed": f"{Colors.BRIGHT_GREEN}✓{Colors.RESET}",
                "failed": f"{Colors.BRIGHT_RED}✗{Colors.RESET}",
                "disabled": f"{Colors.DIM}○{Colors.RESET}"
            }.get(item.status, "●")
            
            # Item number and title
            color = Colors.WHITE if item.enabled else Colors.DIM
            number = f"{Colors.BRIGHT_YELLOW}{i+1}.{Colors.RESET}" if item.enabled else f"{Colors.DIM}{i+1}.{Colors.RESET}"
            
            item_text = f"{status_icon} {number} {color}{item.title}{Colors.RESET}"
            print(item_text[:width-4])  # Truncate if too long
        
        return category_height
    
    def draw_info_panel(self, title: str, content: List[str], 
                       start_y: int, start_x: int, width: int, height: int) -> None:
        """Draw an information panel"""
        self.draw_box(start_x, start_y, width, height, title, Colors.BRIGHT_BLUE, False)
        
        for i, line in enumerate(content[:height-3]):
            self.move_cursor(start_y + 2 + i, start_x + 2)
            print(line[:width-4])  # Truncate if too long
    
    def draw_progress_spinner(self, x: int, y: int, step: int) -> None:
        """Draw animated spinner"""
        spinners = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        spinner = spinners[step % len(spinners)]
        self.move_cursor(y, x)
        print(f"{Colors.BRIGHT_CYAN}{spinner}{Colors.RESET}", end='', flush=True)
    
    def get_input(self, prompt: str, x: int, y: int) -> str:
        """Get user input at specific position"""
        self.move_cursor(y, x)
        self.show_cursor()
        print(f"{Colors.BRIGHT_WHITE}{prompt}{Colors.RESET}", end='', flush=True)
        
        try:
            user_input = input()
            return user_input.strip()
        finally:
            self.hide_cursor()
    
    def display_confirmation(self, message: str, default: bool = True) -> bool:
        """Display confirmation dialog"""
        dialog_width = min(60, self.width - 10)
        dialog_height = 8
        dialog_x = (self.width - dialog_width) // 2
        dialog_y = (self.height - dialog_height) // 2
        
        # Draw dialog box
        self.draw_box(dialog_x, dialog_y, dialog_width, dialog_height, "CONFIRMATION", Colors.BRIGHT_YELLOW, True)
        
        # Message
        self.move_cursor(dialog_y + 3, dialog_x + 2)
        print(f"{Colors.WHITE}{message}{Colors.RESET}")
        
        # Options
        yes_color = Colors.BRIGHT_GREEN if default else Colors.WHITE
        no_color = Colors.WHITE if default else Colors.BRIGHT_RED
        
        self.move_cursor(dialog_y + 5, dialog_x + 2)
        print(f"{yes_color}[Y]es{Colors.RESET}  {no_color}[N]o{Colors.RESET}")
        
        # Get input
        self.move_cursor(dialog_y + 6, dialog_x + 2)
        self.show_cursor()
        print("Choice: ", end='', flush=True)
        
        try:
            choice = input().strip().lower()
            if choice in ['y', 'yes', '']:
                return True
            elif choice in ['n', 'no']:
                return False
            else:
                return default
        finally:
            self.hide_cursor()


class ReconTerminalInterface:
    """Main reconnaissance tool terminal interface"""
    
    def __init__(self):
        self.ui = TerminalUI()
        self.current_menu = "main"
        self.running = True
        self.selected_tools = []
        self.scan_config = {}
        
        # Menu items for different categories
        self.menu_items = {
            "network": [
                MenuItem("port_scan", "Port Scanning", "Comprehensive port scanning with nmap/masscan", "network", icon="🔍"),
                MenuItem("network_discovery", "Network Discovery", "Host discovery and network topology", "network", icon="🗺️"),
                MenuItem("dns_analysis", "DNS Analysis", "DNS enumeration and zone transfer testing", "network", icon="🌐"),
                MenuItem("service_detection", "Service Detection", "Service version detection and banner grabbing", "network", icon="🔎"),
            ],
            "web": [
                MenuItem("tech_detection", "Technology Detection", "Technology stack and CMS identification", "web", icon="🔍"),
                MenuItem("directory_discovery", "Directory Discovery", "Directory and file brute-forcing", "web", icon="📁"),
                MenuItem("web_vulnerabilities", "Web Vulnerabilities", "Web vulnerability scanning with nikto", "web", icon="🛡️"),
                MenuItem("ssl_analysis", "SSL/TLS Analysis", "SSL/TLS security assessment", "web", icon="🔒"),
                MenuItem("api_testing", "API Testing", "REST/GraphQL API security testing", "web", icon="🔌"),
            ],
            "osint": [
                MenuItem("subdomain_enum", "Subdomain Enumeration", "Comprehensive subdomain discovery", "osint", icon="🔍"),
                MenuItem("search_intelligence", "Search Intelligence", "Google dorking and search intelligence", "osint", icon="🔎"),
                MenuItem("cert_transparency", "Certificate Transparency", "SSL certificate monitoring", "osint", icon="📜"),
                MenuItem("wayback_analysis", "Wayback Analysis", "Historical website analysis", "osint", icon="⏰"),
            ],
            "security": [
                MenuItem("vulnerability_scan", "Vulnerability Scanning", "Automated vulnerability detection", "security", icon="🛡️"),
                MenuItem("auth_testing", "Authentication Testing", "Authentication and authorization testing", "security", icon="🔐"),
                MenuItem("compliance_check", "Compliance Testing", "OWASP/NIST compliance checking", "security", icon="📋"),
            ]
        }
    
    def run(self):
        """Main interface loop"""
        try:
            self.ui.hide_cursor()
            
            while self.running:
                if self.current_menu == "main":
                    self.show_main_menu()
                elif self.current_menu == "scan_config":
                    self.show_scan_config()
                elif self.current_menu == "running":
                    self.show_scan_running()
                
                time.sleep(0.1)  # Prevent excessive CPU usage
        
        except KeyboardInterrupt:
            self.ui.clear_screen()
            print(f"\n{Colors.BRIGHT_YELLOW}⚠ Scan interrupted by user{Colors.RESET}")
        finally:
            self.ui.show_cursor()
    
    def show_main_menu(self):
        """Display main menu interface"""
        current_row = self.ui.draw_header("RECON TOOL - PROFESSIONAL EDITION", "Advanced Reconnaissance Framework")
        
        # Calculate layout
        categories = ["network", "web", "osint", "security"]
        cols = 2
        rows = 2
        col_width = (self.ui.width - 6) // cols
        
        for i, category in enumerate(categories):
            row = i // cols
            col = i % cols
            start_x = 3 + col * (col_width + 2)
            start_y = current_row + row * 12
            
            items = self.menu_items[category]
            self.ui.draw_menu_category(category, items, start_y, start_x, col_width)
        
        # Info panel
        info_content = [
            f"{StatusIcon.INFO} Select scan categories and tools",
            f"{StatusIcon.TARGET} Configure target and options", 
            f"{StatusIcon.REPORT} Generate comprehensive reports",
            "",
            f"{Colors.BRIGHT_GREEN}[S]{Colors.RESET} Start Scan Configuration",
            f"{Colors.BRIGHT_YELLOW}[C]{Colors.RESET} View Current Selection",
            f"{Colors.BRIGHT_BLUE}[H]{Colors.RESET} Help & Documentation",
            f"{Colors.BRIGHT_RED}[Q]{Colors.RESET} Quit"
        ]
        
        info_start_y = current_row + 25
        self.ui.draw_info_panel("QUICK ACTIONS", info_content, info_start_y, 3, self.ui.width - 6, 12)
        
        # Status bar
        selected_count = len(self.selected_tools)
        status = f"Ready | Selected Tools: {selected_count} | Press [S] to configure scan"
        self.ui.draw_status_bar(status)
        
        # Handle input (non-blocking in real implementation)
        choice = self.ui.get_input("Choice: ", 3, self.ui.height - 3)
        
        if choice.lower() == 's':
            self.current_menu = "scan_config"
        elif choice.lower() == 'q':
            self.running = False
        elif choice.isdigit():
            # Handle tool selection
            pass
    
    def show_scan_config(self):
        """Display scan configuration interface"""
        current_row = self.ui.draw_header("SCAN CONFIGURATION", "Configure target and scan parameters")
        
        # Configuration form
        config_width = min(80, self.ui.width - 10)
        config_x = (self.ui.width - config_width) // 2
        
        self.ui.draw_box(config_x, current_row, config_width, 20, "TARGET CONFIGURATION", Colors.BRIGHT_GREEN, True)
        
        # Form fields would go here
        form_content = [
            "1. Target Type:",
            "   ○ Single Domain    ○ IP Address    ○ Target File",
            "",
            "2. Target Value:",
            "   [                                        ]",
            "",
            "3. Scan Mode:",
            "   ○ Quick (5-10 min)  ○ Full (15-30 min)  ○ Custom",
            "",
            "4. Output Directory:",
            "   [./recon_results                         ]",
            "",
            "5. Advanced Options:",
            "   Threads: [10]  Timeout: [300]  Rate Limit: [1.0]"
        ]
        
        for i, line in enumerate(form_content):
            self.ui.move_cursor(current_row + 3 + i, config_x + 3)
            print(f"{Colors.WHITE}{line}{Colors.RESET}")
        
        # Navigation
        nav_y = current_row + 25
        self.ui.move_cursor(nav_y, config_x + 3)
        print(f"{Colors.BRIGHT_GREEN}[Enter]{Colors.RESET} Start Scan  {Colors.BRIGHT_YELLOW}[B]{Colors.RESET} Back  {Colors.BRIGHT_RED}[Q]{Colors.RESET} Quit")
        
        self.ui.draw_status_bar("Configuration Mode | Fill in target details and options")
        
        choice = self.ui.get_input("Action: ", config_x + 3, nav_y + 2)
        
        if choice.lower() == 'b':
            self.current_menu = "main"
        elif choice.lower() == 'q':
            self.running = False
        elif choice == '':
            if self.ui.display_confirmation("Start reconnaissance scan with current configuration?"):
                self.current_menu = "running"
    
    def show_scan_running(self):
        """Display running scan interface"""
        current_row = self.ui.draw_header("SCAN IN PROGRESS", "Real-time reconnaissance execution")
        
        # Progress overview
        progress_width = self.ui.width - 10
        progress_x = 5
        
        self.ui.draw_box(progress_x, current_row, progress_width, 15, "SCAN PROGRESS", Colors.BRIGHT_CYAN, True)
        
        # Mock running tools
        running_tools = [
            ("Port Scanning", 85, "completed"),
            ("Subdomain Enumeration", 60, "running"),
            ("Web Vulnerability Scan", 30, "running"),
            ("SSL/TLS Analysis", 0, "pending")
        ]
        
        for i, (tool, progress, status) in enumerate(running_tools):
            tool_y = current_row + 3 + i * 3
            self.ui.move_cursor(tool_y, progress_x + 3)
            
            # Status icon
            if status == "completed":
                icon = StatusIcon.SUCCESS
            elif status == "running":
                icon = StatusIcon.RUNNING
            else:
                icon = StatusIcon.PENDING
            
            # Progress bar
            bar_width = 40
            filled = int((progress / 100) * bar_width)
            bar = f"[{Colors.BRIGHT_GREEN}{'█' * filled}{Colors.DIM}{'░' * (bar_width - filled)}{Colors.RESET}]"
            
            print(f"{icon} {tool:<25} {bar} {progress:3d}%")
        
        # Real-time log
        log_y = current_row + 18
        self.ui.draw_box(progress_x, log_y, progress_width, 8, "LIVE LOG", Colors.BRIGHT_BLUE, False)
        
        log_entries = [
            "✓ Nmap scan completed - 3 open ports found",
            "⟳ Running subfinder on target domain...",
            "⟳ Found 15 subdomains, checking accessibility...",
            "✓ SSL certificate analysis completed",
            "⟳ Starting Nikto web vulnerability scan..."
        ]
        
        for i, entry in enumerate(log_entries[-5:]):
            self.ui.move_cursor(log_y + 2 + i, progress_x + 3)
            print(f"{Colors.DIM}{time.strftime('%H:%M:%S')}{Colors.RESET} {entry}")
        
        # Overall progress
        overall_progress = 45
        self.ui.draw_status_bar("Scanning in progress...", overall_progress)
        
        # Simulate some time passing
        time.sleep(2)
        
        # Eventually return to main menu
        if overall_progress >= 100:
            self.current_menu = "main"


def demo_interface():
    """Demonstration of the terminal interface"""
    print(f"{Colors.BRIGHT_CYAN}🎯 Recon Tool Terminal Interface Demo{Colors.RESET}")
    print(f"{Colors.WHITE}Inspired by Chris Titus LinuxUtil design{Colors.RESET}\n")
    
    interface = ReconTerminalInterface()
    interface.run()


if __name__ == "__main__":
    demo_interface()
