#!/usr/bin/env python3
"""
Demo script to show the new LinUtil-style interface
"""

import os
import sys

def main():
    print("🚀 Recon Tool v3.0 - Enhanced Interactive Interface")
    print("=" * 60)
    print()
    print("✨ NEW FEATURES:")
    print("1. LinUtil-style terminal interface")
    print("2. Left panel: Tool selection with categories")
    print("3. Right panel: Scan options and live output") 
    print("4. Automatic PDF report generation")
    print("5. Real-time scan progress")
    print()
    print("🎯 INTERFACE LAYOUT:")
    print("┌─── Tools Panel ───┐┌─── Scan & Output Panel ───┐")
    print("│ 📁 NETWORK        ││ Tool Options:              │")
    print("│   • Nmap          ││ 1. Quick Port Scan         │")
    print("│   • Masscan       ││ 2. Full Port Scan          │")
    print("│ 📁 WEB            ││ 3. Service Detection       │")
    print("│   • Nikto         ││ Live Output:               │")
    print("│   • Gobuster      ││ 🚀 Starting scan...        │")
    print("│ 📁 OSINT          ││ ⚡ Executing...            │")
    print("│   • Subfinder     ││ ✅ Scan completed!         │")
    print("│   • Amass         ││ 📁 PDF: /path/to/report    │")
    print("└───────────────────┘└────────────────────────────┘")
    print()
    print("🔧 NAVIGATION:")
    print("• ↑↓ arrows: Navigate tools/options")
    print("• ←→ arrows: Switch between panels")
    print("• Enter: Select tool/option")
    print("• 't': Set target")
    print("• 's': Start scan")
    print("• 'c': Clear output")
    print("• 'q' or ESC: Quit")
    print()
    print("🚀 To launch the interface:")
    print("   python main.py --interactive")
    print()
    print("📊 Features:")
    print("• Real-time scan output in the interface")
    print("• Automatic PDF report generation after scan")
    print("• Professional terminal UI with color coding")
    print("• Tool categorization (Network, Web, OSINT, etc.)")
    print("• Multiple scan types per tool")
    print("• Live progress indicators")

if __name__ == "__main__":
    main()
