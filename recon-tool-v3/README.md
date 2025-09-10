# Recon Tool v3.0 - Professional Reconnaissance Toolkit

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Linux](https://img.shields.io/badge/platform-linux-lightgrey)](https://www.linux.org/)

A professional reconnaissance toolkit with a **LinUtil-style interactive terminal interface** for security professionals and penetration testers.

## 🚀 Quick Start

### Default: Interactive Interface
```bash
# Clone and setup
git clone <repository-url>
cd recon-tool-v3

# Launch interactive interface (DEFAULT)
python main.py
```

### Alternative: Command Line Mode
```bash
# Use CLI mode for scripting
python main.py --cli -t example.com --profile quick
python main.py --cli --list-tools
```

## ✨ Key Features

### 🖥️ **Interactive LinUtil-Style Interface (Default)**
- **Two-panel layout**: Tool selection ← → Scan options & output
- **Real-time scan monitoring**: Live progress and output display
- **Automatic PDF reports**: Generated and located after each scan
- **Visual tool categorization**: Network, Web, OSINT, DNS, SSL, Vulnerability
- **Keyboard navigation**: Arrow keys, Enter, hotkeys for quick access

### 🔧 **Professional Tool Arsenal**
- **Network**: Nmap, Masscan
- **Web**: Nikto, Gobuster, Wfuzz, Httpx, Katana, Aquatone
- **OSINT**: Subfinder, Amass, TheHarvester, Waybackurls, Shodan, Censys
- **DNS**: DNSRecon
- **SSL**: SSLScan, Testssl
- **Vulnerability**: Nuclei

### 📊 **Multiple Scan Types Per Tool**
- **Network**: Quick Port Scan, Full Port Scan, Service Detection, OS Detection
- **Web**: Quick Web Scan, Comprehensive Scan, SSL/TLS Check
- **OSINT**: Passive Discovery, DNS Bruteforce, Certificate Transparency

## 🎮 Interface Navigation

### Keyboard Controls
- **↑↓ Arrow Keys**: Navigate tools or scan options
- **←→ Arrow Keys**: Switch between left and right panels
- **Enter**: Select tool or scan type
- **'t' Key**: Set target domain/IP
- **'s' Key**: Start selected scan
- **'c' Key**: Clear output area
- **'q' or ESC**: Quit interface

### Workflow
1. **Launch**: `python main.py`
2. **Set Target**: Press 't' → Enter domain/IP
3. **Select Tool**: Navigate and press Enter
4. **Choose Scan**: Select scan type
5. **Start Scan**: Press 's'
6. **Monitor**: Watch real-time output
7. **Get Report**: PDF location shown on completion

## 📱 Interface Preview

```
★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★ Recon Tool v3.0 ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★
  Professional Reconnaissance Toolkit - Interactive Terminal Interface
  Target: example.com

┌───── Available Tools ──────┐┌─────────── Scan Options & Output ────────────┐
│ 📁 NETWORK                 ││ Nmap Scan Options                            │
│   • Nmap                   ││                                              │
│   • Masscan                ││ Available Scan Types:                        │
│ 📁 WEB                     ││   1. Quick Port Scan - Fast common ports    │
│   • Nikto                  ││   2. Full Port Scan - All 65535 ports       │
│   • Gobuster               ││   3. Service Detection - Identify services   │
│   • Httpx                  ││                                              │
│ 📁 OSINT                   ││ Live Output:                                 │
│   • Subfinder              ││ 🚀 Starting Quick Port Scan...               │
│   • Amass                  ││ ⚡ Executing nmap scan...                    │
│ 📁 VULNERABILITY           ││ ✅ Scan completed!                           │
│   • Nuclei                 ││ 📁 PDF: /path/to/report.pdf                 │
└────────────────────────────┘└──────────────────────────────────────────────┘
[↑↓] Navigate [Enter] Select [t] Target [s] Start [c] Clear [q] Quit
```

## 🛠️ Installation

### Prerequisites
- Python 3.8+
- Linux/macOS (uses built-in curses library)
- Individual reconnaissance tools (install separately)

### Setup
```bash
# Clone repository
git clone <repository-url>
cd recon-tool-v3

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Make launcher executable
chmod +x recon-tool-v3.sh
```

### Tool Dependencies
Install reconnaissance tools separately:
```bash
# Example for Ubuntu/Debian
sudo apt-get update
sudo apt-get install nmap masscan nikto gobuster

# Install Go-based tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/OWASP/Amass/v3/...@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

## 🎯 Usage Examples

### Interactive Mode (Default)
```bash
# Launch interactive interface
python main.py

# Or use shell script
./recon-tool-v3.sh
```

### Command Line Mode
```bash
# Quick scan
python main.py --cli -t example.com --profile quick

# Custom tools
python main.py --cli -t example.com --tools nmap,subfinder,httpx

# Web-focused scan with PDF report
python main.py --cli -t example.com --profile web_focused --format pdf

# List available tools
python main.py --cli --list-tools

# List scan profiles
python main.py --cli --list-profiles
```

### Scan Profiles
- **quick**: Fast scan (3-5 minutes)
- **full**: Comprehensive scan (15-30 minutes)
- **passive**: OSINT-only, no direct target contact
- **web_focused**: Web application security assessment
- **network_focused**: Infrastructure assessment
- **osint_focused**: Intelligence gathering

## 📄 Output & Reports

### PDF Reports (Primary Output)
- **Automatic generation** after each scan
- **Professional formatting** with executive and technical sections
- **Comprehensive results** including vulnerabilities, ports, subdomains
- **Location displayed** in the interface upon completion

### Additional Formats
- **JSON**: Machine-readable raw data
- **HTML**: Web-viewable reports (legacy support)

### Report Types
- **Executive**: High-level summary for management
- **Technical**: Detailed findings for security teams
- **Comprehensive**: Complete analysis (default)

## 🔧 Configuration

### Directory Structure
```
recon-tool-v3/
├── main.py                 # Entry point (launches interactive by default)
├── ui/
│   ├── interactive.py      # LinUtil-style TUI
│   └── cli.py             # Command-line interface
├── tools/                  # Tool implementations
├── core/                   # Core orchestration
├── reporting/              # PDF/HTML/JSON generators
├── config/                 # Configuration files
└── results/
    └── reports/           # Generated PDF reports
```

### Customization
- **Tool selection**: Choose specific tools per scan
- **Output formats**: PDF, JSON, HTML
- **Report types**: Executive, technical, comprehensive
- **Scan profiles**: Predefined tool combinations

## 🚨 Security Considerations

### Ethical Use
- **Authorized testing only**: Only scan systems you own or have permission to test
- **Legal compliance**: Follow applicable laws and regulations
- **Responsible disclosure**: Report vulnerabilities through proper channels

### Network Impact
- **Scan timing**: Use appropriate delays for production systems
- **Bandwidth usage**: Monitor network impact during scans
- **Target selection**: Be precise with target specification

## 🔍 Troubleshooting

### Common Issues
1. **Interface not displaying**: Ensure terminal is at least 80x24
2. **Tools not found**: Install reconnaissance tools separately
3. **Permission errors**: Check file permissions for output directory
4. **Python errors**: Ensure Python 3.8+ and dependencies installed

### Debug Mode
```bash
python main.py --cli --debug -t example.com
```

### Getting Help
```bash
# General help (emphasizes interactive mode)
python main.py --help

# CLI-specific help
python main.py --cli --help

# Interactive mode help
# Press '?' or 'h' within the interface
```

## 🚀 What's New in v3.0

### Major Changes
- **Interactive interface is now DEFAULT** (was opt-in with --interactive)
- **LinUtil-inspired design** with professional two-panel layout
- **Real-time scan monitoring** with live output display
- **Automatic PDF generation** integrated into the workflow
- **CLI mode available** with --cli flag for scripting

### Benefits
- **Better user experience**: Visual, intuitive interface
- **Improved workflow**: Integrated tool selection → scan → report
- **Professional appearance**: Suitable for client demonstrations
- **Real-time feedback**: Live progress and status updates

### Backward Compatibility
- **CLI mode preserved**: Use --cli flag for original command-line experience
- **All tools supported**: No changes to reconnaissance capabilities
- **Same output formats**: PDF, JSON, HTML reports still available
- **Script compatibility**: Shell scripts work with --cli flag

## 📚 Documentation

- **[Interactive UI Guide](INTERACTIVE_UI_GUIDE.md)**: Comprehensive interface documentation
- **[Usage Guide](USAGE_GUIDE.md)**: Detailed usage examples
- **Tool Documentation**: Individual tool configuration and usage

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes
4. Add tests
5. Submit pull request

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🏆 Credits

- **Interface Design**: Inspired by LinUtil for clean, professional TUI
- **Tool Integration**: Leverages industry-standard reconnaissance tools
- **Report Generation**: Professional PDF formatting with ReportLab

---

**Start your reconnaissance with style**: `python main.py` 🚀
