# Recon Tool v3.0 - Clean Architecture

## 🎯 Overview

Professional reconnaissance toolkit with ultra-clean modular design. Built from the ground up with best practices and maintainability in mind.

## ✨ Key Features

- **Ultra-minimal main.py** (25 lines) - Clean entry point
- **Modular Architecture** - Single responsibility principle  
- **Professional UI** - LinuxUtil-inspired terminal interface
- **Comprehensive Tools** - Full security assessment suite
- **Multiple Output Formats** - PDF, HTML, JSON, Markdown
- **Easy to Extend** - Add new tools in minutes

## 🚀 Quick Start

### Installation

```bash
cd recon-tool-v3
pip install -r requirements.txt
```

### Basic Usage

```bash
# Interactive mode (recommended for beginners)
python3 main.py --interactive

# Quick scan
python3 main.py --target example.com --profile quick

# Full comprehensive scan  
python3 main.py --target example.com --profile full

# Custom tool selection
python3 main.py --target example.com --tools nmap,subfinder,nikto
```

## 📁 Project Structure

```
recon-tool-v3/
├── main.py                    # Ultra-clean entry point (25 lines)
├── ui/                        # User interface layer
│   ├── cli.py                 # CLI argument handling
│   ├── interactive.py         # Interactive menu system
│   └── terminal.py            # Enhanced terminal UI
├── core/                      # Business logic
│   ├── orchestrator.py        # Scan coordination
│   ├── validator.py           # Input validation
│   ├── logger.py              # Logging system
│   └── config.py              # Configuration management
├── tools/                     # Individual security tools
│   ├── nmap.py                # Network scanning
│   ├── masscan.py             # Fast port scanning
│   ├── subfinder.py           # Subdomain enumeration
│   ├── nikto.py               # Web vulnerability scanning
│   ├── gobuster.py            # Directory brute forcing
│   ├── sslscan.py             # SSL/TLS analysis
│   └── nuclei.py              # Vulnerability templates
├── reporting/                 # Report generation
│   ├── pdf.py                 # PDF reports
│   ├── html.py                # HTML reports
│   ├── json.py                # JSON output
│   └── markdown.py            # Markdown reports
├── config/                    # Configuration files
│   ├── defaults.json          # Default settings
│   ├── scan_profiles.json     # Predefined scan types
│   └── tool_configs.json      # Tool-specific configs
├── tests/                     # Testing framework
│   ├── unit/                  # Unit tests
│   ├── integration/           # Integration tests
│   └── fixtures/              # Test data
├── docs/                      # Documentation
├── scripts/                   # Utility scripts
└── logs/                      # Application logs
```

## 🛠️ Architecture Principles

### Clean Code
- **Single Responsibility** - Each file has one clear purpose
- **Minimal Dependencies** - Loose coupling between components
- **Easy to Find** - Locate any feature in 5 seconds or less
- **Easy to Update** - Change one thing without breaking others

### Professional Design
- **Modular Tools** - Add new tools without touching core
- **Flexible Configuration** - JSON-based configuration system
- **Comprehensive Logging** - Structured logging for debugging
- **Multiple Interfaces** - CLI and interactive modes

## 📊 Scan Profiles

### Quick Scan (5-10 minutes)
- Port scanning with nmap
- Subdomain enumeration
- Basic security checks

### Full Scan (15-30 minutes)  
- Comprehensive port scanning
- Web vulnerability assessment
- SSL/TLS analysis
- Directory enumeration
- Template-based vulnerability scanning

### Passive Scan
- OSINT-only reconnaissance
- No direct target contact
- Subdomain discovery from public sources

### Custom Scan
- User-selected tools and options
- Flexible configuration
- Advanced customization

## 🎨 User Interfaces

### Interactive Mode
- Guided step-by-step configuration
- Visual menu system with emojis
- Real-time progress indicators
- Professional terminal UI

### CLI Mode
- Command-line interface for automation
- Shell completion support
- CI/CD pipeline integration
- Scripting-friendly output

## 📈 Reporting

### PDF Reports
- Executive summaries
- Technical details
- Compliance-ready format

### HTML Reports  
- Static web interface
- Professional formatting
- Legacy support for web viewing

### JSON Output
- Machine-readable format
- API integration ready
- Structured data

### Markdown Reports
- Human-readable documentation
- GitHub-compatible format
- Easy sharing

## 🔧 Development

### Adding New Tools

1. Create new tool file in `tools/`
2. Implement tool interface
3. Add configuration to `config/tool_configs.json`
4. Update scan profiles as needed

Example:
```python
# tools/newtool.py
class NewToolScanner:
    def __init__(self, config):
        self.config = config
    
    def scan(self, target):
        # Implementation here
        pass
```

### Testing

```bash
# Run unit tests
python3 -m pytest tests/unit/

# Run integration tests  
python3 -m pytest tests/integration/

# Run all tests with coverage
python3 -m pytest --cov=. tests/
```

## 📚 Documentation

- **README.md** - This file (project overview)
- **user_guide.md** - Detailed user instructions
- **developer_guide.md** - Development documentation
- **api_reference.md** - API documentation

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit pull request

## 📝 License

MIT License - See LICENSE file for details

## 🔗 Links

- **GitHub Repository**: [https://github.com/quietcod/Python-Ethical-Hacking](https://github.com/quietcod/Python-Ethical-Hacking)
- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/quietcod/Python-Ethical-Hacking/issues)

---

**Built with ❤️ for the security community**
