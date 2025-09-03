# 🎯 Interactive Mode Guide

## Overview

The Recon Tool now includes a comprehensive **Interactive Mode** that provides a user-friendly guided interface for configuring and running reconnaissance scans. This feature is perfect for both beginners and experienced users who want a streamlined scanning experience.

## 🚀 Quick Start

### Launch Interactive Mode

```bash
# Method 1: Using the launcher (recommended)
./recon_launcher.py

# Method 2: Direct launch
python3 -m recon_tool.main --interactive

# Method 3: Traditional with interactive flag
python3 recon_tool/main.py --interactive
```

### Default Behavior
When you run `./recon_launcher.py` without any arguments, it automatically launches in interactive mode for ease of use.

## 🎯 Scan Modes

### 1. 🏃 Quick Scan (5-10 minutes)
- **Purpose**: Fast reconnaissance for quick assessment
- **Tools**: Basic port scanning, subdomain enumeration, technology detection
- **Use Case**: Initial target assessment, bug bounty recon, quick checks

### 2. 🔍 Full Scan (15-30 minutes)  
- **Purpose**: Comprehensive security assessment
- **Tools**: All available tools with detailed analysis
- **Use Case**: Penetration testing, security audits, thorough assessment

### 3. 🕵️ Passive Scan
- **Purpose**: OSINT-only reconnaissance (no direct target contact)
- **Tools**: Search intelligence, subdomain enumeration, certificate analysis
- **Use Case**: Stealth reconnaissance, compliance-sensitive environments

### 4. 🎯 Custom Scan
- **Purpose**: Select specific tool categories and individual tools
- **Tools**: User-defined selection from comprehensive toolkit
- **Use Case**: Focused testing, specific tool requirements, custom workflows

## 🔧 Scan Categories & Tools

### 🌐 Network Reconnaissance
- **Port Scanning**: nmap, masscan integration
- **Network Discovery**: Host discovery and topology mapping  
- **DNS Analysis**: DNS enumeration and zone transfer testing
- **Service Detection**: Service version detection and banner grabbing
- **Network Security**: Network security assessment and analysis

### 🕸️ Web Application Testing
- **Technology Detection**: Tech stack and CMS identification
- **Directory Discovery**: Directory and file brute-forcing
- **Web Vulnerabilities**: Web vulnerability scanning with nikto
- **SSL/TLS Analysis**: SSL/TLS security assessment
- **API Testing**: REST/GraphQL API security testing
- **Security Headers**: HTTP security headers analysis

### 🔍 OSINT & Intelligence
- **Subdomain Enumeration**: Comprehensive subdomain discovery
- **Search Engine Intel**: Google dorking and search intelligence
- **Social Media Intel**: Social media and public information gathering
- **Certificate Transparency**: SSL certificate monitoring
- **Breach Database**: Credential breach database checking
- **Wayback Analysis**: Historical website analysis

### 🛡️ Security Assessment
- **Vulnerability Scanning**: Automated vulnerability detection
- **Authentication Testing**: Authentication and authorization testing
- **Input Validation**: Input validation and injection testing
- **Configuration Analysis**: Security configuration assessment
- **Compliance Testing**: OWASP/NIST compliance checking

### 📸 Visual & Documentation
- **Screenshot Capture**: Automated website screenshots
- **Visual Analysis**: Visual website analysis and comparison
- **Report Generation**: Comprehensive report generation

## 📝 Interactive Workflow

### Step 1: Scan Mode Selection
```
🎯 RECON TOOL - INTERACTIVE MODE
================================

🚀 Select Scan Mode:
--------------------------------------------------
  1. 🏃 Quick Scan
     Fast reconnaissance (5-10 minutes)

  2. 🔍 Full Scan  
     Comprehensive assessment (15-30 minutes)

  3. 🕵️ Passive Scan
     OSINT only, no direct target contact

  4. 🎯 Custom Scan
     Select specific tools and categories

  0. Exit
--------------------------------------------------

📝 Enter your choice (0-4):
```

### Step 2: Target Specification
```
🎯 TARGET SPECIFICATION
======================

📝 Target Input Options:
----------------------------------------
  1. Single Domain (e.g., example.com)
  2. IP Address (e.g., 192.168.1.1)  
  3. Target File (e.g., targets.txt)
----------------------------------------

📝 Select target type (1-3):
```

### Step 3: Custom Tool Selection (if Custom Scan)
```
🔧 SELECT SCAN CATEGORIES
========================

🔧 Available Scan Categories:
------------------------------------------------------------
  1. 🌐 Network Reconnaissance
     Network-level scanning and discovery

  2. 🕸️ Web Application Testing
     Web application security assessment

  3. 🔍 OSINT & Intelligence
     Open Source Intelligence gathering

  4. 🛡️ Security Assessment
     Comprehensive security vulnerability testing

  5. 📸 Visual & Documentation
     Visual reconnaissance and documentation

  all. Run All Categories
  0. Back to Main Menu
------------------------------------------------------------
```

### Step 4: Advanced Configuration (Optional)
```
⚙️ Advanced Options:
------------------------------
🧵 Number of threads (default: 10): 
⏱️ Timeout in seconds (default: 300):
📢 Verbose output? (y/N):
🐌 Rate limit between requests in seconds (default: 1):
```

### Step 5: Configuration Summary & Confirmation
```
📋 SCAN CONFIGURATION SUMMARY
=============================

🎯 Target: example.com
📁 Output: ./recon_results  
🔧 Mode: 🔍 Full Scan

🛠️ Selected Tools:
   • port
   • web
   • subdomain
   • ssl

⚙️ Advanced Options:
   • threads: 20
   • verbose: True

============================================================

🚀 Start scan with this configuration? (Y/n):
```

## 🎨 Features & Benefits

### ✨ User Experience
- **Guided Interface**: Step-by-step configuration process
- **Visual Design**: Emoji-rich, color-coded interface
- **Clear Navigation**: Intuitive menu system with breadcrumbs
- **Error Handling**: Helpful error messages and recovery options
- **Confirmation Steps**: Review configuration before execution

### 🔧 Technical Features
- **Tool Mapping**: Automatic mapping from interactive selections to CLI tools
- **Configuration Validation**: Real-time validation of inputs
- **Flexible Target Input**: Support for domains, IPs, and target files
- **Advanced Options**: Optional advanced configuration for power users
- **Backward Compatibility**: Full compatibility with existing CLI arguments

### 🛡️ Security & Safety
- **Input Validation**: Comprehensive validation of all user inputs
- **Safe Defaults**: Conservative default settings to prevent issues
- **Rate Limiting**: Built-in rate limiting to avoid overwhelming targets
- **Permission Checks**: Validation of file permissions and access rights

## 📊 Example Usage Scenarios

### Scenario 1: Bug Bounty Quick Assessment
```bash
./recon_launcher.py
# Choose: Quick Scan
# Target: bugcrowd-target.com
# Output: ./results/bugcrowd
# Start scan → 5-10 minute comprehensive recon
```

### Scenario 2: Penetration Testing Full Assessment
```bash
./recon_launcher.py  
# Choose: Full Scan
# Target: client-domain.com
# Advanced: 20 threads, verbose output
# Start scan → 15-30 minute detailed analysis
```

### Scenario 3: Compliance-Sensitive Environment
```bash
./recon_launcher.py
# Choose: Passive Scan
# Target: internal-domain.company.com
# Start scan → OSINT-only, no direct interaction
```

### Scenario 4: Custom Tool Selection
```bash
./recon_launcher.py
# Choose: Custom Scan
# Categories: Web Application Testing + OSINT
# Tools: Technology Detection, SSL Analysis, Subdomain Enum
# Start scan → Focused assessment
```

## 🔍 Output & Results

### Result Structure
```
recon_results/
├── example.com_20250901_143022/
│   ├── nmap/              # Port scan results
│   ├── web/               # Web application scans  
│   ├── subdomains/        # Subdomain enumeration
│   ├── ssl/               # SSL/TLS analysis
│   ├── osint/             # OSINT collection
│   ├── reports/           # Generated reports
│   └── logs/              # Scan logs
```

### Report Formats
- **JSON**: Machine-readable structured data
- **HTML**: Interactive web-based reports
- **Markdown**: Human-readable summaries  
- **PDF**: Professional documents (optional)

## 🚀 Advanced Usage

### Combining Interactive + CLI
```bash
# Start with interactive, then use CLI arguments
python3 -m recon_tool.main --interactive --threads 20 --verbose
```

### Batch Processing
```bash
# Use interactive mode to configure, then process multiple targets
echo -e "target1.com\ntarget2.com\ntarget3.com" > targets.txt
./recon_launcher.py
# Choose: Full Scan
# Target Type: Target File
# File: targets.txt
```

### Custom Configuration Files
```bash
# Use interactive mode with custom config
python3 -m recon_tool.main --interactive --config custom_config.json
```

## 🐛 Troubleshooting

### Common Issues

#### Interactive Mode Not Available
```bash
❌ Interactive mode not available - missing interactive_menu module
```
**Solution**: Ensure `interactive_menu.py` is in the correct location

#### Import Errors
```bash
❌ Import error: No module named 'recon_tool'
```
**Solution**: Run from the correct directory or use the launcher script

#### Permission Errors
```bash
❌ Cannot write to output directory
```
**Solution**: Check write permissions or specify a different output directory

### Debug Mode
```bash
# Enable debug mode for troubleshooting
python3 -m recon_tool.main --interactive --debug
```

## 📚 Documentation Links

- **Main README**: `README.md` - Full project documentation
- **Architecture**: `ARCHITECTURE.md` - Technical architecture details
- **Feature Roadmap**: `FEATURE_ROADMAP.md` - Future enhancement plans
- **Developer Guide**: `DEVELOPER_GUIDE.md` - Development information

## 🤝 Contributing

The interactive mode is designed to be extensible. To add new features:

1. **New Scan Categories**: Add to `scan_categories` in `InteractiveMenu`
2. **New Tools**: Update tool mapping in `convert_interactive_config_to_args`
3. **UI Improvements**: Enhance the menu system and user experience
4. **Validation**: Add new validation rules for better error handling

## 📝 Changelog

### Version 2.1.0 - Interactive Mode Release
- ✅ Added comprehensive interactive menu system
- ✅ Implemented guided scan configuration  
- ✅ Added visual, emoji-rich interface
- ✅ Created flexible tool selection system
- ✅ Integrated with existing CLI framework
- ✅ Added configuration validation and error handling
- ✅ Created launcher script for easy access

---

**🎯 The interactive mode makes professional reconnaissance accessible to everyone - from security beginners to expert penetration testers!**
