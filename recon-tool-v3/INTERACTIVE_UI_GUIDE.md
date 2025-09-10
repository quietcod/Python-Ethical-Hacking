# Recon Tool v3.0 - Interactive Terminal Interface

## Overview

The Recon Tool v3.0 now features a professional **LinUtil-style terminal interface** that provides an intuitive, two-panel layout for reconnaissance operations. This interface combines tool selection, scan configuration, real-time output monitoring, and automatic PDF report generation in a single, cohesive terminal application.

## Interface Layout

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
│   • Wfuzz                  ││   4. OS Detection - Operating system         │
│   • Httpx                  ││                                              │
│   • Curl Probe             ││ Live Output:                                 │
│   • Katana                 ││ 🚀 Starting Quick Port Scan of example.com   │
│   • Aquatone               ││ ⚡ Executing nmap scan...                    │
│ 📁 OSINT                   ││ ✅ Scan completed successfully!              │
│   • Subfinder              ││ 📄 Generating PDF report...                 │
│   • Amass                  ││ 📁 PDF Report: /path/to/report.pdf          │
│   • TheHarvester           ││                                              │
│   • Waybackurls            ││ 📊 Results Summary:                          │
│   • Shodan                 ││   • Open ports: 3                           │
│   • Censys                 ││   • Services found: 3                       │
│ 📁 DNS                     ││   • Vulnerabilities: 0                      │
│   • DNSRecon               ││                                              │
│ 📁 SSL                     ││                                              │
│   • SSLScan                ││                                              │
│   • Testssl                ││                                              │
│ 📁 VULNERABILITY           ││                                              │
│   • Nuclei                 ││                                              │
└────────────────────────────┘└──────────────────────────────────────────────┘
[↑↓] Navigate [Enter] Select [t] Target [s] Start [c] Clear [q] Quit
```

## Key Features

### 🎯 **Two-Panel Design**
- **Left Panel**: Tool selection with categorical organization
- **Right Panel**: Scan options, real-time output, and results

### 🔧 **Tool Categories**
- **NETWORK**: Port scanning and network discovery (Nmap, Masscan)
- **WEB**: Web application testing (Nikto, Gobuster, Wfuzz, Httpx, etc.)
- **OSINT**: Open-source intelligence gathering (Subfinder, Amass, etc.)
- **DNS**: DNS enumeration and analysis (DNSRecon)
- **SSL**: SSL/TLS security assessment (SSLScan, Testssl)
- **VULNERABILITY**: Vulnerability scanning (Nuclei)

### 📊 **Scan Types Per Tool**
Each tool offers multiple scan configurations:

**Network Tools**:
- Quick Port Scan
- Full Port Scan  
- Service Detection
- OS Detection

**Web Tools**:
- Quick Web Scan
- Comprehensive Scan
- SSL/TLS Check

**OSINT Tools**:
- Passive Discovery
- DNS Bruteforce
- Certificate Transparency

### 🚀 **Real-time Features**
- Live scan output display
- Progress indicators
- Automatic PDF report generation
- Results summary with counts

## Navigation & Controls

### Keyboard Navigation
- **↑↓ Arrow Keys**: Navigate through tools or scan options
- **←→ Arrow Keys**: Switch between left and right panels
- **Enter**: Select a tool or scan type
- **'t' Key**: Set target domain/IP
- **'s' Key**: Start the selected scan
- **'c' Key**: Clear output area
- **'q' or ESC**: Quit the interface

### Workflow
1. **Launch Interface**: `python main.py --interactive`
2. **Set Target**: Press 't' and enter your target domain/IP
3. **Select Tool**: Use ↑↓ arrows to navigate and Enter to select
4. **Choose Scan Type**: Navigate scan options and select with Enter
5. **Start Scan**: Press 's' to begin scanning
6. **Monitor Progress**: Watch real-time output in the right panel
7. **Get Results**: PDF report location displayed upon completion

## Usage Examples

### Quick Start
```bash
cd recon-tool-v3
python main.py --interactive
```

### Sample Workflow
1. Press 't' → Enter "example.com"
2. Select "Nmap" from NETWORK tools
3. Choose "Quick Port Scan" 
4. Press 's' to start
5. Monitor output and get PDF report path

## Output & Reports

### PDF Reports
- **Automatic Generation**: Created after each scan completion
- **Professional Format**: Executive and technical report sections
- **Location Display**: Full path shown in the interface
- **Comprehensive Data**: Includes all scan results and analysis

### Real-time Output
- Scan progress indicators
- Live command execution status
- Error handling and reporting
- Results summary with counts

## Technical Details

### Requirements
- Python 3.8+
- Linux/macOS (uses built-in curses library)
- All reconnaissance tools installed separately

### Dependencies
```bash
# Core UI (built-in)
curses  # Terminal UI framework

# Report Generation
reportlab>=4.0.0     # PDF generation
matplotlib>=3.5.0    # Charts and graphs
```

### Directory Structure
```
recon-tool-v3/
├── ui/
│   └── interactive.py    # New LinUtil-style interface
├── reporting/
│   ├── report_manager.py
│   └── generators/
│       └── pdf_generator.py
└── results/
    └── reports/          # Generated PDF reports
```

## Error Handling

### Tool Availability
- Graceful handling of missing tools
- Clear error messages in the interface
- Fallback options suggested

### Target Validation
- Input validation for domains/IPs
- Clear feedback for invalid targets
- Format guidance provided

### Scan Failures
- Error display in real-time
- Partial results preservation
- Recovery suggestions

## Advanced Features

### Color Coding
- **Blue**: Headers and titles
- **Yellow**: Warnings and progress
- **Green**: Success messages
- **Red**: Error messages
- **Cyan**: Information and help
- **White/Black**: Selection highlights

### Multi-threading
- Background scan execution
- Non-blocking UI updates
- Responsive interface during scans

### Memory Management
- Efficient output buffering
- Automatic cleanup of old data
- Resource optimization

## Customization

### Scan Profiles
The interface supports all existing scan profiles:
- Quick, Full, Passive
- Web-focused, Network-focused, OSINT-focused
- Custom tool combinations

### Report Formats
- PDF (primary output)
- JSON (raw data)
- HTML (legacy support)

## Troubleshooting

### Common Issues
1. **Terminal too small**: Resize to at least 80x24
2. **Missing tools**: Install reconnaissance tools separately
3. **Permission errors**: Check file permissions for report directory

### Debug Mode
```bash
python main.py --interactive --debug
```

## Comparison with Previous Interface

| Feature | Old CLI | New TUI |
|---------|---------|---------|
| Interface | Command-line only | Two-panel visual |
| Tool Selection | Manual typing | Visual navigation |
| Scan Progress | Minimal feedback | Real-time output |
| Results | Separate files | Integrated display |
| User Experience | Technical | User-friendly |
| PDF Reports | Manual generation | Automatic |

## Future Enhancements

### Planned Features
- **Multi-target support**: Scan multiple targets simultaneously
- **Scan scheduling**: Automated periodic scans
- **Result comparison**: Compare scan results over time
- **Export options**: Additional output formats
- **Plugin system**: Custom tool integration

### Performance Optimizations
- **Async scanning**: Parallel tool execution
- **Result caching**: Faster repeat scans
- **Memory optimization**: Large target handling
- **Network optimization**: Bandwidth management

---

The new interactive interface transforms the Recon Tool v3.0 into a professional, user-friendly reconnaissance platform while maintaining all the powerful features of the command-line version. The LinUtil-inspired design provides an intuitive workflow for security professionals and penetration testers.
