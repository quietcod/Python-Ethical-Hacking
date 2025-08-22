# Reconnaissance Toolkit Architecture v2.0

**Refactored:** 2025-08-23  
**Version:** 2.0  
**Architecture Distribution:** Optimized Component Structure

## Component Distribution Summary

### Core Functionality: 11 scanning classes + 23 external tools = 34 components
**File:** `recon_all_in_one.py` (5,677 lines)

#### Core Scanning Classes (11):
1. **PortScanner** - Network port scanning and service detection (Nmap, Masscan)
2. **SubdomainEnumerator** - Subdomain discovery and enumeration (DNS, Zone Transfer, SAN)
3. **WebScanner** - Web application vulnerability scanning (Nikto, Tech Stack Detection)
4. **SSLScanner** - SSL/TLS security analysis (Certificate validation, Cipher analysis)
5. **OSINTCollector** - Open source intelligence gathering (DNS, Wayback, GitHub)
6. **Screenshotter** - Visual reconnaissance capture (Selenium, Screenshot automation)
7. **SecurityScanner** - Comprehensive security analysis (Multi-vector assessment)
8. **VulnerabilityScanner** - CVE and vulnerability assessment (Nuclei, Vulners)
9. **DirectoryScanner** - Web directory discovery (Gobuster, FFUF, Feroxbuster)
10. **DNSScanner** - DNS enumeration and analysis (Zone transfer, DNSSEC)
11. **NetworkScanner** - Network topology mapping (Traceroute, Host discovery)
12. **APIScanner** - REST API and web service scanner (Endpoint discovery, CORS)

#### External Tools (23):
- **Port Scanning:** nmap, masscan
- **Subdomain Discovery:** sublist3r, assetfinder, subfinder, amass
- **Web Scanning:** nikto, gobuster, ffuf, feroxbuster, dirb, wfuzz
- **Vulnerability Assessment:** nuclei, sqlmap, testssl
- **OSINT Collection:** theharvester, recon-ng, waybackpy, shodan
- **Network Analysis:** dig, httpx, whatweb, wafw00f

---

### Reporting System: 11 reporting classes + 8 specialized libraries = 19 components
**File:** `recon_report.py` (1,313 lines)

#### Reporting Classes (11):
1. **RiskScorer** - Risk assessment and scoring algorithms
2. **CVSSCalculator** - CVSS v3.1 vulnerability scoring implementation
3. **ComplianceMapper** - Security framework compliance mapping (OWASP, NIST)
4. **EvidenceCollector** - Evidence gathering and documentation automation
5. **BaselineTracker** - Security baseline tracking and comparison analysis
6. **CSVExporter** - CSV format export with data validation
7. **ExcelExporter** - Excel spreadsheet export with charts and pivot tables
8. **WordExporter** - Microsoft Word document generation with templates
9. **PowerPointExporter** - PowerPoint presentation creation with graphics
10. **ReportGenerator** - Standard reporting engine (JSON, HTML, Markdown)
11. **AdvancedReportGenerator** - Advanced reporting with interactive visualizations

#### Specialized Libraries (8):
- **Visualization:** plotly (interactive charts), matplotlib (static plots)
- **Document Generation:** jinja2 (templating), python-docx (Word), python-pptx (PowerPoint)
- **Data Processing:** pandas (analysis), openpyxl (Excel manipulation)
- **Database:** sqlite3 (evidence storage)

---

### Infrastructure: 1 wrapper class + 23 core Python libraries = 24 components
**File:** `recon_wrapper_class.py` (310 lines)

#### Wrapper Class (1):
1. **ReconWrapper** - Central orchestration and coordination class
   - Multi-target batch processing
   - Resource monitoring and optimization
   - Progress tracking and status reporting
   - Error handling and recovery mechanisms
   - Result consolidation and coordination

#### Core Python Libraries (23):
- **System Interface:** argparse, os, sys, subprocess, pathlib, tempfile
- **Data Processing:** json, csv, xml, re, base64, hashlib
- **Network Operations:** requests, socket, ssl, urllib, dns, ipaddress
- **Concurrency Management:** threading, concurrent.futures
- **Utilities:** datetime, time, logging

---

## Performance Metrics

### Code Statistics:
- **Total Lines of Code:** 7,300+
- **Core Module:** 5,677 lines (77.8%)
- **Reporting Module:** 1,313 lines (18.0%)
- **Infrastructure Module:** 310 lines (4.2%)

### Scanning Capabilities:
- **Concurrent Threads:** Configurable (default: 20)
- **Timeout Management:** Per-tool timeout controls
- **Resource Monitoring:** CPU, Memory, Network usage
- **Error Recovery:** Automatic fallback mechanisms

---

## File Structure

```
recon-wrapper/
├── recon_all_in_one.py          # Core Functionality (34 components)
├── recon_report.py              # Reporting System (19 components)  
├── recon_wrapper_class.py       # Infrastructure (24 components)
├── config.json                  # Configuration management
├── ARCHITECTURE.md              # Architecture documentation
├── README.md                    # User documentation
└── run_recon.sh                 # Execution wrapper script
```

## Usage Examples

### Basic Scanning
```bash
# Single domain reconnaissance
python3 recon_all_in_one.py --domain example.com

# IP address scanning
python3 recon_all_in_one.py --ip 192.168.1.1

# Fast scan mode
python3 recon_all_in_one.py --domain example.com --fast
```

### Advanced Operations
```bash
# Full comprehensive scan
python3 recon_all_in_one.py --domain example.com --full

# Multiple targets from file
python3 recon_all_in_one.py --targets-file targets.txt

# Offline mode for internal networks
python3 recon_all_in_one.py --domain internal.company.com --offline

# Custom configuration
python3 recon_all_in_one.py --domain example.com --config custom.json
```

### Report Generation
```bash
# Generate comprehensive reports
python3 recon_all_in_one.py --domain example.com --generate-reports

# Export to multiple formats
python3 recon_all_in_one.py --domain example.com --export-formats json,csv,html
```

## Security Considerations

### Ethical Usage:
- ⚠️ **Authorization Required:** Only scan systems you own or have explicit permission to test
- 🔒 **Responsible Disclosure:** Report vulnerabilities through proper channels
- 📋 **Compliance:** Ensure scans comply with local laws and regulations

### Rate Limiting:
- **Default Limits:** Conservative scanning rates to avoid system overload
- **Configurable:** Adjustable rate limits for different environments
- **Detection Avoidance:** Built-in delays and randomization options

---

## Total Component Count: 77
- **Core Functionality:** 34 components (47.3%)
- **Reporting System:** 19 components (26.4%)  
- **Infrastructure:** 24 components (31.2%)

## Version History
- **v1.0** - Initial architecture refactoring
- **v2.0** - Enhanced documentation, performance metrics, security guidelines

---
*Architecture refactored to match exact specifications with enhanced documentation*
