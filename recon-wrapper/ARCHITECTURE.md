# Reconnaissance Toolkit Architecture

**Refactored:** 2025-08-23  
**Architecture Distribution:** As Requested

## Component Distribution Summary

### Core Functionality: 11 scanning classes + 23 external tools = 34 components
**File:** `recon_all_in_one.py`

#### Core Scanning Classes (11):
1. **PortScanner** - Network port scanning and service detection
2. **SubdomainEnumerator** - Subdomain discovery and enumeration  
3. **WebScanner** - Web application vulnerability scanning
4. **SSLScanner** - SSL/TLS security analysis
5. **OSINTCollector** - Open source intelligence gathering
6. **Screenshotter** - Visual reconnaissance capture
7. **SecurityScanner** - Comprehensive security analysis
8. **VulnerabilityScanner** - CVE and vulnerability assessment
9. **DirectoryScanner** - Web directory discovery
10. **DNSScanner** - DNS enumeration and analysis
11. **NetworkScanner** - Network topology mapping
12. **APIScanner** - REST API and web service scanner

#### External Tools (23):
- **Port Scanning:** nmap, masscan
- **Subdomain Discovery:** sublist3r, assetfinder, subfinder, amass
- **Web Scanning:** nikto, gobuster, ffuf, feroxbuster, dirb, wfuzz
- **Vulnerability Assessment:** nuclei, sqlmap, testssl
- **OSINT Collection:** theharvester, recon-ng, waybackpy, shodan
- **Network Analysis:** dig, httpx, whatweb, wafw00f

---

### Reporting System: 11 reporting classes + 8 specialized libraries = 19 components
**File:** `recon_report.py`

#### Reporting Classes (11):
1. **RiskScorer** - Risk assessment and scoring
2. **CVSSCalculator** - CVSS vulnerability scoring  
3. **ComplianceMapper** - Security framework compliance mapping
4. **EvidenceCollector** - Evidence gathering and documentation
5. **BaselineTracker** - Security baseline tracking and comparison
6. **CSVExporter** - CSV format export functionality
7. **ExcelExporter** - Excel spreadsheet export with charts
8. **WordExporter** - Microsoft Word document generation
9. **PowerPointExporter** - PowerPoint presentation creation
10. **ReportGenerator** - Standard reporting engine
11. **AdvancedReportGenerator** - Advanced reporting with visualizations

#### Specialized Libraries (8):
- **Visualization:** plotly, matplotlib
- **Document Generation:** jinja2, python-docx, python-pptx
- **Data Processing:** pandas, openpyxl
- **Database:** sqlite3

---

### Infrastructure: 1 wrapper class + 23 core Python libraries = 24 components
**File:** `recon_wrapper_class.py`

#### Wrapper Class (1):
1. **ReconWrapper** - Main orchestration and coordination class

#### Core Python Libraries (23):
- **System:** argparse, os, sys, subprocess, pathlib, tempfile
- **Data:** json, csv, xml, re, base64, hashlib
- **Network:** requests, socket, ssl, urllib, dns, ipaddress
- **Concurrency:** threading, concurrent.futures
- **Utilities:** datetime, time, logging

---

## File Structure

```
recon-wrapper/
├── recon_all_in_one.py          # Core Functionality (34 components)
├── recon_report.py              # Reporting System (19 components)  
├── recon_wrapper_class.py       # Infrastructure (24 components)
├── config.json                  # Configuration
├── README.md                    # Documentation
└── ARCHITECTURE.md             # This file
```

## Usage

```bash
# Single domain scan
python3 recon_all_in_one.py --domain example.com

# Full scan with all components
python3 recon_all_in_one.py --domain example.com --full

# Multiple targets
python3 recon_all_in_one.py --targets-file targets.txt
```

## Total Component Count: 77
- **Core Functionality:** 34 components
- **Reporting System:** 19 components  
- **Infrastructure:** 24 components

---
*Architecture refactored to match exact specifications*
