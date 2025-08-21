<!-- Usage Instructions -->
cd /home/quiet/Documents/Python-Ethical-Hacking
source recon-env/bin/activate
python recon-wrapper/recon_all_in_one.py [options]


# � Recon All-in-One - Advanced Reconnaissance Framework

A comprehensive, next-generation reconnaissance tool designed for penetration testing, security research, and authorized security assessments. This tool consolidates **42 enhanced methods** across **10 major capability areas** into a single, powerful Python framework.

## 🎯 Overview

**Recon All-in-One** is an enterprise-grade reconnaissance framework that integrates modern security tools and techniques for comprehensive target assessment. Built for security professionals, penetration testers, and bug bounty hunters.

### 🏆 Key Highlights
- **42 enhanced methods** across 4 core scanning classes
- **Modern tool integration** (gobuster, ffuf, feroxbuster, masscan)
- **Advanced vulnerability detection** with CVE mapping
- **Comprehensive OSINT capabilities** 
- **Production-ready** with graceful error handling and fallbacks

## � Enhanced Features

### **1. 🗂️ Enhanced Directory Discovery**
- **gobuster** integration for high-performance discovery
- **ffuf** integration for advanced web fuzzing  
- **feroxbuster** for recursive content discovery
- Multi-tool approach with intelligent fallbacks

### **2. ⚡ Ultra-Fast Port Scanning**
- **Masscan** integration - scan all 65,535 ports in seconds
- **Hybrid scanning** - Masscan discovery + Nmap service detection
- JSON output parsing for structured results

### **3. 🌐 Advanced DNS Enumeration**
- Enhanced DNS security checks (DNSSEC, SPF, DMARC, CAA)
- Zone transfer detection and testing
- DNS over HTTPS support
- Subdomain brute-forcing with comprehensive wordlists

### **4. 🕰️ Wayback Machine & Historical Analysis**
- Historical URL discovery from Internet Archive
- File and directory intelligence from archived snapshots
- Interesting file detection (configs, backups, etc.)
- Temporal security analysis

### **5. 🔍 GitHub OSINT & Dorking**
- GitHub search integration for leaked secrets
- Configuration file discovery (database configs, API keys)
- Source code intelligence gathering
- Security credential detection

### **6. 🎯 Advanced Technology Stack Detection**
- Wappalyzer-style fingerprinting with confidence scoring
- CMS version detection (WordPress, Drupal, Joomla)
- Framework identification (React, Angular, Laravel, Django)
- Server and database technology mapping
- JavaScript library detection

### **7. 🔌 API Fuzzing & Enumeration**
- Comprehensive API endpoint discovery
- HTTP method testing (GET, POST, PUT, DELETE, etc.)
- Parameter fuzzing with injection vectors
- Rate limiting detection and authentication bypass testing

### **8. 🛡️ Comprehensive Vulnerability Scanning**
- Nmap vulnerability scripts integration (vulners, vulscan)
- CVE detection and mapping
- Multi-tool vulnerability assessment
- Automated exploit discovery

### **9. 🔒 SSL/TLS Security Analysis**
- **Heartbleed** detection (CVE-2014-0160)
- **POODLE** vulnerability testing (CVE-2014-3566)
- **BEAST** attack detection (CVE-2011-3389)
- **DROWN** vulnerability scanning (CVE-2016-0800)
- Weak cipher identification and certificate security analysis

### **10. 🕸️ Web Application Security Testing**
- SQL injection detection with error pattern matching
- Cross-Site Scripting (XSS) vulnerability testing
- Local File Inclusion (LFI) detection
- Command injection testing
- Service-specific vulnerability checks (SSH, FTP, databases)

## 🚀 Quick Start

### Prerequisites
```bash
# Python 3.7+
sudo apt update
sudo apt install python3 python3-pip

# Core dependencies
pip3 install requests python-whois cryptography selenium scapy

# External tools (optional but recommended)
sudo apt install nmap nikto gobuster masscan
```

### Basic Usage

```bash
# Navigate to the tool
cd recon-wrapper

# Full reconnaissance scan
python3 recon_all_in_one.py --target example.com --all

# Fast reconnaissance
python3 recon_all_in_one.py --target example.com --fast

# IP address scanning
python3 recon_all_in_one.py --target 192.168.1.1 --full
```

### Advanced Usage Examples

```bash
# Comprehensive security assessment
python3 recon_all_in_one.py --target example.com --security --all-vulns

# API-focused reconnaissance
python3 recon_all_in_one.py --target api.example.com --api-fuzzing --tech-stack

# Ultra-fast port scanning with masscan
python3 recon_all_in_one.py --target 192.168.1.0/24 --ports --masscan

# OSINT and historical analysis
python3 recon_all_in_one.py --target example.com --osint --wayback --github

# Enhanced web application testing
python3 recon_all_in_one.py --target webapp.com --web --enhanced-discovery

# SSL/TLS security analysis
python3 recon_all_in_one.py --target secure.example.com --ssl-analysis
```

### Multiple Target Scanning

```bash
# Create targets file
echo -e "target1.com\ntarget2.com\napi.target3.com" > targets.txt

# Scan multiple targets
python3 recon_all_in_one.py --targets-file targets.txt --full
```

## 📊 Command Line Options

```bash
Usage: python3 recon_all_in_one.py [options]

Target Options:
  --target TARGET           Single target (domain or IP)
  --targets-file FILE       File containing multiple targets

Scan Types:
  --fast                    Quick reconnaissance scan
  --full                    Comprehensive assessment (default)
  --all                     All modules with maximum coverage

Enhanced Features:
  --enhanced-discovery      Use gobuster, ffuf, feroxbuster
  --masscan                 Ultra-fast port scanning
  --api-fuzzing            API endpoint testing and fuzzing
  --tech-stack             Advanced technology detection
  --wayback                Historical analysis via Wayback Machine
  --github                 GitHub OSINT and dorking
  --ssl-analysis           Comprehensive SSL/TLS testing
  --all-vulns              Full vulnerability assessment

Module Selection:
  --ports                  Port scanning only
  --web                    Web application scanning
  --dns                    DNS enumeration
  --osint                  OSINT collection
  --security               Security/vulnerability scanning

Configuration:
  --config CONFIG          Custom configuration file
  --threads THREADS        Number of threads (default: 10)
  --timeout TIMEOUT        Timeout in seconds (default: 300)
  --output-dir DIR         Custom output directory
  --verbose, -v            Verbose output
  --quiet, -q              Minimal output
```

## � Scan Types Explained

### 🏃 Fast Scan (`--fast`)
- Basic port scan (top 1000 ports)
- Quick subdomain enumeration
- Basic technology detection
- Essential OSINT collection
- **Time**: ~5-10 minutes

### 🔍 Full Scan (`--full`)
- Comprehensive port scanning with service detection
- Multi-tool subdomain enumeration
- Advanced web application analysis
- SSL/TLS security assessment
- **Time**: ~15-30 minutes

### � All Modules (`--all`)
- Ultra-fast masscan port discovery
- Enhanced directory discovery with multiple tools
- Comprehensive vulnerability scanning
- Advanced OSINT with historical analysis
- API fuzzing and enumeration
- **Time**: ~30-60 minutes

## 📁 Output Structure

```
results/
├── target_20250821_143022/
│   ├── ports/                # Port scan results (nmap, masscan)
│   ├── subdomains/          # Subdomain enumeration
│   ├── web/                 # Web application scans
│   │   ├── directories/     # Directory discovery results
│   │   ├── technology/      # Tech stack detection
│   │   └── vulnerabilities/ # Web vulnerability scans
│   ├── ssl/                 # SSL/TLS analysis
│   ├── osint/               # OSINT collection
│   │   ├── dns/            # DNS enumeration
│   │   ├── wayback/        # Historical analysis
│   │   └── github/         # GitHub dorking results
│   ├── vulnerabilities/    # Security assessments
│   ├── api/                # API fuzzing results
│   ├── reports/            # Final reports (JSON, Markdown)
│   └── logs/               # Detailed scan logs
```

## 🛠️ Core Architecture

### **WebScanner Class** (13 enhanced methods)
- `_enhanced_directory_discovery()` - Multi-tool directory enumeration
- `_detect_technology_stack()` - Advanced fingerprinting
- `api_fuzzing()` - Comprehensive API testing
- `_fuzz_parameters()` - Parameter injection testing

### **PortScanner Class** (3 enhanced methods)
- `masscan_scan()` - Ultra-fast port discovery
- `hybrid_scan()` - Masscan + Nmap combination
- `_parse_masscan_json()` - Structured result parsing

### **OSINTCollector Class** (6 enhanced methods)
- `enhanced_dns_enumeration()` - Advanced DNS analysis
- `wayback_analysis()` - Historical intelligence
- `github_dorking()` - Secret and config discovery

### **SecurityScanner Class** (20 enhanced methods)
- `vulnerability_scan()` - Multi-tool vulnerability assessment
- `_analyze_ssl_vulnerabilities()` - SSL/TLS security testing
- `_check_web_vulnerabilities()` - Web application security

## � Security & Legal Notice

### ⚠️ **IMPORTANT DISCLAIMER**

This tool is designed for **authorized security testing only**.

### ✅ Ethical Use Guidelines
- **Only test systems you own** or have **explicit written permission** to test
- **Respect all applicable laws** and regulations
- **Follow responsible disclosure** practices
- **Use rate limiting** to avoid overwhelming targets
- **Maintain confidentiality** of discovered information

### 🚫 Prohibited Uses
- Unauthorized access or testing
- Malicious attacks on infrastructure
- Data theft or unauthorized access
- Service disruption without permission

## 📚 Real-World Use Cases

### 🎯 Penetration Testing
```bash
# External penetration test
python3 recon_all_in_one.py --target client-domain.com --all --verbose

# Internal infrastructure assessment
python3 recon_all_in_one.py --target 10.0.0.0/8 --ports --masscan
```

### 🐛 Bug Bounty Hunting
```bash
# Comprehensive scope reconnaissance
python3 recon_all_in_one.py --targets-file bug-bounty-scope.txt --all

# API-focused hunting
python3 recon_all_in_one.py --target api.target.com --api-fuzzing --github
```

### 🔬 Security Research
```bash
# Historical vulnerability analysis
python3 recon_all_in_one.py --target research-target.com --wayback --tech-stack

# SSL/TLS security research
python3 recon_all_in_one.py --target ssl-test.com --ssl-analysis --all-vulns
```

## 📊 Performance Benchmarks

| Scan Type | Ports Scanned | Time (avg) | Coverage |
|-----------|---------------|------------|----------|
| Fast | Top 1000 | 5-10 min | Basic |
| Full | Top 10000 | 15-30 min | Comprehensive |
| Masscan | All 65535 | 2-5 min | Complete |
| All Modules | All 65535 + Enhanced | 30-60 min | Maximum |

## 🤝 Contributing

Contributions are welcome! Please ensure:
- Code follows Python best practices
- Include comprehensive error handling
- Add appropriate logging and documentation
- Test with various target types
- Maintain ethical use guidelines

## 📈 Version History

### 🎉 **v2.0 - Enhanced Framework** (August 2025)
- **42 new methods** across 4 core classes
- **Modern tool integration**: gobuster, ffuf, feroxbuster, masscan
- **Advanced vulnerability detection** with CVE mapping
- **Comprehensive OSINT** with GitHub and Wayback Machine
- **API security testing** and technology fingerprinting
- **Production-ready** error handling

### v1.0 - Initial Release
- Basic reconnaissance capabilities
- Core tool integration
- Standard reporting

## 📞 Support

For issues, questions, or contributions:
- **GitHub Issues**: Bug reports and feature requests
- **Documentation**: Check `recon-wrapper/README.md` for detailed usage
- **Security**: Report vulnerabilities responsibly

---

**🎯 Advanced reconnaissance made simple. Always hack ethically and legally.**

*"The best offense starts with comprehensive reconnaissance."*