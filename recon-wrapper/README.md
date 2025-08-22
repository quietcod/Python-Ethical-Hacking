<!-- U# 🎯 Recon All-in-One - Enterprise Reconnaissance Framework

A comprehensive, next-generation reconnaissance tool designed for penetration testing, security research, and authorized security assessments. This tool cons## 🎯 Scan Type### 🔍 Full Scan (`--full`)
- **Comprehensive port scanning** with service detection
- **Multi-tool subdomain enumeration** (sublist3r, assetfinder, subfinder)
- **Advanced web application analysis** with Nikto integration
- **SSL/TLS security assessment** with vulnerability testing
- **Enhanced reporting** with risk assessment and compliance mapping
- **Time**: ~15-30 minutes
### 🏃 Fast Scan (`--fast`)
- **Basic port scan** (top 1000 ports with nmap)
- **Quick subdomain enumeration** with primary tools
- **Basic technology detection** and CMS identification
- **Essential OSINT collection** (WHOIS, DNS records)
- **Time**: ~5-10 minutes

### 🔍 Full Scan (`--full`)
- **Comprehensive port scanning** with service detection
- **Multi-tool subdomain enumeration** (sublist3r, assetfinder, subfinder)
- **Advanced web application analysis** with Nikto integration
- **SSL/TLS security assessment** with vulnerability testing
- **Enhanced reporting** with risk assessment and compliance mapping
- **Time**: ~15-30 minutesiple scanning modules** across **comprehensive capability areas** into a single, powerful Python framework with **real-time progress tracking**, **enhanced error handling**, and **enterprise-grade features**.

## 🎯 Overview

**Recon All-in-One** is an enterprise-grade reconnaissance framework that integrates modern security tools and techniques for comprehensive target assessment. Built for security professionals, penetration testers, and bug bounty hunters with advanced features including **progress bars**, **intelligent error recovery**, **resource monitoring**, and **comprehensive reporting**.

### 🏆 Key Highlights
- **Real-time progress tracking** with tqdm integration
- **Enhanced error handling** with intelligent suggestions
- **Resource monitoring** and performance optimization
- **Modern tool integration** (nmap, nikto, sublist3r, masscan)
- **Advanced vulnerability detection** with SSL/TLS analysis
- **Comprehensive OSINT capabilities** with historical analysis
- **Production-ready** with graceful error handling and fallbacks
- **Multi-format reporting** (JSON, CSV, HTML, PDF)
- **Configuration management** with YAML/JSON support
- **Compliance mapping** (OWASP, NIST, PCI DSS)ons -->
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

### **1. � Real-Time Progress Tracking**
- **Advanced progress bars** with tqdm integration
- **Real-time status updates** for all scanning modules
- **Live discovery notifications** with color-coded output
- **Performance monitoring** and resource usage tracking

### **2. 🛡️ Enhanced Error Handling**
- **Intelligent error recovery** with actionable suggestions
- **API error handling** with rate limit detection
- **Network connectivity fallbacks** with timeout management
- **Tool availability checks** with alternative suggestions

### **3. 🔍 Comprehensive Port Scanning**
- **Nmap integration** with XML output parsing
- **Service detection** and version identification
- **Custom port ranges** and scanning profiles
- **SSL/TLS service discovery** on multiple ports

### **4. 🌐 Advanced DNS Enumeration**
- **Multi-server DNS queries** with fallback servers
- **Subdomain enumeration** with multiple tools (sublist3r, assetfinder, subfinder)
- **DNS record analysis** (A, AAAA, MX, TXT, NS, SOA)
- **Zone transfer testing** and DNSSEC validation

### **5. 🕸️ Web Application Analysis**
- **Technology stack detection** with confidence scoring
- **Directory brute-forcing** with custom wordlists
- **CMS detection** (WordPress, Drupal, Joomla)
- **Web vulnerability scanning** with Nikto integration

### **6. 🔒 SSL/TLS Security Analysis**
- **Certificate analysis** with validity checking
- **SSL/TLS vulnerability detection** (Heartbleed, POODLE, BEAST, DROWN)
- **Cipher suite analysis** and weak protocol detection
- **Certificate transparency** log monitoring

### **7. 📸 Visual Intelligence**
- **Screenshot capture** with Selenium/gowitness
- **Visual evidence collection** for reporting
- **Responsive design detection** across multiple resolutions
- **UI/UX analysis** for phishing detection

### **8. �️ OSINT & Intelligence Gathering**
- **WHOIS information** extraction and analysis
- **Historical data** from Wayback Machine
- **Social media profiling** and account discovery
- **Threat intelligence** correlation

### **9. 📊 Advanced Reporting**
- **Multi-format reports** (JSON, CSV, HTML, PDF)
- **Risk assessment** with CVSS scoring
- **Compliance mapping** (OWASP Top 10, NIST, PCI DSS)
- **Executive summaries** with actionable recommendations

### **10. ⚙️ Configuration & Performance**
- **Flexible configuration** with YAML/JSON support
- **Resource monitoring** with CPU/memory tracking
- **Module staggering** for performance optimization
- **Light mode** for resource-constrained environments

## 🚀 Quick Start

### Prerequisites
```bash
# Python 3.7+
sudo apt update
sudo apt install python3 python3-pip

# Core dependencies
pip3 install requests python-whois cryptography selenium tqdm dnspython

# External tools (optional but recommended)
sudo apt install nmap nikto sublist3r assetfinder subfinder gobuster
```

### Basic Usage

```bash
# Navigate to the tool
cd recon-wrapper

# Full reconnaissance scan
python3 recon_all_in_one.py --domain example.com --full

# Fast reconnaissance
python3 recon_all_in_one.py --domain example.com --fast

# IP address scanning
python3 recon_all_in_one.py --ip 192.168.1.1 --full
```

### Advanced Usage Examples

```bash
# Comprehensive security assessment
python3 recon_all_in_one.py --domain example.com --full --verbose

# Light mode for resource-constrained environments
python3 recon_all_in_one.py --domain example.com --fast --light-mode

# Custom configuration and performance tuning
python3 recon_all_in_one.py --domain example.com --full --config custom.json --threads 20

# Offline mode for internal networks
python3 recon_all_in_one.py --ip 10.0.0.1 --full --offline --dns-server 10.0.0.53

# Advanced security scanning with custom ports
python3 recon_all_in_one.py --domain example.com --full --security-ports 443 8443 9443

# Generate reports from existing data
python3 recon_all_in_one.py --domain example.com --reports-only --pdf-reports --csv-export
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
  --domain DOMAIN           Single domain target
  --ip IP                   Single IP target
  --targets-file FILE       File containing multiple targets

Scan Types:
  --fast                    Quick reconnaissance scan
  --full                    Comprehensive assessment (default)

Configuration:
  --config CONFIG           Custom configuration file (JSON/YAML)
  --threads THREADS         Number of threads (default: 10)
  --timeout TIMEOUT         Timeout in seconds (default: 300)
  --verbose, -v             Verbose output

Network & Environment:
  --offline                 Run in offline mode (no external sources)
  --dns-server DNS          Custom DNS server for internal networks
  --cidr CIDR               CIDR range for internal network sweeps
  --light-mode              Reduce resource usage across all modules

Directory Brute Force:
  --dir-wordlist FILE       Custom wordlist for directory brute force
  --rate-limit SECONDS      Rate limit between requests (default: 0)
  --dir-threads THREADS     Threads for directory brute force (default: 10)

Performance & Resource Management:
  --no-stagger              Disable module staggering
  --cooldown SECONDS        Wait time between heavy modules (default: 5)
  --no-resource-monitor     Disable system resource monitoring

Security Analysis:
  --no-security             Skip security analysis (SSL/TLS, vulnerabilities)
  --security-ports PORTS    Ports to check for SSL/TLS services
  --no-cert-transparency    Skip Certificate Transparency log queries
  --security-timeout TIME   Timeout for security checks (default: 30)

Advanced Reporting:
  --no-advanced-reports     Skip advanced reporting features
  --no-risk-assessment      Skip risk scoring and assessment
  --no-compliance           Skip compliance framework analysis
  --reports-only            Generate only reports (skip scanning)
  --pdf-reports             Enable PDF report generation
  --csv-export              Enable CSV data export
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
python3 recon_all_in_one.py --domain client-domain.com --full --verbose

# Internal infrastructure assessment
python3 recon_all_in_one.py --ip 10.0.0.1 --full --offline --dns-server 10.0.0.53
```

### 🐛 Bug Bounty Hunting
```bash
# Comprehensive scope reconnaissance
python3 recon_all_in_one.py --targets-file bug-bounty-scope.txt --full

# Fast reconnaissance for multiple targets
python3 recon_all_in_one.py --domain api.target.com --fast --verbose
```

### 🔬 Security Research
```bash
# Comprehensive security analysis
python3 recon_all_in_one.py --domain research-target.com --full --security-timeout 60

# SSL/TLS focused research
python3 recon_all_in_one.py --domain ssl-test.com --full --security-ports 443 8443 9443
```

## 📊 Performance Benchmarks

| Scan Type | Ports Scanned | Time (avg) | Coverage |
|-----------|---------------|------------|----------|
| Fast | Top 1000 | 5-10 min | Basic |
| Full | Top 10000 | 15-30 min | Comprehensive |

## 🤝 Contributing

Contributions are welcome! Please ensure:
- Code follows Python best practices
- Include comprehensive error handling
- Add appropriate logging and documentation
- Test with various target types
- Maintain ethical use guidelines

## 📈 Version History

### 🎉 **v3.0 - Enterprise Framework** (August 2025)
- **Real-time progress tracking** with tqdm integration
- **Enhanced error handling** with intelligent suggestions
- **Resource monitoring** and performance optimization
- **Advanced configuration** with YAML/JSON support
- **Comprehensive reporting** with PDF/CSV export
- **SSL/TLS security analysis** with vulnerability detection
- **Multi-format output** and compliance mapping
- **Light mode** for resource-constrained environments
- **Module staggering** for performance optimization
- **Production-ready** error handling and fallbacks

### v2.0 - Enhanced Framework (July 2025)
- Enhanced scanning capabilities
- Multi-tool integration
- Advanced vulnerability detection
- Comprehensive OSINT features

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

**🎯 Enterprise reconnaissance made simple. Always hack ethically and legally.**

*"The best offense starts with comprehensive reconnaissance with real-time insights."*

**🎯 Advanced reconnaissance made simple. Always hack ethically and legally.**

*"The best offense starts with comprehensive reconnaissance."*