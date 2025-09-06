#!/usr/bin/env python3
"""
Tool Index - Clean Architecture
Central registry for all reconnaissance tools
"""

# Tool Categories and Registry
TOOL_REGISTRY = {
    "network": {
        "nmap": {
            "name": "Nmap",
            "description": "Comprehensive port scanning and service detection",
            "module": "tools.nmap",
            "class": "NmapScanner",
            "category": "network_scanning",
            "primary": True,
            "specialization": "comprehensive_port_analysis"
        },
        "masscan": {
            "name": "Masscan", 
            "description": "High-speed port discovery and enumeration",
            "module": "tools.masscan",
            "class": "MasscanScanner",
            "category": "network_scanning",
            "primary": False,
            "specialization": "high_speed_port_discovery"
        }
    },
    
    "web": {
        "nikto": {
            "name": "Nikto",
            "description": "Web vulnerability scanner",
            "module": "tools.nikto", 
            "class": "NiktoScanner",
            "category": "web_vulnerability"
        },
        "gobuster": {
            "name": "Gobuster",
            "description": "Fast directory and file brute forcing",
            "module": "tools.gobuster",
            "class": "GobusterScanner", 
            "category": "directory_enum",
            "primary": True,
            "specialization": "fast_directory_discovery"
        },
        "wfuzz": {
            "name": "Wfuzz",
            "description": "Advanced web application parameter fuzzing",
            "module": "tools.wfuzz",
            "class": "WfuzzFuzzer",
            "category": "parameter_fuzzing",
            "primary": True,
            "specialization": "advanced_web_fuzzing"
        },
        "httpx": {
            "name": "Httpx",
            "description": "Fast HTTP probe and analysis",
            "module": "tools.httpx",
            "class": "HttpxProbe",
            "category": "web_discovery"
        },
        "curl_probe": {
            "name": "Curl Probe",
            "description": "HTTP probing using curl",
            "module": "tools.curl_probe",
            "class": "CurlProbe",
            "category": "web_discovery"
        },
        "katana": {
            "name": "Katana",
            "description": "Active web crawling and subdomain discovery",
            "module": "tools.katana",
            "class": "KatanaCrawler",
            "category": "web_crawling",
            "primary": False,
            "specialization": "active_subdomain_crawling"
        },
        "aquatone": {
            "name": "Aquatone",
            "description": "Visual web reconnaissance",
            "module": "tools.aquatone",
            "class": "AquatoneScreenshot",
            "category": "web_visual"
        }
    },
    
    "osint": {
        "subfinder": {
            "name": "Subfinder",
            "description": "Fast passive subdomain enumeration",
            "module": "tools.subfinder",
            "class": "SubfinderScanner",
            "category": "subdomain_enum",
            "primary": True,
            "specialization": "fast_passive_subdomains"
        },
        "amass": {
            "name": "Amass", 
            "description": "Comprehensive OSINT asset discovery and enumeration",
            "module": "tools.amass",
            "class": "AmassEnumerator",
            "category": "comprehensive_osint",
            "primary": True,
            "specialization": "comprehensive_asset_discovery"
        },
        "theharvester": {
            "name": "TheHarvester",
            "description": "Email and contact information gathering",
            "module": "tools.theharvester",
            "class": "TheHarvesterOSINT",
            "category": "contact_osint",
            "primary": True,
            "specialization": "email_contact_gathering"
        },
        "waybackurls": {
            "name": "Waybackurls",
            "description": "Historical URL and subdomain discovery",
            "module": "tools.waybackurls", 
            "class": "WaybackurlsDiscovery",
            "category": "historical_data",
            "primary": False,
            "specialization": "historical_subdomain_discovery"
        },
        "shodan": {
            "name": "Shodan",
            "description": "Internet infrastructure and IoT device discovery",
            "module": "tools.shodan",
            "class": "ShodanScanner",
            "category": "internet_search",
            "primary": True,
            "specialization": "iot_infrastructure_discovery"
        },
        "censys": {
            "name": "Censys",
            "description": "Certificate and network infrastructure analysis",
            "module": "tools.censys",
            "class": "CensysScanner", 
            "category": "certificate_analysis",
            "primary": True,
            "specialization": "certificate_infrastructure_analysis"
        }
    },
    
    "legacy": {
        "dirb": {
            "name": "Dirb",
            "description": "Legacy directory scanning (use Gobuster instead)",
            "module": "tools.dirb",
            "class": "DirbScanner",
            "category": "legacy_directory",
            "deprecated": True,
            "replacement": "gobuster"
        },
        "fierce": {
            "name": "Fierce",
            "description": "Legacy domain enumeration (use DNSRecon instead)",
            "module": "tools.fierce",
            "class": "FierceScanner",
            "category": "legacy_dns",
            "deprecated": True,
            "replacement": "dnsrecon"
        }
    },
    
    "dns": {
        "dnsrecon": {
            "name": "DNSRecon",
            "description": "Comprehensive DNS enumeration and reconnaissance",
            "module": "tools.dnsrecon",
            "class": "DNSReconEnumerator",
            "category": "dns_enum",
            "primary": True,
            "specialization": "comprehensive_dns_analysis"
        }
    },
    
    "ssl": {
        "sslscan": {
            "name": "SSLScan",
            "description": "Fast SSL/TLS cipher and protocol analysis",
            "module": "tools.sslscan",
            "class": "SSLScanner",
            "category": "ssl_quick_scan",
            "primary": False,
            "specialization": "fast_ssl_enumeration"
        },
        "testssl": {
            "name": "Testssl",
            "description": "Comprehensive SSL/TLS vulnerability assessment",
            "module": "tools.testssl",
            "class": "TestsslScanner",
            "category": "ssl_security_audit",
            "primary": True,
            "specialization": "comprehensive_ssl_security"
        }
    },
    
    "vulnerability": {
        "nuclei": {
            "name": "Nuclei",
            "description": "Template-based vulnerability scanner",
            "module": "tools.nuclei",
            "class": "NucleiScanner",
            "category": "vuln_scanning"
        }
    }
}

# Optimized Scan Profile Presets - Complementary Tool Usage
SCAN_PROFILES = {
    "quick": {
        "tools": ["masscan", "subfinder", "sslscan", "gobuster"],  # Fast complementary tools
        "description": "Fast reconnaissance (3-5 minutes) - Speed optimized with complementary tools"
    },
    "full": {
        "tools": ["nmap", "masscan", "amass", "nikto", "gobuster", 
                 "testssl", "nuclei", "httpx", "dnsrecon", "wfuzz"],  # Comprehensive + complementary
        "description": "Comprehensive assessment (15-30 minutes) - Full coverage with complementary scanning"
    },
    "passive": {
        "tools": ["subfinder", "amass", "theharvester", "waybackurls", "shodan", "censys"],
        "description": "OSINT-only, no direct target contact - Passive enumeration"
    },
    "web_focused": {
        "tools": ["httpx", "nikto", "gobuster", "katana", "wfuzz", "testssl", 
                 "nuclei", "aquatone"],  # Web tools with active subdomain discovery
        "description": "Web application security assessment - Includes active subdomain crawling"
    },
    "network_focused": {
        "tools": ["masscan", "nmap", "dnsrecon"],  # Fast discovery + comprehensive analysis
        "description": "Network infrastructure assessment - Complementary port scanning"
    },
    "ssl_audit": {
        "tools": ["sslscan", "testssl"],  # Both specialized SSL tools
        "description": "Complete SSL/TLS security assessment - Fast + comprehensive"
    },
    "dns_deep": {
        "tools": ["dnsrecon"],  # Primary DNS tool
        "description": "Comprehensive DNS enumeration and analysis"
    },
    "subdomain_comprehensive": {
        "tools": ["subfinder", "amass", "waybackurls", "katana", "dnsrecon"],  # All subdomain methods
        "description": "Complete subdomain discovery - Passive, active, historical, and DNS"
    },
    "port_comprehensive": {
        "tools": ["masscan", "nmap"],  # Complementary port scanning approach
        "description": "Complete port analysis - High-speed discovery + comprehensive analysis"
    },
    "osint_comprehensive": {
        "tools": ["subfinder", "amass", "theharvester", "waybackurls", "shodan", 
                 "censys"],  # All OSINT tools
        "description": "Complete OSINT gathering - Subdomains, contacts, infrastructure, historical"
    },
    "directory_enum": {
        "tools": ["gobuster", "wfuzz"],  # Specialized directory tools
        "description": "Complete directory and parameter enumeration"
    }
}

# Complementary Specialization Mappings
COMPLEMENTARY_SPECIALIZATIONS = {
    'high_speed_port_discovery': 'masscan',
    'comprehensive_port_analysis': 'nmap',
    'fast_passive_subdomains': 'subfinder',
    'comprehensive_asset_discovery': 'amass',
    'historical_subdomain_discovery': 'waybackurls', 
    'active_subdomain_crawling': 'katana',
    'fast_directory_discovery': 'gobuster',
    'advanced_web_fuzzing': 'wfuzz',
    'fast_ssl_enumeration': 'sslscan',
    'comprehensive_ssl_security': 'testssl',
    'comprehensive_dns_analysis': 'dnsrecon',
    'email_contact_gathering': 'theharvester',
    'iot_infrastructure_discovery': 'shodan',
    'certificate_infrastructure_analysis': 'censys'
}

def get_tool_info(tool_name):
    """Get tool information by name"""
    # TODO: Implement tool lookup
    pass

def get_tools_by_category(category):
    """Get all tools in a specific category"""
    # TODO: Implement category lookup
    pass

def get_scan_profile(profile_name):
    """Get predefined scan profile"""
    # TODO: Implement profile lookup
    pass

def list_all_tools():
    """List all available tools"""
    # TODO: Implement tool listing
    pass
