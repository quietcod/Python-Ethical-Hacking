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
            "description": "Network port scanning and service detection",
            "module": "tools.nmap",
            "class": "NmapScanner",
            "category": "network_scanning"
        },
        "masscan": {
            "name": "Masscan", 
            "description": "High-speed port scanning",
            "module": "tools.masscan",
            "class": "MasscanScanner",
            "category": "network_scanning"
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
            "description": "Directory and file brute forcing",
            "module": "tools.gobuster",
            "class": "GobusterScanner", 
            "category": "web_enumeration"
        },
        "dirb": {
            "name": "Dirb",
            "description": "Traditional directory scanning",
            "module": "tools.dirb",
            "class": "DirbScanner",
            "category": "web_enumeration"
        },
        "wfuzz": {
            "name": "Wfuzz",
            "description": "Web application fuzzer",
            "module": "tools.wfuzz",
            "class": "WfuzzFuzzer",
            "category": "web_fuzzing"
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
            "description": "Web crawler and endpoint discovery",
            "module": "tools.katana",
            "class": "KatanaCrawler",
            "category": "web_crawling"
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
            "description": "Subdomain enumeration tool",
            "module": "tools.subfinder",
            "class": "SubfinderEnumerator",
            "category": "subdomain_enum"
        },
        "amass": {
            "name": "Amass", 
            "description": "Comprehensive OSINT enumeration",
            "module": "tools.amass",
            "class": "AmassEnumerator",
            "category": "osint_enum"
        },
        "theharvester": {
            "name": "TheHarvester",
            "description": "Email and information gathering",
            "module": "tools.theharvester",
            "class": "TheHarvesterOSINT",
            "category": "osint_gathering"
        },
        "waybackurls": {
            "name": "Waybackurls",
            "description": "Historical URL discovery",
            "module": "tools.waybackurls", 
            "class": "WaybackurlsDiscovery",
            "category": "historical_data"
        },
        "shodan": {
            "name": "Shodan",
            "description": "Internet-connected device discovery",
            "module": "tools.shodan",
            "class": "ShodanScanner",
            "category": "internet_search"
        },
        "censys": {
            "name": "Censys",
            "description": "Internet-wide scanning and discovery",
            "module": "tools.censys",
            "class": "CensysScanner", 
            "category": "internet_search"
        }
    },
    
    "dns": {
        "dnsrecon": {
            "name": "DNSRecon",
            "description": "DNS enumeration and reconnaissance",
            "module": "tools.dnsrecon",
            "class": "DNSReconEnumerator",
            "category": "dns_enum"
        },
        "fierce": {
            "name": "Fierce",
            "description": "Domain scanner and enumerator",
            "module": "tools.fierce",
            "class": "FierceScanner",
            "category": "dns_enum"
        }
    },
    
    "ssl": {
        "sslscan": {
            "name": "SSLScan",
            "description": "SSL/TLS security analysis",
            "module": "tools.sslscan",
            "class": "SSLScanner",
            "category": "ssl_analysis"
        },
        "testssl": {
            "name": "Testssl",
            "description": "Comprehensive SSL/TLS testing",
            "module": "tools.testssl",
            "class": "TestsslScanner",
            "category": "ssl_analysis"
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

# Scan Profile Presets
SCAN_PROFILES = {
    "quick": {
        "tools": ["nmap", "subfinder", "curl_probe"],
        "description": "Fast reconnaissance (5-10 minutes)"
    },
    "full": {
        "tools": ["nmap", "masscan", "subfinder", "amass", "nikto", "gobuster", 
                 "sslscan", "nuclei", "httpx"],
        "description": "Comprehensive assessment (15-30 minutes)"
    },
    "passive": {
        "tools": ["subfinder", "amass", "theharvester", "waybackurls", "shodan", "censys"],
        "description": "OSINT-only, no direct target contact"
    },
    "web_focused": {
        "tools": ["httpx", "nikto", "gobuster", "katana", "wfuzz", "sslscan", 
                 "nuclei", "aquatone"],
        "description": "Web application security assessment"
    },
    "network_focused": {
        "tools": ["nmap", "masscan", "dnsrecon"],
        "description": "Network infrastructure assessment"
    },
    "osint_focused": {
        "tools": ["subfinder", "amass", "theharvester", "waybackurls", "shodan", 
                 "censys", "fierce"],
        "description": "Open source intelligence gathering"
    }
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
