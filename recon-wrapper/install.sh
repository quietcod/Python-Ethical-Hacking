#!/bin/bash
# Reconnaissance Toolkit - Installation Script v2.0
# Installs required external tools for the 77-component architecture

echo "🔧 Installing Reconnaissance Toolkit Dependencies"
echo "=================================================="

# Update package lists
echo "📦 Updating package lists..."
sudo apt-get update -qq

# Core system tools
echo "🛠️  Installing core system tools..."
sudo apt-get install -y \
    nmap \
    masscan \
    nikto \
    dirb \
    dnsutils \
    whatweb \
    traceroute \
    whois

# Python packages
echo "🐍 Installing Python packages..."
pip3 install --user \
    sublist3r \
    wfuzz \
    wafw00f \
    sqlmap \
    waybackpy \
    shodan \
    requests \
    plotly \
    jinja2 \
    openpyxl \
    python-docx \
    python-pptx \
    pandas \
    matplotlib

# Go-based tools
echo "🚀 Installing Go-based tools..."
if command -v go &> /dev/null; then
    go install github.com/OJ/gobuster/v3@latest
    go install github.com/ffuf/ffuf@latest
    go install github.com/tomnomnom/assetfinder@latest
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    echo "✅ Go tools installed"
else
    echo "⚠️  Go not found. Install Go to use advanced tools."
fi

# Optional tools (downloadable)
echo "📋 Optional tools to install manually:"
echo "  • Amass: https://github.com/OWASP/Amass/releases"
echo "  • Feroxbuster: https://github.com/epi052/feroxbuster/releases"
echo "  • TestSSL: https://github.com/drwetter/testssl.sh"
echo "  • TheHarvester: sudo apt-get install theharvester"
echo "  • Recon-ng: sudo apt-get install recon-ng"

echo ""
echo "✅ Installation complete!"
echo "🎯 Architecture: 77 components across 3 modules"
echo "📚 See ARCHITECTURE.md for detailed component breakdown"
echo ""
echo "Usage examples:"
echo "  python3 recon_all_in_one.py --domain example.com"
echo "  python3 recon_all_in_one.py --help"
