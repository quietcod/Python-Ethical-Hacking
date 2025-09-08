# Recon-Tool-v3 Usage Guide

## 🚀 How to Run Recon-Tool-v3

You encountered the "command not found" error because the tool needs to be run from its directory with the proper environment. Here are the correct ways to use it:

### ✅ Method 1: Launcher Script (Recommended)
```bash
cd /home/quietcod/Documents/Python-Ethical-Hacking/recon-tool-v3
./recon-tool-v3.sh -t 192.168.11.134 --profile quick
```

### ✅ Method 2: Direct Python Execution
```bash
cd /home/quietcod/Documents/Python-Ethical-Hacking/recon-tool-v3
source .venv/bin/activate
python main.py -t 192.168.11.134 --profile quick
```

### ✅ Method 3: Create System Alias
Add this to your `~/.bashrc` or `~/.zshrc`:
```bash
alias recon-tool-v3='cd /home/quietcod/Documents/Python-Ethical-Hacking/recon-tool-v3 && ./recon-tool-v3.sh'
```

Then reload your shell:
```bash
source ~/.bashrc  # or ~/.zshrc
```

After that, you can run from anywhere:
```bash
recon-tool-v3 -t 192.168.11.134 --profile quick
```

## 🔧 Installing Missing Tools

The "quick" profile failed because some tools are missing. Install them:

### On Kali Linux/Debian:
```bash
# Install common recon tools
sudo apt update
sudo apt install -y nmap masscan subfinder gobuster sslscan testssl.sh

# Install Go tools (if not available via apt)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/OJ/gobuster/v3@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

### On Other Systems:
```bash
# Using snap
sudo snap install subfinder
sudo snap install gobuster

# Or download releases directly from GitHub
```

## 🎯 Working Examples

### Basic Scans (with available tools):
```bash
# Use only nmap (usually available)
./recon-tool-v3.sh -t 192.168.11.134 --tools nmap

# Network-focused scan
./recon-tool-v3.sh -t 192.168.11.134 --profile network_focused

# Passive OSINT only
./recon-tool-v3.sh -t example.com --profile passive
```

### Advanced Scans (after installing tools):
```bash
# Quick scan (3-5 minutes)
./recon-tool-v3.sh -t 192.168.11.134 --profile quick

# Full comprehensive scan (15-30 minutes)
./recon-tool-v3.sh -t 192.168.11.134 --profile full

# Web application focused
./recon-tool-v3.sh -t example.com --profile web_focused
```

### Custom Tool Selection:
```bash
# Specific tools only
./recon-tool-v3.sh -t 192.168.11.134 --tools nmap,dnsrecon

# Complementary port scanning
./recon-tool-v3.sh -t 192.168.11.134 --profile port_comprehensive
```

## 📊 Available Profiles

- **quick**: Fast scan (masscan, subfinder, sslscan, gobuster)
- **full**: Comprehensive assessment (10 tools)
- **passive**: OSINT-only, no direct contact
- **web_focused**: Web application security
- **network_focused**: Network infrastructure
- **port_comprehensive**: Masscan + Nmap (complementary)
- **subdomain_comprehensive**: All subdomain discovery methods

## 🎮 Interactive Mode

For a guided experience:
```bash
./recon-tool-v3.sh -t 192.168.11.134 --interactive
```

## 📁 Output

Results are saved in:
- `results/reports/` - Generated reports (JSON, HTML, PDF)
- `results/raw_output/` - Raw tool outputs
- `logs/` - Execution logs

## 🔧 Troubleshooting

1. **Command not found**: Use the launcher script or run from the project directory
2. **Tool errors**: Install missing tools or use profiles with available tools
3. **Permission errors**: Some tools (like masscan) require root privileges
4. **Network issues**: Check firewall and network connectivity

The tool is working correctly - you just need to use the proper execution method!
