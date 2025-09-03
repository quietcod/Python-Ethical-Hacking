#!/bin/bash
# ReconTool Setup Script
# This script sets up bash completion and creates convenient aliases

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECON_DIR="$(dirname "$SCRIPT_DIR")"

echo "🔧 ReconTool Setup Script"
echo "=========================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root for system-wide installation
if [[ $EUID -eq 0 ]]; then
    INSTALL_MODE="system"
    COMPLETION_DIR="/etc/bash_completion.d"
    print_status "Running as root - installing system-wide"
else
    INSTALL_MODE="user"
    COMPLETION_DIR="$HOME/.bash_completion.d"
    print_status "Running as user - installing for current user only"
fi

# Create completion directory if it doesn't exist
if [ ! -d "$COMPLETION_DIR" ]; then
    print_status "Creating completion directory: $COMPLETION_DIR"
    mkdir -p "$COMPLETION_DIR"
fi

# Install bash completion
COMPLETION_FILE="$COMPLETION_DIR/recon_tool"
print_status "Installing bash completion to: $COMPLETION_FILE"

if cp "$SCRIPT_DIR/recon_tool_completion.bash" "$COMPLETION_FILE"; then
    print_success "Bash completion installed"
    chmod 644 "$COMPLETION_FILE"
else
    print_error "Failed to install bash completion"
    exit 1
fi

# Add source to .bashrc if not already present (user mode only)
if [ "$INSTALL_MODE" = "user" ]; then
    BASHRC="$HOME/.bashrc"
    COMPLETION_SOURCE="source $COMPLETION_FILE"
    
    if [ -f "$BASHRC" ]; then
        if ! grep -q "recon_tool" "$BASHRC"; then
            print_status "Adding completion source to .bashrc"
            echo "" >> "$BASHRC"
            echo "# ReconTool bash completion" >> "$BASHRC"
            echo "$COMPLETION_SOURCE" >> "$BASHRC"
            print_success "Added to .bashrc"
        else
            print_warning "ReconTool completion already in .bashrc"
        fi
    else
        print_warning ".bashrc not found - you may need to source completion manually"
    fi
fi

# Create convenient aliases
ALIAS_FILE=""
if [ "$INSTALL_MODE" = "system" ]; then
    ALIAS_FILE="/etc/bash_completion.d/recon_tool_aliases"
else
    ALIAS_FILE="$HOME/.bash_aliases"
fi

print_status "Setting up aliases in: $ALIAS_FILE"

# Create alias content
ALIAS_CONTENT="
# ReconTool Aliases
alias recon='python3 -m recon_tool.main'
alias rt='python3 -m recon_tool.main'
alias recon-quick='python3 -m recon_tool.main --quick'
alias recon-full='python3 -m recon_tool.main --full'
alias recon-passive='python3 -m recon_tool.main --passive'
alias recon-version='python3 -m recon_tool.main --version'
alias recon-help='python3 -m recon_tool.main --help'

# ReconTool Helper Functions
recon-domain() {
    if [ -z \"\$1\" ]; then
        echo \"Usage: recon-domain <domain>\"
        return 1
    fi
    python3 -m recon_tool.main --domain \"\$1\"
}

recon-ip() {
    if [ -z \"\$1\" ]; then
        echo \"Usage: recon-ip <ip_address>\"
        return 1
    fi
    python3 -m recon_tool.main --ip \"\$1\"
}

recon-file() {
    if [ -z \"\$1\" ]; then
        echo \"Usage: recon-file <targets_file>\"
        return 1
    fi
    python3 -m recon_tool.main --targets-file \"\$1\"
}
"

# Add aliases to appropriate file
if [ "$INSTALL_MODE" = "user" ]; then
    if [ -f "$ALIAS_FILE" ]; then
        if ! grep -q "ReconTool Aliases" "$ALIAS_FILE"; then
            echo "$ALIAS_CONTENT" >> "$ALIAS_FILE"
            print_success "Aliases added to $ALIAS_FILE"
        else
            print_warning "ReconTool aliases already exist in $ALIAS_FILE"
        fi
    else
        echo "$ALIAS_CONTENT" > "$ALIAS_FILE"
        print_success "Created $ALIAS_FILE with aliases"
    fi
    
    # Add source to .bashrc if needed
    BASHRC="$HOME/.bashrc"
    if [ -f "$BASHRC" ] && [ -f "$ALIAS_FILE" ]; then
        if ! grep -q "\.bash_aliases" "$BASHRC"; then
            echo "" >> "$BASHRC"
            echo "# Source bash aliases" >> "$BASHRC"
            echo "if [ -f ~/.bash_aliases ]; then" >> "$BASHRC"
            echo "    . ~/.bash_aliases" >> "$BASHRC"
            echo "fi" >> "$BASHRC"
            print_success "Added alias sourcing to .bashrc"
        fi
    fi
else
    echo "$ALIAS_CONTENT" > "$ALIAS_FILE"
    print_success "Created system aliases file"
fi

# Test installation
print_status "Testing installation..."

cd "$RECON_DIR"

# Test version
if python3 -m recon_tool.main --version >/dev/null 2>&1; then
    print_success "ReconTool version check passed"
else
    print_error "ReconTool version check failed"
fi

# Test help
if python3 -m recon_tool.main --help >/dev/null 2>&1; then
    print_success "ReconTool help check passed"
else
    print_error "ReconTool help check failed"
fi

echo ""
print_success "Installation completed successfully!"
echo ""
echo "📋 Next Steps:"
echo "  1. Restart your terminal or run: source ~/.bashrc"
echo "  2. Test completion: recon --<TAB><TAB>"
echo "  3. Try aliases:"
echo "     • recon --version"
echo "     • recon-domain example.com"
echo "     • recon-quick --domain example.com"
echo ""
echo "🚀 Available Commands:"
echo "  • recon / rt                    - Main command"
echo "  • recon-quick / recon-full     - Quick modes"
echo "  • recon-domain <domain>        - Scan domain"
echo "  • recon-ip <ip>               - Scan IP"
echo "  • recon-file <file>           - Scan from file"
echo ""
echo "📚 Usage Examples:"
echo "  recon --domain google.com"
echo "  recon --ip 8.8.8.8 --quick"
echo "  recon --targets-file targets.txt --full"
echo ""
print_success "ReconTool is ready to use!"
