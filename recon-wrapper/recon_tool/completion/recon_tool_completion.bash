#!/bin/bash
# Bash completion script for ReconTool
# Place this file in /etc/bash_completion.d/ or source it in your ~/.bashrc

_recon_tool() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Main options
    opts="--domain --ip --targets-file --output-dir --config --full --quick --passive
          --tools --exclude-tools --format --no-report --verbose --quiet --log-file
          --threads --timeout --rate-limit --resume --skip-dns-check --debug --dry-run
          --version --help -d -i -f -o -c -v -q -V -h"

    # Tool choices
    tools="subdomain port web ssl dns network directory api screenshot osint vulnerability"

    # Format choices
    formats="json markdown html all"

    case "${prev}" in
        --domain|-d)
            # Domain completion - could be enhanced with history
            COMPREPLY=()
            return 0
            ;;
        --ip|-i)
            # IP completion - could be enhanced with common IPs
            COMPREPLY=()
            return 0
            ;;
        --targets-file|-f|--config|-c|--log-file|--resume)
            # File completion
            COMPREPLY=( $(compgen -f -- ${cur}) )
            return 0
            ;;
        --output-dir|-o)
            # Directory completion
            COMPREPLY=( $(compgen -d -- ${cur}) )
            return 0
            ;;
        --tools|--exclude-tools)
            # Tool completion
            COMPREPLY=( $(compgen -W "${tools}" -- ${cur}) )
            return 0
            ;;
        --format)
            # Format completion
            COMPREPLY=( $(compgen -W "${formats}" -- ${cur}) )
            return 0
            ;;
        --threads|--timeout|--rate-limit)
            # Numeric completion with suggestions
            case "${prev}" in
                --threads)
                    COMPREPLY=( $(compgen -W "1 5 10 20 50" -- ${cur}) )
                    ;;
                --timeout)
                    COMPREPLY=( $(compgen -W "60 300 600 1200" -- ${cur}) )
                    ;;
                --rate-limit)
                    COMPREPLY=( $(compgen -W "0.5 1.0 2.0 5.0" -- ${cur}) )
                    ;;
            esac
            return 0
            ;;
    esac

    # Complete main options
    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
}

# Register completion function
complete -F _recon_tool recon_tool
complete -F _recon_tool python3\ -m\ recon_tool.main
complete -F _recon_tool ./main.py

# Also provide completion for common usage patterns
_recon_tool_aliases() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local opts="--help --version --domain --ip --quick --full --passive"
    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
}

# Simple alias completions
complete -F _recon_tool_aliases recon
complete -F _recon_tool_aliases rt
