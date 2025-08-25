"""
ReconTool - Professional Reconnaissance Framework
A comprehensive, modular reconnaissance toolkit for security professionals.
"""

__version__ = "1.0.0"
__author__ = "Security Research Team"
__description__ = "Professional reconnaissance framework with advanced scanning capabilities"

from .core import ReconOrchestrator
from .config import ConfigManager

# Main entry point
def main():
    """Main entry point for the reconnaissance tool"""
    from .main import main as main_func
    return main_func()

__all__ = [
    'ReconOrchestrator',
    'ConfigManager',
    'main'
]
