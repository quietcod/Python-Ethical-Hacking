"""
Advanced Reporting System for Recon-Tool-v3
Professional report generation in HTML, PDF, and JSON formats
"""

from .report_manager import ReportManager

# Try to import generators, handle missing dependencies gracefully
try:
    from .generators.html_generator import HTMLReportGenerator
    __all__ = ['ReportManager', 'HTMLReportGenerator']
except ImportError:
    __all__ = ['ReportManager']

try:
    from .generators.simple_html_generator import SimpleHTMLReportGenerator
    __all__.append('SimpleHTMLReportGenerator')
except ImportError:
    pass

try:
    from .generators.pdf_generator import PDFReportGenerator
    __all__.append('PDFReportGenerator')
except ImportError:
    pass

__version__ = "1.0.0"
__author__ = "Recon-Tool-v3 Team"

# Export main classes
# __all__ is set dynamically above based on available generators

# Default report formats
DEFAULT_FORMATS = ['html', 'json']  # Removed PDF for now

# Report type constants
REPORT_TYPES = {
    'EXECUTIVE': 'executive',
    'TECHNICAL': 'technical', 
    'COMPREHENSIVE': 'comprehensive'
}

def create_report_manager(output_dir: str = None) -> ReportManager:
    """
    Factory function to create a ReportManager instance
    
    Args:
        output_dir: Directory to save reports (optional)
        
    Returns:
        Configured ReportManager instance
    """
    return ReportManager(output_dir)

def quick_generate_reports(scan_data: dict, target: str, formats: list = None) -> dict:
    """
    Quick function to generate reports without managing ReportManager instance
    
    Args:
        scan_data: Scan results dictionary
        target: Target being scanned
        formats: List of formats to generate
        
    Returns:
        Dictionary mapping format to file path
    """
    manager = ReportManager()
    return manager.generate_all_reports(scan_data, target, formats)
