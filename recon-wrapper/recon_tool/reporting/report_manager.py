"""
Report Manager
Centralized report generation and management
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

from .base_reporter import JSONReportGenerator, MarkdownReportGenerator
from .html_reporter import HTMLReportGenerator
from ..core.exceptions import ScanError

try:
    from .pdf_reporter import PDFReportGenerator
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False


class ReportManager:
    """Manages multi-format report generation"""
    
    def __init__(self, output_dir: Path, config: Optional[Dict[str, Any]] = None):
        self.output_dir = Path(output_dir)
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Available report generators
        self.generators = {
            'json': JSONReportGenerator,
            'markdown': MarkdownReportGenerator,
            'html': HTMLReportGenerator,
        }
        
        if PDF_AVAILABLE:
            self.generators['pdf'] = PDFReportGenerator
        else:
            self.logger.warning("PDF report generation not available - install reportlab package")
    
    def generate_reports(self, results: Dict[str, Any], target: str, 
                        formats: Optional[List[str]] = None) -> Dict[str, str]:
        """Generate reports in specified formats"""
        
        if formats is None:
            formats = ['json', 'markdown', 'html']
        
        # Filter out unavailable formats
        available_formats = [f for f in formats if f in self.generators]
        unavailable_formats = [f for f in formats if f not in self.generators]
        
        if unavailable_formats:
            self.logger.warning(f"Unavailable report formats: {unavailable_formats}")
        
        if not available_formats:
            raise ScanError("No available report formats specified")
        
        generated_reports = {}
        
        for format_name in available_formats:
            try:
                self.logger.info(f"Generating {format_name.upper()} report...")
                
                # Create generator instance
                generator_class = self.generators[format_name]
                generator = generator_class(
                    output_dir=self.output_dir,
                    results=results,
                    target=target,
                    config=self.config
                )
                
                # Generate report
                report_file = generator.generate_report()
                generated_reports[format_name] = report_file
                
                self.logger.info(f"✅ {format_name.upper()} report generated: {report_file}")
                
            except Exception as e:
                self.logger.error(f"❌ Failed to generate {format_name.upper()} report: {str(e)}")
                # Don't stop generation of other formats
                continue
        
        if not generated_reports:
            raise ScanError("Failed to generate any reports")
        
        return generated_reports
    
    def get_available_formats(self) -> List[str]:
        """Get list of available report formats"""
        return list(self.generators.keys())
    
    def is_format_available(self, format_name: str) -> bool:
        """Check if a report format is available"""
        return format_name in self.generators
    
    def load_scan_results(self, results_file: Path) -> Dict[str, Any]:
        """Load scan results from JSON file"""
        try:
            with open(results_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load scan results from {results_file}: {str(e)}")
            raise ScanError(f"Failed to load scan results: {str(e)}")
    
    def generate_reports_from_file(self, results_file: Path, target: str,
                                  formats: Optional[List[str]] = None) -> Dict[str, str]:
        """Generate reports from existing scan results file"""
        
        # Load results
        results = self.load_scan_results(results_file)
        
        # Generate reports
        return self.generate_reports(results, target, formats)
    
    def get_report_summary(self, reports: Dict[str, str]) -> Dict[str, Any]:
        """Get summary of generated reports"""
        summary = {
            'total_reports': len(reports),
            'formats': list(reports.keys()),
            'files': {},
            'total_size': 0
        }
        
        for format_name, file_path in reports.items():
            try:
                file_path_obj = Path(file_path)
                if file_path_obj.exists():
                    file_size = file_path_obj.stat().st_size
                    summary['files'][format_name] = {
                        'path': str(file_path),
                        'size': file_size,
                        'size_human': self._format_file_size(file_size)
                    }
                    summary['total_size'] += file_size
                else:
                    summary['files'][format_name] = {
                        'path': str(file_path),
                        'size': 0,
                        'size_human': 'File not found'
                    }
            except Exception as e:
                self.logger.error(f"Error getting file info for {file_path}: {str(e)}")
                summary['files'][format_name] = {
                    'path': str(file_path),
                    'size': 0,
                    'size_human': 'Error'
                }
        
        summary['total_size_human'] = self._format_file_size(summary['total_size'])
        return summary
    
    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        
        return f"{size_bytes:.1f} {size_names[i]}"
    
    def cleanup_old_reports(self, keep_days: int = 30) -> int:
        """Clean up old report files"""
        from datetime import datetime, timedelta
        
        reports_dir = self.output_dir / 'reports'
        if not reports_dir.exists():
            return 0
        
        cutoff_date = datetime.now() - timedelta(days=keep_days)
        removed_count = 0
        
        try:
            for report_file in reports_dir.rglob('*.*'):
                if report_file.is_file():
                    # Get file modification time
                    mtime = datetime.fromtimestamp(report_file.stat().st_mtime)
                    
                    if mtime < cutoff_date:
                        try:
                            report_file.unlink()
                            removed_count += 1
                            self.logger.debug(f"Removed old report: {report_file}")
                        except Exception as e:
                            self.logger.error(f"Failed to remove {report_file}: {str(e)}")
            
            self.logger.info(f"Cleaned up {removed_count} old report files")
            return removed_count
            
        except Exception as e:
            self.logger.error(f"Error during report cleanup: {str(e)}")
            return 0
