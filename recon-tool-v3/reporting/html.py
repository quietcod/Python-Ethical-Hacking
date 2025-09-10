#!/usr/bin/env python3
"""
HTML Report Generator - Clean Architecture
Static HTML reports for web viewing (legacy support)
"""

class HTMLReporter:
    """Clean HTML report generation for static reports only"""
    
    def __init__(self, config):
        # Initialize HTML reporter for static reports
        self.config = config
    
    def generate_static_report(self, results):
        """Generate static HTML report for web viewing"""
        # TODO: Implement static HTML report generation
        # This is kept for legacy compatibility
        # Primary output format is PDF
        pass
