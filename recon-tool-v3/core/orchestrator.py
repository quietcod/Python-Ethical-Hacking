#!/usr/bin/env python3
"""
Reconnaissance Orchestrator - Clean Architecture
Central coordination of all reconnaissance operations
"""

import asyncio
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

class ReconOrchestrator:
    """Central coordinator for reconnaissance operations"""
    
    def __init__(self, config: Dict, logger):
        """Initialize orchestrator with configuration and logger"""
        self.config = config
        self.logger = logger
        self.results = {}
        self.start_time = None
        self.end_time = None
        
    def execute_scan(self, scan_params: Dict) -> Dict:
        """Execute reconnaissance scan with given parameters"""
        self.start_time = datetime.now()
        self.logger.info(f"Starting reconnaissance scan: {scan_params['target']}")
        
        try:
            # Validate target
            target = self._validate_target(scan_params['target'])
            
            # Determine tools to run
            tools_to_run = self._determine_tools(scan_params)
            
            # Execute tools
            self.logger.info(f"Running {len(tools_to_run)} tools: {', '.join(tools_to_run)}")
            tool_results = self._execute_tools(target, tools_to_run, scan_params)
            
            # Process results
            processed_results = self._process_results(tool_results, scan_params)
            
            # Generate output
            try:
                self._generate_output(processed_results, scan_params)
            except Exception as e:
                self.logger.error(f"Output generation failed: {e}")
                # Continue without failing the entire scan
            
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            
            self.logger.info(f"Scan completed in {duration:.1f} seconds")
            
            return {
                'success': True,
                'target': target,
                'tools_executed': tools_to_run,
                'duration_seconds': duration,
                'results': processed_results,
                'output_files': []  # Simplified for now
            }
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            raise
    
    def _validate_target(self, target: str) -> str:
        """Validate and normalize target"""
        from core.validator import TargetValidator
        
        validator = TargetValidator()
        return validator.validate_target(target)
    
    def _determine_tools(self, scan_params: Dict) -> List[str]:
        """Determine which tools to run based on scan parameters"""
        if scan_params.get('tools'):
            # Specific tools requested
            return scan_params['tools']
        
        elif scan_params.get('profile'):
            # Profile-based tool selection
            from tools import SCAN_PROFILES
            profile = scan_params['profile']
            
            if profile in SCAN_PROFILES:
                return SCAN_PROFILES[profile]['tools']
            else:
                raise ValueError(f"Unknown scan profile: {profile}")
        
        else:
            # Default to quick profile
            from tools import SCAN_PROFILES
            return SCAN_PROFILES['quick']['tools']
    
    def _execute_tools(self, target: str, tools: List[str], scan_params: Dict) -> Dict:
        """Execute specified tools against target"""
        results = {}
        
        for tool_name in tools:
            self.logger.info(f"Running {tool_name}...")
            
            try:
                tool_result = self._execute_single_tool(tool_name, target, scan_params)
                results[tool_name] = {
                    'success': True,
                    'data': tool_result,
                    'timestamp': datetime.now().isoformat()
                }
                self.logger.info(f"✅ {tool_name} completed successfully")
                
            except Exception as e:
                self.logger.error(f"❌ {tool_name} failed: {e}")
                results[tool_name] = {
                    'success': False,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                }
        
        return results
    
    def _execute_single_tool(self, tool_name: str, target: str, scan_params: Dict) -> Dict:
        """Execute a single reconnaissance tool"""
        from tools import TOOL_REGISTRY
        
        # Find tool in registry
        tool_info = None
        for category, tools in TOOL_REGISTRY.items():
            if tool_name in tools:
                tool_info = tools[tool_name]
                break
        
        if not tool_info:
            raise ValueError(f"Unknown tool: {tool_name}")
        
        # Import and instantiate tool
        module_name = tool_info['module']
        class_name = tool_info['class']
        
        try:
            # Dynamic import
            module = __import__(module_name, fromlist=[class_name])
            tool_class = getattr(module, class_name)
            
            # Create tool instance
            tool_instance = tool_class(self.config, self.logger)
            
            # Execute tool
            return tool_instance.scan(target, scan_params)
            
        except ImportError as e:
            self.logger.warning(f"Tool {tool_name} not implemented yet: {e}")
            return {
                'status': 'not_implemented',
                'message': f'Tool {tool_name} is not yet implemented',
                'placeholder_data': self._generate_placeholder_data(tool_name, target)
            }
    
    def _generate_placeholder_data(self, tool_name: str, target: str) -> Dict:
        """Generate placeholder data for tools not yet implemented"""
        return {
            'tool': tool_name,
            'target': target,
            'status': 'simulated',
            'message': f'This is placeholder data for {tool_name}. Tool implementation pending.',
            'timestamp': datetime.now().isoformat(),
            'sample_findings': [
                f'Example finding 1 for {target}',
                f'Example finding 2 for {target}',
                f'Example finding 3 for {target}'
            ]
        }
    
    def _process_results(self, tool_results: Dict, scan_params: Dict) -> Dict:
        """Process and consolidate tool results"""
        processed = {
            'scan_metadata': {
                'target': scan_params['target'],
                'profile': scan_params.get('profile'),
                'tools_requested': scan_params.get('tools'),
                'start_time': self.start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'scan_type': 'automated_reconnaissance'
            },
            'tool_results': tool_results,
            'summary': self._generate_summary(tool_results),
            'findings': self._extract_findings(tool_results)
        }
        
        return processed
    
    def _generate_summary(self, tool_results: Dict) -> Dict:
        """Generate summary of scan results"""
        total_tools = len(tool_results)
        successful_tools = sum(1 for result in tool_results.values() if result['success'])
        failed_tools = total_tools - successful_tools
        
        return {
            'total_tools_executed': total_tools,
            'successful_tools': successful_tools,
            'failed_tools': failed_tools,
            'success_rate': f"{(successful_tools/total_tools)*100:.1f}%" if total_tools > 0 else "0%"
        }
    
    def _extract_findings(self, tool_results: Dict) -> List[Dict]:
        """Extract key findings from tool results"""
        findings = []
        
        for tool_name, result in tool_results.items():
            if result['success'] and 'data' in result:
                tool_findings = self._extract_tool_findings(tool_name, result['data'])
                findings.extend(tool_findings)
        
        return findings
    
    def _extract_tool_findings(self, tool_name: str, tool_data: Dict) -> List[Dict]:
        """Extract findings from individual tool data"""
        # This is a placeholder - each tool should have its own finding extraction logic
        findings = []
        
        if 'sample_findings' in tool_data:
            for finding in tool_data['sample_findings']:
                findings.append({
                    'tool': tool_name,
                    'type': 'information',
                    'description': finding,
                    'severity': 'info'
                })
        
        return findings
    
    def _generate_output(self, results: Dict, scan_params: Dict) -> None:
        """Generate output files in specified format"""
        output_dir = scan_params.get('output_dir', './results')
        output_format = scan_params.get('output_format', 'json')
        
        # Create output directory
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Generate timestamp for unique filenames
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        target_safe = scan_params['target'].replace('.', '_').replace(':', '_')
        
        self.logger.info(f"Generating output: format={output_format}, dir={output_dir}")
        
        if output_format == 'json':
            self._write_json_output(results, output_dir, target_safe, timestamp)
        elif output_format == 'html':
            self._write_html_output(results, output_dir, target_safe, timestamp)
        elif output_format == 'markdown':
            self._write_markdown_output(results, output_dir, target_safe, timestamp)
        else:
            # Default to JSON if unknown format
            self._write_json_output(results, output_dir, target_safe, timestamp)
        
        self.logger.info(f"Results saved to {output_dir}")
    
    def _write_json_output(self, results: Dict, output_dir: str, target: str, timestamp: str) -> None:
        """Write results in JSON format"""
        import json
        
        filename = f"{target}_{timestamp}.json"
        filepath = Path(output_dir) / filename
        
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        
        self.logger.info(f"Results saved to {filepath}")
    
    def _write_html_output(self, results: Dict, output_dir: str, target: str, timestamp: str) -> None:
        """Write results in HTML format"""
        # TODO: Implement HTML output
        self.logger.info("HTML output not yet implemented")
    
    def _write_markdown_output(self, results: Dict, output_dir: str, target: str, timestamp: str) -> None:
        """Write results in Markdown format"""
        # TODO: Implement Markdown output
        self.logger.info("Markdown output not yet implemented")
    
    def _get_output_files(self, scan_params: Dict) -> List[str]:
        """Get list of generated output files"""
        output_dir = scan_params.get('output_dir', './results')
        target_safe = scan_params['target'].replace('.', '_').replace(':', '_')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        output_format = scan_params.get('output_format', 'json')
        filename = f"{target_safe}_{timestamp}.{output_format}"
        
        return [str(Path(output_dir) / filename)]
