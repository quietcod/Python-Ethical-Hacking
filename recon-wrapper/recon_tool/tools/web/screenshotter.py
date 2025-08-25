"""
Screenshotter
Web service screenshot capture and visual analysis
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List

import requests

from ...core.exceptions import ScanError


class Screenshotter:
    """Web service screenshot capture tool"""
    
    def __init__(self, output_dir: Path, config: Dict[str, Any], logger: logging.Logger):
        self.output_dir = output_dir
        self.config = config
        self.logger = logger
        
        # Create screenshots output directory
        self.screenshots_dir = output_dir / 'screenshots'
        self.screenshots_dir.mkdir(exist_ok=True)
        
    def capture_screenshots(self, targets: List[str]) -> Dict[str, Any]:
        """Capture screenshots of multiple targets"""
        self.logger.info(f"Capturing screenshots for {len(targets)} targets")
        
        results = {
            'targets': targets,
            'screenshots': [],
            'tool_used': 'basic_info_capture',
            'success_count': 0,
            'failed_count': 0
        }
        
        # Prepare URLs (limit to prevent overwhelming)
        max_targets = self.config.get('screenshots', {}).get('max_targets', 10)
        urls = []
        
        for target in targets[:max_targets]:
            if target.startswith('http'):
                urls.append(target)
            else:
                # Try HTTPS first, then HTTP
                urls.append(f'https://{target}')
                urls.append(f'http://{target}')
        
        # Capture screenshots using available methods
        screenshots = self._capture_with_requests(urls)
        results['screenshots'] = screenshots
        
        # Count successes and failures
        results['success_count'] = len([s for s in screenshots if s.get('status') != 'failed'])
        results['failed_count'] = len([s for s in screenshots if s.get('status') == 'failed'])
        
        # Save results
        self._save_screenshot_results(results)
        
        self.logger.info(f"Screenshot capture completed: {results['success_count']} successful, {results['failed_count']} failed")
        
        return results
    
    def _capture_with_requests(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Capture basic web information using requests (fallback method)"""
        screenshots = []
        timeout = self.config.get('screenshots', {}).get('timeout', 10)
        
        for url in urls:
            try:
                self.logger.debug(f"Capturing info for {url}")
                
                # Make request with proper headers
                headers = {
                    'User-Agent': self.config.get('general', {}).get('user_agent', 
                        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
                }
                
                response = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
                
                if response.status_code < 400:
                    # Extract useful information
                    title = self._extract_title(response.text)
                    server = response.headers.get('Server', 'Unknown')
                    content_type = response.headers.get('Content-Type', 'Unknown')
                    content_length = len(response.content)
                    
                    # Check for interesting technologies
                    technologies = self._detect_basic_technologies(response.text, response.headers)
                    
                    screenshot_info = {
                        'url': url,
                        'status_code': response.status_code,
                        'final_url': response.url,  # After redirects
                        'title': title,
                        'server': server,
                        'content_type': content_type,
                        'content_length': content_length,
                        'technologies': technologies,
                        'status': 'info_captured',
                        'timestamp': self._get_timestamp(),
                        'response_time': response.elapsed.total_seconds()
                    }
                    
                    screenshots.append(screenshot_info)
                    self.logger.info(f"✓ Captured info for {url} [{response.status_code}] - {title}")
                    
                else:
                    screenshots.append({
                        'url': url,
                        'status_code': response.status_code,
                        'status': 'failed',
                        'error': f'HTTP {response.status_code}',
                        'timestamp': self._get_timestamp()
                    })
                    self.logger.warning(f"✗ Failed to capture {url} - HTTP {response.status_code}")
                    
            except requests.exceptions.Timeout:
                screenshots.append({
                    'url': url,
                    'status': 'failed',
                    'error': 'Request timeout',
                    'timestamp': self._get_timestamp()
                })
                self.logger.warning(f"✗ Timeout capturing {url}")
                
            except requests.exceptions.ConnectionError:
                screenshots.append({
                    'url': url,
                    'status': 'failed',
                    'error': 'Connection error',
                    'timestamp': self._get_timestamp()
                })
                self.logger.debug(f"✗ Connection error for {url}")
                
            except Exception as e:
                screenshots.append({
                    'url': url,
                    'status': 'failed',
                    'error': str(e),
                    'timestamp': self._get_timestamp()
                })
                self.logger.warning(f"✗ Error capturing {url}: {str(e)}")
        
        return screenshots
    
    def _extract_title(self, html: str) -> str:
        """Extract title from HTML content"""
        try:
            html_lower = html.lower()
            
            # Look for title tags
            if '<title>' in html_lower and '</title>' in html_lower:
                start_idx = html_lower.find('<title>') + 7
                end_idx = html_lower.find('</title>', start_idx)
                
                if end_idx > start_idx:
                    # Get original case title
                    title = html[start_idx:end_idx].strip()
                    
                    # Clean up title
                    title = title.replace('\n', ' ').replace('\r', ' ')
                    title = ' '.join(title.split())  # Normalize whitespace
                    
                    # Limit length
                    return title[:200] if title else "No Title"
            
            # Fallback: look for h1 tags
            if '<h1>' in html_lower and '</h1>' in html_lower:
                start_idx = html_lower.find('<h1>') + 4
                end_idx = html_lower.find('</h1>', start_idx)
                
                if end_idx > start_idx:
                    h1_title = html[start_idx:end_idx].strip()
                    h1_title = h1_title.replace('\n', ' ').replace('\r', ' ')
                    h1_title = ' '.join(h1_title.split())
                    return h1_title[:100] if h1_title else "No Title"
            
            return "No Title"
            
        except Exception as e:
            self.logger.debug(f"Error extracting title: {str(e)}")
            return "Title Extraction Error"
    
    def _detect_basic_technologies(self, html: str, headers: Dict[str, str]) -> List[str]:
        """Detect basic web technologies from response"""
        technologies = []
        html_lower = html.lower()
        
        try:
            # Server header analysis
            server = headers.get('Server', '').lower()
            if 'apache' in server:
                technologies.append('Apache')
            elif 'nginx' in server:
                technologies.append('Nginx')
            elif 'iis' in server:
                technologies.append('IIS')
            elif 'cloudflare' in server:
                technologies.append('Cloudflare')
            
            # X-Powered-By header
            powered_by = headers.get('X-Powered-By', '').lower()
            if 'php' in powered_by:
                technologies.append('PHP')
            elif 'asp.net' in powered_by:
                technologies.append('ASP.NET')
            
            # Content analysis
            if 'wordpress' in html_lower or 'wp-content' in html_lower:
                technologies.append('WordPress')
            
            if 'drupal' in html_lower or 'sites/default' in html_lower:
                technologies.append('Drupal')
            
            if 'joomla' in html_lower:
                technologies.append('Joomla')
            
            # JavaScript frameworks
            if 'react' in html_lower or 'data-reactroot' in html_lower:
                technologies.append('React')
            
            if 'angular' in html_lower or 'ng-app' in html_lower:
                technologies.append('Angular')
            
            if 'vue.js' in html_lower or 'vue' in html_lower:
                technologies.append('Vue.js')
            
            # jQuery
            if 'jquery' in html_lower:
                technologies.append('jQuery')
            
            # Bootstrap
            if 'bootstrap' in html_lower:
                technologies.append('Bootstrap')
            
            # Remove duplicates and return
            return list(set(technologies))
            
        except Exception as e:
            self.logger.debug(f"Error detecting technologies: {str(e)}")
            return []
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def _save_screenshot_results(self, results: Dict[str, Any]) -> None:
        """Save screenshot results to files"""
        try:
            # Save JSON results
            json_file = self.screenshots_dir / 'screenshot_results.json'
            with open(json_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            self.logger.info(f"Screenshot results saved to {json_file}")
            
            # Create human-readable summary
            txt_file = self.screenshots_dir / 'screenshot_summary.txt'
            
            with open(txt_file, 'w') as f:
                f.write("Screenshot Capture Summary\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Total Targets: {len(results['targets'])}\n")
                f.write(f"Successful Captures: {results['success_count']}\n")
                f.write(f"Failed Captures: {results['failed_count']}\n")
                f.write(f"Tool Used: {results['tool_used']}\n\n")
                
                f.write("Successful Captures:\n")
                f.write("-" * 30 + "\n")
                
                for screenshot in results['screenshots']:
                    if screenshot.get('status') != 'failed':
                        f.write(f"URL: {screenshot['url']}\n")
                        f.write(f"  Status: {screenshot.get('status_code', 'N/A')}\n")
                        f.write(f"  Title: {screenshot.get('title', 'N/A')}\n")
                        f.write(f"  Server: {screenshot.get('server', 'N/A')}\n")
                        f.write(f"  Content Type: {screenshot.get('content_type', 'N/A')}\n")
                        f.write(f"  Response Time: {screenshot.get('response_time', 'N/A')}s\n")
                        
                        if screenshot.get('technologies'):
                            f.write(f"  Technologies: {', '.join(screenshot['technologies'])}\n")
                        
                        f.write("\n")
                
                # Failed captures
                failed_captures = [s for s in results['screenshots'] if s.get('status') == 'failed']
                if failed_captures:
                    f.write("Failed Captures:\n")
                    f.write("-" * 30 + "\n")
                    
                    for screenshot in failed_captures:
                        f.write(f"URL: {screenshot['url']}\n")
                        f.write(f"  Error: {screenshot.get('error', 'Unknown error')}\n\n")
            
            self.logger.info(f"Screenshot summary saved to {txt_file}")
            
        except Exception as e:
            self.logger.error(f"Error saving screenshot results: {str(e)}")
    
    def capture_single_screenshot(self, url: str) -> Dict[str, Any]:
        """Capture screenshot of a single URL"""
        self.logger.info(f"Capturing screenshot for single URL: {url}")
        
        results = self.capture_screenshots([url])
        
        if results['screenshots']:
            return results['screenshots'][0]
        else:
            return {
                'url': url,
                'status': 'failed',
                'error': 'No screenshot captured'
            }
