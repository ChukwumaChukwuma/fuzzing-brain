"""
Web Base Strategy

Base class for web application security testing strategies.
Extends BaseStrategy with web-specific functionality.
"""

import os
from typing import TYPE_CHECKING, Optional
from opentelemetry import trace

from core.base_strategy import BaseStrategy
from common.web import (
    BrowserPool,
    BrowserSession,
    BrowserConfig,
    HTTPTester,
    DOMAnalyzer,
    JavaScriptParser,
    PayloadGenerator,
)

if TYPE_CHECKING:
    from common.config import StrategyConfig
    from common.logging.logger import StrategyLogger
    from common.llm.client import LLMClient


class WebBaseStrategy(BaseStrategy):
    """
    Base class for web application security testing strategies.

    Extends BaseStrategy with:
    - Browser automation (Playwright)
    - HTTP testing utilities
    - DOM analysis
    - JavaScript parsing
    - Web payload generation
    - Evidence collection

    Provides the foundation for web-specific PoV generation strategies.
    """

    def __init__(self, config: 'StrategyConfig'):
        """
        Initialize web base strategy.

        Args:
            config: Strategy configuration with web-specific fields
        """
        super().__init__(config)

        # Initialize web-specific components
        self._init_web_components()

    def _init_web_components(self):
        """Initialize web-specific tools and utilities"""
        # Browser configuration
        self.browser_config = BrowserConfig(
            browser_type=self.config.browser_type,
            headless=self.config.headless,
            timeout=self.config.browser_timeout * 1000,  # Convert to milliseconds
            viewport_width=self.config.viewport_width,
            viewport_height=self.config.viewport_height,
            max_instances=self.config.max_browser_instances,
        )

        # Browser pool (lazy initialization - only create when needed)
        self._browser_pool: Optional[BrowserPool] = None

        # HTTP tester
        self.http_tester = HTTPTester(logger=self.logger)

        # DOM analyzer
        self.dom_analyzer = DOMAnalyzer(logger=self.logger)

        # JavaScript parser
        self.js_parser = JavaScriptParser(logger=self.logger)

        # Payload generator
        self.payload_generator = PayloadGenerator(logger=self.logger)

        # Evidence directory
        self.evidence_dir = self.config.evidence_dir
        os.makedirs(self.evidence_dir, exist_ok=True)

        self.logger.log(f"Initialized web testing components")
        self.logger.log(f"Browser: {self.config.browser_type} (headless={self.config.headless})")
        self.logger.log(f"Target URL: {self.config.target_url}")
        self.logger.log(f"Evidence dir: {self.evidence_dir}")

    def get_browser_pool(self) -> BrowserPool:
        """
        Get or create browser pool.

        Uses lazy initialization to avoid creating browsers until needed.

        Returns:
            BrowserPool instance
        """
        if self._browser_pool is None:
            self.logger.log("Creating browser pool...")
            self._browser_pool = BrowserPool(self.browser_config)
            self._browser_pool.start()
            self.logger.log(f"Browser pool created (max {self.browser_config.max_instances} instances)")

        return self._browser_pool

    def create_browser_session(self) -> BrowserSession:
        """
        Create a new browser session.

        Returns:
            BrowserSession ready for testing
        """
        pool = self.get_browser_pool()
        browser = pool.get_browser()

        session = BrowserSession(
            browser=browser,
            config=self.browser_config,
            logger=self.logger,
        )

        return session

    def cleanup_browser_pool(self):
        """Clean up browser pool and release resources"""
        if self._browser_pool is not None:
            self.logger.log("Cleaning up browser pool...")
            self._browser_pool.cleanup()
            self._browser_pool = None
            self.logger.log("Browser pool cleaned up")

    def find_web_app_code(self, directory: Optional[str] = None) -> Optional[str]:
        """
        Find and extract web application code (JavaScript/HTML).

        Similar to find_fuzzer_source() but for web applications.

        Args:
            directory: Directory to search (defaults to project_src_dir)

        Returns:
            Combined JavaScript/HTML source code or None
        """
        if directory is None:
            directory = self.config.project_src_dir

        if not os.path.exists(directory):
            self.logger.warning(f"Web app directory not found: {directory}")
            return None

        self.logger.log(f"Searching for web app code in: {directory}")

        # Collect JavaScript files
        js_files = []
        html_files = []

        for root, dirs, files in os.walk(directory):
            # Skip common directories
            dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', 'dist', 'build', '__pycache__']]

            for file in files:
                file_path = os.path.join(root, file)

                if file.endswith('.js') or file.endswith('.jsx') or file.endswith('.ts') or file.endswith('.tsx'):
                    js_files.append(file_path)
                elif file.endswith('.html') or file.endswith('.htm'):
                    html_files.append(file_path)

        self.logger.log(f"Found {len(js_files)} JavaScript files, {len(html_files)} HTML files")

        if not js_files and not html_files:
            self.logger.warning("No web app code found")
            return None

        # Combine code (limit to avoid token overflow)
        combined_code = []
        total_chars = 0
        max_chars = 50000  # Limit to ~50KB

        # Add JavaScript files first
        for js_file in js_files[:10]:  # Limit to 10 files
            try:
                with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if total_chars + len(content) > max_chars:
                        break

                    relative_path = os.path.relpath(js_file, directory)
                    combined_code.append(f"// File: {relative_path}\n{content}\n")
                    total_chars += len(content)
            except Exception as e:
                self.logger.warning(f"Failed to read {js_file}: {e}")

        # Add HTML files
        for html_file in html_files[:5]:  # Limit to 5 HTML files
            try:
                with open(html_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if total_chars + len(content) > max_chars:
                        break

                    relative_path = os.path.relpath(html_file, directory)
                    combined_code.append(f"<!-- File: {relative_path} -->\n{content}\n")
                    total_chars += len(content)
            except Exception as e:
                self.logger.warning(f"Failed to read {html_file}: {e}")

        if not combined_code:
            return None

        result = '\n'.join(combined_code)
        self.logger.log(f"Extracted {len(result)} characters of web app code")
        return result

    def analyze_web_app_code(self, code: str) -> dict:
        """
        Analyze web application code for vulnerabilities.

        Args:
            code: JavaScript/HTML source code

        Returns:
            Analysis results dictionary
        """
        self.logger.log("Analyzing web application code...")

        results = {
            'javascript_analysis': None,
            'dom_analysis': None,
            'html_analysis': None,
        }

        # JavaScript analysis
        if '.js' in code or 'function' in code or 'const ' in code:
            self.logger.log("Running JavaScript analysis...")
            js_result = self.js_parser.analyze_code(code)
            results['javascript_analysis'] = js_result
            self.logger.log(f"Found {len(js_result['security_issues'])} security issues in JavaScript")

        # DOM analysis
        if 'function' in code or 'eval' in code:
            self.logger.log("Running DOM sink/source analysis...")
            dom_result = self.dom_analyzer.analyze_javascript(code)
            results['dom_analysis'] = dom_result
            self.logger.log(f"Found {len(dom_result['sinks'])} sinks, {len(dom_result['sources'])} sources")

        # HTML analysis
        if '<html' in code or '<script' in code or '<form' in code:
            self.logger.log("Running HTML analysis...")
            html_result = self.dom_analyzer.analyze_html_for_sinks(code)
            results['html_analysis'] = html_result
            self.logger.log(f"Found {len(html_result['inline_scripts'])} inline scripts")

        return results

    def _set_span_attributes(self, span):
        """Set web-specific telemetry attributes"""
        super()._set_span_attributes(span)

        # Add web-specific attributes
        span.set_attribute("web.target_url", self.config.target_url or "")
        span.set_attribute("web.browser_type", self.config.browser_type)
        span.set_attribute("web.framework", self.config.web_framework or "unknown")
        span.set_attribute("web.vulnerability_types", ",".join(self.config.web_vulnerability_types))

    def __del__(self):
        """Cleanup on destruction"""
        try:
            self.cleanup_browser_pool()
            if hasattr(self, 'http_tester') and self.http_tester:
                self.http_tester.close()
        except Exception:
            pass  # Ignore cleanup errors
