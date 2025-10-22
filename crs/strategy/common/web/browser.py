"""
Browser Automation Framework for WebFuzzingBrain

Provides browser automation using Playwright for web application vulnerability testing.
Handles browser pool management, session lifecycle, and evidence collection.

Critical for resource-constrained environments (2-core, 8GB RAM):
- Limits concurrent browser instances
- Aggressive cleanup after each test
- Memory-efficient browser reuse
"""

import os
import time
import asyncio
import json
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

try:
    from playwright.sync_api import sync_playwright, Browser, Page, BrowserContext, Error as PlaywrightError
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    Browser = None
    Page = None
    BrowserContext = None
    PlaywrightError = Exception


@dataclass
class BrowserConfig:
    """Configuration for browser automation"""
    browser_type: str = "chromium"  # chromium, firefox, webkit
    headless: bool = True
    timeout: int = 30000  # milliseconds
    viewport_width: int = 1280
    viewport_height: int = 720
    user_agent: Optional[str] = None
    ignore_https_errors: bool = True
    slow_mo: int = 0  # milliseconds to slow down operations (for debugging)
    max_instances: int = 3  # maximum concurrent browser instances

    # Browser arguments for resource efficiency
    browser_args: List[str] = field(default_factory=lambda: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--disable-gpu',
        '--window-size=1280,720',
        '--single-process',  # More memory efficient
        '--no-zygote',
    ])


@dataclass
class ConsoleMessage:
    """Browser console message"""
    type: str  # log, warning, error, info, debug
    text: str
    timestamp: float
    location: Optional[str] = None
    args: Optional[List[Any]] = None

    def __post_init__(self):
        if self.args is None:
            self.args = []


@dataclass
class NetworkRequest:
    """Network request captured during testing"""
    url: str
    method: str
    headers: Dict[str, str]
    timestamp: float
    post_data: Optional[str] = None
    response_status: Optional[int] = None
    response_headers: Optional[Dict[str, str]] = None


class BrowserPool:
    """
    Manages a pool of browser instances for parallel testing.

    Implements resource management for constrained environments:
    - Limits concurrent browsers to max_instances
    - Reuses browser instances when possible
    - Aggressive cleanup on errors
    - Automatic browser recycling after N uses
    """

    def __init__(self, config: BrowserConfig):
        """Initialize browser pool"""
        if not PLAYWRIGHT_AVAILABLE:
            raise ImportError(
                "Playwright is not installed. Install with: pip install playwright && playwright install"
            )

        self.config = config
        self.playwright = None
        self.browsers: List[Tuple[Browser, int]] = []  # (browser, use_count)
        self.active_sessions = 0
        self.max_uses_per_browser = 50  # Recycle browser after N uses
        self._lock = asyncio.Lock() if asyncio.get_event_loop().is_running() else None

    def __enter__(self):
        """Context manager entry"""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.cleanup()

    def start(self):
        """Start the Playwright instance"""
        if self.playwright is None:
            self.playwright = sync_playwright().start()

    def get_browser(self) -> Browser:
        """
        Get a browser instance from the pool.

        Returns:
            Browser instance ready for use

        Raises:
            RuntimeError: If max instances reached
        """
        if self.playwright is None:
            self.start()

        # Check if we can reuse an existing browser
        for i, (browser, use_count) in enumerate(self.browsers):
            if browser.is_connected() and use_count < self.max_uses_per_browser:
                self.browsers[i] = (browser, use_count + 1)
                self.active_sessions += 1
                return browser

        # Create new browser if under limit
        if len(self.browsers) < self.config.max_instances:
            browser = self._create_browser()
            self.browsers.append((browser, 1))
            self.active_sessions += 1
            return browser

        # Wait and retry if at limit
        time.sleep(1)
        return self.get_browser()

    def _create_browser(self) -> Browser:
        """Create a new browser instance"""
        browser_type = getattr(self.playwright, self.config.browser_type)

        browser = browser_type.launch(
            headless=self.config.headless,
            args=self.config.browser_args,
            slow_mo=self.config.slow_mo,
        )

        return browser

    def release_browser(self, browser: Browser):
        """Release a browser back to the pool"""
        self.active_sessions = max(0, self.active_sessions - 1)

        # Check if browser should be recycled
        for i, (b, use_count) in enumerate(self.browsers):
            if b == browser and use_count >= self.max_uses_per_browser:
                try:
                    browser.close()
                    self.browsers.pop(i)
                except Exception:
                    pass
                break

    def cleanup(self):
        """Clean up all browser instances"""
        for browser, _ in self.browsers:
            try:
                if browser.is_connected():
                    browser.close()
            except Exception:
                pass

        self.browsers.clear()

        if self.playwright:
            try:
                self.playwright.stop()
            except Exception:
                pass
            self.playwright = None

    def get_stats(self) -> Dict[str, int]:
        """Get pool statistics"""
        return {
            'total_browsers': len(self.browsers),
            'active_sessions': self.active_sessions,
            'max_instances': self.config.max_instances,
        }


class BrowserSession:
    """
    Manages a single browser testing session.

    Provides high-level interface for web vulnerability testing:
    - Navigation and interaction
    - Console log capture
    - Network traffic monitoring
    - DOM snapshots
    - Screenshot capture
    - Evidence collection
    """

    def __init__(self, browser: Browser, config: BrowserConfig, logger=None):
        """Initialize browser session"""
        self.browser = browser
        self.config = config
        self.logger = logger
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None

        # Evidence collection
        self.console_messages: List[ConsoleMessage] = []
        self.network_requests: List[NetworkRequest] = []
        self.errors: List[Dict[str, Any]] = []
        self.csp_violations: List[Dict[str, Any]] = []

    def __enter__(self):
        """Context manager entry"""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()

    def start(self):
        """Start the browser session"""
        # Create new context with configuration
        self.context = self.browser.new_context(
            viewport={'width': self.config.viewport_width, 'height': self.config.viewport_height},
            user_agent=self.config.user_agent,
            ignore_https_errors=self.config.ignore_https_errors,
        )

        # Create new page
        self.page = self.context.new_page()
        self.page.set_default_timeout(self.config.timeout)

        # Set up event listeners
        self._setup_listeners()

    def _setup_listeners(self):
        """Set up event listeners for evidence collection"""
        if not self.page:
            return

        # Console messages
        self.page.on('console', self._on_console)

        # Page errors
        self.page.on('pageerror', self._on_page_error)

        # Request monitoring
        self.page.on('request', self._on_request)
        self.page.on('response', self._on_response)

    def _on_console(self, msg):
        """Handle console message"""
        console_msg = ConsoleMessage(
            type=msg.type,
            text=msg.text,
            timestamp=time.time(),
            location=msg.location.get('url', '') if msg.location else None,
        )
        self.console_messages.append(console_msg)

        if self.logger and msg.type in ['error', 'warning']:
            self.logger.debug(f"Browser console [{msg.type}]: {msg.text}")

    def _on_page_error(self, error):
        """Handle page error"""
        error_info = {
            'message': str(error),
            'timestamp': time.time(),
        }
        self.errors.append(error_info)

        if self.logger:
            self.logger.debug(f"Browser error: {error}")

    def _on_request(self, request):
        """Handle network request"""
        net_req = NetworkRequest(
            url=request.url,
            method=request.method,
            headers=request.headers,
            post_data=request.post_data,
            timestamp=time.time(),
        )
        self.network_requests.append(net_req)

    def _on_response(self, response):
        """Handle network response"""
        # Update corresponding request with response info
        for req in reversed(self.network_requests):
            if req.url == response.url and req.response_status is None:
                req.response_status = response.status
                req.response_headers = response.headers

                # Check for CSP violations in headers
                if 'content-security-policy-report-only' in response.headers:
                    self.csp_violations.append({
                        'url': response.url,
                        'timestamp': time.time(),
                    })
                break

    def navigate(self, url: str, wait_until: str = 'networkidle') -> bool:
        """
        Navigate to URL.

        Args:
            url: Target URL
            wait_until: Wait condition (load, domcontentloaded, networkidle)

        Returns:
            True if successful, False otherwise
        """
        if not self.page:
            return False

        try:
            self.page.goto(url, wait_until=wait_until)
            return True
        except PlaywrightError as e:
            if self.logger:
                self.logger.error(f"Navigation failed: {e}")
            return False

    def execute_script(self, js_code: str) -> Any:
        """
        Execute JavaScript code in the page context.

        Args:
            js_code: JavaScript code to execute

        Returns:
            Result of execution
        """
        if not self.page:
            return None

        try:
            return self.page.evaluate(js_code)
        except PlaywrightError as e:
            if self.logger:
                self.logger.error(f"Script execution failed: {e}")
            return None

    def inject_payload(self, payload: str, target_selector: Optional[str] = None) -> bool:
        """
        Inject payload into page (for XSS testing).

        Args:
            payload: JavaScript/HTML payload
            target_selector: CSS selector of target element (optional)

        Returns:
            True if injection successful
        """
        if not self.page:
            return False

        try:
            if target_selector:
                # Inject into specific element
                element = self.page.query_selector(target_selector)
                if element:
                    element.evaluate(f"el => el.innerHTML = `{payload}`")
            else:
                # Inject into page
                self.page.evaluate(f"document.body.innerHTML += `{payload}`")
            return True
        except PlaywrightError as e:
            if self.logger:
                self.logger.error(f"Payload injection failed: {e}")
            return False

    def get_console_logs(self, filter_type: Optional[str] = None) -> List[ConsoleMessage]:
        """
        Get console messages.

        Args:
            filter_type: Filter by message type (error, warning, etc.)

        Returns:
            List of console messages
        """
        if filter_type:
            return [msg for msg in self.console_messages if msg.type == filter_type]
        return self.console_messages.copy()

    def get_errors(self) -> List[Dict[str, Any]]:
        """Get page errors"""
        return self.errors.copy()

    def get_network_traffic(self) -> List[NetworkRequest]:
        """Get captured network traffic"""
        return self.network_requests.copy()

    def get_csp_violations(self) -> List[Dict[str, Any]]:
        """Get CSP violations"""
        return self.csp_violations.copy()

    def take_screenshot(self, path: str, full_page: bool = True) -> bool:
        """
        Take screenshot of current page.

        Args:
            path: Output file path
            full_page: Capture full page or just viewport

        Returns:
            True if successful
        """
        if not self.page:
            return False

        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            self.page.screenshot(path=path, full_page=full_page)
            return True
        except PlaywrightError as e:
            if self.logger:
                self.logger.error(f"Screenshot failed: {e}")
            return False

    def get_dom_snapshot(self) -> Optional[str]:
        """
        Get DOM snapshot as HTML string.

        Returns:
            HTML content or None
        """
        if not self.page:
            return None

        try:
            return self.page.content()
        except PlaywrightError as e:
            if self.logger:
                self.logger.error(f"DOM snapshot failed: {e}")
            return None

    def save_har(self, path: str) -> bool:
        """
        Save HAR (HTTP Archive) file.

        Args:
            path: Output file path

        Returns:
            True if successful
        """
        # HAR recording needs to be started at context creation
        # This is a simplified version
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            har_data = {
                'log': {
                    'version': '1.2',
                    'creator': {'name': 'WebFuzzingBrain', 'version': '1.0'},
                    'entries': [
                        {
                            'request': {
                                'method': req.method,
                                'url': req.url,
                                'headers': [{'name': k, 'value': v} for k, v in req.headers.items()],
                            },
                            'response': {
                                'status': req.response_status or 0,
                                'headers': [{'name': k, 'value': v} for k, v in (req.response_headers or {}).items()],
                            },
                            'time': 0,
                        }
                        for req in self.network_requests
                    ],
                }
            }

            with open(path, 'w') as f:
                json.dump(har_data, f, indent=2)
            return True
        except Exception as e:
            if self.logger:
                self.logger.error(f"HAR save failed: {e}")
            return False

    def collect_evidence(self, output_dir: str, test_name: str) -> Dict[str, str]:
        """
        Collect all evidence for vulnerability report.

        Args:
            output_dir: Output directory
            test_name: Test identifier

        Returns:
            Dictionary of evidence file paths
        """
        os.makedirs(output_dir, exist_ok=True)
        evidence = {}

        # Screenshot
        screenshot_path = os.path.join(output_dir, f"{test_name}_screenshot.png")
        if self.take_screenshot(screenshot_path):
            evidence['screenshot'] = screenshot_path

        # Console logs
        console_path = os.path.join(output_dir, f"{test_name}_console.json")
        with open(console_path, 'w') as f:
            json.dump([
                {
                    'type': msg.type,
                    'text': msg.text,
                    'timestamp': msg.timestamp,
                    'location': msg.location,
                }
                for msg in self.console_messages
            ], f, indent=2)
        evidence['console'] = console_path

        # Errors
        if self.errors:
            errors_path = os.path.join(output_dir, f"{test_name}_errors.json")
            with open(errors_path, 'w') as f:
                json.dump(self.errors, f, indent=2)
            evidence['errors'] = errors_path

        # Network traffic (HAR)
        har_path = os.path.join(output_dir, f"{test_name}_traffic.har")
        if self.save_har(har_path):
            evidence['har'] = har_path

        # DOM snapshot
        dom_path = os.path.join(output_dir, f"{test_name}_dom.html")
        dom_content = self.get_dom_snapshot()
        if dom_content:
            with open(dom_path, 'w') as f:
                f.write(dom_content)
            evidence['dom'] = dom_path

        # CSP violations
        if self.csp_violations:
            csp_path = os.path.join(output_dir, f"{test_name}_csp_violations.json")
            with open(csp_path, 'w') as f:
                json.dump(self.csp_violations, f, indent=2)
            evidence['csp'] = csp_path

        return evidence

    def check_xss_success(self) -> Tuple[bool, str]:
        """
        Check if XSS payload executed successfully.

        Returns:
            (success, evidence) tuple
        """
        # Check console for alert/prompt/confirm
        for msg in self.console_messages:
            if 'alert' in msg.text.lower() or 'xss' in msg.text.lower():
                return True, f"XSS detected in console: {msg.text}"

        # Check for common XSS indicators in errors
        for error in self.errors:
            msg = error.get('message', '')
            if any(indicator in msg.lower() for indicator in ['alert', 'xss', 'script', 'onerror']):
                return True, f"XSS detected in error: {msg}"

        return False, "No XSS indicators found"

    def check_sql_injection(self) -> Tuple[bool, str]:
        """
        Check if SQL injection was successful.

        Returns:
            (success, evidence) tuple
        """
        # Check for SQL error messages
        sql_errors = [
            'sql syntax',
            'mysql',
            'postgresql',
            'sqlite',
            'ora-',
            'sql server',
            'syntax error',
            'unclosed quotation',
        ]

        for msg in self.console_messages:
            text_lower = msg.text.lower()
            if any(error in text_lower for error in sql_errors):
                return True, f"SQL error detected: {msg.text}"

        for error in self.errors:
            msg_lower = error.get('message', '').lower()
            if any(err in msg_lower for err in sql_errors):
                return True, f"SQL error detected: {error['message']}"

        return False, "No SQL injection indicators found"

    def close(self):
        """Close the browser session"""
        if self.context:
            try:
                self.context.close()
            except Exception:
                pass
            self.context = None

        self.page = None

        # Clear evidence
        self.console_messages.clear()
        self.network_requests.clear()
        self.errors.clear()
        self.csp_violations.clear()
