"""
HTTP Client Utilities for WebFuzzingBrain

Provides HTTP request testing, CORS policy testing, CSRF token handling,
and other web-specific HTTP functionality for vulnerability testing.
"""

import re
import json
import time
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode
import html

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


@dataclass
class HTTPRequest:
    """HTTP request representation"""
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)
    data: Optional[Any] = None
    json_data: Optional[Dict] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    timeout: int = 30
    allow_redirects: bool = True


@dataclass
class HTTPResponse:
    """HTTP response representation"""
    status_code: int
    headers: Dict[str, str]
    content: bytes
    text: str
    url: str
    elapsed: float
    cookies: Dict[str, str] = field(default_factory=dict)


@dataclass
class CORSPolicy:
    """CORS policy analysis result"""
    allows_credentials: bool = False
    allowed_origins: List[str] = field(default_factory=list)
    allowed_methods: List[str] = field(default_factory=list)
    allowed_headers: List[str] = field(default_factory=list)
    exposed_headers: List[str] = field(default_factory=list)
    max_age: Optional[int] = None
    is_permissive: bool = False
    vulnerabilities: List[str] = field(default_factory=list)


@dataclass
class CSRFToken:
    """CSRF token information"""
    name: str
    value: str
    location: str  # cookie, header, form, meta
    element: Optional[str] = None  # HTML element if from DOM


class HTTPTester:
    """
    HTTP testing utility for web vulnerability assessment.

    Provides functionality for:
    - Standard HTTP requests with advanced options
    - CORS policy testing
    - CSRF token extraction and validation
    - Header injection testing
    - Cookie manipulation
    - Authentication testing
    """

    def __init__(self, logger=None):
        """Initialize HTTP tester"""
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library is not installed. Install with: pip install requests")

        self.logger = logger
        self.session = self._create_session()
        self.last_response: Optional[HTTPResponse] = None

    def _create_session(self) -> requests.Session:
        """Create requests session with retry logic"""
        session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    def send_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        json_data: Optional[Dict] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: int = 30,
        allow_redirects: bool = True,
        verify_ssl: bool = True,
    ) -> Optional[HTTPResponse]:
        """
        Send HTTP request.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            headers: Request headers
            params: Query parameters
            data: Request body data
            json_data: JSON request body
            cookies: Request cookies
            timeout: Request timeout in seconds
            allow_redirects: Follow redirects
            verify_ssl: Verify SSL certificates

        Returns:
            HTTPResponse or None on failure
        """
        try:
            start_time = time.time()

            response = self.session.request(
                method=method.upper(),
                url=url,
                headers=headers or {},
                params=params,
                data=data,
                json=json_data,
                cookies=cookies,
                timeout=timeout,
                allow_redirects=allow_redirects,
                verify=verify_ssl,
            )

            elapsed = time.time() - start_time

            http_response = HTTPResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                content=response.content,
                text=response.text,
                url=response.url,
                elapsed=elapsed,
                cookies=dict(response.cookies),
            )

            self.last_response = http_response

            if self.logger:
                self.logger.debug(
                    f"HTTP {method} {url} -> {response.status_code} ({elapsed:.2f}s)"
                )

            return http_response

        except requests.exceptions.RequestException as e:
            if self.logger:
                self.logger.error(f"HTTP request failed: {e}")
            return None

    def test_cors_policy(self, url: str, origin: str = "https://evil.com") -> CORSPolicy:
        """
        Test CORS policy of target URL.

        Args:
            url: Target URL
            origin: Origin to test from

        Returns:
            CORSPolicy analysis result
        """
        policy = CORSPolicy()

        # Send preflight request
        headers = {
            'Origin': origin,
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'Content-Type, X-Custom-Header',
        }

        response = self.send_request('OPTIONS', url, headers=headers)

        if not response:
            return policy

        resp_headers = {k.lower(): v for k, v in response.headers.items()}

        # Parse CORS headers
        if 'access-control-allow-origin' in resp_headers:
            allow_origin = resp_headers['access-control-allow-origin']
            policy.allowed_origins.append(allow_origin)

            # Check for permissive wildcard with credentials
            if allow_origin == '*':
                policy.is_permissive = True
                policy.vulnerabilities.append(
                    "Wildcard origin (*) allows any domain to access resources"
                )

            # Check if reflects origin
            if allow_origin == origin:
                policy.vulnerabilities.append(
                    "Origin is reflected without validation - potential CORS bypass"
                )

        if 'access-control-allow-credentials' in resp_headers:
            policy.allows_credentials = resp_headers['access-control-allow-credentials'].lower() == 'true'

            # Wildcard with credentials is a vulnerability
            if policy.allows_credentials and '*' in policy.allowed_origins:
                policy.vulnerabilities.append(
                    "CRITICAL: Credentials allowed with wildcard origin"
                )

        if 'access-control-allow-methods' in resp_headers:
            methods = resp_headers['access-control-allow-methods']
            policy.allowed_methods = [m.strip() for m in methods.split(',')]

        if 'access-control-allow-headers' in resp_headers:
            headers_str = resp_headers['access-control-allow-headers']
            policy.allowed_headers = [h.strip() for h in headers_str.split(',')]

        if 'access-control-expose-headers' in resp_headers:
            headers_str = resp_headers['access-control-expose-headers']
            policy.exposed_headers = [h.strip() for h in headers_str.split(',')]

        if 'access-control-max-age' in resp_headers:
            try:
                policy.max_age = int(resp_headers['access-control-max-age'])
            except ValueError:
                pass

        return policy

    def extract_csrf_tokens(self, html_content: str, url: str = "") -> List[CSRFToken]:
        """
        Extract CSRF tokens from HTML content.

        Args:
            html_content: HTML page content
            url: Source URL (for context)

        Returns:
            List of found CSRF tokens
        """
        tokens = []

        # Common CSRF token patterns
        token_patterns = [
            # Hidden input fields
            (r'<input[^>]*name=["\']([^"\']*csrf[^"\']*)["\'][^>]*value=["\']([^"\']+)["\'][^>]*>', 'form'),
            (r'<input[^>]*value=["\']([^"\']+)["\'][^>]*name=["\']([^"\']*csrf[^"\']*)["\'][^>]*>', 'form'),
            # Meta tags
            (r'<meta[^>]*name=["\']([^"\']*csrf[^"\']*)["\'][^>]*content=["\']([^"\']+)["\'][^>]*>', 'meta'),
            # Data attributes
            (r'data-csrf-token=["\']([^"\']+)["\']', 'data-attribute'),
            # JavaScript variables
            (r'csrf[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'javascript'),
        ]

        for pattern, location in token_patterns:
            matches = re.finditer(pattern, html_content, re.IGNORECASE)
            for match in matches:
                if len(match.groups()) == 2:
                    name, value = match.groups()
                elif len(match.groups()) == 1:
                    name = 'csrf_token'
                    value = match.group(1)
                else:
                    continue

                tokens.append(CSRFToken(
                    name=name,
                    value=value,
                    location=location,
                    element=match.group(0)[:100]  # First 100 chars
                ))

        if self.logger and tokens:
            self.logger.debug(f"Found {len(tokens)} CSRF tokens in page")

        return tokens

    def test_csrf_protection(
        self,
        url: str,
        method: str = 'POST',
        data: Optional[Dict] = None,
        valid_token: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Test CSRF protection on an endpoint.

        Args:
            url: Target URL
            method: HTTP method
            data: Request data
            valid_token: Valid CSRF token for comparison

        Returns:
            (is_vulnerable, details) tuple
        """
        results = []

        # Test 1: Request without token
        response_no_token = self.send_request(method, url, data=data or {})
        if response_no_token and response_no_token.status_code < 400:
            return True, "Request succeeded without CSRF token"

        # Test 2: Request with invalid token
        test_data = (data or {}).copy()
        test_data['csrf_token'] = 'invalid_token_12345'
        response_invalid = self.send_request(method, url, data=test_data)
        if response_invalid and response_invalid.status_code < 400:
            return True, "Request succeeded with invalid CSRF token"

        # Test 3: Request with empty token
        test_data['csrf_token'] = ''
        response_empty = self.send_request(method, url, data=test_data)
        if response_empty and response_empty.status_code < 400:
            return True, "Request succeeded with empty CSRF token"

        # Test 4: If valid token provided, test if it's properly validated
        if valid_token:
            test_data['csrf_token'] = valid_token[::-1]  # Reversed token
            response_modified = self.send_request(method, url, data=test_data)
            if response_modified and response_modified.status_code < 400:
                return True, "Request succeeded with modified CSRF token"

        return False, "CSRF protection appears to be working"

    def test_header_injection(
        self,
        url: str,
        injection_headers: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Test for header injection vulnerabilities.

        Args:
            url: Target URL
            injection_headers: Custom headers to test

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []

        # Default test headers
        if injection_headers is None:
            injection_headers = {
                'X-Forwarded-For': '127.0.0.1',
                'X-Forwarded-Host': 'evil.com',
                'X-Original-URL': '/admin',
                'X-Rewrite-URL': '/admin',
                'Host': 'evil.com',
            }

        for header, value in injection_headers.items():
            response = self.send_request('GET', url, headers={header: value})

            if response:
                # Check if header is reflected in response
                if value in response.text:
                    vulnerabilities.append({
                        'header': header,
                        'value': value,
                        'type': 'reflection',
                        'details': f"Header {header} reflected in response",
                    })

                # Check for bypass indicators
                if response.status_code == 200 and header in ['X-Original-URL', 'X-Rewrite-URL']:
                    vulnerabilities.append({
                        'header': header,
                        'value': value,
                        'type': 'bypass',
                        'details': f"Possible access control bypass via {header}",
                    })

        return vulnerabilities

    def test_http_methods(self, url: str) -> Dict[str, bool]:
        """
        Test which HTTP methods are allowed.

        Args:
            url: Target URL

        Returns:
            Dictionary of method: allowed
        """
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT']
        results = {}

        for method in methods:
            response = self.send_request(method, url)
            if response:
                # Method is allowed if status is not 405 (Method Not Allowed)
                results[method] = response.status_code != 405
            else:
                results[method] = False

        if self.logger:
            allowed = [m for m, allowed in results.items() if allowed]
            self.logger.debug(f"Allowed HTTP methods: {', '.join(allowed)}")

        return results

    def test_open_redirect(self, url: str, redirect_param: str = 'url') -> Tuple[bool, str]:
        """
        Test for open redirect vulnerability.

        Args:
            url: Target URL
            redirect_param: Parameter name for redirect

        Returns:
            (is_vulnerable, details) tuple
        """
        # Test payloads
        evil_domain = 'https://evil.com'
        payloads = [
            evil_domain,
            f'//{evil_domain[8:]}',  # Protocol-relative
            f'@{evil_domain[8:]}',
            f'?redirect={evil_domain}',
            f'%0d%0aLocation:%20{evil_domain}',  # CRLF injection
        ]

        for payload in payloads:
            # Parse URL and add redirect parameter
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[redirect_param] = payload

            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"

            response = self.send_request('GET', test_url, allow_redirects=False)

            if response:
                # Check if redirects to evil domain
                location = response.headers.get('Location', '')
                if 'evil.com' in location:
                    return True, f"Open redirect to {location} with payload: {payload}"

        return False, "No open redirect detected"

    def extract_cookies(self, url: str) -> Dict[str, Any]:
        """
        Extract and analyze cookies from URL.

        Args:
            url: Target URL

        Returns:
            Dictionary of cookie analysis
        """
        response = self.send_request('GET', url)

        if not response:
            return {}

        cookie_analysis = {
            'cookies': {},
            'vulnerabilities': [],
        }

        for name, value in response.cookies.items():
            cookie_info = {
                'value': value,
                'httponly': False,
                'secure': False,
                'samesite': None,
            }

            # Parse Set-Cookie header for attributes
            set_cookie_header = response.headers.get('Set-Cookie', '')
            if name in set_cookie_header:
                if 'HttpOnly' in set_cookie_header:
                    cookie_info['httponly'] = True
                if 'Secure' in set_cookie_header:
                    cookie_info['secure'] = True

                samesite_match = re.search(r'SameSite=(\w+)', set_cookie_header, re.IGNORECASE)
                if samesite_match:
                    cookie_info['samesite'] = samesite_match.group(1)

            cookie_analysis['cookies'][name] = cookie_info

            # Check for vulnerabilities
            if 'session' in name.lower() or 'token' in name.lower():
                if not cookie_info['httponly']:
                    cookie_analysis['vulnerabilities'].append(
                        f"Session cookie '{name}' missing HttpOnly flag - XSS can steal it"
                    )
                if not cookie_info['secure'] and url.startswith('https'):
                    cookie_analysis['vulnerabilities'].append(
                        f"Session cookie '{name}' missing Secure flag - can be sent over HTTP"
                    )
                if not cookie_info['samesite']:
                    cookie_analysis['vulnerabilities'].append(
                        f"Session cookie '{name}' missing SameSite attribute - CSRF possible"
                    )

        return cookie_analysis

    def test_ssrf(
        self,
        url: str,
        param: str = 'url',
        callback_url: str = 'http://169.254.169.254',  # AWS metadata service
    ) -> Tuple[bool, str]:
        """
        Test for Server-Side Request Forgery (SSRF).

        Args:
            url: Target URL
            param: Parameter for URL input
            callback_url: URL to test SSRF with

        Returns:
            (is_vulnerable, details) tuple
        """
        # SSRF test payloads
        payloads = [
            callback_url,
            'http://localhost',
            'http://127.0.0.1',
            'http://[::1]',
            'http://0.0.0.0',
            'file:///etc/passwd',
            'dict://127.0.0.1:11211',
        ]

        for payload in payloads:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param] = payload

            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"

            response = self.send_request('GET', test_url, timeout=10)

            if response:
                # Check for SSRF indicators
                if 'ami-' in response.text or 'i-' in response.text:  # AWS metadata
                    return True, f"SSRF detected - AWS metadata accessible with payload: {payload}"

                if 'root:x:0:0' in response.text:  # /etc/passwd
                    return True, f"SSRF detected - file:// access with payload: {payload}"

                if response.elapsed < 1 and 'localhost' in payload:
                    # Quick response to localhost might indicate SSRF
                    return True, f"Possible SSRF - localhost accessible with payload: {payload}"

        return False, "No SSRF detected"

    def close(self):
        """Close the session"""
        if self.session:
            self.session.close()
