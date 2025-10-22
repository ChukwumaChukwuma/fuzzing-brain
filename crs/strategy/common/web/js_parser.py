"""
JavaScript AST Parser for WebFuzzingBrain

Provides JavaScript parsing and analysis using AST-based approaches
for accurate vulnerability detection and code understanding.
"""

import re
import json
from typing import List, Dict, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

try:
    import esprima
    ESPRIMA_AVAILABLE = True
except ImportError:
    ESPRIMA_AVAILABLE = False


class VulnerabilityType(Enum):
    """Types of JavaScript vulnerabilities"""
    DANGEROUS_FUNCTION = "dangerous_function"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    EVAL_USAGE = "eval_usage"
    DOM_XSS = "dom_xss"
    INSECURE_RANDOM = "insecure_random"
    WEAK_CRYPTO = "weak_crypto"
    HARDCODED_SECRET = "hardcoded_secret"
    UNSAFE_REDIRECT = "unsafe_redirect"


@dataclass
class FunctionInfo:
    """Information about a JavaScript function"""
    name: str
    params: List[str] = field(default_factory=list)
    line_number: Optional[int] = None
    body: Optional[str] = None
    is_async: bool = False
    is_generator: bool = False
    calls: List[str] = field(default_factory=list)  # Functions it calls


@dataclass
class VariableInfo:
    """Information about a variable"""
    name: str
    type: str  # var, let, const
    line_number: Optional[int] = None
    initial_value: Optional[str] = None
    scope: str = "global"  # global, function, block


@dataclass
class SecurityIssue:
    """Security issue found in JavaScript code"""
    vulnerability_type: VulnerabilityType
    severity: str  # critical, high, medium, low
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    description: str = ""
    recommendation: str = ""


class JavaScriptParser:
    """
    JavaScript parser and analyzer using AST-based analysis.

    Provides:
    - JavaScript parsing with esprima (ES2022+)
    - Function extraction and analysis
    - Variable tracking
    - Dangerous pattern detection
    - Prototype pollution detection
    - Security vulnerability scanning
    """

    # Dangerous functions that should be flagged
    DANGEROUS_FUNCTIONS = {
        'eval': 'Executes arbitrary code - major XSS risk',
        'Function': 'Dynamic function creation - XSS risk',
        'setTimeout': 'Can execute strings as code',
        'setInterval': 'Can execute strings as code',
        'execScript': 'IE-specific code execution',
        'setImmediate': 'Can execute strings as code',
    }

    # Dangerous DOM APIs
    DANGEROUS_DOM_APIS = {
        'innerHTML',
        'outerHTML',
        'insertAdjacentHTML',
        'document.write',
        'document.writeln',
    }

    # Prototype pollution indicators
    PROTOTYPE_PROPERTIES = {
        '__proto__',
        'constructor',
        'prototype',
    }

    def __init__(self, logger=None):
        """Initialize JavaScript parser"""
        self.logger = logger
        self.use_ast_parsing = ESPRIMA_AVAILABLE

        if not self.use_ast_parsing and self.logger:
            self.logger.warning(
                "esprima not available - using regex-based fallback. "
                "Install with: pip install esprima"
            )

        self.functions: List[FunctionInfo] = []
        self.variables: List[VariableInfo] = []
        self.security_issues: List[SecurityIssue] = []

    def parse_source(self, code: str) -> Optional[Dict]:
        """
        Parse JavaScript source code.

        Args:
            code: JavaScript source code

        Returns:
            AST dictionary or None if parsing fails
        """
        if not self.use_ast_parsing:
            return None

        try:
            ast = esprima.parseScript(code, options={
                'loc': True,
                'range': True,
                'comment': True,
                'tokens': True,
            })
            return ast.toDict()
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to parse JavaScript: {e}")
            return None

    def analyze_code(self, code: str) -> Dict[str, Any]:
        """
        Perform comprehensive code analysis.

        Args:
            code: JavaScript source code

        Returns:
            Analysis results
        """
        self.functions.clear()
        self.variables.clear()
        self.security_issues.clear()

        if self.use_ast_parsing:
            ast = self.parse_source(code)
            if ast:
                self._analyze_ast(ast, code)
        else:
            # Fallback to regex-based analysis
            self._analyze_regex(code)

        # Additional security scans
        self._scan_for_secrets(code)
        self._scan_for_weak_crypto(code)

        return {
            'functions': self.functions.copy(),
            'variables': self.variables.copy(),
            'security_issues': self.security_issues.copy(),
            'summary': self.get_summary(),
        }

    def _analyze_ast(self, ast: Dict, source_code: str):
        """Analyze AST for functions, variables, and security issues"""
        lines = source_code.split('\n')

        def visit_node(node: Dict, parent: Optional[Dict] = None):
            """Visit AST node recursively"""
            if not isinstance(node, dict):
                return

            node_type = node.get('type')

            # Function declarations
            if node_type == 'FunctionDeclaration':
                self._extract_function_from_ast(node, lines)

            # Function expressions
            elif node_type in ['FunctionExpression', 'ArrowFunctionExpression']:
                self._extract_function_from_ast(node, lines, is_expression=True)

            # Variable declarations
            elif node_type == 'VariableDeclaration':
                self._extract_variables_from_ast(node, lines)

            # Call expressions (function calls)
            elif node_type == 'CallExpression':
                self._check_dangerous_call(node, lines)

            # Member expressions (property access)
            elif node_type == 'MemberExpression':
                self._check_dangerous_member_access(node, lines)

            # Assignment expressions (for prototype pollution)
            elif node_type == 'AssignmentExpression':
                self._check_prototype_pollution(node, lines)

            # Recurse into child nodes
            for key, value in node.items():
                if isinstance(value, dict):
                    visit_node(value, node)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            visit_node(item, node)

        # Start visiting from root
        visit_node(ast)

    def _extract_function_from_ast(self, node: Dict, lines: List[str], is_expression: bool = False):
        """Extract function information from AST node"""
        func_id = node.get('id')
        func_name = func_id.get('name') if func_id else '<anonymous>'

        params = []
        for param in node.get('params', []):
            if param.get('type') == 'Identifier':
                params.append(param.get('name'))

        line_number = None
        loc = node.get('loc')
        if loc and 'start' in loc:
            line_number = loc['start'].get('line')

        # Extract function body (simplified)
        body = None
        if line_number and line_number <= len(lines):
            body = lines[line_number - 1].strip()

        func_info = FunctionInfo(
            name=func_name,
            params=params,
            line_number=line_number,
            body=body,
            is_async=node.get('async', False),
            is_generator=node.get('generator', False),
        )

        self.functions.append(func_info)

    def _extract_variables_from_ast(self, node: Dict, lines: List[str]):
        """Extract variable declarations from AST node"""
        var_kind = node.get('kind', 'var')  # var, let, const

        for declaration in node.get('declarations', []):
            var_id = declaration.get('id')
            if var_id and var_id.get('type') == 'Identifier':
                var_name = var_id.get('name')

                line_number = None
                loc = declaration.get('loc')
                if loc and 'start' in loc:
                    line_number = loc['start'].get('line')

                var_info = VariableInfo(
                    name=var_name,
                    type=var_kind,
                    line_number=line_number,
                )

                self.variables.append(var_info)

    def _check_dangerous_call(self, node: Dict, lines: List[str]):
        """Check for dangerous function calls"""
        callee = node.get('callee', {})

        # Check for direct dangerous function calls
        if callee.get('type') == 'Identifier':
            func_name = callee.get('name')
            if func_name in self.DANGEROUS_FUNCTIONS:
                line_number = None
                loc = node.get('loc')
                if loc and 'start' in loc:
                    line_number = loc['start'].get('line')

                code_snippet = lines[line_number - 1].strip() if line_number and line_number <= len(lines) else None

                self.security_issues.append(SecurityIssue(
                    vulnerability_type=VulnerabilityType.DANGEROUS_FUNCTION,
                    severity='critical',
                    line_number=line_number,
                    code_snippet=code_snippet,
                    description=f"Dangerous function '{func_name}' used: {self.DANGEROUS_FUNCTIONS[func_name]}",
                    recommendation=f"Avoid using '{func_name}'. Use safer alternatives.",
                ))

    def _check_dangerous_member_access(self, node: Dict, lines: List[str]):
        """Check for dangerous DOM API access"""
        property_node = node.get('property', {})
        if property_node.get('type') == 'Identifier':
            property_name = property_node.get('name')

            if property_name in self.DANGEROUS_DOM_APIS:
                line_number = None
                loc = node.get('loc')
                if loc and 'start' in loc:
                    line_number = loc['start'].get('line')

                code_snippet = lines[line_number - 1].strip() if line_number and line_number <= len(lines) else None

                self.security_issues.append(SecurityIssue(
                    vulnerability_type=VulnerabilityType.DOM_XSS,
                    severity='high',
                    line_number=line_number,
                    code_snippet=code_snippet,
                    description=f"Potentially dangerous DOM API '{property_name}' used",
                    recommendation="Sanitize user input before using DOM manipulation APIs.",
                ))

    def _check_prototype_pollution(self, node: Dict, lines: List[str]):
        """Check for prototype pollution patterns"""
        left = node.get('left', {})

        # Check if left side is member expression
        if left.get('type') == 'MemberExpression':
            # Check for __proto__, constructor, or prototype access
            property_node = left.get('property', {})
            if property_node.get('type') == 'Identifier':
                property_name = property_node.get('name')

                if property_name in self.PROTOTYPE_PROPERTIES:
                    line_number = None
                    loc = node.get('loc')
                    if loc and 'start' in loc:
                        line_number = loc['start'].get('line')

                    code_snippet = lines[line_number - 1].strip() if line_number and line_number <= len(lines) else None

                    self.security_issues.append(SecurityIssue(
                        vulnerability_type=VulnerabilityType.PROTOTYPE_POLLUTION,
                        severity='critical',
                        line_number=line_number,
                        code_snippet=code_snippet,
                        description=f"Potential prototype pollution via '{property_name}' assignment",
                        recommendation="Avoid modifying prototype chain. Use Object.create(null) for dictionaries.",
                    ))

    def _analyze_regex(self, code: str):
        """Fallback regex-based analysis when AST parsing unavailable"""
        lines = code.split('\n')

        # Extract functions using regex
        func_pattern = r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(([^)]*)\)'
        for match in re.finditer(func_pattern, code):
            func_name = match.group(1)
            params_str = match.group(2)
            params = [p.strip() for p in params_str.split(',') if p.strip()]

            # Find line number
            line_number = code[:match.start()].count('\n') + 1

            self.functions.append(FunctionInfo(
                name=func_name,
                params=params,
                line_number=line_number,
            ))

        # Check for dangerous functions
        for func_name, description in self.DANGEROUS_FUNCTIONS.items():
            pattern = rf'\b{func_name}\s*\('
            for match in re.finditer(pattern, code):
                line_number = code[:match.start()].count('\n') + 1
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else None

                self.security_issues.append(SecurityIssue(
                    vulnerability_type=VulnerabilityType.DANGEROUS_FUNCTION,
                    severity='critical',
                    line_number=line_number,
                    code_snippet=code_snippet,
                    description=f"Dangerous function '{func_name}' used: {description}",
                    recommendation=f"Avoid using '{func_name}'.",
                ))

        # Check for prototype pollution
        proto_pattern = r'(\w+)\[["\'](__proto__|constructor|prototype)["\']\]'
        for match in re.finditer(proto_pattern, code):
            line_number = code[:match.start()].count('\n') + 1
            code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else None

            self.security_issues.append(SecurityIssue(
                vulnerability_type=VulnerabilityType.PROTOTYPE_POLLUTION,
                severity='critical',
                line_number=line_number,
                code_snippet=code_snippet,
                description="Potential prototype pollution pattern detected",
                recommendation="Avoid modifying prototype chain.",
            ))

    def _scan_for_secrets(self, code: str):
        """Scan for hardcoded secrets"""
        lines = code.split('\n')

        # Patterns for common secrets
        secret_patterns = [
            (r'api[_-]?key\s*[=:]\s*["\']([^"\']{20,})["\']', 'API Key'),
            (r'password\s*[=:]\s*["\']([^"\']+)["\']', 'Password'),
            (r'secret\s*[=:]\s*["\']([^"\']{20,})["\']', 'Secret'),
            (r'token\s*[=:]\s*["\']([^"\']{20,})["\']', 'Token'),
            (r'aws_access_key_id\s*[=:]\s*["\']([^"\']+)["\']', 'AWS Access Key'),
        ]

        for pattern, secret_type in secret_patterns:
            for match in re.finditer(pattern, code, re.IGNORECASE):
                line_number = code[:match.start()].count('\n') + 1
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else None

                self.security_issues.append(SecurityIssue(
                    vulnerability_type=VulnerabilityType.HARDCODED_SECRET,
                    severity='high',
                    line_number=line_number,
                    code_snippet=code_snippet,
                    description=f"Hardcoded {secret_type} detected",
                    recommendation=f"Move {secret_type} to environment variables or secure configuration.",
                ))

    def _scan_for_weak_crypto(self, code: str):
        """Scan for weak cryptography"""
        lines = code.split('\n')

        # Weak crypto patterns
        weak_crypto_patterns = [
            (r'Math\.random\(\)', 'Math.random() is not cryptographically secure'),
            (r'MD5|md5', 'MD5 is cryptographically broken'),
            (r'SHA1|sha1', 'SHA1 is considered weak'),
        ]

        for pattern, description in weak_crypto_patterns:
            for match in re.finditer(pattern, code):
                line_number = code[:match.start()].count('\n') + 1
                code_snippet = lines[line_number - 1].strip() if line_number <= len(lines) else None

                self.security_issues.append(SecurityIssue(
                    vulnerability_type=VulnerabilityType.WEAK_CRYPTO,
                    severity='medium',
                    line_number=line_number,
                    code_snippet=code_snippet,
                    description=description,
                    recommendation="Use crypto.getRandomValues() or secure hash functions (SHA-256+).",
                ))

    def find_dangerous_patterns(self, code: str) -> List[SecurityIssue]:
        """
        Find dangerous patterns in JavaScript code.

        Args:
            code: JavaScript source code

        Returns:
            List of security issues
        """
        self.analyze_code(code)
        return self.security_issues.copy()

    def extract_functions(self, code: str) -> List[FunctionInfo]:
        """
        Extract function definitions from code.

        Args:
            code: JavaScript source code

        Returns:
            List of function information
        """
        self.analyze_code(code)
        return self.functions.copy()

    def detect_prototype_pollution(self, code: str) -> List[SecurityIssue]:
        """
        Detect prototype pollution vulnerabilities.

        Args:
            code: JavaScript source code

        Returns:
            List of prototype pollution issues
        """
        self.analyze_code(code)
        return [
            issue for issue in self.security_issues
            if issue.vulnerability_type == VulnerabilityType.PROTOTYPE_POLLUTION
        ]

    def get_summary(self) -> Dict[str, Any]:
        """
        Get analysis summary.

        Returns:
            Summary dictionary
        """
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
        }

        for issue in self.security_issues:
            severity_counts[issue.severity] = severity_counts.get(issue.severity, 0) + 1

        return {
            'total_functions': len(self.functions),
            'total_variables': len(self.variables),
            'total_security_issues': len(self.security_issues),
            'critical_issues': severity_counts['critical'],
            'high_issues': severity_counts['high'],
            'medium_issues': severity_counts['medium'],
            'low_issues': severity_counts['low'],
            'ast_parsing_available': self.use_ast_parsing,
        }
