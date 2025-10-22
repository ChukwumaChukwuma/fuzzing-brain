"""
DOM Analysis Engine for WebFuzzingBrain

Provides DOM structure analysis, sink/source detection, and data flow tracking
for web vulnerability discovery, particularly DOM-based XSS and client-side attacks.
"""

import re
from typing import List, Dict, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum


class SinkType(Enum):
    """Types of DOM sinks"""
    EXECUTION = "execution"  # eval, Function, setTimeout, setInterval
    HTML_WRITE = "html_write"  # innerHTML, outerHTML, document.write
    DOM_MANIPULATION = "dom_manipulation"  # insertAdjacentHTML, appendChild
    URL_NAVIGATION = "url_navigation"  # location, window.open
    SCRIPT_SRC = "script_src"  # script.src, iframe.src
    EVENT_HANDLER = "event_handler"  # onclick, onerror, onload
    STORAGE = "storage"  # localStorage, sessionStorage
    WEBSOCKET = "websocket"  # WebSocket constructor


class SourceType(Enum):
    """Types of DOM sources"""
    URL_PARAM = "url_param"  # location.search, location.hash
    URL_PATH = "url_path"  # location.pathname
    REFERRER = "referrer"  # document.referrer
    POST_MESSAGE = "post_message"  # window.addEventListener('message')
    LOCAL_STORAGE = "local_storage"  # localStorage.getItem
    SESSION_STORAGE = "session_storage"  # sessionStorage.getItem
    COOKIE = "cookie"  # document.cookie
    DOM_ELEMENT = "dom_element"  # element.value, element.innerHTML


@dataclass
class Sink:
    """DOM sink that could execute attacker-controlled data"""
    sink_type: SinkType
    property_or_method: str
    element_selector: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    severity: str = "high"  # high, medium, low
    context: Optional[str] = None


@dataclass
class Source:
    """DOM source that provides attacker-controlled data"""
    source_type: SourceType
    property_or_method: str
    element_selector: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    context: Optional[str] = None


@dataclass
class DataFlow:
    """Data flow from source to sink"""
    source: Source
    sink: Sink
    flow_path: List[str] = field(default_factory=list)
    confidence: float = 0.0  # 0.0 to 1.0
    exploitable: bool = False


@dataclass
class EventListener:
    """Event listener information"""
    event_type: str
    handler: str
    element_selector: Optional[str] = None
    is_inline: bool = False


class DOMAnalyzer:
    """
    Analyzes DOM structure to find potential vulnerability points.

    Key features:
    - Identifies dangerous sinks (eval, innerHTML, etc.)
    - Identifies attacker-controlled sources (URL params, postMessage, etc.)
    - Tracks data flow from sources to sinks
    - Enumerates event listeners
    - Detects prototype pollution opportunities
    """

    # Dangerous DOM sinks
    EXECUTION_SINKS = [
        'eval',
        'Function',
        'setTimeout',
        'setInterval',
        'execScript',
        'setImmediate',
    ]

    HTML_WRITE_SINKS = [
        'innerHTML',
        'outerHTML',
        'document.write',
        'document.writeln',
        'insertAdjacentHTML',
    ]

    DOM_MANIPULATION_SINKS = [
        'appendChild',
        'insertBefore',
        'replaceChild',
        'append',
        'prepend',
        'after',
        'before',
    ]

    URL_NAVIGATION_SINKS = [
        'location',
        'location.href',
        'location.assign',
        'location.replace',
        'window.open',
        'window.location',
    ]

    SCRIPT_SRC_SINKS = [
        'script.src',
        'iframe.src',
        'embed.src',
        'object.data',
    ]

    EVENT_HANDLER_SINKS = [
        'onclick', 'onload', 'onerror', 'onmouseover', 'onmouseout',
        'onfocus', 'onblur', 'onchange', 'onsubmit', 'onkeydown',
        'onkeyup', 'onkeypress',
    ]

    # DOM sources
    URL_SOURCES = [
        'location.search',
        'location.hash',
        'location.href',
        'location.pathname',
        'window.location.search',
        'window.location.hash',
        'window.location.href',
    ]

    STORAGE_SOURCES = [
        'localStorage.getItem',
        'sessionStorage.getItem',
        'localStorage',
        'sessionStorage',
    ]

    MESSAGE_SOURCES = [
        'postMessage',
        'addEventListener',
        'onmessage',
    ]

    OTHER_SOURCES = [
        'document.referrer',
        'document.cookie',
        'document.URL',
        'window.name',
    ]

    def __init__(self, logger=None):
        """Initialize DOM analyzer"""
        self.logger = logger
        self.found_sinks: List[Sink] = []
        self.found_sources: List[Source] = []
        self.data_flows: List[DataFlow] = []
        self.event_listeners: List[EventListener] = []

    def analyze_javascript(self, js_code: str, file_path: Optional[str] = None) -> Dict[str, List]:
        """
        Analyze JavaScript code for sinks and sources.

        Args:
            js_code: JavaScript source code
            file_path: Optional file path for context

        Returns:
            Dictionary with 'sinks', 'sources', and 'flows'
        """
        self.found_sinks.clear()
        self.found_sources.clear()
        self.data_flows.clear()

        lines = js_code.split('\n')

        # Find sinks
        for line_num, line in enumerate(lines, 1):
            self._find_sinks_in_line(line, line_num)
            self._find_sources_in_line(line, line_num)

        # Analyze data flows
        self._analyze_data_flows(js_code)

        if self.logger:
            self.logger.debug(
                f"Found {len(self.found_sinks)} sinks, "
                f"{len(self.found_sources)} sources, "
                f"{len(self.data_flows)} potential flows"
            )

        return {
            'sinks': self.found_sinks.copy(),
            'sources': self.found_sources.copy(),
            'flows': self.data_flows.copy(),
        }

    def _find_sinks_in_line(self, line: str, line_num: int):
        """Find sinks in a line of code"""
        line_stripped = line.strip()

        # Skip comments
        if line_stripped.startswith('//') or line_stripped.startswith('/*'):
            return

        # Check execution sinks
        for sink in self.EXECUTION_SINKS:
            if re.search(rf'\b{sink}\s*\(', line):
                self.found_sinks.append(Sink(
                    sink_type=SinkType.EXECUTION,
                    property_or_method=sink,
                    line_number=line_num,
                    code_snippet=line.strip(),
                    severity="high",
                ))

        # Check HTML write sinks
        for sink in self.HTML_WRITE_SINKS:
            if sink in line:
                self.found_sinks.append(Sink(
                    sink_type=SinkType.HTML_WRITE,
                    property_or_method=sink,
                    line_number=line_num,
                    code_snippet=line.strip(),
                    severity="high",
                ))

        # Check URL navigation sinks
        for sink in self.URL_NAVIGATION_SINKS:
            if sink in line and '=' in line:
                self.found_sinks.append(Sink(
                    sink_type=SinkType.URL_NAVIGATION,
                    property_or_method=sink,
                    line_number=line_num,
                    code_snippet=line.strip(),
                    severity="medium",
                ))

        # Check event handler sinks
        for sink in self.EVENT_HANDLER_SINKS:
            if re.search(rf'\b{sink}\s*=', line):
                self.found_sinks.append(Sink(
                    sink_type=SinkType.EVENT_HANDLER,
                    property_or_method=sink,
                    line_number=line_num,
                    code_snippet=line.strip(),
                    severity="high",
                ))

    def _find_sources_in_line(self, line: str, line_num: int):
        """Find sources in a line of code"""
        line_stripped = line.strip()

        # Skip comments
        if line_stripped.startswith('//') or line_stripped.startswith('/*'):
            return

        # Check URL sources
        for source in self.URL_SOURCES:
            if source in line:
                self.found_sources.append(Source(
                    source_type=SourceType.URL_PARAM,
                    property_or_method=source,
                    line_number=line_num,
                    code_snippet=line.strip(),
                ))

        # Check storage sources
        for source in self.STORAGE_SOURCES:
            if source in line:
                source_type = SourceType.LOCAL_STORAGE if 'localStorage' in source else SourceType.SESSION_STORAGE
                self.found_sources.append(Source(
                    source_type=source_type,
                    property_or_method=source,
                    line_number=line_num,
                    code_snippet=line.strip(),
                ))

        # Check message sources
        if 'postMessage' in line or 'addEventListener' in line and 'message' in line:
            self.found_sources.append(Source(
                source_type=SourceType.POST_MESSAGE,
                property_or_method='postMessage',
                line_number=line_num,
                code_snippet=line.strip(),
            ))

        # Check other sources
        for source in self.OTHER_SOURCES:
            if source in line:
                if 'referrer' in source:
                    source_type = SourceType.REFERRER
                elif 'cookie' in source:
                    source_type = SourceType.COOKIE
                else:
                    source_type = SourceType.URL_PARAM

                self.found_sources.append(Source(
                    source_type=source_type,
                    property_or_method=source,
                    line_number=line_num,
                    code_snippet=line.strip(),
                ))

    def _analyze_data_flows(self, js_code: str):
        """Analyze potential data flows from sources to sinks"""
        # Simple heuristic: check if source and sink share variable names
        for source in self.found_sources:
            for sink in self.found_sinks:
                # Extract variable names from source
                source_vars = self._extract_variables(source.code_snippet or '')

                # Extract variable names from sink
                sink_vars = self._extract_variables(sink.code_snippet or '')

                # Check for common variables
                common_vars = source_vars & sink_vars

                if common_vars:
                    flow = DataFlow(
                        source=source,
                        sink=sink,
                        flow_path=list(common_vars),
                        confidence=0.7,
                        exploitable=True,
                    )
                    self.data_flows.append(flow)

    def _extract_variables(self, code: str) -> Set[str]:
        """Extract variable names from code snippet"""
        # Simple regex to find variable-like identifiers
        var_pattern = r'\b([a-zA-Z_$][a-zA-Z0-9_$]*)\b'
        variables = set(re.findall(var_pattern, code))

        # Remove JavaScript keywords
        keywords = {
            'var', 'let', 'const', 'function', 'if', 'else', 'for', 'while',
            'do', 'switch', 'case', 'break', 'continue', 'return', 'new',
            'typeof', 'instanceof', 'this', 'true', 'false', 'null', 'undefined',
        }
        variables -= keywords

        return variables

    def find_prototype_pollution(self, js_code: str) -> List[Dict[str, Any]]:
        """
        Find potential prototype pollution vulnerabilities.

        Args:
            js_code: JavaScript source code

        Returns:
            List of potential vulnerabilities
        """
        vulnerabilities = []
        lines = js_code.split('\n')

        # Patterns that indicate prototype pollution
        pollution_patterns = [
            (r'(\w+)\[(["\']?__proto__["\']?)\]', 'Direct __proto__ access'),
            (r'(\w+)\[(["\']?constructor["\']?)\]\[(["\']?prototype["\']?)\]', 'constructor.prototype access'),
            (r'Object\.setPrototypeOf', 'Object.setPrototypeOf usage'),
            (r'(\w+)\.prototype\s*=', 'Prototype assignment'),
        ]

        for line_num, line in enumerate(lines, 1):
            for pattern, description in pollution_patterns:
                if re.search(pattern, line):
                    vulnerabilities.append({
                        'line': line_num,
                        'code': line.strip(),
                        'type': description,
                        'severity': 'high',
                    })

        return vulnerabilities

    def enumerate_event_listeners(self, html_content: str) -> List[EventListener]:
        """
        Enumerate event listeners from HTML.

        Args:
            html_content: HTML content

        Returns:
            List of event listeners
        """
        self.event_listeners.clear()

        # Find inline event handlers
        inline_pattern = r'<\w+[^>]*\s+(on\w+)\s*=\s*["\']([^"\']+)["\']'
        for match in re.finditer(inline_pattern, html_content, re.IGNORECASE):
            event_type = match.group(1)
            handler = match.group(2)

            self.event_listeners.append(EventListener(
                event_type=event_type,
                handler=handler,
                is_inline=True,
            ))

        # Find addEventListener calls in script tags
        script_pattern = r'<script[^>]*>(.*?)</script>'
        for script_match in re.finditer(script_pattern, html_content, re.DOTALL | re.IGNORECASE):
            script_content = script_match.group(1)

            listener_pattern = r'addEventListener\s*\(\s*["\'](\w+)["\']'
            for listener_match in re.finditer(listener_pattern, script_content):
                event_type = listener_match.group(1)

                self.event_listeners.append(EventListener(
                    event_type=event_type,
                    handler='addEventListener',
                    is_inline=False,
                ))

        return self.event_listeners.copy()

    def find_dom_clobbering_opportunities(self, html_content: str) -> List[Dict[str, Any]]:
        """
        Find DOM clobbering opportunities.

        Args:
            html_content: HTML content

        Returns:
            List of potential DOM clobbering points
        """
        opportunities = []

        # Find elements with id or name attributes
        # These can clobber window properties
        id_name_pattern = r'<(\w+)[^>]*\s+(id|name)\s*=\s*["\']([^"\']+)["\']'

        for match in re.finditer(id_name_pattern, html_content, re.IGNORECASE):
            element_type = match.group(1)
            attribute = match.group(2)
            value = match.group(3)

            opportunities.append({
                'element': element_type,
                'attribute': attribute,
                'value': value,
                'type': 'dom_clobbering',
                'details': f'{element_type} with {attribute}="{value}" can clobber window.{value}',
            })

        return opportunities

    def analyze_html_for_sinks(self, html_content: str) -> Dict[str, List]:
        """
        Analyze HTML content for potential sinks.

        Args:
            html_content: HTML content

        Returns:
            Dictionary with analysis results
        """
        results = {
            'inline_scripts': [],
            'external_scripts': [],
            'inline_event_handlers': [],
            'forms': [],
            'dangerous_elements': [],
        }

        # Find inline scripts
        inline_script_pattern = r'<script[^>]*>(.*?)</script>'
        for match in re.finditer(inline_script_pattern, html_content, re.DOTALL | re.IGNORECASE):
            script_content = match.group(1)
            results['inline_scripts'].append(script_content)

        # Find external scripts
        external_script_pattern = r'<script[^>]*\ssrc\s*=\s*["\']([^"\']+)["\']'
        for match in re.finditer(external_script_pattern, html_content, re.IGNORECASE):
            src = match.group(1)
            results['external_scripts'].append(src)

        # Find inline event handlers
        results['inline_event_handlers'] = self.enumerate_event_listeners(html_content)

        # Find forms
        form_pattern = r'<form[^>]*action\s*=\s*["\']([^"\']+)["\']'
        for match in re.finditer(form_pattern, html_content, re.IGNORECASE):
            action = match.group(1)
            results['forms'].append({'action': action})

        # Find dangerous elements
        dangerous_elements = ['iframe', 'embed', 'object', 'frame']
        for element in dangerous_elements:
            pattern = rf'<{element}[^>]*>'
            for match in re.finditer(pattern, html_content, re.IGNORECASE):
                results['dangerous_elements'].append({
                    'element': element,
                    'html': match.group(0),
                })

        return results

    def get_summary(self) -> Dict[str, Any]:
        """
        Get analysis summary.

        Returns:
            Summary dictionary
        """
        return {
            'total_sinks': len(self.found_sinks),
            'total_sources': len(self.found_sources),
            'total_flows': len(self.data_flows),
            'total_event_listeners': len(self.event_listeners),
            'high_severity_sinks': len([s for s in self.found_sinks if s.severity == 'high']),
            'exploitable_flows': len([f for f in self.data_flows if f.exploitable]),
        }
