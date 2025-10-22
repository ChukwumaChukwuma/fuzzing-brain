"""
Web Code Analyzer

Provides JavaScript/TypeScript analysis for web fuzzing strategies.
Supports DOM analysis, data flow tracking, and framework-specific pattern detection.
"""
import os
import json
from typing import Dict, List, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from common.config import StrategyConfig
    from common.logging.logger import StrategyLogger


class WebAnalyzer:
    """
    Analyzes JavaScript/TypeScript code for web vulnerabilities

    Provides:
    - DOM sink/source detection
    - Data flow analysis
    - Framework-specific pattern detection
    - Security issue identification

    Usage:
        analyzer = WebAnalyzer(config, logger)
        dom_analysis = analyzer.analyze_dom_sinks_sources(js_code)
        data_flows = analyzer.extract_data_flows(js_code)
        framework = analyzer.detect_framework(js_code)
    """

    def __init__(self, config: 'StrategyConfig', logger: 'StrategyLogger'):
        """
        Initialize web code analyzer

        Args:
            config: Strategy configuration
            logger: Logger instance
        """
        self.config = config
        self.logger = logger

        # Initialize component analyzers from common.web
        from common.web import DOMAnalyzer, JavaScriptParser
        self.dom_analyzer = DOMAnalyzer(logger=logger)
        self.js_parser = JavaScriptParser(logger=logger)

    def analyze_dom_sinks_sources(self, code: str) -> Dict[str, Any]:
        """
        Analyze JavaScript code for DOM sinks and sources

        Args:
            code: JavaScript/TypeScript source code

        Returns:
            Dictionary with:
            {
                'sinks': [Sink, ...],
                'sources': [Source, ...],
                'flows': [(source, sink), ...],
                'security_issues': [SecurityIssue, ...]
            }
        """
        self.logger.log("Analyzing DOM sinks and sources...")

        # Extract sinks and sources using DOM analyzer
        sinks = self.dom_analyzer.find_sinks(code)
        sources = self.dom_analyzer.find_sources(code)

        self.logger.log(f"Found {len(sinks)} sinks and {len(sources)} sources")

        # Analyze JavaScript for security issues
        js_analysis = self.js_parser.analyze_code(code)
        security_issues = js_analysis.get('security_issues', [])

        self.logger.log(f"Found {len(security_issues)} security issues")

        # Extract potential data flows (simple heuristic: match sources to sinks in same scope)
        flows = self._extract_simple_flows(sources, sinks, code)

        return {
            'sinks': sinks,
            'sources': sources,
            'flows': flows,
            'security_issues': security_issues,
            'dangerous_patterns': js_analysis.get('dangerous_patterns', []),
        }

    def extract_data_flows(self, code: str, target_file: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Extract data flows from sources to sinks

        Args:
            code: JavaScript/TypeScript source code
            target_file: Optional target file path for analysis service

        Returns:
            List of data flow dictionaries:
            [
                {
                    'source': Source,
                    'sink': Sink,
                    'flow_path': [variable_name, ...],
                    'confidence': float,
                    'vulnerability_type': str
                },
                ...
            ]
        """
        self.logger.log("Extracting data flows...")

        # Analyze DOM sinks/sources
        dom_analysis = self.analyze_dom_sinks_sources(code)
        sinks = dom_analysis['sinks']
        sources = dom_analysis['sources']

        # If we have an analysis service, query it for precise data flows
        if target_file and os.environ.get("WEB_ANALYSIS_SERVICE_URL"):
            flows = self._query_analysis_service_for_flows(target_file, sinks, sources)
            if flows:
                return flows

        # Fallback: Use heuristic-based flow extraction
        flows = []
        for source, sink in dom_analysis['flows']:
            flow = {
                'source': source,
                'sink': sink,
                'flow_path': [],  # Would be filled by taint analysis
                'confidence': 0.6,  # Heuristic confidence
                'vulnerability_type': self._infer_vuln_type(source, sink)
            }
            flows.append(flow)

        self.logger.log(f"Extracted {len(flows)} data flows")
        return flows

    def detect_framework(self, code: str) -> str:
        """
        Detect web framework from code

        Args:
            code: JavaScript/TypeScript source code

        Returns:
            Framework name: 'react', 'vue', 'angular', or 'unknown'
        """
        code_lower = code.lower()

        # React detection
        if any(pattern in code_lower for pattern in [
            'react', 'jsx', 'usestate', 'useeffect', 'component',
            'dangerouslysetinnerhtml', 'reactdom'
        ]):
            return 'react'

        # Vue detection
        if any(pattern in code_lower for pattern in [
            'vue', 'v-model', 'v-bind', 'v-html', 'v-on',
            'createapp', '$refs', '$emit'
        ]):
            return 'vue'

        # Angular detection
        if any(pattern in code_lower for pattern in [
            'angular', '@angular', 'ngmodel', 'ngoninit',
            'component({', 'domsanitizer', 'httplient'
        ]):
            return 'angular'

        # Express.js (backend framework)
        if any(pattern in code_lower for pattern in [
            'express()', 'app.get(', 'app.post(', 'req.body', 'res.send'
        ]):
            return 'express'

        # Next.js
        if any(pattern in code_lower for pattern in [
            'getserversideprops', 'getstaticprops', 'next/router'
        ]):
            return 'nextjs'

        return 'unknown'

    def detect_framework_specific_vulnerabilities(self, code: str, framework: str) -> List[Dict[str, Any]]:
        """
        Detect framework-specific vulnerability patterns

        Args:
            code: JavaScript/TypeScript source code
            framework: Detected framework name

        Returns:
            List of vulnerability dictionaries:
            [
                {
                    'type': str,
                    'severity': str,
                    'description': str,
                    'line_number': int,
                    'code_snippet': str
                },
                ...
            ]
        """
        vulnerabilities = []

        if framework == 'react':
            vulnerabilities.extend(self._detect_react_vulns(code))
        elif framework == 'vue':
            vulnerabilities.extend(self._detect_vue_vulns(code))
        elif framework == 'angular':
            vulnerabilities.extend(self._detect_angular_vulns(code))
        elif framework == 'express':
            vulnerabilities.extend(self._detect_express_vulns(code))

        return vulnerabilities

    def get_analysis_feedback(self, code: str, previous_payloads: List[str]) -> str:
        """
        Generate analysis feedback for LLM prompt

        Args:
            code: JavaScript/TypeScript source code
            previous_payloads: Previously attempted payloads

        Returns:
            Formatted analysis feedback string
        """
        # Analyze code
        dom_analysis = self.analyze_dom_sinks_sources(code)
        framework = self.detect_framework(code)
        framework_vulns = self.detect_framework_specific_vulnerabilities(code, framework)

        # Build feedback message
        feedback_parts = []

        if dom_analysis['sinks']:
            feedback_parts.append(f"\nDetected DOM Sinks ({len(dom_analysis['sinks'])}):")
            for sink in dom_analysis['sinks'][:5]:  # Limit to 5
                feedback_parts.append(f"  - {sink.property_or_method} at line {sink.line_number}")

        if dom_analysis['sources']:
            feedback_parts.append(f"\nDetected DOM Sources ({len(dom_analysis['sources'])}):")
            for source in dom_analysis['sources'][:5]:  # Limit to 5
                feedback_parts.append(f"  - {source.property_or_method} at line {source.line_number}")

        if framework and framework != 'unknown':
            feedback_parts.append(f"\nDetected Framework: {framework.upper()}")

        if framework_vulns:
            feedback_parts.append(f"\nFramework-Specific Vulnerabilities ({len(framework_vulns)}):")
            for vuln in framework_vulns[:3]:  # Limit to 3
                feedback_parts.append(f"  - {vuln['type']}: {vuln['description']}")

        if dom_analysis['flows']:
            feedback_parts.append(f"\nPotential Data Flows ({len(dom_analysis['flows'])}):")
            for source, sink in dom_analysis['flows'][:3]:  # Limit to 3
                feedback_parts.append(f"  - {source.property_or_method} → {sink.property_or_method}")

        if not feedback_parts:
            return ""

        return "\n".join(feedback_parts)

    def _extract_simple_flows(self, sources: List, sinks: List, code: str) -> List[tuple]:
        """
        Extract simple data flows using heuristics

        Args:
            sources: List of Source objects
            sinks: List of Sink objects
            code: Full source code

        Returns:
            List of (source, sink) tuples representing potential flows
        """
        flows = []

        # Simple heuristic: sources and sinks on nearby lines (within 50 lines)
        for source in sources:
            for sink in sinks:
                line_distance = abs(source.line_number - sink.line_number)
                if line_distance <= 50:
                    flows.append((source, sink))

        return flows

    def _infer_vuln_type(self, source, sink) -> str:
        """
        Infer vulnerability type from source-sink pair

        Args:
            source: Source object
            sink: Sink object

        Returns:
            Vulnerability type (xss, sqli, etc.)
        """
        from common.web.dom_analyzer import SinkType

        # Map sink types to vulnerability types
        if sink.sink_type == SinkType.HTML_WRITE:
            return 'xss'
        elif sink.sink_type == SinkType.EXECUTION:
            return 'code_injection'
        elif sink.sink_type == SinkType.URL_MANIPULATION:
            return 'open_redirect'
        elif sink.sink_type == SinkType.STORAGE:
            return 'data_exposure'
        elif sink.sink_type == SinkType.DOM_MANIPULATION:
            return 'dom_xss'
        else:
            return 'unknown'

    def _query_analysis_service_for_flows(self, target_file: str, sinks: List, sources: List) -> Optional[List[Dict[str, Any]]]:
        """
        Query static analysis service for precise data flows

        Args:
            target_file: Path to JavaScript file
            sinks: List of Sink objects
            sources: List of Source objects

        Returns:
            List of data flow dictionaries, or None on failure
        """
        # Import web analysis service interface
        from common.utils.web_analysis import extract_web_data_flows_from_analysis_service

        try:
            flows = extract_web_data_flows_from_analysis_service(
                target_file=target_file,
                project_dir=self.config.project_dir,
                sinks=sinks,
                sources=sources
            )
            return flows
        except Exception as e:
            self.logger.log(f"Failed to query web analysis service: {e}")
            return None

    def _detect_react_vulns(self, code: str) -> List[Dict[str, Any]]:
        """Detect React-specific vulnerabilities"""
        vulns = []
        lines = code.split('\n')

        for i, line in enumerate(lines, 1):
            # dangerouslySetInnerHTML usage
            if 'dangerouslySetInnerHTML' in line:
                vulns.append({
                    'type': 'react_xss',
                    'severity': 'high',
                    'description': 'Usage of dangerouslySetInnerHTML may allow XSS',
                    'line_number': i,
                    'code_snippet': line.strip()
                })

            # Direct DOM manipulation in React
            if 'document.getElementById' in line or 'document.querySelector' in line:
                vulns.append({
                    'type': 'react_antipattern',
                    'severity': 'medium',
                    'description': 'Direct DOM manipulation bypasses React virtual DOM',
                    'line_number': i,
                    'code_snippet': line.strip()
                })

        return vulns

    def _detect_vue_vulns(self, code: str) -> List[Dict[str, Any]]:
        """Detect Vue-specific vulnerabilities"""
        vulns = []
        lines = code.split('\n')

        for i, line in enumerate(lines, 1):
            # v-html usage
            if 'v-html' in line:
                vulns.append({
                    'type': 'vue_xss',
                    'severity': 'high',
                    'description': 'v-html directive may allow XSS if used with user input',
                    'line_number': i,
                    'code_snippet': line.strip()
                })

            # Dynamic component rendering
            if ':is=' in line or 'v-bind:is' in line:
                vulns.append({
                    'type': 'vue_dynamic_component',
                    'severity': 'medium',
                    'description': 'Dynamic component rendering may be exploited',
                    'line_number': i,
                    'code_snippet': line.strip()
                })

        return vulns

    def _detect_angular_vulns(self, code: str) -> List[Dict[str, Any]]:
        """Detect Angular-specific vulnerabilities"""
        vulns = []
        lines = code.split('\n')

        for i, line in enumerate(lines, 1):
            # bypassSecurityTrust* methods
            if 'bypassSecurityTrust' in line:
                vulns.append({
                    'type': 'angular_sanitizer_bypass',
                    'severity': 'high',
                    'description': 'DomSanitizer bypass may allow XSS',
                    'line_number': i,
                    'code_snippet': line.strip()
                })

            # innerHTML usage
            if '.innerHTML' in line and '=' in line:
                vulns.append({
                    'type': 'angular_innerhtml',
                    'severity': 'high',
                    'description': 'Direct innerHTML assignment bypasses Angular sanitization',
                    'line_number': i,
                    'code_snippet': line.strip()
                })

        return vulns

    def _detect_express_vulns(self, code: str) -> List[Dict[str, Any]]:
        """Detect Express.js-specific vulnerabilities"""
        vulns = []
        lines = code.split('\n')

        for i, line in enumerate(lines, 1):
            # SQL concatenation
            if ('query(' in line or 'execute(' in line) and ('+' in line or '${' in line):
                vulns.append({
                    'type': 'express_sqli',
                    'severity': 'critical',
                    'description': 'SQL query concatenation may allow SQL injection',
                    'line_number': i,
                    'code_snippet': line.strip()
                })

            # Unsafe eval usage
            if 'eval(' in line and ('req.' in line or 'request.' in line):
                vulns.append({
                    'type': 'express_code_injection',
                    'severity': 'critical',
                    'description': 'eval() with user input allows code injection',
                    'line_number': i,
                    'code_snippet': line.strip()
                })

            # Missing CSRF protection
            if 'app.post(' in line and 'csrf' not in code.lower():
                vulns.append({
                    'type': 'express_csrf',
                    'severity': 'medium',
                    'description': 'POST route may lack CSRF protection',
                    'line_number': i,
                    'code_snippet': line.strip()
                })

        return vulns


class WebCoverageAnalyzer:
    """
    Browser-based coverage analyzer for web applications

    Tracks JavaScript code coverage during payload execution.
    Provides feedback on which code paths were exercised.
    """

    def __init__(self, config: 'StrategyConfig', logger: 'StrategyLogger'):
        """
        Initialize web coverage analyzer

        Args:
            config: Strategy configuration
            logger: Logger instance
        """
        self.config = config
        self.logger = logger

    def get_coverage_feedback(self, payload_path: str, target_url: str) -> str:
        """
        Get JavaScript coverage feedback for the given payload

        Args:
            payload_path: Path to payload file
            target_url: Target URL

        Returns:
            Formatted coverage feedback string for LLM prompt
        """
        self.logger.log(f"Collecting JavaScript coverage for {payload_path}...")

        # In a real implementation, this would:
        # 1. Use Playwright's coverage API
        # 2. Execute payload against target
        # 3. Collect JavaScript coverage data
        # 4. Format for LLM feedback

        # Placeholder for now - would integrate with browser automation
        return ""

    def analyze_coverage(self, coverage_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze JavaScript coverage data

        Args:
            coverage_data: Raw coverage data from Playwright

        Returns:
            Analysis results with covered/uncovered functions, lines, etc.
        """
        # Placeholder for coverage analysis
        return {
            'total_functions': 0,
            'covered_functions': 0,
            'total_lines': 0,
            'covered_lines': 0,
            'uncovered_critical_paths': []
        }
