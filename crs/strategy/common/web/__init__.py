"""
Web Utilities Package for WebFuzzingBrain

This package provides comprehensive web application security testing utilities
adapted from the original FuzzingBrain binary fuzzing framework.

Modules:
    browser: Browser automation using Playwright
    http_client: HTTP request testing and manipulation
    dom_analyzer: DOM structure analysis and sink/source detection
    js_parser: JavaScript AST parsing and analysis
    payload_generators: Web vulnerability payload generation

Usage:
    from common.web import BrowserPool, BrowserSession
    from common.web import HTTPTester
    from common.web import DOMAnalyzer
    from common.web import JavaScriptParser
    from common.web import PayloadGenerator
"""

from .browser import BrowserPool, BrowserSession, BrowserConfig, ConsoleMessage, NetworkRequest
from .http_client import HTTPTester
from .dom_analyzer import DOMAnalyzer, Sink, Source
from .js_parser import JavaScriptParser
from .payload_generators import PayloadGenerator, PayloadContext, SQLDatabase

__all__ = [
    'BrowserPool',
    'BrowserSession',
    'BrowserConfig',
    'ConsoleMessage',
    'NetworkRequest',
    'HTTPTester',
    'DOMAnalyzer',
    'Sink',
    'Source',
    'JavaScriptParser',
    'PayloadGenerator',
    'PayloadContext',
    'SQLDatabase',
]

__version__ = '1.0.0'
