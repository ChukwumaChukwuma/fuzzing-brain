"""
Code Analysis Package

Provides various code analysis capabilities for fuzzing strategies,
including coverage analysis, control flow extraction, and static analysis.

Binary Fuzzing Analysis:
- CoverageAnalyzer: C/C++/Java coverage and control flow analysis

Web Fuzzing Analysis:
- WebAnalyzer: JavaScript/TypeScript DOM and security analysis
- WebCoverageAnalyzer: Browser-based JavaScript coverage tracking
"""
from code_analysis.coverage_analyzer import CoverageAnalyzer
from code_analysis.web_analyzer import WebAnalyzer, WebCoverageAnalyzer

__all__ = [
    # Binary fuzzing analysis
    'CoverageAnalyzer',
    # Web fuzzing analysis
    'WebAnalyzer',
    'WebCoverageAnalyzer',
]
