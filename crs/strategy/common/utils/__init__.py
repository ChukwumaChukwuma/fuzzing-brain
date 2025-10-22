"""Utility functions for strategies"""

# Text utilities
from common.utils.text_utils import (
    truncate_output,
    is_likely_source_for_fuzzer,
    strip_license_text,
    filter_instrumented_lines,
)

# Code extraction utilities
from common.utils.code_extract import (
    extract_code,
    is_python_code,
    extract_python_code_from_response,
    extract_function_name_from_code,
    extract_function_body,
)

# Git and diff utilities
from common.utils.git_utils import (
    process_large_diff,
    get_commit_info,
    extract_diff_functions_using_funtarget,
    parse_commit_diff,
)

# Code analysis utilities (binary fuzzing)
from common.utils.code_analysis import (
    extract_call_paths_from_analysis_service,
)

# Web analysis utilities
from common.utils.web_analysis import (
    extract_web_data_flows_from_analysis_service,
    query_framework_vulnerabilities,
    query_dependency_vulnerabilities,
    extract_call_graph,
    analyze_typescript_types,
)

# Crash parsing utilities
from common.utils.crash_utils import (
    extract_java_fallback_location,
    extract_asan_fallback_location,
    extract_ubsan_fallback_location,
    extract_msan_fallback_location,
    extract_crash_location,
    generate_vulnerability_signature,
    extract_crash_trace,
    extract_crash_output,
)

# Task and file utilities
from common.utils.task_utils import (
    load_task_detail,
    cleanup_seed_corpus,
    extract_and_save_crash_input,
    run_fuzzer_with_coverage,
)

# Fuzzer utilities
from common.utils.fuzzer_utils import (
    find_fuzzer_source,
)

__all__ = [
    # Text utilities
    'truncate_output',
    'is_likely_source_for_fuzzer',
    'strip_license_text',
    'filter_instrumented_lines',
    # Code extraction
    'extract_code',
    'is_python_code',
    'extract_python_code_from_response',
    'extract_function_name_from_code',
    'extract_function_body',
    # Git/diff
    'process_large_diff',
    'get_commit_info',
    'extract_diff_functions_using_funtarget',
    'parse_commit_diff',
    # Code analysis (binary)
    'extract_call_paths_from_analysis_service',
    # Web analysis
    'extract_web_data_flows_from_analysis_service',
    'query_framework_vulnerabilities',
    'query_dependency_vulnerabilities',
    'extract_call_graph',
    'analyze_typescript_types',
    # Crash parsing
    'extract_java_fallback_location',
    'extract_asan_fallback_location',
    'extract_ubsan_fallback_location',
    'extract_msan_fallback_location',
    'extract_crash_location',
    'generate_vulnerability_signature',
    'extract_crash_trace',
    'extract_crash_output',
    # Task/file utilities
    'load_task_detail',
    'cleanup_seed_corpus',
    'extract_and_save_crash_input',
    'run_fuzzer_with_coverage',
    # Fuzzer utilities
    'find_fuzzer_source',
]

# Web vulnerability utilities
from .web_vulnerability_signature import (
    generate_web_vulnerability_signature,
    generate_web_vulnerability_report,
    deduplicate_vulnerabilities,
    classify_vulnerability_severity,
)

# Add web vulnerability utilities to __all__
__all__.extend([
    'generate_web_vulnerability_signature',
    'generate_web_vulnerability_report',
    'deduplicate_vulnerabilities',
    'classify_vulnerability_severity',
])
