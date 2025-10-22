"""
Prompt Generation Module for CRS Strategies

Provides centralized prompt management for all POV and patch generation strategies.

Binary Fuzzing Public API:
- create_commit_based_prompt(): Phase 0 basic commit-based prompt
- create_category_based_prompt_c(): Phase 1 CWE category prompt for C
- create_category_based_prompt_java(): Phase 1 CWE category prompt for Java
- create_modified_functions_prompt(): Phase 2 modified functions analysis
- create_call_path_prompt(): Phase 3 single call path analysis
- create_combined_call_paths_prompt(): Phase 3 multiple call paths combined

Web Fuzzing Public API:
- create_web_commit_based_prompt(): Basic web vulnerability prompt
- create_xss_category_prompt(): XSS-specific with context awareness
- create_sqli_category_prompt(): SQL injection with database-specific patterns
- create_csrf_category_prompt(): CSRF attack generation
- create_prototype_pollution_prompt(): JavaScript prototype pollution
- create_dom_flow_prompt(): DOM-based data flow analysis
- create_framework_specific_prompt(): React/Vue/Angular vulnerabilities
- create_multi_phase_prompt(): Multi-phase strategy with feedback
- create_feedback_prompt(): Iterative payload improvement
- create_combined_category_prompt(): Multiple vulnerability categories

Usage (Binary):
    from common.prompts import create_commit_based_prompt

    prompt = create_commit_based_prompt(
        fuzzer_code=code,
        commit_diff=diff,
        sanitizer="address",
        language="c"
    )

Usage (Web):
    from common.prompts import create_xss_category_prompt

    prompt = create_xss_category_prompt(
        target_url="https://example.com",
        web_app_code=code,
        commit_diff=diff,
        context="html",
        payload_count=5
    )
"""

from common.prompts.builder import (
    create_commit_based_prompt,
    create_category_based_prompt_c,
    create_category_based_prompt_java,
    create_modified_functions_prompt,
    create_call_path_prompt,
    create_combined_call_paths_prompt,
)

from common.prompts.web_builder import (
    create_web_commit_based_prompt,
    create_xss_category_prompt,
    create_sqli_category_prompt,
    create_csrf_category_prompt,
    create_prototype_pollution_prompt,
    create_dom_flow_prompt,
    create_framework_specific_prompt,
    create_multi_phase_prompt,
    create_feedback_prompt,
    create_combined_category_prompt,
)

__all__ = [
    # Binary fuzzing prompts
    'create_commit_based_prompt',
    'create_category_based_prompt_c',
    'create_category_based_prompt_java',
    'create_modified_functions_prompt',
    'create_call_path_prompt',
    'create_combined_call_paths_prompt',
    # Web fuzzing prompts
    'create_web_commit_based_prompt',
    'create_xss_category_prompt',
    'create_sqli_category_prompt',
    'create_csrf_category_prompt',
    'create_prototype_pollution_prompt',
    'create_dom_flow_prompt',
    'create_framework_specific_prompt',
    'create_multi_phase_prompt',
    'create_feedback_prompt',
    'create_combined_category_prompt',
]

__version__ = '1.0.0'
