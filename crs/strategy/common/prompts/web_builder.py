"""
Web Prompt Builder

Functions to build web-specific prompts from templates and context data.
Similar to builder.py but for web vulnerabilities.
"""

import os
from typing import Dict, List, Optional, Any
from common.prompts.web_templates import *


def create_web_commit_based_prompt(
    target_url: str,
    web_app_code: str,
    commit_diff: str,
    web_framework: str = "Unknown",
    payload_count: int = 5,
    vulnerability_types: Optional[List[str]] = None,
) -> str:
    """
    Create basic commit-based prompt for web vulnerability discovery.

    Args:
        target_url: Target web application URL
        web_app_code: Web application source code (JavaScript/HTML)
        commit_diff: Commit diff showing vulnerability introduction
        web_framework: Web framework (React, Vue, Angular, etc.)
        payload_count: Number of payloads to generate
        vulnerability_types: List of target vulnerability types

    Returns:
        Complete prompt string
    """
    if vulnerability_types is None:
        vulnerability_types = ["xss", "sqli", "csrf"]

    # Build base prompt
    prompt = WEB_BASE_PROMPT.format(
        target_url=target_url,
        web_framework=web_framework,
        payload_count=payload_count,
        web_app_code=web_app_code[:10000],  # Truncate to avoid token overflow
        commit_diff=commit_diff[:5000],  # Truncate diff
    )

    # Add ending
    prompt += WEB_PROMPT_ENDING.format(payload_count=payload_count)

    return prompt


def create_xss_category_prompt(
    target_url: str,
    web_app_code: str,
    commit_diff: str,
    context: str = "html",  # html, attribute, javascript, url
    payload_count: int = 5,
    dom_analysis: Optional[Dict] = None,
) -> str:
    """
    Create XSS-specific category prompt with context awareness.

    Args:
        target_url: Target URL
        web_app_code: Web application code
        commit_diff: Commit diff
        context: Injection context (html, attribute, javascript, url)
        payload_count: Number of payloads
        dom_analysis: Optional DOM analysis results

    Returns:
        XSS-specific prompt
    """
    category_desc = CWE_DESCRIPTIONS_WEB["CWE-79"]

    # Base prompt
    prompt = CATEGORY_PROMPT_WEB_BASE.format(
        category_desc=category_desc,
        target_url=target_url,
        category="CWE-79",
        payload_count=payload_count,
        web_app_code=web_app_code[:10000],
        commit_diff=commit_diff[:5000],
    )

    # Add context-specific guidance
    context_guidance_map = {
        "html": XSS_CONTEXT_HTML,
        "attribute": XSS_CONTEXT_ATTRIBUTE,
        "javascript": XSS_CONTEXT_JAVASCRIPT,
        "url": XSS_CONTEXT_URL,
    }

    if context in context_guidance_map:
        prompt += "\n" + context_guidance_map[context]

    # Add DOM analysis if available
    if dom_analysis:
        sinks = dom_analysis.get('sinks', [])
        sources = dom_analysis.get('sources', [])

        if sinks or sources:
            sinks_desc = "\n".join([f"- {s.property_or_method} (line {s.line_number})" for s in sinks[:5]])
            sources_desc = "\n".join([f"- {s.property_or_method} (line {s.line_number})" for s in sources[:5]])

            prompt += "\n" + DOM_XSS_GUIDANCE.format(
                dom_sinks=sinks_desc or "None detected",
                dom_sources=sources_desc or "None detected",
            )

    # Add ending
    prompt += "\n" + WEB_PROMPT_ENDING.format(payload_count=payload_count)

    return prompt


def create_sqli_category_prompt(
    target_url: str,
    web_app_code: str,
    commit_diff: str,
    database_type: str = "generic",
    payload_count: int = 5,
) -> str:
    """
    Create SQL injection specific prompt.

    Args:
        target_url: Target URL
        web_app_code: Web application code
        commit_diff: Commit diff
        database_type: Database type (mysql, postgresql, mssql, etc.)
        payload_count: Number of payloads

    Returns:
        SQLi-specific prompt
    """
    category_desc = CWE_DESCRIPTIONS_WEB["CWE-89"]

    # Base prompt
    prompt = CATEGORY_PROMPT_WEB_BASE.format(
        category_desc=category_desc,
        target_url=target_url,
        category="CWE-89",
        payload_count=payload_count,
        web_app_code=web_app_code[:10000],
        commit_diff=commit_diff[:5000],
    )

    # Database-specific patterns
    db_patterns = {
        "mysql": [
            "' OR '1'='1",
            "' UNION SELECT NULL,NULL,NULL--",
            "' AND SLEEP(5)--",
        ],
        "postgresql": [
            "' OR '1'='1",
            "'; SELECT pg_sleep(5)--",
            "' UNION SELECT NULL,NULL,version()--",
        ],
        "mssql": [
            "' OR '1'='1",
            "'; WAITFOR DELAY '00:00:05'--",
            "' UNION SELECT @@version,NULL,NULL--",
        ],
        "oracle": [
            "' OR '1'='1",
            "' UNION SELECT banner FROM v$version--",
            "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--",
        ],
    }

    patterns = db_patterns.get(database_type, ["' OR '1'='1", "' UNION SELECT NULL--"])
    patterns_desc = "\n".join([f"- {p}" for p in patterns])

    # Add SQL injection guidance
    prompt += "\n" + SQLI_GUIDANCE.format(
        database_type=database_type,
        database_patterns=patterns_desc,
    )

    # Add ending
    prompt += "\n" + WEB_PROMPT_ENDING.format(payload_count=payload_count)

    return prompt


def create_csrf_category_prompt(
    target_url: str,
    web_app_code: str,
    commit_diff: str,
    http_method: str = "POST",
    parameters: Optional[Dict[str, str]] = None,
    payload_count: int = 5,
) -> str:
    """
    Create CSRF-specific prompt.

    Args:
        target_url: Target endpoint URL
        web_app_code: Web application code
        commit_diff: Commit diff
        http_method: HTTP method (GET, POST)
        parameters: Request parameters
        payload_count: Number of payloads

    Returns:
        CSRF-specific prompt
    """
    category_desc = CWE_DESCRIPTIONS_WEB["CWE-352"]

    if parameters is None:
        parameters = {"action": "delete", "id": "123"}

    # Base prompt
    prompt = CATEGORY_PROMPT_WEB_BASE.format(
        category_desc=category_desc,
        target_url=target_url,
        category="CWE-352",
        payload_count=payload_count,
        web_app_code=web_app_code[:10000],
        commit_diff=commit_diff[:5000],
    )

    # Add CSRF guidance
    params_desc = "\n".join([f"- {k}: {v}" for k, v in parameters.items()])
    prompt += "\n" + CSRF_GUIDANCE.format(
        target_url=target_url,
        http_method=http_method,
        parameters=params_desc,
    )

    # Add ending
    prompt += "\n" + WEB_PROMPT_ENDING.format(payload_count=payload_count)

    return prompt


def create_prototype_pollution_prompt(
    target_url: str,
    web_app_code: str,
    commit_diff: str,
    payload_count: int = 5,
    js_analysis: Optional[Dict] = None,
) -> str:
    """
    Create prototype pollution specific prompt.

    Args:
        target_url: Target URL
        web_app_code: Web application code
        commit_diff: Commit diff
        payload_count: Number of payloads
        js_analysis: Optional JavaScript analysis results

    Returns:
        Prototype pollution prompt
    """
    category_desc = CWE_DESCRIPTIONS_WEB["CWE-1321"]

    # Base prompt
    prompt = CATEGORY_PROMPT_WEB_BASE.format(
        category_desc=category_desc,
        target_url=target_url,
        category="CWE-1321",
        payload_count=payload_count,
        web_app_code=web_app_code[:10000],
        commit_diff=commit_diff[:5000],
    )

    # Add pollution patterns from analysis
    pollution_patterns = []
    if js_analysis:
        issues = js_analysis.get('security_issues', [])
        for issue in issues:
            if 'prototype' in str(issue.description).lower():
                pollution_patterns.append(f"- Line {issue.line_number}: {issue.code_snippet}")

    patterns_desc = "\n".join(pollution_patterns[:5]) if pollution_patterns else "Check for merge/extend/assign functions"

    prompt += "\n" + PROTOTYPE_POLLUTION_GUIDANCE.format(
        pollution_patterns=patterns_desc,
    )

    # Add ending
    prompt += "\n" + WEB_PROMPT_ENDING.format(payload_count=payload_count)

    return prompt


def create_dom_flow_prompt(
    target_url: str,
    web_app_code: str,
    commit_diff: str,
    data_flow: Dict[str, Any],
    payload_count: int = 5,
) -> str:
    """
    Create prompt based on detected DOM data flow.

    Args:
        target_url: Target URL
        web_app_code: Web application code
        commit_diff: Commit diff
        data_flow: Data flow information (source, sink, path)
        payload_count: Number of payloads

    Returns:
        DOM flow-specific prompt
    """
    # Extract flow components
    source = data_flow.get('source')
    sink = data_flow.get('sink')
    flow_path = data_flow.get('flow_path', [])

    # Build descriptions
    sources_desc = f"- {source.property_or_method} (line {source.line_number})" if source else "Unknown"
    sinks_desc = f"- {sink.property_or_method} (line {sink.line_number})" if sink else "Unknown"
    flow_path_desc = " → ".join(flow_path) if flow_path else "Direct flow"

    data_flow_description = f"""
Source: {source.property_or_method if source else 'Unknown'}
  ↓
{flow_path_desc}
  ↓
Sink: {sink.property_or_method if sink else 'Unknown'}
"""

    # Build prompt
    prompt = DOM_FLOW_PROMPT.format(
        data_flow_description=data_flow_description,
        sources=sources_desc,
        sinks=sinks_desc,
        flow_path=flow_path_desc,
        web_app_code=web_app_code[:10000],
        payload_count=payload_count,
    )

    # Add ending
    prompt += "\n" + WEB_PROMPT_ENDING.format(payload_count=payload_count)

    return prompt


def create_framework_specific_prompt(
    framework: str,
    target_url: str,
    web_app_code: str,
    commit_diff: str,
    payload_count: int = 5,
) -> str:
    """
    Create framework-specific vulnerability prompt.

    Args:
        framework: Framework name (react, vue, angular)
        target_url: Target URL
        web_app_code: Web application code
        commit_diff: Commit diff
        payload_count: Number of payloads

    Returns:
        Framework-specific prompt
    """
    framework_lower = framework.lower()

    # Framework-specific vulnerabilities
    framework_vulns = {
        "react": [
            "dangerouslySetInnerHTML usage",
            "Unescaped props rendering",
            "Server-Side Rendering (SSR) escaping",
            "React Router parameter injection",
        ],
        "vue": [
            "v-html directive usage",
            "Template injection",
            "Vue Router parameter injection",
            "Vuex store manipulation",
        ],
        "angular": [
            "innerHTML with DomSanitizer bypass",
            "Template injection",
            "Expression Language injection",
            "$http without validation",
        ],
    }

    vulns = framework_vulns.get(framework_lower, ["Framework-specific vulnerabilities"])
    vulns_desc = "\n".join([f"- {v}" for v in vulns])

    # Build prompt
    prompt = FRAMEWORK_PROMPT_BASE.format(
        framework=framework,
        framework_vulnerabilities=vulns_desc,
        web_app_code=web_app_code[:10000],
        commit_diff=commit_diff[:5000],
    )

    # Add framework-specific guidance
    if framework_lower == "react":
        prompt += "\n" + REACT_SPECIFIC
    elif framework_lower == "vue":
        prompt += "\n" + VUE_SPECIFIC
    elif framework_lower == "angular":
        prompt += "\n" + ANGULAR_SPECIFIC

    # Add ending
    prompt += "\n" + WEB_PROMPT_ENDING.format(payload_count=payload_count)

    return prompt


def create_multi_phase_prompt(
    base_prompt: str,
    current_phase: int,
    phase_description: str,
    previous_attempts: List[str],
    previous_results: List[str],
) -> str:
    """
    Create multi-phase prompt with feedback from previous attempts.

    Args:
        base_prompt: Base prompt for current phase
        current_phase: Current phase number
        phase_description: Description of current phase
        previous_attempts: List of previous payloads
        previous_results: List of previous results

    Returns:
        Multi-phase prompt with context
    """
    # Build previous attempts summary
    attempts_summary = []
    for i, (attempt, result) in enumerate(zip(previous_attempts, previous_results), 1):
        attempts_summary.append(f"Attempt {i}: {attempt[:100]}... → {result}")

    attempts_desc = "\n".join(attempts_summary[-3:])  # Last 3 attempts
    results_desc = "\n".join(previous_results[-3:])  # Last 3 results

    # Add multi-phase intro
    intro = MULTI_PHASE_INTRO.format(
        current_phase=current_phase,
        phase_description=phase_description,
        previous_attempts=attempts_desc,
        previous_results=results_desc,
    )

    return intro + "\n\n" + base_prompt


def create_feedback_prompt(
    previous_payload: str,
    test_outcome: str,
    console_output: str,
    errors: List[str],
    network_activity: str,
    base_prompt: str,
) -> str:
    """
    Create prompt with feedback from test results.

    Args:
        previous_payload: Previously tested payload
        test_outcome: Outcome (success/failure/error)
        console_output: Browser console output
        errors: List of errors
        network_activity: Network request/response info
        base_prompt: Base prompt to append to

    Returns:
        Prompt with feedback
    """
    errors_desc = "\n".join(errors[:5]) if errors else "No errors"

    feedback = FEEDBACK_PROMPT.format(
        payload=previous_payload[:200],
        outcome=test_outcome,
        console_output=console_output[:500],
        errors=errors_desc,
        network_activity=network_activity[:500],
    )

    return feedback + "\n\n" + base_prompt


def create_combined_category_prompt(
    target_url: str,
    web_app_code: str,
    commit_diff: str,
    categories: List[str],
    payload_count: int = 5,
) -> str:
    """
    Create prompt targeting multiple vulnerability categories.

    Args:
        target_url: Target URL
        web_app_code: Web application code
        commit_diff: Commit diff
        categories: List of CWE categories to target
        payload_count: Number of payloads per category

    Returns:
        Combined category prompt
    """
    prompt = f"""You are a top web security expert.
The provided commit introduces one or more web vulnerabilities.
Your job is to create attack payloads targeting the following vulnerability types:

"""

    for category in categories:
        if category in CWE_DESCRIPTIONS_WEB:
            desc = CWE_DESCRIPTIONS_WEB[category]
            prompt += f"- {category}: {desc}\n"

    prompt += f"""

Target Application: {target_url}

Web Application Code:
{web_app_code[:10000]}

# Commit Diff
{commit_diff[:5000]}

Create {payload_count} payloads for EACH vulnerability type listed above.
Name them appropriately: xss1.js, sql1.txt, csrf1.html, etc.
"""

    prompt += "\n" + WEB_PROMPT_ENDING.format(payload_count=payload_count * len(categories))

    return prompt
