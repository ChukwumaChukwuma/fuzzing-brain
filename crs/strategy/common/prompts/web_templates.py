"""
Web Prompt Templates for WebFuzzingBrain

All web-specific prompt templates for client-side vulnerability discovery.
Templates use Python f-string format for variable substitution.

Organization:
- Phase 0: Basic commit-based prompts for web
- Phase 1: CWE category-based prompts (XSS, SQLi, CSRF, etc.)
- Phase 2: DOM-based analysis prompts
- Phase 3: Framework-specific prompts (React, Vue, Angular)
"""

# ==================== Phase 0: Basic Commit-Based Web Prompts ====================

WEB_BASE_PROMPT = """You are a top web security expert specializing in client-side vulnerability discovery.
The provided commit introduces a web application vulnerability. Your job is to create attack payloads that will trigger the vulnerability.

Target Application: {target_url}
Web Framework: {web_framework}

Please output a Python script that creates {payload_count} payload files. Each payload will be tested against the web application.

For XSS vulnerabilities: Create xss1.js, xss2.js, xss3.js, etc.
For SQL injection: Create sql1.txt, sql2.txt, sql3.txt, etc.
For CSRF: Create csrf1.html, csrf2.html, etc.
For Prototype Pollution: Create proto1.json, proto2.json, etc.

Web Application Code:
{web_app_code}

# Commit Diff (JavaScript/HTML Changes)
{commit_diff}
"""

# ==================== Context-Specific Guidance ====================

XSS_CONTEXT_HTML = """
CONTEXT: HTML Body Context

You need to inject XSS payloads that work in HTML body context. Consider:
1. Direct script injection: <script>alert(document.domain)</script>
2. Event handlers: <img src=x onerror=alert(1)>
3. SVG-based: <svg/onload=alert(1)>
4. Form elements with autofocus: <input autofocus onfocus=alert(1)>
5. Details/summary: <details open ontoggle=alert(1)>

Break out of existing HTML tags if the injection point is inside an element.
Test both single and double quote contexts.
"""

XSS_CONTEXT_ATTRIBUTE = """
CONTEXT: HTML Attribute Context

You need to inject XSS payloads that work inside HTML attributes. Consider:
1. Breaking out of attribute: " onload="alert(1)
2. Breaking out with newline: "\\n\\nonload=alert(1)\\n"
3. JavaScript protocol: javascript:alert(1)
4. Data URI: data:text/html,<script>alert(1)</script>
5. Multiple quotes: '''onload=alert(1)'''

The injection point is inside an attribute value, so focus on breaking out.
"""

XSS_CONTEXT_JAVASCRIPT = """
CONTEXT: JavaScript Code Context

You need to inject XSS payloads that work inside JavaScript code blocks. Consider:
1. Breaking out of string with single quote: ';alert(1);//
2. Breaking out of string with double quote: ";alert(1);//
3. Breaking out of template literal: `;alert(1);//
4. Breaking out of comment: */alert(1);//
5. Unicode/hex escaping: \\u0027;alert(1);//

The injection point is inside a JavaScript code block or string.
Ensure proper syntax to avoid JavaScript errors.
"""

XSS_CONTEXT_URL = """
CONTEXT: URL Parameter Context

You need to inject XSS payloads via URL parameters. Consider:
1. JavaScript protocol: javascript:alert(1)
2. Data URI: data:text/html,<script>alert(1)</script>
3. URL encoding bypass: javascript%3Aalert(1)
4. Double encoding: javascript%253Aalert(1)
5. Mixed case bypass: JaVaScRiPt:alert(1)

The payload will be passed as a URL parameter.
Consider URL encoding and WAF bypasses.
"""

DOM_XSS_GUIDANCE = """
DOM-BASED XSS ANALYSIS

The application uses client-side JavaScript to process user input.
Key DOM sinks detected:
{dom_sinks}

Key sources detected:
{dom_sources}

Focus on:
1. Data flows from sources (location.search, location.hash) to sinks (innerHTML, eval)
2. Insufficient sanitization in client-side code
3. DOM clobbering opportunities
4. Prototype pollution leading to XSS

Create payloads that specifically target the identified data flows.
"""

SQLI_GUIDANCE = """
SQL INJECTION ANALYSIS

Target database type: {database_type}

Common SQL injection patterns for {database_type}:
{database_patterns}

The application appears to construct SQL queries with user input.
Focus on:
1. Breaking out of existing SQL queries with quotes
2. Union-based injection to extract data
3. Boolean-based blind injection
4. Time-based blind injection
5. Stacked queries if supported

Test both string and numeric contexts.
Include proper SQL syntax for the target database.
"""

CSRF_GUIDANCE = """
CSRF ATTACK ANALYSIS

Target endpoint: {target_url}
HTTP method: {http_method}
Parameters: {parameters}

Create CSRF payloads that:
1. Auto-submit forms on page load
2. Use hidden iframes to avoid user awareness
3. Include all required parameters
4. Test CORS policy for cross-origin requests
5. Bypass CSRF token validation if weak

Each payload should be a complete HTML page that performs the attack.
"""

PROTOTYPE_POLLUTION_GUIDANCE = """
PROTOTYPE POLLUTION ANALYSIS

JavaScript code analysis shows potential prototype pollution vectors.
Common patterns detected:
{pollution_patterns}

Focus on:
1. Polluting Object.prototype via __proto__
2. Polluting via constructor.prototype
3. Testing for merge/extend functions without proper checks
4. Using URL parameters or JSON payloads
5. Checking for client-side DoS via prototype pollution

Create payloads that modify Object.prototype properties.
Test if pollution affects application behavior.
"""

# ==================== Language/Framework Specific ====================

REACT_SPECIFIC = """
REACT FRAMEWORK ANALYSIS

This is a React application. Consider:
1. dangerouslySetInnerHTML usage - prime XSS vector
2. React component props passed from URL
3. React Router parameters
4. State management (Redux, Context) vulnerabilities
5. Server-Side Rendering (SSR) escaping issues

Look for:
- Components that render user-controlled data
- Props passed through multiple component layers
- useEffect hooks with external data sources
"""

VUE_SPECIFIC = """
VUE FRAMEWORK ANALYSIS

This is a Vue.js application. Consider:
1. v-html directive usage - XSS vector
2. Template injection via user input
3. Vue Router parameters
4. Vuex store manipulation
5. Custom directive vulnerabilities

Look for:
- Templates that use user-controlled data
- Computed properties based on URL parameters
- Event handlers with eval or Function()
"""

ANGULAR_SPECIFIC = """
ANGULAR FRAMEWORK ANALYSIS

This is an Angular application. Consider:
1. Bypassing Angular's sanitization
2. Template injection in older Angular versions
3. $http without proper input validation
4. Expression Language injection
5. Angular Router parameter injection

Look for:
- innerHTML usage with DomSanitizer bypass
- Template strings with user input
- HTTP requests with unsanitized parameters
"""

# ==================== Prompt Ending ====================

WEB_PROMPT_ENDING = """
Limit each payload file to 100KB max.

Your output must be a single Python script that creates {payload_count} payload files with appropriate naming:
- For XSS: xss1.js, xss2.js, xss3.js, etc.
- For SQL injection: sql1.txt, sql2.txt, sql3.txt, etc.
- For CSRF: csrf1.html, csrf2.html, etc.
- For Prototype Pollution: proto1.json, proto2.json, etc.

Each file should include a brief comment describing:
1. The vulnerability type being targeted
2. The expected behavior when successful
3. The injection context (HTML, JS, URL, etc.)

Diversify the payloads to maximize the likelihood of success.
It's acceptable if only one payload successfully triggers the vulnerability.

Example Python script structure:

```python
# XSS Payload Generator

# Payload 1: HTML context
with open('xss1.js', 'w') as f:
    payload = '''<script>alert('XSS in HTML context')</script>'''
    f.write(payload)

# Payload 2: Attribute context
with open('xss2.js', 'w') as f:
    payload = '''" onload="alert('XSS in attribute')"'''
    f.write(payload)

# ... more payloads
```
"""

# ==================== Phase 1: CWE Category Descriptions for Web ====================

CWE_DESCRIPTIONS_WEB = {
    "CWE-79": "Cross-Site Scripting (XSS) - Injection of malicious scripts into web pages",
    "CWE-89": "SQL Injection - Manipulation of SQL queries through unsanitized input",
    "CWE-352": "Cross-Site Request Forgery (CSRF) - Forcing authenticated users to perform unintended actions",
    "CWE-1321": "Prototype Pollution - Modifying JavaScript object prototypes",
    "CWE-915": "DOM Clobbering - Using HTML to override JavaScript variables",
    "CWE-20": "Improper Input Validation - Insufficient validation of user input",
    "CWE-434": "Unrestricted File Upload - Allowing dangerous file types",
    "CWE-601": "Open Redirect - Redirecting to arbitrary URLs",
    "CWE-918": "Server-Side Request Forgery (SSRF) - Making server perform unintended requests",
    "CWE-1275": "Content Security Policy (CSP) Bypass - Circumventing CSP protections",
    "CWE-942": "Permissive CORS Policy - Overly permissive cross-origin resource sharing",
    "CWE-94": "Code Injection - Injection of executable code",
    "CWE-200": "Information Disclosure - Exposure of sensitive information",
    "CWE-345": "Insufficient Verification of Data Authenticity - Weak authentication",
    "CWE-639": "Authorization Bypass - Circumventing access controls"
}

CATEGORY_PROMPT_WEB_BASE = """You are a top web security expert specializing in {category_desc}.
The provided commit introduces a web vulnerability. Your job is to create attack payloads that will trigger this specific vulnerability type.

Target Application: {target_url}
Vulnerability Focus: {category}

Please output a Python script that creates {payload_count} payload files targeting {category_desc}.

Web Application Code:
{web_app_code}

# Commit Diff (JavaScript/HTML Changes)
{commit_diff}
"""

# ==================== Phase 2: DOM Analysis Prompts ====================

DOM_FLOW_PROMPT = """You are a web security expert analyzing DOM-based vulnerabilities.

The following data flow has been detected:

SOURCE → SINK Data Flow:
{data_flow_description}

Sources (attacker-controlled):
{sources}

Sinks (dangerous operations):
{sinks}

Intermediate variables:
{flow_path}

Web Application Code:
{web_app_code}

Your task is to create attack payloads that exploit this data flow.
Consider:
1. The source provides attacker-controlled data
2. Data flows through the application code
3. Data reaches a dangerous sink without proper sanitization
4. Create payloads that successfully exploit each sink

Generate {payload_count} payloads that specifically target this data flow.
"""

# ==================== Phase 3: Framework-Specific Prompts ====================

FRAMEWORK_PROMPT_BASE = """You are a web security expert specializing in {framework} security.

The target application uses {framework}. Common {framework} vulnerabilities include:
{framework_vulnerabilities}

Web Application Code ({framework} components):
{web_app_code}

# Commit Diff
{commit_diff}

Create attack payloads that specifically target {framework}-specific vulnerability patterns.
Focus on framework-specific features that can be exploited.
"""

# ==================== Multi-Phase Strategy Prompts ====================

MULTI_PHASE_INTRO = """This is a multi-phase vulnerability discovery approach.
We will systematically test different vulnerability types and contexts.

Current Phase: {current_phase}
Phase Description: {phase_description}

Previous attempts: {previous_attempts}
Previous results: {previous_results}

Based on previous attempts, adjust the payloads to:
1. Avoid patterns that didn't work
2. Try different encoding/obfuscation techniques
3. Target different injection contexts
4. Use framework-specific bypasses if applicable
"""

# ==================== Feedback Loop Prompts ====================

FEEDBACK_PROMPT = """
Test Result Analysis:

Previous payload: {payload}
Test outcome: {outcome}

Browser Console Output:
{console_output}

Error Messages:
{errors}

Network Activity:
{network_activity}

The payload did not successfully trigger the vulnerability. Analyze why:
1. Was the payload blocked by input validation?
2. Was the context incorrect (HTML vs JS vs URL)?
3. Was there insufficient encoding/escaping?
4. Did the payload cause a JavaScript error that prevented execution?

Generate an improved payload that addresses these issues.
"""
