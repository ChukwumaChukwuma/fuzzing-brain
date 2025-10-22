"""
Web PoV Strategy

Base class for web application Proof-of-Vulnerability generation strategies.
Extends WebBaseStrategy with PoV-specific functionality for web vulnerabilities.
"""

import os
import sys
import json
import time
import subprocess
import uuid
from abc import abstractmethod
from typing import Tuple, Dict, Any, List, Optional
from pathlib import Path

from core.web_base_strategy import WebBaseStrategy
from common.web import PayloadContext, SQLDatabase
from common.utils import (
    get_commit_info,
    extract_python_code_from_response,
    truncate_output,
)


class WebPoVStrategy(WebBaseStrategy):
    """
    Base class for web POV generation strategies.

    Similar to PoVStrategy but for web vulnerabilities (XSS, SQLi, CSRF, etc.).

    Subclasses MUST implement:
    - do_pov(initial_msg) -> Tuple[bool, dict]
    - submit_pov(metadata) -> bool

    Provides optional methods with default implementations:
    - execute_core_logic() - Main flow (find web app, get commit, create prompt, call do_pov)
    - create_initial_prompt() - Creates basic commit-based prompt for web
    - generate_payloads() - Executes Python code to create attack payloads
    - test_web_payloads() - Tests payloads in browser or via HTTP
    - detect_vulnerability() - Detects if vulnerability was triggered
    - save_web_pov_artifacts() - Saves POV evidence (screenshots, HAR, etc.)
    - has_successful_pov() - Checks for existing web POVs
    """

    # ========== Abstract methods (subclasses MUST implement) ==========

    @abstractmethod
    def do_pov(self, initial_msg: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Main POV generation loop - MUST be implemented by subclasses

        Args:
            initial_msg: Initial prompt for the LLM

        Returns:
            Tuple of (success: bool, metadata: dict)
        """
        pass

    @abstractmethod
    def submit_pov(self, pov_metadata: Dict[str, Any]) -> bool:
        """
        Submit web POV to endpoint - MUST be implemented by subclasses

        Args:
            pov_metadata: POV metadata to submit (includes payload, evidence, etc.)

        Returns:
            True if submission successful, False otherwise
        """
        pass

    # ========== Optional methods with default implementations ==========

    def execute_core_logic(self) -> bool:
        """
        Execute web POV generation logic.
        Called by BaseStrategy.run()

        Default implementation:
        - Find web application code
        - Get commit info (JavaScript/HTML changes)
        - Analyze code for vulnerabilities
        - Create initial prompt
        - Call do_pov()

        Can be overridden for completely custom flow.
        """
        self.logger.log("Starting web POV generation...")

        # Find web application code
        web_app_code = self.find_web_app_code()
        if not web_app_code:
            self.logger.warning("Failed to find web app code, continuing with target URL only")
            web_app_code = f"Target URL: {self.config.target_url}"

        # Get commit information (JavaScript/HTML changes)
        commit_msg, commit_diff = get_commit_info(
            self.config.project_dir,
            language="javascript",  # Web-specific
            logger=self.logger
        )

        # Analyze code for existing vulnerabilities
        if len(web_app_code) < 100000:  # Only analyze if not too large
            analysis_results = self.analyze_web_app_code(web_app_code)
            self.logger.log(f"Code analysis complete")
        else:
            analysis_results = {}

        # Create initial prompt (strategy-specific)
        initial_msg = self.create_initial_prompt(web_app_code, commit_diff, analysis_results)

        # Execute POV generation loop
        success, metadata = self.do_pov(initial_msg)

        return success

    def create_initial_prompt(
        self,
        web_app_code: str,
        commit_diff: str,
        analysis_results: Optional[Dict] = None
    ) -> str:
        """
        Create the initial prompt for web POV generation.

        Default implementation creates a web-focused prompt.
        Strategies can override for custom prompts.

        Args:
            web_app_code: Web application source code (JavaScript/HTML)
            commit_diff: Commit diff introducing the vulnerability
            analysis_results: Optional code analysis results

        Returns:
            Initial prompt string for LLM
        """
        # Build context from analysis
        context_parts = []

        if analysis_results:
            js_analysis = analysis_results.get('javascript_analysis')
            if js_analysis and js_analysis.get('security_issues'):
                issues = js_analysis['security_issues']
                context_parts.append(f"Found {len(issues)} potential security issues in JavaScript code.")

            dom_analysis = analysis_results.get('dom_analysis')
            if dom_analysis:
                sinks = dom_analysis.get('sinks', [])
                sources = dom_analysis.get('sources', [])
                if sinks or sources:
                    context_parts.append(
                        f"DOM analysis found {len(sinks)} dangerous sinks and {len(sources)} attacker-controlled sources."
                    )

        analysis_context = '\n'.join(context_parts) if context_parts else "No automated analysis available."

        prompt = f"""You are a web security expert specializing in finding client-side vulnerabilities.

Target: {self.config.target_url}
Web Framework: {self.config.web_framework or 'Unknown'}

Web Application Code:
```javascript
{web_app_code[:10000]}  # Truncate to avoid token overflow
```

Vulnerability Commit Diff:
```diff
{commit_diff[:5000]}  # Truncate diff
```

Automated Analysis:
{analysis_context}

Your task is to create attack payloads that will trigger the vulnerability in this web application.

Target vulnerability types: {', '.join(self.config.web_vulnerability_types)}

Please write a Python script that generates {self.config.payload_count} payload files.
For XSS: Create xss1.js, xss2.js, xss3.js, etc.
For SQL injection: Create sql1.txt, sql2.txt, sql3.txt, etc.
For CSRF: Create csrf1.html, csrf2.html, etc.

Each payload should be context-aware and designed to exploit the identified vulnerability.
"""
        return prompt

    def generate_payloads(
        self,
        code: str,
        payload_dir: str,
        vulnerability_type: str = "xss"
    ) -> List[str]:
        """
        Execute LLM-generated Python code to create attack payloads.

        Similar to generate_blobs() but creates web attack payloads.

        Args:
            code: Python code generated by LLM
            payload_dir: Directory to store payload files
            vulnerability_type: Type of vulnerability (xss, sqli, csrf, etc.)

        Returns:
            List of payload file paths
        """
        os.makedirs(payload_dir, exist_ok=True)

        # Save code to temp file
        code_file = os.path.join(payload_dir, "generate_payloads.py")
        with open(code_file, "w") as f:
            f.write(code)

        self.logger.log(f"Executing payload generation code...")

        # Execute code
        try:
            result = subprocess.run(
                [sys.executable, code_file],
                cwd=payload_dir,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                self.logger.error(f"Payload generation failed: {result.stderr}")
                raise RuntimeError(f"Code execution failed: {result.stderr}")

            # Find generated payload files
            payload_extensions = {
                'xss': ['.js', '.html', '.txt'],
                'sqli': ['.txt', '.sql'],
                'csrf': ['.html', '.txt'],
                'prototype_pollution': ['.json', '.txt'],
                'xxe': ['.xml'],
                'ssrf': ['.txt'],
            }

            extensions = payload_extensions.get(vulnerability_type, ['.txt', '.js', '.html'])

            payload_files = []
            for ext in extensions:
                for i in range(1, self.config.payload_count + 1):
                    # Try different naming patterns
                    patterns = [
                        f"{vulnerability_type}{i}{ext}",
                        f"payload{i}{ext}",
                        f"xss{i}{ext}",  # Common pattern
                        f"x{i}{ext}",
                    ]

                    for pattern in patterns:
                        payload_path = os.path.join(payload_dir, pattern)
                        if os.path.exists(payload_path):
                            payload_files.append(payload_path)
                            break

            if not payload_files:
                self.logger.warning("No payload files found, checking all files in directory...")
                # Fallback: check all files created in directory
                for file in os.listdir(payload_dir):
                    if file.endswith(tuple(extensions)) and file != "generate_payloads.py":
                        payload_files.append(os.path.join(payload_dir, file))

            if not payload_files:
                raise RuntimeError(f"Code did not create any payload files with extensions {extensions}")

            self.logger.log(f"Generated {len(payload_files)} payload files")
            return payload_files

        except subprocess.TimeoutExpired:
            self.logger.error("Payload generation timed out")
            raise RuntimeError("Code execution timed out")
        except Exception as e:
            self.logger.error(f"Payload generation error: {str(e)}")
            raise RuntimeError(f"Code execution error: {str(e)}")

    def test_web_payloads(
        self,
        payload_files: List[str],
        vulnerability_type: str = "xss",
        target_url: Optional[str] = None
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Test web payloads against target application.

        Similar to run_fuzzer() but for web payloads.

        Args:
            payload_files: List of payload file paths to test
            vulnerability_type: Type of vulnerability being tested
            target_url: Target URL (defaults to config.target_url)

        Returns:
            Tuple of (vulnerability_detected: bool, output: str, evidence: dict)
        """
        target_url = target_url or self.config.target_url

        if not target_url:
            self.logger.error("No target URL specified")
            return False, "No target URL", {}

        self.logger.log(f"Testing {len(payload_files)} payloads against {target_url}")

        for payload_file in payload_files:
            try:
                # Read payload content
                with open(payload_file, 'r', encoding='utf-8', errors='ignore') as f:
                    payload_content = f.read()

                self.logger.log(f"Testing payload: {os.path.basename(payload_file)}")

                # Test based on vulnerability type
                if vulnerability_type in ['xss', 'dom_xss']:
                    detected, output, evidence = self._test_xss_payload(
                        payload_content,
                        target_url,
                        payload_file
                    )
                elif vulnerability_type in ['sqli', 'sql_injection']:
                    detected, output, evidence = self._test_sqli_payload(
                        payload_content,
                        target_url,
                        payload_file
                    )
                elif vulnerability_type == 'csrf':
                    detected, output, evidence = self._test_csrf_payload(
                        payload_content,
                        target_url,
                        payload_file
                    )
                else:
                    # Generic HTTP test
                    detected, output, evidence = self._test_generic_payload(
                        payload_content,
                        target_url,
                        payload_file
                    )

                if detected:
                    self.logger.success(f"Vulnerability detected with payload: {os.path.basename(payload_file)}")
                    return True, output, evidence

            except Exception as e:
                self.logger.error(f"Error testing payload {payload_file}: {str(e)}")
                continue

        self.logger.log("No vulnerability detected with any payload")
        return False, "No vulnerability detected", {}

    def _test_xss_payload(
        self,
        payload: str,
        target_url: str,
        payload_file: str
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Test XSS payload using browser automation"""
        self.logger.log("Testing XSS payload in browser...")

        session = None
        try:
            session = self.create_browser_session()
            session.start()

            # Navigate to target
            if not session.navigate(target_url):
                return False, "Failed to navigate to target", {}

            # Inject payload
            success = session.inject_payload(payload)
            if not success:
                return False, "Failed to inject payload", {}

            # Wait a moment for execution
            time.sleep(2)

            # Check for XSS success
            xss_detected, evidence_text = session.check_xss_success()

            if xss_detected:
                # Collect evidence
                test_name = f"xss_{uuid.uuid4().hex[:8]}"
                evidence = session.collect_evidence(self.evidence_dir, test_name)
                evidence['payload_file'] = payload_file
                evidence['detection_method'] = evidence_text

                output = f"XSS detected: {evidence_text}\nConsole errors: {len(session.get_errors())}"
                return True, output, evidence

            return False, "XSS not detected", {}

        finally:
            if session:
                session.close()

    def _test_sqli_payload(
        self,
        payload: str,
        target_url: str,
        payload_file: str
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Test SQL injection payload using browser automation"""
        self.logger.log("Testing SQL injection payload...")

        session = None
        try:
            session = self.create_browser_session()
            session.start()

            # Navigate to target with payload in URL parameter
            test_url = f"{target_url}?id={payload}"
            if not session.navigate(test_url):
                return False, "Failed to navigate", {}

            time.sleep(1)

            # Check for SQL injection success
            sqli_detected, evidence_text = session.check_sql_injection()

            if sqli_detected:
                # Collect evidence
                test_name = f"sqli_{uuid.uuid4().hex[:8]}"
                evidence = session.collect_evidence(self.evidence_dir, test_name)
                evidence['payload_file'] = payload_file
                evidence['detection_method'] = evidence_text

                output = f"SQL injection detected: {evidence_text}"
                return True, output, evidence

            return False, "SQL injection not detected", {}

        finally:
            if session:
                session.close()

    def _test_csrf_payload(
        self,
        payload: str,
        target_url: str,
        payload_file: str
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Test CSRF payload"""
        self.logger.log("Testing CSRF payload...")

        # CSRF testing typically requires hosting the payload
        # For now, we'll do basic validation

        # Check if payload contains target URL
        if target_url in payload:
            evidence = {
                'payload_file': payload_file,
                'detection_method': 'CSRF payload contains target URL',
            }
            output = "CSRF payload validated (contains target URL)"
            return True, output, evidence

        return False, "CSRF payload validation failed", {}

    def _test_generic_payload(
        self,
        payload: str,
        target_url: str,
        payload_file: str
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Test generic payload via HTTP"""
        self.logger.log("Testing generic payload via HTTP...")

        try:
            # Try as URL parameter
            response = self.http_tester.send_request(
                'GET',
                f"{target_url}?input={payload}",
                timeout=10
            )

            if response:
                # Check for error indicators
                error_indicators = [
                    'error',
                    'exception',
                    'warning',
                    'sql',
                    'syntax',
                    'unexpected',
                ]

                if any(indicator in response.text.lower() for indicator in error_indicators):
                    evidence = {
                        'payload_file': payload_file,
                        'status_code': response.status_code,
                        'detection_method': 'Error indicators in response',
                    }
                    output = f"Potential vulnerability detected (status: {response.status_code})"
                    return True, output, evidence

            return False, "No vulnerability detected", {}

        except Exception as e:
            self.logger.error(f"Generic test error: {str(e)}")
            return False, str(e), {}

    def save_web_pov_artifacts(
        self,
        payload_files: List[str],
        evidence: Dict[str, Any],
        test_output: str
    ) -> Dict[str, Any]:
        """
        Save web POV artifacts and evidence.

        Similar to save_pov_artifacts() but for web evidence.

        Args:
            payload_files: Successful payload files
            evidence: Evidence dictionary (screenshots, HAR, etc.)
            test_output: Test output/logs

        Returns:
            POV metadata dictionary
        """
        # Create POV directory
        pov_dir = os.path.join(self.config.pov_success_dir, f"pov_{uuid.uuid4().hex[:8]}")
        os.makedirs(pov_dir, exist_ok=True)

        self.logger.log(f"Saving POV artifacts to {pov_dir}")

        # Copy payload files
        payload_copies = []
        for payload_file in payload_files:
            dest = os.path.join(pov_dir, os.path.basename(payload_file))
            with open(payload_file, 'r') as src_f:
                with open(dest, 'w') as dst_f:
                    dst_f.write(src_f.read())
            payload_copies.append(dest)

        # Save evidence files (move from evidence_dir to pov_dir)
        evidence_copies = {}
        for key, path in evidence.items():
            if isinstance(path, str) and os.path.exists(path):
                dest = os.path.join(pov_dir, os.path.basename(path))
                try:
                    with open(path, 'rb') as src_f:
                        with open(dest, 'wb') as dst_f:
                            dst_f.write(src_f.read())
                    evidence_copies[key] = dest
                except Exception as e:
                    self.logger.warning(f"Failed to copy evidence file {path}: {e}")

        # Save test output
        output_file = os.path.join(pov_dir, "test_output.txt")
        with open(output_file, 'w') as f:
            f.write(test_output)

        # Create metadata
        metadata = {
            'pov_dir': pov_dir,
            'payload_files': payload_copies,
            'evidence': evidence_copies,
            'test_output': output_file,
            'target_url': self.config.target_url,
            'vulnerability_types': self.config.web_vulnerability_types,
            'timestamp': time.time(),
        }

        # Save metadata JSON
        metadata_file = os.path.join(pov_dir, "metadata.json")
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)

        self.logger.success(f"POV artifacts saved to {pov_dir}")

        return metadata

    def has_successful_pov(self) -> bool:
        """
        Check if a successful web POV already exists.

        Returns:
            True if successful POV found, False otherwise
        """
        if not os.path.exists(self.config.pov_success_dir):
            return False

        # Check for any pov_* directories
        pov_dirs = [
            d for d in os.listdir(self.config.pov_success_dir)
            if d.startswith('pov_') and os.path.isdir(os.path.join(self.config.pov_success_dir, d))
        ]

        return len(pov_dirs) > 0

    def generate_pov(self, messages: List[Dict[str, str]], model_name: str) -> str:
        """
        Generate POV code using LLM (same as parent class).

        This method is the same for binary and web strategies.
        """
        # Log the user input
        user_messages = [m for m in messages if m.get("role") == "user"]
        if user_messages:
            last_user_msg = user_messages[-1].get("content", "")
            self.logger.log_user_input(last_user_msg, round_number=len(user_messages))

        start_time = time.time()
        response, success = self.llm_client.call(messages, model_name)
        end_time = time.time()

        self.logger.log_time(start_time, end_time, "generate_pov", f"Model: {model_name}")

        if not success:
            self.logger.warning(f"LLM call failed with model {model_name}")
            return ""

        # Log the LLM response
        self.logger.log_llm_response(response, model_name=model_name)

        # Extract Python code from response
        code = extract_python_code_from_response(
            response,
            self.llm_client,
            max_retries=2,
            timeout=30,
            logger=self.logger
        )

        if not code:
            self.logger.warning("Failed to extract Python code from LLM response")
            return ""

        self.logger.log(f"Successfully generated {len(code)} characters of POV code")
        return code
