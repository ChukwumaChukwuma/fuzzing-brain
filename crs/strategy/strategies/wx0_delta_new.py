#!/usr/bin/env python3
"""
WX0 Delta Strategy - Advanced multi-phase web vulnerability discovery

Web adaptation of AS0 Delta Strategy with multiple sophisticated approaches:
- Phase 0: Basic commit-based (similar to WS0)
- Phase 1: Vulnerability category-based (XSS, SQLi, CSRF, etc.)
- Phase 2: DOM flow analysis-based (source → sink tracking)
- Phase 3: Framework-specific (React, Vue, Angular vulnerabilities)
"""
import os
import sys
import uuid
import time
import shutil
import random
from typing import Dict, Any, Tuple, List, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from core.web_pov_strategy import WebPoVStrategy
from common.config import StrategyConfig
from common.logging.logger import StrategyLogger
from common.llm.client import LLMClient
from common.llm.models import CLAUDE_MODEL_SONNET_4, OPENAI_MODEL_O3
from common.prompts import (
    create_web_commit_based_prompt,
    create_xss_category_prompt,
    create_sqli_category_prompt,
    create_csrf_category_prompt,
    create_prototype_pollution_prompt,
    create_dom_flow_prompt,
    create_framework_specific_prompt,
)
from common.utils import truncate_output
from common.utils.web_vulnerability_signature import (
    generate_web_vulnerability_signature,
    generate_web_vulnerability_report,
)


# Web vulnerability categories for Phase 1
WEB_VUL_CATEGORIES = [
    "CWE-79",   # Cross-Site Scripting (XSS)
    "CWE-89",   # SQL Injection
    "CWE-352",  # Cross-Site Request Forgery (CSRF)
    "CWE-1321", # Prototype Pollution
    "CWE-94",   # Code Injection
    "CWE-611",  # XML External Entity (XXE)
    "CWE-918",  # Server-Side Request Forgery (SSRF)
    "CWE-601",  # Open Redirect
    "CWE-22",   # Path Traversal
    "CWE-434",  # Unrestricted File Upload
    "CWE-798",  # Hard-coded Credentials
    "CWE-287",  # Improper Authentication
    "CWE-862",  # Missing Authorization
    "CWE-1275", # DOM Clobbering
]


class WX0DeltaStrategy(WebPoVStrategy):
    """
    WX0 Delta Strategy: Advanced multi-phase web vulnerability discovery

    Generates multiple web attack payloads per iteration.
    Supports multiple phases with different prompt strategies.
    """

    # System prompt for LLM guidance
    SYSTEM_PROMPT = "You are a security expert specializing in web application vulnerability detection."

    def get_strategy_name(self) -> str:
        """Return strategy name for logging"""
        return "wx0_delta"

    def create_initial_prompt(self, web_app_code: str, commit_diff: str) -> str:
        """
        Override parent method to use WX0-specific prompt (generates multiple payloads)

        Args:
            web_app_code: Web application source code (JavaScript/HTML)
            commit_diff: Commit diff introducing the vulnerability

        Returns:
            Initial prompt string for LLM
        """
        return create_web_commit_based_prompt(
            target_url=self.config.target_url,
            web_app_code=web_app_code,
            commit_diff=commit_diff,
            web_framework=self.config.web_framework,
            vulnerability_types=self.config.web_vulnerability_types,
            payload_count=5,
        )

    def execute_core_logic(self) -> bool:
        """
        Override to save web_app_code and commit_diff for Phase 1-3
        """
        self.logger.log("Starting advanced web vulnerability discovery...")

        # Validate target URL
        if not self.config.target_url:
            self.logger.error("target_url is required for web vulnerability discovery")
            return False

        # Find web application code
        self.web_app_code = self.find_web_app_code()
        if not self.web_app_code:
            self.logger.error("Failed to find web application code")
            return False

        # Get commit information
        from common.utils import get_commit_info
        commit_msg, self.commit_diff = get_commit_info(
            self.config.project_dir,
            self.config.language,
            logger=self.logger
        )

        # Analyze web app code for DOM sinks/sources
        self.dom_analysis = self.analyze_web_app_code(self.web_app_code)
        self.logger.log(f"DOM analysis found {len(self.dom_analysis.get('sinks', []))} sinks and {len(self.dom_analysis.get('sources', []))} sources")

        # Detect web framework if not specified
        if not self.config.web_framework:
            self.config.web_framework = self._detect_framework(self.web_app_code)
            self.logger.log(f"Detected web framework: {self.config.web_framework}")

        # Create initial prompt (for Phase 0, Phase 1-3 will override)
        initial_msg = self.create_initial_prompt(self.web_app_code, self.commit_diff)

        # Execute POV generation loop
        success, metadata = self.do_pov(initial_msg)

        return success

    def do_pov(self, initial_msg: str) -> Tuple[bool, Dict[str, Any]]:
        """
        WX0 web POV generation with multi-phase support

        Args:
            initial_msg: Initial prompt for LLM

        Returns:
            Tuple of (success: bool, metadata: dict)
        """
        pov_phase = self.config.pov_phase
        self.logger.log(f"POV_PHASE: {pov_phase} WX0 Delta Strategy")

        # Route to appropriate phase handler
        if pov_phase == 0:
            return self._do_pov_phase_0(initial_msg)
        elif pov_phase == 1:
            return self._do_pov_phase_1(initial_msg)
        elif pov_phase == 2:
            return self._do_pov_phase_2(initial_msg)
        elif pov_phase == 3:
            return self._do_pov_phase_3(initial_msg)
        else:
            self.logger.error(f"POV_PHASE: {pov_phase} does not exist")
            return False, {}

    def _do_pov_phase_0(self, initial_msg: str, max_iterations: Optional[int] = None, models: Optional[List[str]] = None) -> Tuple[bool, Dict[str, Any]]:
        """
        Phase 0: Basic commit-based web vulnerability discovery (similar to WS0)

        Args:
            initial_msg: Initial prompt for LLM
            max_iterations: Override max iterations (defaults to config value)
            models: Override models to try (defaults to config value)

        Returns:
            Tuple of (success: bool, metadata: dict)
        """
        pov_id = str(uuid.uuid4())[:8]

        if self.config.check_patch_success:
            self.logger.log("Will check for successful patches periodically")

        start_time = time.time()
        end_time = start_time + (self.config.fuzzing_timeout_minutes * 60)

        self.logger.log(f"Web vulnerability discovery timeout: {self.config.fuzzing_timeout_minutes} minutes")

        found_pov = False
        successful_pov_metadata = {}

        # Use provided values or fall back to config
        actual_max_iterations = max_iterations if max_iterations is not None else self.config.max_iterations
        actual_models = models if models is not None else self.config.models

        # Try with different models
        for model_name in actual_models:
            self.logger.log(f"Attempting web vulnerability discovery with model: {model_name}")

            # Initialize messages with system prompt and user message
            messages = [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": initial_msg}
            ]
            model_success_count = 0

            for iteration in range(1, actual_max_iterations + 1):
                current_time = time.time()
                if current_time > end_time:
                    self.logger.log(f"Timeout reached after {iteration-1} iterations with {model_name}")
                    break

                # Check for successful patches if enabled
                if self.config.check_patch_success:
                    if self.check_for_successful_patches():
                        self.logger.log("Successful patch detected, stopping web POV generation")
                        return True, {}

                # Check if POV already exists
                if self.has_successful_pov():
                    self.logger.log("Successful web POV already exists")
                    return True, {}

                self.logger.log(f"Iteration {iteration} with {model_name}")

                # Generate POV code using LLM
                code = self.generate_pov(messages, model_name)

                if not code:
                    self.logger.warning("No valid Python code generated, continuing to next iteration")
                    messages.append({"role": "user", "content": "No valid Python code generated, please try again"})
                    continue

                # Create unique directory for this iteration
                unique_id = str(uuid.uuid4())[:8]
                payload_dir = os.path.join(self.config.project_dir, f"wp{self.config.pov_phase}", unique_id)
                os.makedirs(payload_dir, exist_ok=True)
                self.logger.log(f"Created payload_dir: {payload_dir}")

                # Generate web payload files
                try:
                    payload_files = self.generate_payloads(code, payload_dir)
                except Exception as e:
                    self.logger.error(f"Failed to generate payloads: {str(e)}")
                    messages.append({
                        "role": "user",
                        "content": f"Python code failed with error: {str(e)}\n\nPlease try again."
                    })
                    continue

                if not payload_files:
                    self.logger.warning("No payloads generated")
                    messages.append({
                        "role": "user",
                        "content": "Python code failed to create payload files, please try again."
                    })
                    continue

                # Detect vulnerability type from payload files
                vulnerability_type = self._detect_vulnerability_type(payload_files)
                self.logger.log(f"Detected vulnerability type: {vulnerability_type}")

                # Test web payloads
                vuln_detected, test_output, evidence = self.test_web_payloads(
                    payload_files=payload_files,
                    vulnerability_type=vulnerability_type,
                    target_url=self.config.target_url
                )

                if vuln_detected:
                    found_pov = True
                    model_success_count += 1

                    # Save successful web POV
                    pov_metadata = self.save_web_pov_artifacts(
                        pov_id=pov_id,
                        model_name=model_name,
                        iteration=iteration,
                        code=code,
                        payload_files=payload_files,
                        test_output=test_output,
                        evidence=evidence,
                        messages=messages,
                        vulnerability_type=vulnerability_type,
                        target_url=self.config.target_url
                    )

                    # Submit POV
                    submission_result = self.submit_pov(pov_metadata)
                    if submission_result or True:  # For local test w/o submission endpoint
                        successful_pov_metadata = pov_metadata
                        self.logger.log(f"Web POV SUCCESS! Vulnerability triggered with {model_name} on iteration {iteration}")
                        break  # Break from iteration loop

                else:
                    # No vulnerability detected - provide feedback
                    if iteration == 1:
                        user_message = f"""
Test output:
{truncate_output(test_output, 500)}

The payloads did not trigger the vulnerability. Please analyze the output and try again with an improved approach. Consider:
1. Different attack vectors for the detected vulnerability type
2. Different injection contexts (HTML, attribute, JavaScript, URL)
3. WAF/filter bypass techniques
4. Framework-specific vulnerabilities
5. Pay attention to details in the commit diff
6. Think step by step
"""
                    else:
                        user_message = f"""
Test output:
{truncate_output(test_output, 200)}

The payloads did not trigger the vulnerability. Please analyze the output and try again with a different approach.
"""

                    if iteration == actual_max_iterations - 1:
                        user_message += "\nThis is your last attempt. This task is very very important to me. If you generate successful payloads, I will tip you 2000 dollars."

                    messages.append({"role": "user", "content": user_message})

            # If found POV with this model, break from model loop
            if found_pov:
                break

        # Final summary
        total_time = time.time() - start_time
        self.logger.log(f"WX0 Delta Phase 0 completed in {total_time:.2f} seconds")

        # Check if any successful POVs were found
        if os.path.exists(self.config.pov_success_dir):
            pov_files = [f for f in os.listdir(self.config.pov_success_dir) if f.startswith("web_pov_metadata_")]
            if pov_files:
                self.logger.log(f"Found {len(pov_files)} successful web POVs")
                return True, successful_pov_metadata

        self.logger.log("No successful web POVs found")
        return False, {}

    def _do_pov_phase_1(self, initial_msg: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Phase 1: Vulnerability category-based web POV generation

        Tries different web vulnerability categories with randomized order.
        Uses reduced iterations (3) compared to Phase 0.
        """
        self.logger.log("Phase 1: Web vulnerability category-based approach")

        # Use web vulnerability categories
        categories = WEB_VUL_CATEGORIES[:]
        self.logger.log(f"Using web vulnerability categories ({len(categories)} types)")

        # Randomize order to avoid bias
        random.shuffle(categories)

        # Try each category
        for idx, category in enumerate(categories, 1):
            self.logger.log(f"[{idx}/{len(categories)}] Trying category: {category}")

            # Generate category-specific prompt
            category_prompt = self._create_category_prompt(category)

            # Run Phase 0 logic with this category-specific prompt (with 3 iterations instead of 5)
            pov_success, pov_metadata = self._do_pov_phase_0(
                category_prompt,
                max_iterations=3,
                models=[CLAUDE_MODEL_SONNET_4, CLAUDE_MODEL_SONNET_4, OPENAI_MODEL_O3]
            )

            if pov_success:
                self.logger.log(f"SUCCESS! Category {category} found web POV")
                return True, pov_metadata
            else:
                self.logger.log(f"Category {category} did not find web POV, trying next...")

        self.logger.log(f"Phase 1 exhausted all {len(categories)} categories without success")
        return False, {}

    def _do_pov_phase_2(self, initial_msg: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Phase 2: DOM flow analysis-based web POV generation

        Analyzes data flows from sources to sinks and generates targeted payloads.
        """
        self.logger.log("Phase 2: DOM flow analysis-based approach")

        # Extract data flows from DOM analysis
        dom_analysis = self.analyze_web_app_code(self.web_app_code)
        sinks = dom_analysis.get('sinks', [])
        sources = dom_analysis.get('sources', [])

        if not sinks or not sources:
            self.logger.log("No DOM sinks/sources found, skipping Phase 2")
            return False, {}

        self.logger.log(f"Found {len(sinks)} sinks and {len(sources)} sources")

        # Try each sink-source combination
        for idx, sink in enumerate(sinks[:5], 1):  # Limit to 5 sinks
            for source in sources[:3]:  # Limit to 3 sources per sink
                self.logger.log(f"[{idx}] Trying flow: {source.property_or_method} → {sink.property_or_method}")

                # Create data flow structure
                data_flow = {
                    'source': source,
                    'sink': sink,
                    'flow_path': []  # Would be filled by taint analysis
                }

                # Generate DOM flow-based prompt
                flow_prompt = create_dom_flow_prompt(
                    target_url=self.config.target_url,
                    web_app_code=self.web_app_code,
                    commit_diff=self.commit_diff,
                    data_flow=data_flow,
                    payload_count=5
                )

                # Run Phase 0 logic with this flow-based prompt
                pov_success, pov_metadata = self._do_pov_phase_0(flow_prompt)

                if pov_success:
                    self.logger.log(f"SUCCESS! Flow analysis found web POV")
                    return True, pov_metadata

        self.logger.log("Phase 2 exhausted all data flows without success")
        return False, {}

    def _do_pov_phase_3(self, initial_msg: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Phase 3: Framework-specific web POV generation

        Uses framework-specific vulnerability patterns (React, Vue, Angular).
        """
        self.logger.log("Phase 3: Framework-specific approach")

        # Detect framework if not specified
        framework = self.config.web_framework or self._detect_framework(self.web_app_code)

        if not framework or framework.lower() == 'unknown':
            self.logger.log("No web framework detected, trying common frameworks")
            frameworks = ['react', 'vue', 'angular']
        else:
            frameworks = [framework.lower()]
            self.logger.log(f"Using detected framework: {framework}")

        # Try each framework
        for idx, fw in enumerate(frameworks, 1):
            self.logger.log(f"[{idx}/{len(frameworks)}] Trying framework: {fw}")

            # Generate framework-specific prompt
            fw_prompt = create_framework_specific_prompt(
                framework=fw,
                target_url=self.config.target_url,
                web_app_code=self.web_app_code,
                commit_diff=self.commit_diff,
                payload_count=5
            )

            # Run Phase 0 logic with this framework-specific prompt
            pov_success, pov_metadata = self._do_pov_phase_0(fw_prompt)

            if pov_success:
                self.logger.log(f"SUCCESS! Framework-specific approach found web POV")
                return True, pov_metadata

        self.logger.log(f"Phase 3 exhausted all frameworks without success")
        return False, {}

    def _create_category_prompt(self, category: str) -> str:
        """
        Create category-specific prompt based on CWE

        Args:
            category: CWE category (e.g., "CWE-79")

        Returns:
            Category-specific prompt
        """
        # Map CWE to prompt builder
        if category == "CWE-79":  # XSS
            return create_xss_category_prompt(
                target_url=self.config.target_url,
                web_app_code=self.web_app_code,
                commit_diff=self.commit_diff,
                context="html",
                payload_count=5,
                dom_analysis=self.dom_analysis
            )
        elif category == "CWE-89":  # SQLi
            return create_sqli_category_prompt(
                target_url=self.config.target_url,
                web_app_code=self.web_app_code,
                commit_diff=self.commit_diff,
                database_type="mysql",
                payload_count=5
            )
        elif category == "CWE-352":  # CSRF
            return create_csrf_category_prompt(
                target_url=self.config.target_url,
                web_app_code=self.web_app_code,
                commit_diff=self.commit_diff,
                http_method="POST",
                payload_count=5
            )
        elif category == "CWE-1321":  # Prototype Pollution
            return create_prototype_pollution_prompt(
                target_url=self.config.target_url,
                web_app_code=self.web_app_code,
                commit_diff=self.commit_diff,
                payload_count=5
            )
        else:
            # Default to basic web prompt
            return create_web_commit_based_prompt(
                target_url=self.config.target_url,
                web_app_code=self.web_app_code,
                commit_diff=self.commit_diff,
                vulnerability_types=[category.lower()],
                payload_count=5
            )

    def _detect_framework(self, web_app_code: str) -> str:
        """
        Detect web framework from code

        Args:
            web_app_code: Web application source code

        Returns:
            Detected framework name (react, vue, angular, or unknown)
        """
        code_lower = web_app_code.lower()

        if 'react' in code_lower or 'jsx' in code_lower or 'usestate' in code_lower:
            return 'react'
        elif 'vue' in code_lower or 'v-model' in code_lower or 'v-bind' in code_lower:
            return 'vue'
        elif 'angular' in code_lower or '@angular' in code_lower or 'ngmodel' in code_lower:
            return 'angular'
        else:
            return 'unknown'

    def _detect_vulnerability_type(self, payload_files: List[str]) -> str:
        """
        Detect vulnerability type from payload filenames

        Args:
            payload_files: List of payload file paths

        Returns:
            Detected vulnerability type
        """
        for payload_file in payload_files:
            filename = os.path.basename(payload_file).lower()

            if 'xss' in filename or filename.endswith('.js'):
                return 'xss'
            elif 'sql' in filename or 'sqli' in filename:
                return 'sqli'
            elif 'csrf' in filename or filename.endswith('.html'):
                return 'csrf'
            elif 'proto' in filename or 'pollution' in filename:
                return 'prototype_pollution'
            elif 'xxe' in filename or filename.endswith('.xml'):
                return 'xxe'
            elif 'ssrf' in filename:
                return 'ssrf'

        # Default to XSS
        return 'xss'

    def submit_pov(self, pov_metadata: Dict[str, Any]) -> bool:
        """
        Submit web POV to endpoint (same as WS0 for now)
        """
        import base64
        import requests

        self.logger.log("Submitting web POV to submission endpoint")

        # Get API credentials from environment
        api_key_id = os.environ.get("COMPETITION_API_KEY_ID")
        api_token = os.environ.get("COMPETITION_API_KEY_TOKEN")
        submission_endpoint = os.environ.get("SUBMISSION_ENDPOINT")
        task_id = os.environ.get("TASK_ID")

        if not submission_endpoint:
            self.logger.log("SUBMISSION_ENDPOINT not set, skipping submission")
            return False

        if not task_id:
            self.logger.log("TASK_ID not set, skipping submission")
            return False

        if not api_key_id or not api_token:
            api_key_id = os.environ.get("CRS_KEY_ID")
            api_token = os.environ.get("CRS_KEY_TOKEN")
            if not api_key_id or not api_token:
                self.logger.log("API credentials not set, skipping submission")
                return False

        # Read payload file
        payload_file = pov_metadata.get("payload_files", [])[0] if pov_metadata.get("payload_files") else None
        if not payload_file or not os.path.exists(payload_file):
            self.logger.error(f"Payload file {payload_file} does not exist")
            return False

        with open(payload_file, "rb") as f:
            payload_data = f.read()

        # Create submission payload
        submission = {
            "task_id": task_id,
            "architecture": "web",
            "engine": "playwright",
            "target_url": pov_metadata.get("target_url", ""),
            "vulnerability_type": pov_metadata.get("vulnerability_type", ""),
            "payload": base64.b64encode(payload_data).decode('utf-8'),
            "signature": pov_metadata.get("pov_signature", ""),
            "evidence": pov_metadata.get("evidence", {}),
        }

        # Add strategy information
        submission["strategy"] = "wx0_delta"
        submission["strategy_version"] = "1.0"
        submission["pov_phase"] = self.config.pov_phase

        try:
            # Build URL
            url = f"{submission_endpoint}/v1/task/{task_id}/web/pov/"

            headers = {"Content-Type": "application/json"}
            auth = (api_key_id, api_token) if api_key_id and api_token else None

            # Send request
            response = requests.post(
                url,
                headers=headers,
                auth=auth,
                json=submission,
                timeout=60
            )

            # Check response
            if response.status_code in [200, 201]:
                self.logger.log(f"Successfully submitted web POV: {response.status_code}")
                try:
                    response_data = response.json()
                    self.logger.log(f"Response: {response_data}")
                except:
                    self.logger.log(f"Raw response: {response.text}")
                return True
            else:
                self.logger.error(f"Submission failed with status {response.status_code}: {response.text}")
                return False

        except Exception as e:
            self.logger.error(f"Error submitting web POV: {str(e)}")
            return False


def main():
    """
    Main entry point for WX0 Delta strategy (called by Go goroutines)
    """
    import argparse

    parser = argparse.ArgumentParser(description="WX0 Delta Advanced Web Strategy")
    parser.add_argument("target_url", help="Target web application URL")
    parser.add_argument("project_name", help="Project name")
    parser.add_argument("focus", help="Focus directory")
    parser.add_argument("language", help="Project language (e.g., javascript, typescript)")

    # Optional arguments
    parser.add_argument("--web-framework", type=str, default="",
                        help="Web framework (react, vue, angular, etc.)")
    parser.add_argument("--vulnerability-types", type=str, default="xss,sqli,csrf,prototype_pollution",
                        help="Comma-separated list of vulnerability types to test")
    parser.add_argument("--check-patch-success", action="store_true",
                        help="Check for successful patches and exit early if found")
    parser.add_argument("--max-iterations", dest="max_iterations", type=int, default=5,
                        help="Maximum number of iterations")
    parser.add_argument("--fuzzing-timeout", dest="fuzzing_timeout", type=int, default=45,
                        help="Discovery timeout in minutes")
    parser.add_argument("--pov-metadata-dir", dest="pov_metadata_dir", type=str, default="successful_web_povs",
                        help="Directory to store web POV metadata")
    parser.add_argument("--model", type=str, default="",
                        help="Specific model to use (overrides default model list)")
    parser.add_argument("--log-dir", type=str, default="./logs",
                        help="Directory to store log files (default: ./logs)")
    parser.add_argument("--browser-type", type=str, default="chromium",
                        help="Browser type (chromium, firefox, webkit)")
    parser.add_argument("--headless", type=lambda x: x.lower() == 'true', default=True,
                        help="Run browser in headless mode (true/false)")
    parser.add_argument("--pov-phase", type=int, default=0,
                        help="POV generation phase (0-3, default: 0)")

    args = parser.parse_args()

    # Parse vulnerability types
    vuln_types = [v.strip() for v in args.vulnerability_types.split(',')]

    # Create config
    config = StrategyConfig(
        strategy_name="wx0_delta",
        project_name=args.project_name,
        focus=args.focus,
        language=args.language,
        target_url=args.target_url,
        web_framework=args.web_framework,
        web_vulnerability_types=vuln_types,
        browser_type=args.browser_type,
        headless=args.headless,
        check_patch_success=args.check_patch_success,
        max_iterations=args.max_iterations,
        fuzzing_timeout_minutes=args.fuzzing_timeout,
        pov_metadata_dir=args.pov_metadata_dir,
        log_dir=args.log_dir,
        pov_phase=args.pov_phase,
        models=[args.model] if args.model else None,  # None uses default from config
    )

    # Create and run strategy
    strategy = WX0DeltaStrategy(config)
    success = strategy.run()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
