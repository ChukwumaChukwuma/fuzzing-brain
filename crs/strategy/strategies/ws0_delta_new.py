#!/usr/bin/env python3
"""
WS0 Delta Strategy - LLM-guided web vulnerability discovery

Web adaptation of XS0 Delta Strategy for web application security testing.
Generates web attack payloads and tests them with browser automation and HTTP client.
"""
import os
import sys
import uuid
import time
import shutil
from typing import Dict, Any, Tuple, List

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from core.web_pov_strategy import WebPoVStrategy
from common.config import StrategyConfig
from common.logging.logger import StrategyLogger
from common.llm.client import LLMClient
from common.prompts import create_web_commit_based_prompt
from common.utils import truncate_output
from common.utils.web_vulnerability_signature import (
    generate_web_vulnerability_signature,
    generate_web_vulnerability_report,
)


class WS0DeltaStrategy(WebPoVStrategy):
    """
    WS0 Delta Strategy: Basic commit-based web vulnerability discovery

    Generates web attack payloads per iteration and tests with browser/HTTP client.
    Web equivalent of XS0 Delta Strategy.
    """

    # System prompt for LLM guidance
    SYSTEM_PROMPT = """You are a world-leading web security expert specializing in finding web application vulnerabilities.
Do not apologize when you are wrong. Just keep optimizing the result directly and proceed the progress. Do not lie or guess when you are unsure about the answer.
If possible, show the information needed to make the response better apart from the answer given. Focus on real-world web vulnerabilities like XSS, SQL injection, CSRF, and prototype pollution."""

    def get_strategy_name(self) -> str:
        """Return strategy name for logging"""
        return "ws0_delta"

    def create_initial_prompt(self, web_app_code: str, commit_diff: str) -> str:
        """
        Create initial prompt for web vulnerability discovery

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
            payload_count=5,  # WS0 generates 5 payloads per iteration
        )

    def execute_core_logic(self) -> bool:
        """
        Main execution logic for WS0 Delta Strategy
        """
        self.logger.log("Starting web vulnerability discovery...")

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

        # Create initial prompt
        initial_msg = self.create_initial_prompt(self.web_app_code, self.commit_diff)

        # Execute POV generation loop
        success, metadata = self.do_pov(initial_msg)

        return success

    def do_pov(self, initial_msg: str) -> Tuple[bool, Dict[str, Any]]:
        """
        WS0 web vulnerability discovery main loop

        Args:
            initial_msg: Initial prompt for LLM

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

        # Try with different models
        for model_name in self.config.models:
            self.logger.log(f"Attempting web vulnerability discovery with model: {model_name}")

            # Initialize messages with system prompt and user message
            messages = [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": initial_msg}
            ]
            model_success_count = 0

            for iteration in range(1, self.config.max_iterations + 1):
                current_time = time.time()
                if current_time > end_time:
                    self.logger.log(f"Timeout reached after {iteration-1} iterations with {model_name}")
                    break

                # Check for successful patches if enabled
                if self.config.check_patch_success:
                    if self.check_for_successful_patches():
                        self.logger.log("Successful patch detected, stopping web vulnerability discovery")
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
                payload_dir = os.path.join(self.config.project_dir, "wp0", unique_id)
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
                    self.submit_pov(pov_metadata)

                    successful_pov_metadata = pov_metadata

                    # Continue searching for different vulnerabilities
                    user_message = """
Great job! You've successfully found a web vulnerability.

Now, let's try to find a different vulnerability in the web application.
Can you create different payloads that might trigger a different vulnerability through a different code path or with different attack vectors?

Focus on:
1. Different vulnerability types (XSS, SQLi, CSRF, prototype pollution, etc.)
2. Different injection contexts (HTML, attribute, JavaScript, URL)
3. Edge cases that weren't covered by your previous solution
4. Other potential vulnerabilities in the code

Please provide a new Python script that creates different web attack payloads.
"""
                    messages.append({"role": "user", "content": user_message})

                    # If we found enough POVs with this model, move to next model
                    if model_success_count >= 1:
                        self.logger.log(f"Found {model_success_count} successful web POVs with {model_name}, moving to next model")
                        break

                else:
                    # No vulnerability detected - provide feedback and continue
                    self.logger.log("Web vulnerability not detected, enhancing context and continuing")

                    # Provide feedback for next iteration
                    if iteration == 1:
                        user_message = f"""
Test output:
{truncate_output(test_output, 500)}

The payloads did not trigger a vulnerability. Please analyze the output and try again with an improved approach. Consider:
1. Different attack vectors (XSS, SQLi, CSRF, prototype pollution)
2. Different injection contexts (HTML body, attribute, JavaScript, URL parameter)
3. WAF/filter bypass techniques
4. Framework-specific vulnerabilities (React, Vue, Angular)
5. Pay attention to details in the code
6. Think step by step

The web application code shows potential vulnerabilities. Focus on the modified parts in the commit diff.
"""
                    else:
                        user_message = f"""
Test output:
{truncate_output(test_output, 200)}

The payloads did not trigger a vulnerability. Please analyze the output and try again with a different approach.
"""

                    if iteration == self.config.max_iterations - 1:
                        user_message += "\n\nThis is your last attempt. This task is very important. If you generate successful payloads, I will tip you 2000 dollars."

                    messages.append({"role": "user", "content": user_message})

            # If found POV with this model, potentially stop
            if model_success_count >= 1:
                self.logger.log(f"Found {model_success_count} successful web POVs! Breaking model loop.")
                break

        # Final summary
        total_time = time.time() - start_time
        self.logger.log(f"WS0 Delta strategy completed in {total_time:.2f} seconds")

        # Check if any successful POVs were found
        if os.path.exists(self.config.pov_success_dir):
            pov_files = [f for f in os.listdir(self.config.pov_success_dir) if f.startswith("web_pov_metadata_")]
            if pov_files:
                self.logger.log(f"Found {len(pov_files)} successful web POVs")
                return True, successful_pov_metadata

        self.logger.log("No successful web POVs found")
        return False, {}

    def _detect_vulnerability_type(self, payload_files: List[str]) -> str:
        """
        Detect vulnerability type from payload filenames

        Args:
            payload_files: List of payload file paths

        Returns:
            Detected vulnerability type (xss, sqli, csrf, etc.)
        """
        # Check filenames for vulnerability type indicators
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

        # Default to XSS if cannot detect
        return 'xss'

    def submit_pov(self, pov_metadata: Dict[str, Any]) -> bool:
        """
        Submit web POV to endpoint

        Args:
            pov_metadata: Web POV metadata to submit

        Returns:
            True if submission successful, False otherwise
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
        submission["strategy"] = "ws0_delta"
        submission["strategy_version"] = "1.0"

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
    Main entry point for WS0 Delta strategy (called by Go goroutines)
    """
    import argparse

    parser = argparse.ArgumentParser(description="WS0 Delta Web Strategy")
    parser.add_argument("target_url", help="Target web application URL")
    parser.add_argument("project_name", help="Project name")
    parser.add_argument("focus", help="Focus directory")
    parser.add_argument("language", help="Project language (e.g., javascript, typescript)")

    # Optional arguments
    parser.add_argument("--web-framework", type=str, default="",
                        help="Web framework (react, vue, angular, etc.)")
    parser.add_argument("--vulnerability-types", type=str, default="xss,sqli,csrf",
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

    args = parser.parse_args()

    # Parse vulnerability types
    vuln_types = [v.strip() for v in args.vulnerability_types.split(',')]

    # Create config
    config = StrategyConfig(
        strategy_name="ws0_delta",
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
        models=[args.model] if args.model else None,  # None uses default from config
    )

    # Create and run strategy
    strategy = WS0DeltaStrategy(config)
    success = strategy.run()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
