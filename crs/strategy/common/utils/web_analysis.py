"""
Web Static Analysis Service Interface

Functions for querying static analysis services and processing web analysis results.
Supports JavaScript/TypeScript analysis, data flow tracking, and framework detection.
"""
import os
import time
import requests
from typing import Dict, List, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from opentelemetry import trace


def extract_web_data_flows_from_analysis_service(
    target_file: str,
    project_dir: str,
    sinks: List[Any],
    sources: List[Any]
) -> List[Dict[str, Any]]:
    """
    Extract data flows from sources to sinks by querying a web static analysis service

    Makes HTTP requests to an analysis service endpoint that performs static
    analysis to find data flow paths from sources to sinks in JavaScript/TypeScript code.

    Args:
        target_file: Path to the JavaScript/TypeScript file to analyze
        project_dir: Path to the project directory
        sinks: List of Sink objects from DOM analysis
        sources: List of Source objects from DOM analysis

    Returns:
        List of data flow dictionaries:
        [
            {
                "source": {"property": "location.search", "line": 10, ...},
                "sink": {"property": "innerHTML", "line": 20, ...},
                "flow_path": ["userInput", "processedData", "output"],
                "confidence": 0.95,
                "vulnerability_type": "xss"
            },
            ...
        ]

    Environment Variables:
        WEB_ANALYSIS_SERVICE_URL: Base URL of the web analysis service (default: http://localhost:7083)
        TASK_ID: Task identifier for tracking analysis requests
    """
    # Get web analysis service endpoint
    WEB_ANALYSIS_SERVICE_URL = os.environ.get("WEB_ANALYSIS_SERVICE_URL", "http://localhost:7083")

    if "/v1/web_analysis" not in WEB_ANALYSIS_SERVICE_URL:
        WEB_ANALYSIS_SERVICE_URL = f"{WEB_ANALYSIS_SERVICE_URL}/v1/web_analysis"

    # Convert Sink and Source objects to dictionaries
    sinks_data = []
    for sink in sinks[:20]:  # Limit to 20 sinks
        sinks_data.append({
            "property_or_method": sink.property_or_method,
            "line_number": sink.line_number,
            "code_snippet": sink.code_snippet,
            "sink_type": str(sink.sink_type)
        })

    sources_data = []
    for source in sources[:20]:  # Limit to 20 sources
        sources_data.append({
            "property_or_method": source.property_or_method,
            "line_number": source.line_number,
            "code_snippet": source.code_snippet,
            "source_type": str(source.source_type)
        })

    # Build request payload
    payload = {
        "task_id": os.environ.get("TASK_ID"),
        "target_file": target_file,
        "project_dir": project_dir,
        "sinks": sinks_data,
        "sources": sources_data,
    }

    # Initialize result list
    data_flows = []

    # Retry configuration
    max_tries = 30  # Total attempts (web analysis is faster than binary)
    backoff_sec = 10  # Initial back-off in seconds

    # Import tracer if available
    try:
        from opentelemetry import trace
        tracer = trace.get_tracer(__name__)
        use_tracing = True
    except ImportError:
        use_tracing = False

    # Attempt requests with retries
    for attempt in range(1, max_tries + 1):
        try:
            print(f"WEB_ANALYSIS_SERVICE_URL: {WEB_ANALYSIS_SERVICE_URL}")

            if use_tracing:
                with tracer.start_as_current_span("web_analysis_service.request") as span:
                    span.set_attribute("crs.action.category", "web_static_analysis")
                    span.set_attribute("crs.action.name", "extract_data_flows")
                    span.set_attribute("target_file", target_file)

                    # Make request to analysis service (3 mins timeout)
                    response = requests.post(WEB_ANALYSIS_SERVICE_URL, json=payload, timeout=180)
            else:
                # Make request without tracing
                response = requests.post(WEB_ANALYSIS_SERVICE_URL, json=payload, timeout=180)

            if response.status_code == 200:
                result = response.json()

                if "data_flows" in result and isinstance(result["data_flows"], list):
                    raw_flows = result["data_flows"]

                    # Process each data flow
                    for flow_obj in raw_flows:
                        processed_flow = {
                            "source": flow_obj.get("source", {}),
                            "sink": flow_obj.get("sink", {}),
                            "flow_path": flow_obj.get("flow_path", []),
                            "confidence": flow_obj.get("confidence", 0.5),
                            "vulnerability_type": flow_obj.get("vulnerability_type", "unknown")
                        }
                        data_flows.append(processed_flow)

                # Success - break out of retry loop
                break

            else:
                print(f"Web analysis service returned non-200 status: {response.status_code}")
                try:
                    error_details = response.json()
                    print("Error details (JSON):", error_details)
                except Exception:
                    print("Response body (not JSON):", response.text)

        except Exception as e:
            print(f"Error querying web analysis service: {str(e)}")

        # Only sleep if we will retry again
        if attempt < max_tries:
            time.sleep(backoff_sec)

    print(f"Received {len(data_flows)} data flows\n")
    return data_flows


def query_framework_vulnerabilities(
    target_file: str,
    project_dir: str,
    framework: str
) -> List[Dict[str, Any]]:
    """
    Query static analysis service for framework-specific vulnerabilities

    Args:
        target_file: Path to the JavaScript/TypeScript file
        project_dir: Path to the project directory
        framework: Framework name (react, vue, angular, etc.)

    Returns:
        List of framework-specific vulnerability dictionaries:
        [
            {
                "type": "react_xss",
                "severity": "high",
                "description": "dangerouslySetInnerHTML usage",
                "line_number": 42,
                "code_snippet": "...",
                "cwe_id": "CWE-79"
            },
            ...
        ]
    """
    # Get web analysis service endpoint
    WEB_ANALYSIS_SERVICE_URL = os.environ.get("WEB_ANALYSIS_SERVICE_URL", "http://localhost:7083")

    if "/v1/framework_analysis" not in WEB_ANALYSIS_SERVICE_URL:
        WEB_ANALYSIS_SERVICE_URL = f"{WEB_ANALYSIS_SERVICE_URL}/v1/framework_analysis"

    # Build request payload
    payload = {
        "task_id": os.environ.get("TASK_ID"),
        "target_file": target_file,
        "project_dir": project_dir,
        "framework": framework,
    }

    vulnerabilities = []

    try:
        response = requests.post(WEB_ANALYSIS_SERVICE_URL, json=payload, timeout=120)

        if response.status_code == 200:
            result = response.json()
            vulnerabilities = result.get("vulnerabilities", [])
        else:
            print(f"Framework analysis service returned status: {response.status_code}")

    except Exception as e:
        print(f"Error querying framework analysis service: {str(e)}")

    return vulnerabilities


def query_dependency_vulnerabilities(project_dir: str) -> List[Dict[str, Any]]:
    """
    Query static analysis service for dependency vulnerabilities

    Analyzes package.json, package-lock.json, yarn.lock for known vulnerabilities.

    Args:
        project_dir: Path to the project directory

    Returns:
        List of dependency vulnerability dictionaries:
        [
            {
                "package": "lodash",
                "version": "4.17.15",
                "vulnerability": "Prototype Pollution",
                "severity": "high",
                "cve_id": "CVE-2020-8203",
                "fixed_version": "4.17.21"
            },
            ...
        ]
    """
    # Get web analysis service endpoint
    WEB_ANALYSIS_SERVICE_URL = os.environ.get("WEB_ANALYSIS_SERVICE_URL", "http://localhost:7083")

    if "/v1/dependency_analysis" not in WEB_ANALYSIS_SERVICE_URL:
        WEB_ANALYSIS_SERVICE_URL = f"{WEB_ANALYSIS_SERVICE_URL}/v1/dependency_analysis"

    # Build request payload
    payload = {
        "task_id": os.environ.get("TASK_ID"),
        "project_dir": project_dir,
    }

    vulnerabilities = []

    try:
        response = requests.post(WEB_ANALYSIS_SERVICE_URL, json=payload, timeout=120)

        if response.status_code == 200:
            result = response.json()
            vulnerabilities = result.get("vulnerabilities", [])
        else:
            print(f"Dependency analysis service returned status: {response.status_code}")

    except Exception as e:
        print(f"Error querying dependency analysis service: {str(e)}")

    return vulnerabilities


def extract_call_graph(
    target_file: str,
    project_dir: str,
    entry_function: str = "main"
) -> Dict[str, Any]:
    """
    Extract call graph from JavaScript/TypeScript code

    Args:
        target_file: Path to the JavaScript/TypeScript file
        project_dir: Path to the project directory
        entry_function: Entry function name (default: "main")

    Returns:
        Call graph dictionary:
        {
            "nodes": [
                {"id": "func1", "file": "app.js", "line": 10},
                {"id": "func2", "file": "app.js", "line": 20},
                ...
            ],
            "edges": [
                {"from": "func1", "to": "func2"},
                ...
            ]
        }
    """
    # Get web analysis service endpoint
    WEB_ANALYSIS_SERVICE_URL = os.environ.get("WEB_ANALYSIS_SERVICE_URL", "http://localhost:7083")

    if "/v1/call_graph" not in WEB_ANALYSIS_SERVICE_URL:
        WEB_ANALYSIS_SERVICE_URL = f"{WEB_ANALYSIS_SERVICE_URL}/v1/call_graph"

    # Build request payload
    payload = {
        "task_id": os.environ.get("TASK_ID"),
        "target_file": target_file,
        "project_dir": project_dir,
        "entry_function": entry_function,
    }

    call_graph = {"nodes": [], "edges": []}

    try:
        response = requests.post(WEB_ANALYSIS_SERVICE_URL, json=payload, timeout=180)

        if response.status_code == 200:
            result = response.json()
            call_graph = result.get("call_graph", call_graph)
        else:
            print(f"Call graph service returned status: {response.status_code}")

    except Exception as e:
        print(f"Error querying call graph service: {str(e)}")

    return call_graph


def analyze_typescript_types(
    target_file: str,
    project_dir: str
) -> Dict[str, Any]:
    """
    Analyze TypeScript type information

    Args:
        target_file: Path to the TypeScript file
        project_dir: Path to the project directory

    Returns:
        Type analysis results:
        {
            "functions": [
                {
                    "name": "processInput",
                    "parameters": [{"name": "input", "type": "string"}],
                    "return_type": "void",
                    "line": 10
                },
                ...
            ],
            "interfaces": [...],
            "type_errors": [...]
        }
    """
    # Get web analysis service endpoint
    WEB_ANALYSIS_SERVICE_URL = os.environ.get("WEB_ANALYSIS_SERVICE_URL", "http://localhost:7083")

    if "/v1/typescript_analysis" not in WEB_ANALYSIS_SERVICE_URL:
        WEB_ANALYSIS_SERVICE_URL = f"{WEB_ANALYSIS_SERVICE_URL}/v1/typescript_analysis"

    # Build request payload
    payload = {
        "task_id": os.environ.get("TASK_ID"),
        "target_file": target_file,
        "project_dir": project_dir,
    }

    analysis_results = {
        "functions": [],
        "interfaces": [],
        "type_errors": []
    }

    try:
        response = requests.post(WEB_ANALYSIS_SERVICE_URL, json=payload, timeout=120)

        if response.status_code == 200:
            result = response.json()
            analysis_results = result.get("analysis", analysis_results)
        else:
            print(f"TypeScript analysis service returned status: {response.status_code}")

    except Exception as e:
        print(f"Error querying TypeScript analysis service: {str(e)}")

    return analysis_results
