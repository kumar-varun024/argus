"""
Adversarial Stress and Boundary Test Suite for OS Command Injection (CMDi) Detection Engine.

Covers:
1. False Positive Resistance (static HTML containing OS terms, verbatim reflection, arithmetic canaries).
2. Boundary Latency Differentials (exact sub-second delta thresholds: 3.9s vs 4.1s, high baseline traps).
3. Error-Based Matching against Non-Shell Errors (404, 500, Java/Python/Node/Ruby traces, SQL errors).
4. Parameter Fuzzing across Diverse Formats (nested JSON, empty query strings, special path characters, headers).
"""
import json
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

import pytest

from argus.collectors.command_injection import (
    CommandInjectionAnalyzer,
    CommandInjectionCollector,
    CommandInjectionPayloadGenerator,
    CommandInjectionResult,
    Severity,
    OS_RESULT_SIGNATURES,
    SHELL_ERROR_SIGNATURES,
)
from argus.evidence.model import Evidence
from argus.graph.graph import KnowledgeGraph
from argus.http.client import HttpResponse
from argus.runtime.mission import Mission


class AdversarialMockHttpClient:
    """Configurable mock HTTP client for adversarial test cases."""

    def __init__(self):
        self.get_routes: Dict[str, Tuple[int, str, float]] = {}
        self.post_routes: Dict[str, Tuple[int, str, float]] = {}
        self.header_routes: Dict[str, Tuple[int, str, float]] = {}
        self.request_history: List[Dict[str, Any]] = []

    def set_get_response(self, url_or_keyword: str, status_code: int, body: str, elapsed: float = 0.05):
        self.get_routes[url_or_keyword] = (status_code, body, elapsed)

    def set_post_response(self, keyword_or_url: str, status_code: int, body: str, elapsed: float = 0.05):
        self.post_routes[keyword_or_url] = (status_code, body, elapsed)

    def set_header_response(self, header_key: str, header_val_substr: str, status_code: int, body: str, elapsed: float = 0.05):
        self.header_routes[f"{header_key}:{header_val_substr}"] = (status_code, body, elapsed)

    def get(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)

        headers = kwargs.get("headers") or {}
        self.request_history.append({"method": "GET", "url": target_url, "headers": headers})

        # 1. Header routes
        for hk, hv in headers.items():
            for key, val in self.header_routes.items():
                req_hk, req_hsub = key.split(":", 1)
                if hk.lower() == req_hk.lower() and req_hsub in str(hv):
                    return HttpResponse(
                        success=(200 <= val[0] < 300),
                        status_code=val[0],
                        raw_body=val[1],
                        body=val[1],
                        url=target_url,
                        elapsed=val[2],
                    )

        # 2. Exact GET URL match
        if target_url in self.get_routes:
            sc, b, el = self.get_routes[target_url]
            return HttpResponse(success=(200 <= sc < 300), status_code=sc, raw_body=b, body=b, url=target_url, elapsed=el)

        # 3. Partial keyword match (raw and unquoted)
        unquoted = urllib.parse.unquote_plus(target_url)
        for kw, (sc, b, el) in self.get_routes.items():
            if kw in target_url or kw in unquoted:
                return HttpResponse(success=(200 <= sc < 300), status_code=sc, raw_body=b, body=b, url=target_url, elapsed=el)

        # Default clean response
        return HttpResponse(
            success=True,
            status_code=200,
            raw_body="<html><body><h1>Clean Application Page</h1><p>Welcome to the portal.</p></body></html>",
            body="Clean Application Page",
            url=target_url,
            elapsed=0.05,
        )

    def post(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)

        data = kwargs.get("data")
        json_data = kwargs.get("json")
        headers = kwargs.get("headers") or {}
        self.request_history.append({"method": "POST", "url": target_url, "data": data, "json": json_data, "headers": headers})

        # Check payload matches
        payload_str = ""
        if isinstance(json_data, dict):
            payload_str = json.dumps(json_data)
        elif isinstance(data, dict):
            payload_str = "&".join(f"{k}={v}" for k, v in data.items())
        elif isinstance(data, str):
            payload_str = data

        for kw, (sc, b, el) in self.post_routes.items():
            if kw in payload_str or kw in target_url:
                return HttpResponse(success=(200 <= sc < 300), status_code=sc, raw_body=b, body=b, url=target_url, elapsed=el)

        return HttpResponse(
            success=True,
            status_code=200,
            raw_body="<html><body><h1>POST Received</h1><p>Operation completed successfully.</p></body></html>",
            body="POST Received",
            url=target_url,
            elapsed=0.05,
        )


# =============================================================================
# 1. FALSE POSITIVE RESISTANCE STRESS TESTS
# =============================================================================

class TestFalsePositiveResistance:
    """Stress tests verifying that static HTML, benign texts, and echo reflections are rejected."""

    def test_static_html_linux_documentation_portal(self):
        """Static docs mentioning 'Linux 5.15.0-76-generic' in baseline must NOT trigger finding."""
        analyzer = CommandInjectionAnalyzer()
        doc_html = (
            "<!DOCTYPE html><html><head><title>Linux Documentation Portal</title></head>"
            "<body><h1>Linux Server Administration Guide</h1>"
            "<p>Tested on Linux 5.15.0-76-generic Ubuntu Server 22.04 LTS.</p>"
            "<p>Ensure root privileges are configured properly.</p></body></html>"
        )
        base_resp = HttpResponse(success=True, status_code=200, raw_body=doc_html, body=doc_html, url="http://example.com/docs")
        injected_resp = HttpResponse(success=True, status_code=200, raw_body=doc_html, body=doc_html, url="http://example.com/docs?q=%3B+id")

        # Baseline subtraction must prevent false positive
        res = analyzer.analyze_result_based(
            response=injected_resp,
            baseline=base_resp,
            payload_info={"cmd": "uname -a", "signature": "unix_uname", "os": "posix"},
        )
        assert res is None, "Static documentation matching uname regex must be suppressed via baseline subtraction"

    def test_user_profile_containing_root_admin_usernames(self):
        """User profiles displaying username 'root' or 'admin' in HTML elements without command output."""
        analyzer = CommandInjectionAnalyzer()
        profile_html = (
            "<html><body><div class='profile-card'>"
            "<h2>User Profile</h2>"
            "<p>Username: <span id='user'>root</span></p>"
            "<p>Role: System Administrator</p>"
            "</div></body></html>"
        )
        base_resp = HttpResponse(success=True, status_code=200, raw_body=profile_html, body=profile_html, url="http://example.com/profile")
        injected_resp = HttpResponse(success=True, status_code=200, raw_body=profile_html, body=profile_html, url="http://example.com/profile?id=1%3Bid")

        res = analyzer.analyze_result_based(
            response=injected_resp,
            baseline=base_resp,
            payload_info={"cmd": "whoami", "signature": "unix_whoami", "os": "posix"},
        )
        assert res is None

    def test_verbatim_search_reflection_of_whoami(self):
        """Echoing the search term 'whoami' verbatim in title or heading must be rejected."""
        analyzer = CommandInjectionAnalyzer()
        search_echo_html = (
            "<html><head><title>Search: whoami</title></head>"
            "<body><h1>Search Results for 'whoami'</h1>"
            "<p>Found 0 matching articles for term whoami.</p>"
            "<input type='text' name='q' value='whoami'>"
            "</body></html>"
        )
        resp = HttpResponse(success=True, status_code=200, raw_body=search_echo_html, body=search_echo_html, url="http://example.com/search?q=whoami")

        res = analyzer.analyze_result_based(
            response=resp,
            baseline=None,
            payload_info={"cmd": "whoami", "signature": "unix_whoami", "os": "posix"},
        )
        assert res is None, "Verbatim search reflection of whoami must be suppressed"

    def test_verbatim_search_reflection_of_semicolon_id(self):
        """Echoing '; id' verbatim in input box without executing command must be rejected."""
        analyzer = CommandInjectionAnalyzer()
        echo_html = (
            "<html><body>"
            "<form action='/search'><input name='term' value='; id'></form>"
            "<p>No results found for '; id'.</p>"
            "</body></html>"
        )
        resp = HttpResponse(success=True, status_code=200, raw_body=echo_html, body=echo_html, url="http://example.com/search?term=%3B+id")

        res = analyzer.analyze_result_based(
            response=resp,
            baseline=None,
            payload_info={"cmd": "id", "signature": "unix_id", "os": "posix"},
        )
        assert res is None, "Echoing '; id' without uid= pattern must not trigger finding"

    def test_arithmetic_canary_reflection_without_computation(self):
        """Echoing 'expr 28412 + 19283' verbatim WITHOUT computing '47695' must be rejected."""
        analyzer = CommandInjectionAnalyzer()
        reflected_html = (
            "<html><body>"
            "<h2>Formula Evaluation</h2>"
            "<p>Input formula: expr 28412 + 19283</p>"
            "<p>Status: Unsupported expression</p>"
            "</body></html>"
        )
        resp = HttpResponse(success=True, status_code=200, raw_body=reflected_html, body=reflected_html, url="http://example.com/calc")

        res = analyzer.analyze_result_based(
            response=resp,
            baseline=None,
            payload_info={"cmd": "expr 28412 + 19283", "canary_type": "exact", "expected": "47695", "os": "posix"},
        )
        assert res is None, "Canary not computed must return None"

    def test_arithmetic_canary_present_in_baseline(self):
        """If '47695' was already a product ID in baseline HTML, it must NOT trigger finding."""
        analyzer = CommandInjectionAnalyzer()
        product_html = "<html><body><h1>Product #47695</h1><p>Price: $19.99</p></body></html>"
        base_resp = HttpResponse(success=True, status_code=200, raw_body=product_html, body=product_html, url="http://example.com/product/47695")
        injected_resp = HttpResponse(success=True, status_code=200, raw_body=product_html, body=product_html, url="http://example.com/product/47695?calc=%3Bexpr")

        res = analyzer.analyze_result_based(
            response=injected_resp,
            baseline=base_resp,
            payload_info={"cmd": "expr 28412 + 19283", "canary_type": "exact", "expected": "47695", "os": "posix"},
        )
        assert res is None, "Canary present in baseline must be rejected via baseline subtraction"

    def test_windows_static_directory_mention(self):
        """Static technical blog mentioning 'Directory of C:\\Windows' in baseline must be rejected."""
        analyzer = CommandInjectionAnalyzer()
        blog_html = "<div>Guide: Look at Directory of C:\\Windows\\System32 for DLL files.</div>"
        base_resp = HttpResponse(success=True, status_code=200, raw_body=blog_html, body=blog_html, url="http://example.com/blog")
        injected_resp = HttpResponse(success=True, status_code=200, raw_body=blog_html, body=blog_html, url="http://example.com/blog?page=1")

        res = analyzer.analyze_result_based(
            response=injected_resp,
            baseline=base_resp,
            payload_info={"cmd": "dir C:\\", "signature": "windows_dir", "os": "windows"},
        )
        assert res is None

    def test_is_false_positive_helper(self):
        """Tests helper method is_false_positive across edge conditions."""
        analyzer = CommandInjectionAnalyzer()

        # Empty response
        assert analyzer.is_false_positive(None, "id") is True
        assert analyzer.is_false_positive(HttpResponse(success=True, status_code=200, raw_body="", body="", url=""), "id") is True
        assert analyzer.is_false_positive(HttpResponse(success=True, status_code=200, raw_body="abc", body="abc", url=""), "id") is True

        # Identical to baseline
        base = HttpResponse(success=True, status_code=200, raw_body="Exact Same Content 12345", body="", url="")
        injected = HttpResponse(success=True, status_code=200, raw_body="Exact Same Content 12345", body="", url="")
        assert analyzer.is_false_positive(injected, "id", baseline=base) is True

        # Non-empty distinct body
        distinct = HttpResponse(success=True, status_code=200, raw_body="uid=0(root) gid=0(root)", body="", url="")
        assert analyzer.is_false_positive(distinct, "id", baseline=base) is False


# =============================================================================
# 2. BOUNDARY LATENCY DIFFERENTIAL TESTS
# =============================================================================

class TestBoundaryLatencyDifferentials:
    """Stress tests evaluating precision at the >= 4.0s threshold boundary."""

    def test_latency_delta_below_threshold_rejected(self):
        """Baseline 0.50s + Injected 4.40s -> delta 3.90s < 4.0s -> MUST REJECT."""
        analyzer = CommandInjectionAnalyzer()
        base = HttpResponse(success=True, status_code=200, raw_body="OK", body="OK", url="http://test", elapsed=0.50)
        injected = HttpResponse(success=True, status_code=200, raw_body="OK", body="OK", url="http://test", elapsed=4.40)

        res = analyzer.analyze_time_blind(injected, base, threshold=4.0)
        assert res is None, f"Delta 3.90s must be rejected (res was {res})"

    def test_latency_delta_at_boundary_3_99s_rejected(self):
        """Baseline 0.50s + Injected 4.49s -> delta 3.99s < 4.0s -> MUST REJECT."""
        analyzer = CommandInjectionAnalyzer()
        base = HttpResponse(success=True, status_code=200, raw_body="OK", body="OK", url="http://test", elapsed=0.50)
        injected = HttpResponse(success=True, status_code=200, raw_body="OK", body="OK", url="http://test", elapsed=4.49)

        res = analyzer.analyze_time_blind(injected, base, threshold=4.0)
        assert res is None, "Delta 3.99s must be strictly rejected"

    def test_latency_delta_at_boundary_4_00s_accepted(self):
        """Baseline 0.50s + Injected 4.50s -> delta 4.00s >= 4.0s -> MUST ACCEPT."""
        analyzer = CommandInjectionAnalyzer()
        base = HttpResponse(success=True, status_code=200, raw_body="OK", body="OK", url="http://test", elapsed=0.50)
        injected = HttpResponse(success=True, status_code=200, raw_body="OK", body="OK", url="http://test", elapsed=4.50)

        res = analyzer.analyze_time_blind(injected, base, threshold=4.0)
        assert res is not None, "Delta 4.00s must be accepted"
        assert res["technique"] == "time_blind"
        assert res["delay_delta"] == pytest.approx(4.00, abs=1e-3)
        assert res["severity"] == Severity.CRITICAL

    def test_latency_delta_above_threshold_accepted(self):
        """Baseline 0.50s + Injected 4.60s -> delta 4.10s >= 4.0s -> MUST ACCEPT."""
        analyzer = CommandInjectionAnalyzer()
        base = HttpResponse(success=True, status_code=200, raw_body="OK", body="OK", url="http://test", elapsed=0.50)
        injected = HttpResponse(success=True, status_code=200, raw_body="OK", body="OK", url="http://test", elapsed=4.60)

        res = analyzer.analyze_time_blind(injected, base, threshold=4.0)
        assert res is not None, "Delta 4.10s must be accepted"
        assert res["delay_delta"] == pytest.approx(4.10, abs=1e-3)

    def test_high_baseline_latency_trap(self):
        """Baseline 6.00s (slow server) + Injected 6.50s -> delta 0.50s < 4.0s -> MUST REJECT."""
        analyzer = CommandInjectionAnalyzer()
        base = HttpResponse(success=True, status_code=200, raw_body="OK", body="OK", url="http://test", elapsed=6.00)
        injected = HttpResponse(success=True, status_code=200, raw_body="OK", body="OK", url="http://test", elapsed=6.50)

        res = analyzer.analyze_time_blind(injected, base, threshold=4.0)
        assert res is None, "Injected elapsed >= 4.0s but delta < 4.0s must be rejected"

    def test_custom_threshold_parameterization(self):
        """Verifies configurable delay thresholds (e.g. 2.0s and 6.0s)."""
        analyzer = CommandInjectionAnalyzer()
        base = HttpResponse(success=True, status_code=200, raw_body="OK", body="OK", url="http://test", elapsed=0.20)
        injected = HttpResponse(success=True, status_code=200, raw_body="OK", body="OK", url="http://test", elapsed=2.50)

        # Threshold 2.0s -> delta 2.30s >= 2.0s -> ACCEPT
        res_2 = analyzer.analyze_time_blind(injected, base, threshold=2.0)
        assert res_2 is not None

        # Threshold 3.0s -> delta 2.30s < 3.0s -> REJECT
        res_3 = analyzer.analyze_time_blind(injected, base, threshold=3.0)
        assert res_3 is None

    def test_collector_end_to_end_boundary_differential(self):
        """End-to-end collector testing with boundary delays."""
        mock_http = AdversarialMockHttpClient()
        # Endpoint 1: delta 3.85s (baseline 0.15s, injected 4.00s) -> Rejected
        mock_http.set_get_response("http://example.com/api/slow?t=1", 200, "Slow baseline", elapsed=0.15)
        mock_http.set_get_response("http://example.com/api/slow?t=%3B+sleep+5", 200, "Slow response", elapsed=4.00)
        mock_http.set_get_response("http://example.com/api/slow?t=sleep+5", 200, "Slow response", elapsed=4.00)

        # Endpoint 2: delta 4.50s (baseline 0.10s, injected 4.60s) -> Accepted
        mock_http.set_get_response("http://example.com/api/vulnerable?t=1", 200, "Vulnerable baseline", elapsed=0.10)
        mock_http.set_get_response("http://example.com/api/vulnerable?t=%3B+sleep+5", 200, "Vulnerable Delayed", elapsed=4.60)
        mock_http.set_get_response("http://example.com/api/vulnerable?t=sleep+5", 200, "Vulnerable Delayed", elapsed=4.60)

        collector = CommandInjectionCollector(http_client=mock_http, delay_threshold=4.0)
        mission = Mission(target="http://example.com")
        mission.endpoints = [
            "http://example.com/api/slow?t=1",
            "http://example.com/api/vulnerable?t=1",
        ]
        mission.evidence = []
        mission.vulnerabilities = []
        mission.attack_surface_graph = KnowledgeGraph()

        evidence_list = collector.collect(mission)
        # Only vulnerable endpoint must be reported
        assert len(evidence_list) == 1
        assert "vulnerable" in evidence_list[0].value


# =============================================================================
# 3. ERROR-BASED MATCHING AGAINST NON-SHELL ERRORS
# =============================================================================

class TestErrorBasedNonShellExclusions:
    """Stress tests verifying that non-shell errors (HTTP errors, DB errors, app stack traces) are rejected."""

    def test_http_404_not_found_page_rejection(self):
        """Standard 404 Not Found error page must NOT trigger error-based CMDi finding."""
        analyzer = CommandInjectionAnalyzer()
        html_404 = (
            "<!DOCTYPE HTML PUBLIC '-//IETF//DTD HTML 2.0//EN'>"
            "<html><head><title>404 Not Found</title></head>"
            "<body><h1>Not Found</h1><p>The requested URL /api/tools;id was not found on this server.</p>"
            "<hr><address>Apache/2.4.41 (Ubuntu) Server at example.com Port 80</address></body></html>"
        )
        resp_404 = HttpResponse(success=False, status_code=404, raw_body=html_404, body=html_404, url="http://example.com/404")

        res = analyzer.analyze_error_based(resp_404, baseline=None, payload="; nonexistent_cmd ;")
        assert res is None, "404 Not Found page must NOT trigger error-based finding"

    def test_http_500_generic_internal_server_error_rejection(self):
        """Standard 500 Internal Server Error without shell traces must NOT trigger finding."""
        analyzer = CommandInjectionAnalyzer()
        html_500 = (
            "<html><head><title>500 Internal Server Error</title></head>"
            "<body><h1>Server Error</h1><p>An unexpected condition was encountered.</p></body></html>"
        )
        resp_500 = HttpResponse(success=False, status_code=500, raw_body=html_500, body=html_500, url="http://example.com/500")

        res = analyzer.analyze_error_based(resp_500, baseline=None, payload="; bad_cmd ;")
        assert res is None, "Generic 500 Internal Server Error must NOT trigger finding"

    def test_java_spring_stack_trace_rejection(self):
        """Java / Spring Boot exception stack trace must NOT trigger error-based CMDi."""
        analyzer = CommandInjectionAnalyzer()
        java_trace = (
            "org.springframework.web.bind.MissingServletRequestParameterException: "
            "Required request parameter 'id' for method parameter type Long is not present\n"
            "\tat org.springframework.web.method.annotation.RequestParamMethodArgumentResolver.handleMissingValue(RequestParamMethodArgumentResolver.java:204)\n"
            "\tat org.springframework.web.servlet.DispatcherServlet.doDispatch(DispatcherServlet.java:1064)\n"
        )
        resp = HttpResponse(success=False, status_code=500, raw_body=java_trace, body=java_trace, url="http://example.com/api")

        res = analyzer.analyze_error_based(resp, baseline=None, payload="; bad_cmd ;")
        assert res is None, "Java stack trace must not trigger shell error detection"

    def test_python_django_traceback_rejection(self):
        """Python / Django traceback must NOT trigger error-based CMDi."""
        analyzer = CommandInjectionAnalyzer()
        py_trace = (
            "Traceback (most recent call last):\n"
            '  File "/usr/local/lib/python3.10/site-packages/django/core/handlers/exception.py", line 55, in inner\n'
            "    response = get_response(request)\n"
            '  File "/app/views.py", line 42, in get_item\n'
            "    item_id = int(request.GET['id'])\n"
            "ValueError: invalid literal for int() with base 10: '; id'\n"
        )
        resp = HttpResponse(success=False, status_code=500, raw_body=py_trace, body=py_trace, url="http://example.com/item")

        res = analyzer.analyze_error_based(resp, baseline=None, payload="; id")
        assert res is None, "Python ValueError must not trigger shell error detection"

    def test_sql_database_errors_rejection(self):
        """Database syntax errors (SQLi) must NOT trigger OS command injection error findings."""
        analyzer = CommandInjectionAnalyzer()

        db_errors = [
            "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1",
            "ERROR: syntax error at or near \"foo\" at character 14",
            "ORA-00933: SQL command not properly ended",
            "SQLite3::SQLException: near 'syntax': syntax error",
            "Microsoft OLE DB Provider for SQL Server: Unclosed quotation mark after the character string 'test'.",
            "PostgreSQL query failed: column \"admin\" does not exist",
        ]

        for err in db_errors:
            resp = HttpResponse(success=False, status_code=500, raw_body=err, body=err, url="http://example.com/db")
            res = analyzer.analyze_error_based(resp, baseline=None, payload="; bad_cmd ;")
            assert res is None, f"Database error '{err[:40]}...' must NOT trigger CMDi error finding"

    def test_valid_shell_error_signatures_all_shells(self):
        """Verifies genuine shell error triggers across Bash, Dash, Zsh, CMD, and PowerShell."""
        analyzer = CommandInjectionAnalyzer()

        cases = [
            ("sh: 1: nonexistent_token_999: not found", "unix_bash", "dash_not_found"),
            ("/bin/bash: line 1: fake_cmd_123: command not found", "unix_bash", "bash_not_found"),
            ("zsh: command not found: unknown_bin_x", "unix_bash", "zsh_not_found"),
            ("/bin/sh: syntax error near unexpected token `;'", "unix_bash", "bash_syntax_error"),
            ("/bin/sh: /bin/cat: Permission denied", "unix_bash", "permission_denied"),
            ("'fake_cmd' is not recognized as an internal or external command, operable program or batch file.", "windows_cmd", "cmd_not_recognized"),
            ("The syntax of the command is incorrect.", "windows_cmd", "cmd_syntax_incorrect"),
            ("The term 'Invoke-BadCmd' is not recognized as the name of a cmdlet, function, script file", "windows_powershell", "ps_cmdlet_not_found"),
            ("CommandNotFoundException: Could not resolve command", "windows_powershell", "ps_command_not_found_exc"),
        ]

        for output_snippet, expected_family, expected_pattern in cases:
            resp = HttpResponse(success=False, status_code=500, raw_body=output_snippet, body=output_snippet, url="http://example.com/exec")
            res = analyzer.analyze_error_based(resp, baseline=None, payload="; fake_cmd ;")
            assert res is not None, f"Expected match for shell error: {output_snippet}"
            assert res["technique"] == "error_based"
            assert res["shell_flavor"] == expected_family
            assert res["severity"] == Severity.HIGH

    def test_baseline_shell_error_suppression(self):
        """If baseline already returned a shell error (e.g. server-side broken script), suppress finding."""
        analyzer = CommandInjectionAnalyzer()
        broken_server_msg = "sh: 1: config_reader: not found\nServer initialization failure."
        base_resp = HttpResponse(success=False, status_code=500, raw_body=broken_server_msg, body=broken_server_msg, url="http://example.com/health")
        injected_resp = HttpResponse(success=False, status_code=500, raw_body=broken_server_msg, body=broken_server_msg, url="http://example.com/health?check=%3B")

        res = analyzer.analyze_error_based(injected_resp, baseline=base_resp, payload="; nonexistent ;")
        assert res is None, "Shell error present in baseline must be suppressed"


# =============================================================================
# 4. PARAMETER FUZZING ACROSS DIVERSE BODY FORMATS & EDGE CASES
# =============================================================================

class TestParameterFuzzingDiverseFormats:
    """Stress tests parameter extraction and fuzzing across complex JSON, query, path, and header payloads."""

    def test_fuzzing_nested_and_structured_json(self):
        """Fuzzing JSON POST bodies containing string, int, boolean, array, and dict values."""
        mock_http = AdversarialMockHttpClient()
        # When filename inside JSON is injected with 'cat /etc/passwd'
        mock_http.set_post_response(
            "cat /etc/passwd",
            200,
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        )

        collector = CommandInjectionCollector(http_client=mock_http)
        mission = Mission(target="http://example.com")
        mission.endpoints = [{
            "url": "http://example.com/api/export",
            "method": "POST",
            "body": {
                "format": "tar.gz",
                "compress_level": 9,
                "async_mode": True,
                "target_file": "report.pdf",
            },
        }]
        mission.evidence = []
        mission.vulnerabilities = []
        mission.attack_surface_graph = KnowledgeGraph()

        evidence_list = collector.collect(mission)
        assert len(evidence_list) >= 1
        ev = evidence_list[0]
        assert ev.category == "command_injection"
        assert ev.metadata["parameter_type"] == "json"
        assert ev.metadata["parameter"] in ("target_file", "format")
        assert "root:x:0:0:" in ev.metadata["evidence_snippet"]

    def test_fuzzing_empty_and_edge_query_strings(self):
        """Handles endpoints with empty query parameters gracefully (?foo=&bar=)."""
        mock_http = AdversarialMockHttpClient()
        mock_http.set_get_response("id", 200, "uid=1000(worker) gid=1000(worker)")

        collector = CommandInjectionCollector(http_client=mock_http)
        mission = Mission(target="http://example.com")
        mission.endpoints = [
            "http://example.com/api/ping?",
            "http://example.com/api/ping?host=&count=",
            "http://example.com/api/ping?debug",
        ]
        mission.evidence = []
        mission.vulnerabilities = []
        mission.attack_surface_graph = KnowledgeGraph()

        evidence_list = collector.collect(mission)
        assert len(evidence_list) >= 1
        assert any("worker" in ev.description for ev in evidence_list)

    def test_fuzzing_special_and_traversal_path_segments(self):
        """Fuzzing numeric and resource path segments with slashes and special characters."""
        mock_http = AdversarialMockHttpClient()
        mock_http.set_get_response("; id", 200, "uid=0(root) gid=0(root)")

        collector = CommandInjectionCollector(http_client=mock_http)
        mission = Mission(target="http://example.com")
        mission.endpoints = [
            "http://example.com/admin/tools/1042",
            "http://example.com/view/item/8888",
        ]
        mission.evidence = []
        mission.vulnerabilities = []
        mission.attack_surface_graph = KnowledgeGraph()

        evidence_list = collector.collect(mission)
        assert len(evidence_list) >= 1
        assert any(ev.metadata.get("param_type") == "path" or ev.metadata.get("parameter_type") == "path" for ev in evidence_list)

    def test_fuzzing_all_header_vectors(self):
        """Verifies injection into User-Agent, Referer, Cookie, X-Forwarded-For, and X-Client-IP."""
        headers_tested = [
            ("User-Agent", "Mozilla/5.0; ; id"),
            ("Referer", "http://example.com/; id"),
            ("Cookie", "session_id=; id"),
            ("X-Forwarded-For", "127.0.0.1; ; id"),
            ("X-Client-IP", "127.0.0.1; ; id"),
        ]

        for h_name, h_val in headers_tested:
            mock_http = AdversarialMockHttpClient()
            mock_http.set_header_response(h_name, "; id", 200, "uid=0(root) gid=0(root)")

            collector = CommandInjectionCollector(http_client=mock_http)
            mission = Mission(target="http://example.com")
            mission.endpoints = ["http://example.com/analytics/log"]
            mission.evidence = []
            mission.vulnerabilities = []
            mission.attack_surface_graph = KnowledgeGraph()

            evidence_list = collector.collect(mission)
            assert len(evidence_list) >= 1, f"Failed header injection test for {h_name}"
            ev = evidence_list[0]
            assert ev.metadata["parameter_type"] == "header"
            assert ev.metadata["parameter"] == h_name

    def test_mutation_engine_distinct_strategies(self):
        """Verifies that all 8 mutation strategies in CommandInjectionPayloadGenerator produce valid variants."""
        gen = CommandInjectionPayloadGenerator()

        # 1. Semicolons
        semi = gen.mutate_semicolons("whoami")
        assert len(semi) >= 4 and all("whoami" in s for s in semi)

        # 2. Pipes
        pipes = gen.mutate_pipes("whoami")
        assert len(pipes) >= 4 and any("| whoami" in p for p in pipes)

        # 3. Ampersands
        amp = gen.mutate_ampersands("whoami")
        assert len(amp) >= 4 and any("& whoami" in a for a in amp)

        # 4. Command Substitutions
        subs = gen.mutate_substitution("id")
        assert len(subs) >= 4 and any("`id`" in s for s in subs) and any("$(id)" in s for s in subs)

        # 5. Newlines
        newlines = gen.mutate_newlines("id")
        assert len(newlines) >= 4 and any("%0aid" in n for n in newlines)

        # 6. URL Encoding
        encs = gen.mutate_url_encoding("; id")
        assert len(encs) == 2 and "%3B" in encs[0] and "%253B" in encs[1]

        # 7. Whitespace
        ws = gen.mutate_whitespace("cat /etc/passwd")
        assert len(ws) >= 4 and any("${IFS}" in w for w in ws) and any("%09" in w for w in ws)

        # 8. Inline Quotes
        quotes = gen.mutate_inline_quotes("whoami")
        assert len(quotes) >= 3 and any("'" in q for q in quotes)
