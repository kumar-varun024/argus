"""
Unit and Component tests for CommandInjectionCollector, CommandInjectionPayloadGenerator,
CommandInjectionAnalyzer, and associated data models.
"""
from typing import Any, Dict, List, Optional, Tuple
import pytest
import urllib.parse

from argus.collectors.command_injection import (
    CommandInjectionCollector,
    CommandInjectionPayloadGenerator,
    CommandInjectionAnalyzer,
    CommandInjectionResult,
    Severity,
    RESULT_COMMAND_PAYLOADS,
    DEFAULT_TIME_DELAY_PAYLOADS,
    DEFAULT_ERROR_TRIGGER_PAYLOADS,
    OS_RESULT_SIGNATURES,
    SHELL_ERROR_SIGNATURES,
)
from argus.evidence.model import Evidence
from argus.graph.graph import KnowledgeGraph
from argus.http.client import HttpResponse
from argus.runtime.mission import Mission
from argus.plugins.interfaces import ControlledMission


class MockCmdiHttpClient:
    """Mock HTTP client for command injection testing."""

    def __init__(self, routes: Optional[Dict[str, Tuple[int, str, float]]] = None):
        # routes: key -> (status_code, body, elapsed)
        self.routes: Dict[str, Tuple[int, str, float]] = dict(routes or {})
        self.requested_urls: List[str] = []
        self.requested_posts: List[Dict[str, Any]] = []

    def set_route(self, key: str, status_code: int, body: str, elapsed: float = 0.05):
        self.routes[key] = (status_code, body, elapsed)

    def get(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)
        self.requested_urls.append(target_url)

        headers = kwargs.get("headers") or {}
        # Check header-based routing
        for hk, hv in headers.items():
            header_key = f"header:{hk}:{hv}"
            if header_key in self.routes:
                status_code, body, elapsed = self.routes[header_key]
                return HttpResponse(
                    success=(200 <= status_code < 300),
                    status_code=status_code,
                    raw_body=body,
                    body=body,
                    url=target_url,
                    elapsed=elapsed,
                )

        # Exact URL match
        if target_url in self.routes:
            status_code, body, elapsed = self.routes[target_url]
            return HttpResponse(
                success=(200 <= status_code < 300),
                status_code=status_code,
                raw_body=body,
                body=body,
                url=target_url,
                elapsed=elapsed,
            )

        # Partial URL or payload match (including unquoted variants)
        unquoted_url = urllib.parse.unquote_plus(target_url)
        for reg_key, (status_code, body, elapsed) in self.routes.items():
            if reg_key in target_url or reg_key in unquoted_url:
                return HttpResponse(
                    success=(200 <= status_code < 300),
                    status_code=status_code,
                    raw_body=body,
                    body=body,
                    url=target_url,
                    elapsed=elapsed,
                )

        return HttpResponse(
            success=True,
            status_code=200,
            raw_body="OK Clean Application Response",
            body="OK Clean Application Response",
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
        self.requested_posts.append({"url": target_url, "data": data, "json": json_data})

        # Check payload matches in json or data
        payload_val = ""
        if isinstance(json_data, dict):
            for v in json_data.values():
                if isinstance(v, str):
                    payload_val = v
                    break
        elif isinstance(data, dict):
            for v in data.values():
                if isinstance(v, str):
                    payload_val = v
                    break

        if payload_val:
            for reg_key, (status_code, body, elapsed) in self.routes.items():
                if reg_key in payload_val or payload_val in reg_key:
                    return HttpResponse(
                        success=(200 <= status_code < 300),
                        status_code=status_code,
                        raw_body=body,
                        body=body,
                        url=target_url,
                        elapsed=elapsed,
                    )

        if target_url in self.routes:
            status_code, body, elapsed = self.routes[target_url]
            return HttpResponse(
                success=(200 <= status_code < 300),
                status_code=status_code,
                raw_body=body,
                body=body,
                url=target_url,
                elapsed=elapsed,
            )

        return HttpResponse(
            success=True,
            status_code=200,
            raw_body="OK Clean Application Response",
            body="OK Clean Application Response",
            url=target_url,
            elapsed=0.05,
        )


# =============================================================================
# 1. Payload Generator Unit Tests
# =============================================================================

def test_cmdi_payload_generator_base_suites():
    """Verifies that base result, time, and error payloads are generated properly."""
    generator = CommandInjectionPayloadGenerator()

    result_payloads = generator.generate_result_payloads()
    assert len(result_payloads) >= 6
    cmds = [p["cmd"] for p in result_payloads]
    assert "id" in cmds
    assert "whoami" in cmds
    assert "uname -a" in cmds
    assert "cat /etc/passwd" in cmds
    assert "expr 28412 + 19283" in cmds
    assert "ver" in cmds

    time_payloads = generator.generate_time_payloads(delay=7)
    assert len(time_payloads) >= 4
    time_cmds = [p["cmd"] for p in time_payloads]
    assert "sleep 7" in time_cmds
    assert any("timeout /t 7" in c for c in time_cmds)

    error_payloads = generator.generate_error_payloads()
    assert len(error_payloads) >= 5
    assert any("argus_nonexistent_cmd" in p for p in error_payloads)


def test_cmdi_mutations_semicolons():
    """Strategy 1: Semicolon chaining mutations."""
    generator = CommandInjectionPayloadGenerator()
    variants = generator.mutate_semicolons("id")
    assert "; id" in variants
    assert "; id ;" in variants
    assert ";; id" in variants
    assert "1; id" in variants


def test_cmdi_mutations_pipes_and_ampersands():
    """Strategy 2 & 3: Pipes and Ampersands mutations."""
    generator = CommandInjectionPayloadGenerator()
    pipes = generator.mutate_pipes("whoami")
    assert "| whoami" in pipes
    assert "|| whoami" in pipes
    assert "1 | whoami" in pipes

    ampersands = generator.mutate_ampersands("whoami")
    assert "& whoami" in ampersands
    assert "&& whoami" in ampersands
    assert "1 && whoami" in ampersands


def test_cmdi_mutations_command_substitution():
    """Strategy 4: Command substitutions."""
    generator = CommandInjectionPayloadGenerator()
    subs = generator.mutate_substitution("id")
    assert "`id`" in subs
    assert "$(id)" in subs
    assert "`echo id | sh`" in subs
    assert "$(echo id | sh)" in subs


def test_cmdi_mutations_newlines():
    """Strategy 5: Newline mutations (raw & encoded)."""
    generator = CommandInjectionPayloadGenerator()
    newlines = generator.mutate_newlines("id")
    assert "\nid" in newlines
    assert "%0aid" in newlines
    assert "%0d%0aid" in newlines


def test_cmdi_mutations_url_encoding():
    """Strategy 6: URL and Double-URL percent encoding."""
    generator = CommandInjectionPayloadGenerator()
    encs = generator.mutate_url_encoding("; id")
    assert len(encs) == 2
    assert "%3B%20id" in encs[0]
    assert "%253B" in encs[1]


def test_cmdi_mutations_whitespace_substitution():
    """Strategy 7: Whitespace substitutions using $IFS, ${IFS}, $IFS$9, %09, +."""
    generator = CommandInjectionPayloadGenerator()
    ws = generator.mutate_whitespace("cat /etc/passwd")
    assert "cat${IFS}/etc/passwd" in ws
    assert "cat$IFS$9/etc/passwd" in ws
    assert "cat%09/etc/passwd" in ws
    assert "cat+/etc/passwd" in ws


def test_cmdi_mutations_inline_quotes():
    """Strategy 8: Inline quote and backslash obfuscations."""
    generator = CommandInjectionPayloadGenerator()
    quotes = generator.mutate_inline_quotes("whoami")
    assert any("'" in q for q in quotes)
    assert any('"' in q for q in quotes)
    assert any("\\" in q for q in quotes)


def test_cmdi_mutations_combined_generation():
    """Verifies full mutation generation with deduplication."""
    generator = CommandInjectionPayloadGenerator()
    all_muts = generator.generate_mutated_payloads("id")
    assert len(all_muts) > 10
    # Must be deduplicated
    assert len(all_muts) == len(set(all_muts))
    assert "; id" in all_muts
    assert "| id" in all_muts
    assert "& id" in all_muts
    assert "`id`" in all_muts
    assert "%0aid" in all_muts


# =============================================================================
# 2. Command Injection Analyzer Unit Tests
# =============================================================================

def test_cmdi_analyzer_posix_result_signatures():
    """Tests POSIX execution output regex matching."""
    analyzer = CommandInjectionAnalyzer()

    # Unix ID
    resp_id = HttpResponse(success=True, status_code=200, raw_body="uid=0(root) gid=0(root) groups=0(root)", body="", url="http://test")
    res = analyzer.analyze_result_based(resp_id, baseline=None, payload_info={"cmd": "id", "signature": "unix_id", "os": "posix"})
    assert res is not None
    assert res["technique"] == "result_based"
    assert res["severity"] == Severity.CRITICAL
    assert res["os_family"] == "posix"
    assert "uid=0(root)" in res["snippet"]

    # Unix /etc/passwd
    resp_passwd = HttpResponse(success=True, status_code=200, raw_body="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin", body="", url="http://test")
    res = analyzer.analyze_result_based(resp_passwd, baseline=None, payload_info={"cmd": "cat /etc/passwd", "signature": "unix_passwd", "os": "posix"})
    assert res is not None
    assert "root:x:0:0:" in res["snippet"]

    # Unix uname
    resp_uname = HttpResponse(success=True, status_code=200, raw_body="Linux web-prod-01 5.15.0-76-generic #83-Ubuntu SMP", body="", url="http://test")
    res = analyzer.analyze_result_based(resp_uname, baseline=None, payload_info={"cmd": "uname -a", "signature": "unix_uname", "os": "posix"})
    assert res is not None
    assert "Linux web-prod-01" in res["snippet"]


def test_cmdi_analyzer_arithmetic_canary():
    """Tests exact arithmetic canary matching (expr 28412 + 19283 -> 47695)."""
    analyzer = CommandInjectionAnalyzer()

    payload_info = {"cmd": "expr 28412 + 19283", "canary_type": "exact", "expected": "47695", "os": "posix"}
    resp = HttpResponse(success=True, status_code=200, raw_body="<div>Output: 47695</div>", body="", url="http://test")
    baseline = HttpResponse(success=True, status_code=200, raw_body="<div>Output: 0</div>", body="", url="http://test")

    res = analyzer.analyze_result_based(resp, baseline=baseline, payload_info=payload_info)
    assert res is not None
    assert res["technique"] == "result_based"
    assert res["severity"] == Severity.CRITICAL
    assert "47695" in res["matched_pattern"]


def test_cmdi_analyzer_windows_result_signatures():
    """Tests Windows execution output regex matching."""
    analyzer = CommandInjectionAnalyzer()

    # Windows whoami
    resp_whoami = HttpResponse(success=True, status_code=200, raw_body="nt authority\\system\r\n", body="", url="http://test")
    res = analyzer.analyze_result_based(resp_whoami, baseline=None, payload_info={"cmd": "whoami", "signature": "windows_whoami", "os": "windows"})
    assert res is not None
    assert res["os_family"] == "windows"
    assert "nt authority\\system" in res["snippet"].lower()

    # Windows ver
    resp_ver = HttpResponse(success=True, status_code=200, raw_body="Microsoft Windows [Version 10.0.19045.3324]\r\n(c) Microsoft Corporation.", body="", url="http://test")
    res = analyzer.analyze_result_based(resp_ver, baseline=None, payload_info={"cmd": "ver", "signature": "windows_ver", "os": "windows"})
    assert res is not None
    assert "Microsoft Windows" in res["snippet"]

    # Windows ipconfig
    resp_ipc = HttpResponse(success=True, status_code=200, raw_body="Windows IP Configuration\r\n\r\nEthernet adapter Ethernet0:", body="", url="http://test")
    res = analyzer.analyze_result_based(resp_ipc, baseline=None, payload_info={"cmd": "ipconfig", "signature": "windows_ipconfig", "os": "windows"})
    assert res is not None
    assert "Windows IP Configuration" in res["snippet"]


def test_cmdi_analyzer_shell_error_signatures():
    """Tests shell error detection for Bash, CMD, and PowerShell."""
    analyzer = CommandInjectionAnalyzer()

    # Bash command not found
    resp_bash = HttpResponse(success=True, status_code=500, raw_body="/bin/sh: line 1: argus_bad_cmd: command not found", body="", url="http://test")
    res = analyzer.analyze_error_based(resp_bash, baseline=None, payload="; argus_bad_cmd ;")
    assert res is not None
    assert res["technique"] == "error_based"
    assert res["severity"] == Severity.HIGH
    assert res["confidence"] == 0.90
    assert "not found" in res["snippet"]

    # Windows CMD not recognized
    resp_cmd = HttpResponse(success=True, status_code=500, raw_body="'argus_bad_cmd' is not recognized as an internal or external command, operable program or batch file.", body="", url="http://test")
    res = analyzer.analyze_error_based(resp_cmd, baseline=None, payload="& argus_bad_cmd &")
    assert res is not None
    assert res["shell_flavor"] == "windows_cmd"

    # PowerShell error
    resp_ps = HttpResponse(success=True, status_code=500, raw_body="The term 'argus_cmd' is not recognized as the name of a cmdlet, function, script file, or operable program.", body="", url="http://test")
    res = analyzer.analyze_error_based(resp_ps, baseline=None, payload="| argus_cmd")
    assert res is not None
    assert res["shell_flavor"] == "windows_powershell"


def test_cmdi_analyzer_time_blind_differential():
    """Tests latency differential calculation with threshold >= 4.0s."""
    analyzer = CommandInjectionAnalyzer()

    base_resp = HttpResponse(success=True, status_code=200, raw_body="OK", body="OK", url="http://test", elapsed=0.10)

    # Valid timing injection: 5.2s elapsed (delta = 5.1s >= 4.0s)
    injected_valid = HttpResponse(success=True, status_code=200, raw_body="OK", body="OK", url="http://test", elapsed=5.20)
    res = analyzer.analyze_time_blind(injected_valid, base_resp, threshold=4.0)
    assert res is not None
    assert res["technique"] == "time_blind"
    assert res["severity"] == Severity.CRITICAL
    assert res["delay_delta"] >= 5.0

    # Insufficient delta: 2.5s elapsed (delta = 2.4s < 4.0s)
    injected_fast = HttpResponse(success=True, status_code=200, raw_body="OK", body="OK", url="http://test", elapsed=2.50)
    res_fast = analyzer.analyze_time_blind(injected_fast, base_resp, threshold=4.0)
    assert res_fast is None


def test_cmdi_analyzer_false_positive_rejection_baseline():
    """Ensures pre-existing baseline text or errors do not trigger false positives."""
    analyzer = CommandInjectionAnalyzer()

    static_server_info = "Running on Linux web-server 5.15.0 with root:x:0:0: configuration"
    base_resp = HttpResponse(success=True, status_code=200, raw_body=static_server_info, body="", url="http://test")
    injected_resp = HttpResponse(success=True, status_code=200, raw_body=static_server_info, body="", url="http://test")

    res = analyzer.analyze_result_based(injected_resp, baseline=base_resp, payload_info={"cmd": "id", "signature": "unix_id", "os": "posix"})
    assert res is None


def test_cmdi_analyzer_false_positive_reflection_guard():
    """Ensures that pure reflection of command string in HTML search/heading without output is rejected."""
    analyzer = CommandInjectionAnalyzer()

    # Reflected search echo: <h1>Results for 'whoami'</h1>
    reflected_body = "<html><body><h1>Results for 'whoami'</h1><p>No records found.</p></body></html>"
    resp = HttpResponse(success=True, status_code=200, raw_body=reflected_body, body="", url="http://test")

    res = analyzer.analyze_result_based(resp, baseline=None, payload_info={"cmd": "whoami", "signature": "unix_whoami", "os": "posix"})
    assert res is None


# =============================================================================
# 3. Collector Component & Vector Fuzzing Tests
# =============================================================================

def test_cmdi_collector_get_query_param_result_based():
    """Tests fuzzing GET query parameter for result-based OS command injection."""
    mock_http = MockCmdiHttpClient()
    # When '?ip=127.0.0.1; id' or similar is requested, return uid=0(root) output
    mock_http.set_route("; id", 200, "PING 127.0.0.1 (127.0.0.1) 56(84) bytes\nuid=0(root) gid=0(root) groups=0(root)")

    collector = CommandInjectionCollector(http_client=mock_http)
    mission = Mission(target="http://example.com/tools/ping?ip=127.0.0.1")
    mission.endpoints = ["http://example.com/tools/ping?ip=127.0.0.1"]
    mission.evidence = []
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    evidence_list = collector.collect(mission)
    assert len(evidence_list) >= 1
    ev = evidence_list[0]
    assert ev.category == "command_injection"
    assert ev.severity == "critical"
    assert ev.confidence >= 0.90
    assert "uid=0(root)" in ev.metadata.get("evidence_snippet", "")
    assert len(mission.vulnerabilities) >= 1
    assert mission.attack_surface_graph.get(f"vulnerability:cmdi:http://example.com/tools/ping?ip=%3B+id:ip") is not None or len(mission.attack_surface_graph.nodes) >= 3


def test_cmdi_collector_get_query_param_time_blind():
    """Tests fuzzing GET query parameter with time-based blind sleep payload."""
    mock_http = MockCmdiHttpClient()
    # Base response fast (0.05s), sleep 5 payload delayed (5.1s)
    mock_http.set_route("; sleep 5", 200, "PING 127.0.0.1", elapsed=5.10)
    mock_http.set_route("sleep 5", 200, "PING 127.0.0.1", elapsed=5.10)

    collector = CommandInjectionCollector(http_client=mock_http, delay_threshold=4.0)
    mission = Mission(target="http://example.com/api/ping?host=127.0.0.1")
    mission.endpoints = ["http://example.com/api/ping?host=127.0.0.1"]
    mission.evidence = []
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    evidence_list = collector.collect(mission)
    assert len(evidence_list) >= 1
    ev = evidence_list[0]
    assert ev.category == "command_injection"
    assert ev.severity == "critical"
    assert ev.metadata["technique"] == "time_blind"


def test_cmdi_collector_get_query_param_error_based():
    """Tests fuzzing GET query parameter with shell error-trigger payload."""
    mock_http = MockCmdiHttpClient()
    mock_http.set_route("argus_nonexistent_cmd_xyz", 500, "/bin/bash: line 1: argus_nonexistent_cmd_xyz: command not found")

    collector = CommandInjectionCollector(http_client=mock_http)
    mission = Mission(target="http://example.com/api/run?cmd=status")
    mission.endpoints = ["http://example.com/api/run?cmd=status"]
    mission.evidence = []
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    evidence_list = collector.collect(mission)
    assert len(evidence_list) >= 1
    ev = evidence_list[0]
    assert ev.category == "command_injection"
    assert ev.severity == "high"
    assert ev.metadata["technique"] == "error_based"


def test_cmdi_collector_post_json_body_result_based():
    """Tests fuzzing JSON body parameters in POST requests."""
    mock_http = MockCmdiHttpClient()
    mock_http.set_route("cat /etc/passwd", 200, "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin")

    collector = CommandInjectionCollector(http_client=mock_http)
    mission = Mission(target="http://example.com")
    mission.endpoints = [{
        "url": "http://example.com/api/backup",
        "method": "POST",
        "body": {"filename": "backup_2026.tar"},
    }]
    mission.evidence = []
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    evidence_list = collector.collect(mission)
    assert len(evidence_list) >= 1
    ev = evidence_list[0]
    assert ev.category == "command_injection"
    assert ev.metadata["parameter_type"] == "json"
    assert ev.metadata["parameter"] == "filename"


def test_cmdi_collector_post_form_body_result_based():
    """Tests fuzzing form URL-encoded body in POST requests."""
    mock_http = MockCmdiHttpClient()
    mock_http.set_route("id", 200, "uid=1000(app) gid=1000(app) groups=1000(app)")

    collector = CommandInjectionCollector(http_client=mock_http)
    mission = Mission(target="http://example.com")
    mission.endpoints = [{
        "url": "http://example.com/admin/diagnostics",
        "method": "POST",
        "body": "target=8.8.8.8&count=4",
        "params": {"target": "8.8.8.8", "count": "4"},
    }]
    mission.evidence = []
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    evidence_list = collector.collect(mission)
    assert len(evidence_list) >= 1
    ev = evidence_list[0]
    assert ev.category == "command_injection"
    assert ev.metadata["parameter"] == "target"


def test_cmdi_collector_path_segment_injection():
    """Tests fuzzing RESTful path segments (e.g. /tools/ping/127.0.0.1;id)."""
    mock_http = MockCmdiHttpClient()
    mock_http.set_route("; id", 200, "uid=0(root) gid=0(root) groups=0(root)")

    collector = CommandInjectionCollector(http_client=mock_http)
    mission = Mission(target="http://example.com")
    mission.endpoints = ["http://example.com/tools/ping/127.0.0.1"]
    mission.evidence = []
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    evidence_list = collector.collect(mission)
    assert len(evidence_list) >= 1
    ev = evidence_list[0]
    assert ev.category == "command_injection"
    assert ev.metadata["parameter_type"] == "path"


def test_cmdi_collector_http_header_injection():
    """Tests fuzzing HTTP request headers (User-Agent, Referer, Cookie, X-Forwarded-For)."""
    mock_http = MockCmdiHttpClient()
    mock_http.set_route("header:User-Agent:Mozilla/5.0; ; id", 200, "uid=0(root) gid=0(root)")
    mock_http.set_route("header:X-Forwarded-For:127.0.0.1; ; id", 200, "uid=0(root) gid=0(root)")

    collector = CommandInjectionCollector(http_client=mock_http)
    mission = Mission(target="http://example.com")
    mission.endpoints = ["http://example.com/api/analytics"]
    mission.evidence = []
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    evidence_list = collector.collect(mission)
    assert len(evidence_list) >= 1
    ev = evidence_list[0]
    assert ev.category == "command_injection"
    assert ev.metadata["parameter_type"] == "header"


def test_cmdi_collector_mutation_waf_bypass():
    """Tests endpoint blocking raw semicolon ';' with 403, bypassed via newline %0a or $IFS."""
    mock_http = MockCmdiHttpClient()
    # Raw semicolon blocked
    mock_http.set_route("; id", 403, "Forbidden WAF Blocked")
    # Mutated newline or $IFS succeeds
    mock_http.set_route("%0aid", 200, "uid=33(www-data) gid=33(www-data)")
    mock_http.set_route("\nid", 200, "uid=33(www-data) gid=33(www-data)")

    collector = CommandInjectionCollector(http_client=mock_http)
    mission = Mission(target="http://example.com/api/exec?target=localhost")
    mission.endpoints = ["http://example.com/api/exec?target=localhost"]
    mission.evidence = []
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    evidence_list = collector.collect(mission)
    assert len(evidence_list) >= 1
    ev = evidence_list[0]
    assert ev.category == "command_injection"
    assert ev.severity == "critical"


def test_cmdi_collector_empty_mission_handling():
    """Ensures collector gracefully exits with [] on empty mission assets."""
    collector = CommandInjectionCollector()
    mission = Mission(target="")
    mission.endpoints = []
    mission.live_hosts = []
    mission.subdomains = []

    res = collector.collect(mission)
    assert res == []


def test_cmdi_collector_controlled_mission_wrapper():
    """Ensures collector works transparently with ControlledMission wrapper."""
    mock_http = MockCmdiHttpClient()
    mock_http.set_route("; id", 200, "uid=0(root) gid=0(root)")

    base_mission = Mission(target="http://example.com/ping?ip=127.0.0.1")
    base_mission.endpoints = ["http://example.com/ping?ip=127.0.0.1"]
    base_mission.evidence = []
    base_mission.vulnerabilities = []
    base_mission.attack_surface_graph = KnowledgeGraph()

    controlled = ControlledMission(base_mission)
    collector = CommandInjectionCollector(http_client=mock_http)
    results = collector.execute(controlled)
    assert len(results) >= 1
    assert len(base_mission.evidence) >= 1
    assert len(base_mission.vulnerabilities) >= 1
