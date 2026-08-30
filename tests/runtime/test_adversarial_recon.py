"""
Adversarial Stress Test Suite for ARGUS Sprint 1 Recon Intelligence.
Verifies robustness, edge cases, malformed inputs, boundaries, and evidence integrity for:
- ReconParser.parse_subfinder
- ReconParser.parse_httpx
- ReconParser.parse_katana
- ReconParser.parse_nuclei
- ExternalToolExecutor.execute
"""
import json
import time
from unittest.mock import patch, MagicMock
import pytest

from argus.runtime.parser import ReconParser
from argus.runtime.executor import ExternalToolExecutor
from argus.runtime.models import Tool, ToolExecutionStatus
from argus.runtime.mission import Mission
from argus.evidence.store import EvidenceStore
from argus.planning.models import ResearchTask, TaskCategory


# ============================================================================
# 1. ADVERSARIAL TESTS: SUBFINDER PARSER
# ============================================================================

class TestAdversarialSubfinder:
    """Stress tests and boundary condition tests for ReconParser.parse_subfinder."""

    def test_empty_and_whitespace_inputs(self):
        """Test with None, empty strings, and diverse whitespace characters."""
        assert ReconParser.parse_subfinder("") == []
        assert ReconParser.parse_subfinder(None) == []
        assert ReconParser.parse_subfinder("   \t  \r\n  \v\f \n ") == []

    def test_corrupt_and_truncated_json(self):
        """Test with truncated JSON and invalid JSON lines."""
        corrupt_inputs = (
            '{"host": "api.example.com", "source": \n'
            '{"host": "valid.example.com", "source": "subfinder"}\n'
            '{"hostname": \n'
            '{truncated-json\n'
            '{"subdomain": "dev.example.com"}'
        )
        results = ReconParser.parse_subfinder(corrupt_inputs)
        hostnames = [r["hostname"] for r in results]
        assert "valid.example.com" in hostnames
        assert "dev.example.com" in hostnames
        for r in results:
            assert isinstance(r, dict)
            assert "hostname" in r
            assert isinstance(r["hostname"], str)

    def test_mixed_banners_logs_and_plain_domains(self):
        """Test with tool banners, ANSI escape sequences, logging prefixes."""
        mixed_input = (
            "               __    _____           __         \n"
            "   _______  __/ /_  / __(_)___  ____/ /__  _____\n"
            " [INF] Current subfinder version 2.6.3\n"
            " [INF] Loading passive sources...\n"
            " \x1b[32m[INF]\x1b[0m Found subdomain: target.example.com\n"
            " api.example.com\n"
            " admin.example.com\n"
            " [WARN] Rate limited by Shodan\n"
            " https://portal.example.com:8443/login\n"
        )
        results = ReconParser.parse_subfinder(mixed_input)
        assert len(results) > 0
        hostnames = [r["hostname"] for r in results]
        assert "api.example.com" in hostnames
        assert "admin.example.com" in hostnames
        assert "portal.example.com" in hostnames
        for r in results:
            assert isinstance(r["hostname"], str)
            assert len(r["hostname"]) > 0

    def test_unicode_emojis_punycode(self):
        """Test with internationalized domains, emojis, and special chars."""
        unicode_input = (
            '{"host": "🔥.example.com"}\n'
            '{"host": "xn--e1aybc.xn--p1ai"}\n'
            'тест.рф\n'
            'https://sub.domain.co.uk:443\n'
        )
        results = ReconParser.parse_subfinder(unicode_input)
        assert len(results) == 4
        hostnames = [r["hostname"] for r in results]
        assert "🔥.example.com" in hostnames
        assert "xn--e1aybc.xn--p1ai" in hostnames
        assert "тест.рф" in hostnames
        assert "sub.domain.co.uk" in hostnames

    def test_boundary_scale_10k_lines(self):
        """Test scaling up to 10,000 output lines with duplicates."""
        lines = [f"sub{i % 500}.example.com" for i in range(10000)]
        large_input = "\n".join(lines)
        start = time.perf_counter()
        results = ReconParser.parse_subfinder(large_input)
        duration = time.perf_counter() - start
        
        assert len(results) == 500  # Correctly deduplicated
        assert duration < 1.0  # Must complete in under 1 second
        assert all(r["source"] == "subfinder" for r in results)

    def test_deeply_nested_and_missing_keys(self):
        """Test lines with missing keys or empty dicts."""
        input_data = (
            '{}\n'
            '{"other_key": "ignore"}\n'
            '{"host": ""}\n'
            '{"hostname": "   "}\n'
            '{"host": "sub1.example.com"}\n'
        )
        results = ReconParser.parse_subfinder(input_data)
        assert len(results) >= 1
        assert any(r["hostname"] == "sub1.example.com" for r in results)


# ============================================================================
# 2. ADVERSARIAL TESTS: HTTPX PARSER
# ============================================================================

class TestAdversarialHttpx:
    """Stress tests and boundary condition tests for ReconParser.parse_httpx."""

    def test_empty_and_whitespace_inputs(self):
        """Test with None, empty strings, and whitespace."""
        assert ReconParser.parse_httpx("") == []
        assert ReconParser.parse_httpx(None) == []
        assert ReconParser.parse_httpx("   \n\n\t  \r\n ") == []

    def test_truncated_json_and_mixed_logs(self):
        """Test with truncated JSON lines, tool banners, and mixed output."""
        mixed_input = (
            "    __  ____  __  _____\n"
            "   / /_/ / /_/ /_/ ___/\n"
            " [INF] Current httpx version v1.3.8\n"
            '{"url":"https://api.example.com","status_code":200,"title":"API"}\n'
            '{"url":"https://admin.example.com", "status_code": 40\n'
            'not a json line\n'
            'https://fallback.example.com:8443/auth\n'
            '{"url":"http://portal.example.com","status":302,"server":"nginx"}\n'
        )
        results = ReconParser.parse_httpx(mixed_input)
        assert len(results) == 3
        urls = [r["url"] for r in results]
        assert "https://api.example.com" in urls
        assert "https://fallback.example.com:8443/auth" in urls
        assert "http://portal.example.com" in urls

        # Verify fallback parsed correctly
        fallback = next(r for r in results if "fallback" in r["url"])
        assert fallback["scheme"] == "https"
        assert fallback["host"] == "fallback.example.com"
        assert fallback["port"] == 8443
        assert fallback["technologies"] == []

    def test_extreme_boundary_status_codes(self):
        """Test boundary status codes (negative, string, 0, large int)."""
        input_data = (
            '{"url":"http://neg.com","status_code":-1}\n'
            '{"url":"http://str.com","status_code":"200 OK"}\n'
            '{"url":"http://zero.com","status":0}\n'
            '{"url":"http://large.com","status-code":999999}\n'
            '{"url":"http://none.com","status":null}\n'
        )
        results = ReconParser.parse_httpx(input_data)
        assert len(results) == 5
        assert results[0]["status"] == -1
        assert results[1]["status"] == "200 OK"
        assert results[2]["status"] == 0
        assert results[3]["status"] == 999999
        assert results[4]["status"] is None

    def test_extreme_boundary_ports_and_schemes(self):
        """Test missing ports, string ports, custom schemes."""
        input_data = (
            '{"url":"https://secure.com"}\n'
            '{"url":"http://insecure.com"}\n'
            '{"url":"http://custom.com:8080","port":8080}\n'
            '{"url":"http://strport.com","port":"9000"}\n'
            '{"url":"ftp://files.com","scheme":"ftp"}\n'
        )
        results = ReconParser.parse_httpx(input_data)
        assert len(results) == 5
        assert results[0]["port"] == 443
        assert results[1]["port"] == 80
        assert results[2]["port"] == 8080
        assert results[3]["port"] == "9000"
        assert results[4]["scheme"] == "ftp"

    def test_technologies_normalization_adversarial(self):
        """Test tech field with list containing dirty values, comma strings, nulls."""
        input_data = (
            '{"url":"http://t1.com","tech":["Nginx", "", "  ", "React", "123"]}\n'
            '{"url":"http://t2.com","technologies":"Apache, , PHP , MySQL, "}\n'
            '{"url":"http://t3.com","technologies":null}\n'
            '{"url":"http://t4.com","tech":12345}\n'
            '{"url":"http://t5.com"}\n'
        )
        results = ReconParser.parse_httpx(input_data)
        assert len(results) == 5
        assert results[0]["technologies"] == ["Nginx", "React", "123"]
        assert results[1]["technologies"] == ["Apache", "PHP", "MySQL"]
        assert results[2]["technologies"] == []
        assert results[3]["technologies"] == []
        assert results[4]["technologies"] == []

    def test_all_null_fields(self):
        """Test JSON record where all fields are null."""
        input_data = '{"url":null,"scheme":null,"host":null,"port":null,"status_code":null,"title":null,"server":null,"technologies":null}'
        results = ReconParser.parse_httpx(input_data)
        assert len(results) == 1
        r = results[0]
        assert r["url"] is None
        assert r["technologies"] == []

    def test_boundary_scale_10k_lines(self):
        """Test processing 10,000 JSON lines under high throughput."""
        lines = [
            f'{{"url":"https://host{i}.example.com","status_code":200,"tech":["Nginx"]}}'
            for i in range(10000)
        ]
        start = time.perf_counter()
        results = ReconParser.parse_httpx("\n".join(lines))
        duration = time.perf_counter() - start
        
        assert len(results) == 10000
        assert duration < 1.0
        assert results[9999]["host"] == "host9999.example.com"


# ============================================================================
# 3. ADVERSARIAL TESTS: KATANA PARSER
# ============================================================================

class TestAdversarialKatana:
    """Stress tests and boundary condition tests for ReconParser.parse_katana."""

    def test_empty_and_whitespace_inputs(self):
        """Test with None, empty strings, and whitespace."""
        assert ReconParser.parse_katana("") == []
        assert ReconParser.parse_katana(None) == []
        assert ReconParser.parse_katana("   \t  \r\n ") == []

    def test_truncated_json_and_mixed_logs(self):
        """Test with mixed crawl logs, truncated JSON, and plain URLs."""
        mixed_input = (
            "   __        __                 \n"
            "  / /_____ _/ /_____ _____  ____\n"
            " [INF] Current katana version v1.0.5\n"
            '{"request":{"endpoint":"https://api.com/v1/users","method":"GET"}}\n'
            '{"request":{"endpoint":"https://api.com/v2/items", "meth\n'
            'http://example.com/login\n'
            'https://example.com/dashboard?tab=overview&ref=home\n'
        )
        results = ReconParser.parse_katana(mixed_input)
        urls = [r["url"] for r in results]
        assert "https://api.com/v1/users" in urls
        assert "http://example.com/login" in urls
        assert "https://example.com/dashboard?tab=overview&ref=home" in urls

        dashboard = next(r for r in results if "dashboard" in r["url"])
        assert dashboard["path"] == "/dashboard"
        assert dashboard["params"] == {"tab": ["overview"], "ref": ["home"]}

    def test_complex_query_params_and_methods(self):
        """Test complex query parameters, HTTP methods, and empty paths."""
        input_data = (
            '{"url":"https://api.com/items","method":"POST","params":{"id":"123","filter":"active"}}\n'
            '{"endpoint":"https://api.com:8443","method":"PUT"}\n'
            'https://search.com/q?term=hello+world&tags=a&tags=b\n'
        )
        results = ReconParser.parse_katana(input_data)
        assert len(results) == 3
        assert results[0]["method"] == "POST"
        assert results[0]["params"] == {"id": "123", "filter": "active"}
        assert results[1]["url"] == "https://api.com:8443"
        assert results[1]["path"] == "/"
        assert results[1]["method"] == "PUT"

        search = results[2]
        assert search["path"] == "/q"
        assert search["params"]["tags"] == ["a", "b"]
        assert search["params"]["term"] == ["hello world"]

    def test_deduplication_and_10k_scale(self):
        """Test deduplication and throughput with 10,000 endpoint strings."""
        lines = [f"https://api.example.com/endpoint/{i % 250}?id={i % 50}" for i in range(10000)]
        start = time.perf_counter()
        results = ReconParser.parse_katana("\n".join(lines))
        duration = time.perf_counter() - start

        # Distinct URLs
        distinct_count = len(set(lines))
        assert len(results) == distinct_count
        assert duration < 1.0


# ============================================================================
# 4. ADVERSARIAL TESTS: NUCLEI PARSER
# ============================================================================

class TestAdversarialNuclei:
    """Stress tests and boundary condition tests for ReconParser.parse_nuclei."""

    def test_empty_and_whitespace_inputs(self):
        """Test with None, empty strings, and whitespace."""
        assert ReconParser.parse_nuclei("") == []
        assert ReconParser.parse_nuclei(None) == []
        assert ReconParser.parse_nuclei("   \r\n \t \n") == []

    def test_truncated_json_and_mixed_logs(self):
        """Test with mixed scan banners, ANSI codes, and truncated JSON."""
        mixed_input = (
            "                      __     _ \n"
            "   ____  __  _______ / /__  (_)\n"
            " [INF] Current nuclei version: v3.2.0\n"
            " \x1b[31m[CRITICAL]\x1b[0m [cve-2024-9999] [http] Matched at http://target.com\n"
            '{"template-id":"cve-2024-9999","info":{"name":"Critical RCE","severity":"critical"},"host":"http://target.com"}\n'
            '{"template-id":"truncated-finding", "info": {"sever\n'
            'not a json line\n'
            '{"id":"info-leak","info":{"name":"Info Leak","severity":"low"},"host":"http://target.com/api"}\n'
        )
        results = ReconParser.parse_nuclei(mixed_input)
        assert len(results) == 2
        assert results[0]["template_id"] == "cve-2024-9999"
        assert results[0]["severity"] == "critical"
        assert results[1]["template_id"] == "info-leak"
        assert results[1]["severity"] == "low"

    def test_missing_info_and_null_fields(self):
        """Test when info block is null, string, or missing fields."""
        input_data = (
            '{"template_id":"t1","info":null,"host":"http://a.com"}\n'
            '{"id":"t2","info":"not-dict","host":"http://b.com"}\n'
            '{"template-id":"t3","name":"Direct Name","severity":"high","host":"http://c.com"}\n'
            '{"template-id":"t4","info":{"name":null,"severity":null,"tags":null,"description":null}}\n'
        )
        results = ReconParser.parse_nuclei(input_data)
        assert len(results) == 4
        assert results[0]["name"] == "t1"
        assert results[0]["severity"] == "info"
        assert results[1]["name"] == "t2"
        assert results[2]["name"] == "Direct Name"
        assert results[2]["severity"] == "high"
        assert results[3]["severity"] == "info"
        assert results[3]["tags"] == []
        assert results[3]["description"] == ""

    def test_tags_and_extracted_results_variations(self):
        """Test tags as comma string, list with nulls/ints, and extracted results as string/list."""
        input_data = (
            '{"template-id":"t1","info":{"tags":"cve,rce,auth-bypass"},"extracted-results":"token=secret123"}\n'
            '{"template-id":"t2","info":{"tags":["cve", "", "  ", "ssrf", "123"]},"extracted_results":["res1","res2"]}\n'
            '{"template-id":"t3","info":{"tags":12345},"extractedResults":null}\n'
        )
        results = ReconParser.parse_nuclei(input_data)
        assert len(results) == 3
        assert results[0]["tags"] == ["cve", "rce", "auth-bypass"]
        assert results[0]["extracted_results"] == ["token=secret123"]

        assert results[1]["tags"] == ["cve", "ssrf", "123"]
        assert results[1]["extracted_results"] == ["res1", "res2"]

        assert results[2]["tags"] == []
        assert results[2]["extracted_results"] == []

    def test_boundary_scale_10k_lines(self):
        """Test processing 10,000 vulnerability JSON lines under load."""
        lines = [
            f'{{"template-id":"cve-{i}","info":{{"name":"Vuln {i}","severity":"medium","tags":["cve"]}},"host":"http://target{i}.com"}}'
            for i in range(10000)
        ]
        start = time.perf_counter()
        results = ReconParser.parse_nuclei("\n".join(lines))
        duration = time.perf_counter() - start

        assert len(results) == 10000
        assert duration < 1.0
        assert results[9999]["template_id"] == "cve-9999"


# ============================================================================
# 5. ADVERSARIAL TESTS: EXTERNAL TOOL EXECUTOR
# ============================================================================

class TestAdversarialExternalToolExecutor:
    """Stress tests and boundary condition tests for ExternalToolExecutor.execute()."""

    def test_executor_subfinder_evidence_and_state(self):
        """Verify subfinder execution updates mission.subdomains as str and creates Evidence."""
        executor = ExternalToolExecutor()
        tool = Tool(
            id="subfinder", name="Subfinder", capability="subdomain_discovery",
            supported_tasks=[TaskCategory.TECHNOLOGY_DISCOVERY], command="subfinder", timeout=10.0
        )
        mission = Mission(target="example.com")
        mission.evidence = EvidenceStore()
        
        task = ResearchTask(title="Subfinder Task", description="Desc", goal="Goal", category=TaskCategory.TECHNOLOGY_DISCOVERY)
        context = MagicMock()
        context.mission = mission
        context.task = task

        subfinder_output = "api.example.com\nadmin.example.com\n"
        with patch("argus.runtime.sandbox.Sandbox.execute_command", return_value={"stdout": subfinder_output, "stderr": ""}):
            result = executor.execute(tool, context)

        assert result.status == ToolExecutionStatus.SUCCEEDED
        assert mission.subdomains == ["api.example.com", "admin.example.com"]
        assert all(isinstance(s, str) for s in mission.subdomains)

        ev_list = mission.evidence.filter("subdomain")
        assert len(ev_list) == 2
        assert ev_list[0].value == "api.example.com"
        assert ev_list[0].metadata == {"source": "subfinder", "hostname": "api.example.com"}

    def test_executor_httpx_evidence_and_state(self):
        """Verify httpx execution updates mission.live_hosts as dicts, mission.technologies, and Evidence."""
        executor = ExternalToolExecutor()
        tool = Tool(
            id="httpx", name="HTTPX", capability="http_probing",
            supported_tasks=[TaskCategory.TECHNOLOGY_DISCOVERY], command="httpx", timeout=10.0
        )
        mission = Mission(target="example.com")
        mission.evidence = EvidenceStore()
        
        task = ResearchTask(title="HTTPX Task", description="Desc", goal="Goal", category=TaskCategory.TECHNOLOGY_DISCOVERY)
        context = MagicMock()
        context.mission = mission
        context.task = task

        httpx_output = (
            '{"url":"https://api.example.com","host":"api.example.com","status_code":200,"technologies":["Nginx","FastAPI"]}\n'
            '{"url":"http://admin.example.com","host":"admin.example.com","status_code":403,"technologies":["Apache"]}'
        )
        with patch("argus.runtime.sandbox.Sandbox.execute_command", return_value={"stdout": httpx_output, "stderr": ""}):
            result = executor.execute(tool, context)

        assert result.status == ToolExecutionStatus.SUCCEEDED
        assert len(mission.live_hosts) == 2
        assert isinstance(mission.live_hosts[0], dict)
        assert mission.live_hosts[0]["url"] == "https://api.example.com"
        assert mission.technologies == ["Nginx", "FastAPI", "Apache"]

        live_evs = mission.evidence.filter("live_host")
        assert len(live_evs) == 2
        assert live_evs[0].metadata["url"] == "https://api.example.com"
        assert live_evs[0].metadata["status"] == 200

        tech_evs = mission.evidence.filter("technology")
        assert len(tech_evs) == 3
        tech_names = [ev.metadata["name"] for ev in tech_evs]
        assert tech_names == ["Nginx", "FastAPI", "Apache"]

    def test_executor_katana_evidence_and_state(self):
        """Verify katana execution updates mission.endpoints as dicts and creates Evidence."""
        executor = ExternalToolExecutor()
        tool = Tool(
            id="katana_crawler", name="Katana", capability="web_crawling",
            supported_tasks=[TaskCategory.API_DISCOVERY], command="katana", timeout=10.0
        )
        mission = Mission(target="example.com")
        mission.evidence = EvidenceStore()
        
        task = ResearchTask(title="Katana Task", description="Desc", goal="Goal", category=TaskCategory.API_DISCOVERY)
        context = MagicMock()
        context.mission = mission
        context.task = task

        katana_output = "http://example.com/v1/users\nhttp://example.com/v1/auth\n"
        with patch("argus.runtime.sandbox.Sandbox.execute_command", return_value={"stdout": katana_output, "stderr": ""}):
            result = executor.execute(tool, context)

        assert result.status == ToolExecutionStatus.SUCCEEDED
        assert len(mission.endpoints) == 2
        assert isinstance(mission.endpoints[0], dict)
        assert mission.endpoints[0]["url"] == "http://example.com/v1/users"
        assert mission.endpoints[0]["path"] == "/v1/users"

        endpoint_evs = mission.evidence.filter("endpoint")
        assert len(endpoint_evs) == 2
        assert endpoint_evs[0].metadata["url"] == "http://example.com/v1/users"

    def test_executor_nuclei_evidence_and_state(self):
        """Verify nuclei execution updates mission.vulnerabilities as dicts and creates Evidence."""
        executor = ExternalToolExecutor()
        tool = Tool(
            id="nuclei", name="Nuclei", capability="vulnerability_scanning",
            supported_tasks=[TaskCategory.EVIDENCE_CORRELATION], command="nuclei", timeout=10.0
        )
        mission = Mission(target="example.com")
        mission.evidence = EvidenceStore()
        
        task = ResearchTask(title="Nuclei Task", description="Desc", goal="Goal", category=TaskCategory.EVIDENCE_CORRELATION)
        context = MagicMock()
        context.mission = mission
        context.task = task

        nuclei_output = (
            '{"template-id":"cve-2024-1111","info":{"name":"SQL Injection","severity":"critical"},"host":"http://example.com"}\n'
            '{"template-id":"info-disclosure","info":{"name":"Debug Mode","severity":"low"},"host":"http://example.com/debug"}'
        )
        with patch("argus.runtime.sandbox.Sandbox.execute_command", return_value={"stdout": nuclei_output, "stderr": ""}):
            result = executor.execute(tool, context)

        assert result.status == ToolExecutionStatus.SUCCEEDED
        assert len(mission.vulnerabilities) == 2
        assert isinstance(mission.vulnerabilities[0], dict)
        assert mission.vulnerabilities[0]["template_id"] == "cve-2024-1111"

        vuln_evs = mission.evidence.filter("vulnerability")
        assert len(vuln_evs) == 2
        assert vuln_evs[0].severity == "critical"
        assert vuln_evs[0].metadata["template_id"] == "cve-2024-1111"
        assert vuln_evs[1].severity == "low"
        assert vuln_evs[1].metadata["template_id"] == "info-disclosure"

    def test_executor_uninitialized_attributes_and_missing_evidence_store(self):
        """Test resilience when mission attributes are None or missing."""
        executor = ExternalToolExecutor()
        tool = Tool(
            id="katana_crawler", name="Katana", capability="web_crawling",
            supported_tasks=[TaskCategory.API_DISCOVERY], command="katana", timeout=10.0
        )
        mission = Mission(target="example.com")
        mission.endpoints = None
        mission.evidence = None  # Missing evidence store
        
        task = ResearchTask(title="Katana Task", description="Desc", goal="Goal", category=TaskCategory.API_DISCOVERY)
        context = MagicMock()
        context.mission = mission
        context.task = task

        with patch("argus.runtime.sandbox.Sandbox.execute_command", return_value={"stdout": "http://test.com/api", "stderr": ""}):
            result = executor.execute(tool, context)

        assert result.status == ToolExecutionStatus.SUCCEEDED
        assert len(mission.endpoints) == 1
        assert len(result.evidence) == 1

    def test_executor_timeout_handling(self):
        """Verify TimeoutError in sandbox produces TIMED_OUT status."""
        executor = ExternalToolExecutor()
        tool = Tool(
            id="subfinder", name="Subfinder", capability="subdomain_discovery",
            supported_tasks=[TaskCategory.TECHNOLOGY_DISCOVERY], command="subfinder", timeout=5.0
        )
        mission = Mission(target="example.com")
        task = ResearchTask(title="Subfinder Task", description="Desc", goal="Goal", category=TaskCategory.TECHNOLOGY_DISCOVERY)
        context = MagicMock()
        context.mission = mission
        context.task = task

        with patch("argus.runtime.sandbox.Sandbox.execute_command", side_effect=TimeoutError("Command timed out after 5.0s")):
            result = executor.execute(tool, context)

        assert result.status == ToolExecutionStatus.TIMED_OUT
        assert "timed out" in result.error.lower()

    def test_executor_sandbox_crash_handling(self):
        """Verify generic exception in sandbox produces FAILED status."""
        executor = ExternalToolExecutor()
        tool = Tool(
            id="nuclei", name="Nuclei", capability="vulnerability_scanning",
            supported_tasks=[TaskCategory.EVIDENCE_CORRELATION], command="nuclei", timeout=5.0
        )
        mission = Mission(target="example.com")
        task = ResearchTask(title="Nuclei Task", description="Desc", goal="Goal", category=TaskCategory.EVIDENCE_CORRELATION)
        context = MagicMock()
        context.mission = mission
        context.task = task

        with patch("argus.runtime.sandbox.Sandbox.execute_command", side_effect=RuntimeError("Sandbox execution failed")):
            result = executor.execute(tool, context)

        assert result.status == ToolExecutionStatus.FAILED
        assert "Sandbox execution failed" in result.error
