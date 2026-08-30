"""
Unit tests for ReconParser (Subfinder, HTTPX, Katana, Nuclei)
and authoritative verification script from ORIGINAL_REQUEST.md.
"""
import pytest
from argus.runtime.parser import ReconParser
from argus.evidence.model import Evidence


class TestReconParserSubfinder:
    """Comprehensive tests for ReconParser.parse_subfinder."""

    def test_parse_subfinder_plain_text(self):
        output = "api.example.com\nadmin.example.com\nportal.example.com"
        results = ReconParser.parse_subfinder(output)
        assert len(results) == 3
        assert results[0] == {"hostname": "api.example.com", "source": "subfinder"}
        assert results[1] == {"hostname": "admin.example.com", "source": "subfinder"}
        assert results[2] == {"hostname": "portal.example.com", "source": "subfinder"}

    def test_parse_subfinder_json_lines(self):
        output = (
            '{"host": "api.example.com", "source": "subfinder"}\n'
            '{"hostname": "admin.example.com", "source": "shodan"}\n'
            '{"subdomain": "dev.example.com"}\n'
        )
        results = ReconParser.parse_subfinder(output)
        assert len(results) == 3
        assert results[0] == {"hostname": "api.example.com", "source": "subfinder"}
        assert results[1] == {"hostname": "admin.example.com", "source": "shodan"}
        assert results[2] == {"hostname": "dev.example.com", "source": "subfinder"}

    def test_parse_subfinder_url_strings(self):
        output = "https://vpn.example.com/login\nhttp://mail.example.com:8080"
        results = ReconParser.parse_subfinder(output)
        assert len(results) == 2
        assert results[0]["hostname"] == "vpn.example.com"
        assert results[1]["hostname"] == "mail.example.com"

    def test_parse_subfinder_whitespace_and_empty(self):
        assert ReconParser.parse_subfinder("") == []
        assert ReconParser.parse_subfinder(None) == []
        assert ReconParser.parse_subfinder("   \n\n\t  \n  ") == []

    def test_parse_subfinder_deduplication(self):
        output = "api.example.com\napi.example.com\nadmin.example.com\napi.example.com"
        results = ReconParser.parse_subfinder(output)
        assert len(results) == 2
        hostnames = [r["hostname"] for r in results]
        assert hostnames == ["api.example.com", "admin.example.com"]

    def test_parse_subfinder_malformed_json_fallback(self):
        output = "{not-valid-json-but-starts-with-brace.example.com"
        results = ReconParser.parse_subfinder(output)
        assert len(results) == 1
        assert results[0]["hostname"] == "{not-valid-json-but-starts-with-brace.example.com"


class TestReconParserHttpx:
    """Comprehensive tests for ReconParser.parse_httpx."""

    def test_parse_httpx_standard_jsonl(self):
        output = (
            '{"url":"https://api.example.com","scheme":"https","host":"api.example.com",'
            '"port":443,"status_code":200,"title":"API Portal","webserver":"nginx",'
            '"tech":["Nginx","React"]}\n'
            '{"url":"http://admin.example.com","scheme":"http","host":"admin.example.com",'
            '"port":80,"status":403,"title":"Forbidden","server":"Apache",'
            '"technologies":["Apache","PHP"]}'
        )
        results = ReconParser.parse_httpx(output)
        assert len(results) == 2

        # Verify all 8 keys present on first item
        r0 = results[0]
        expected_keys = {"url", "scheme", "host", "port", "status", "title", "server", "technologies"}
        assert set(r0.keys()) == expected_keys
        assert r0["url"] == "https://api.example.com"
        assert r0["scheme"] == "https"
        assert r0["host"] == "api.example.com"
        assert r0["port"] == 443
        assert r0["status"] == 200
        assert r0["title"] == "API Portal"
        assert r0["server"] == "nginx"
        assert r0["technologies"] == ["Nginx", "React"]

        # Verify second item
        r1 = results[1]
        assert r1["url"] == "http://admin.example.com"
        assert r1["scheme"] == "http"
        assert r1["host"] == "admin.example.com"
        assert r1["port"] == 80
        assert r1["status"] == 403
        assert r1["title"] == "Forbidden"
        assert r1["server"] == "Apache"
        assert r1["technologies"] == ["Apache", "PHP"]

    def test_parse_httpx_derived_scheme_host_port(self):
        output = (
            '{"url":"https://secure.example.com"}\n'
            '{"url":"http://insecure.example.com"}\n'
            '{"url":"http://custom.example.com:8080"}\n'
            '{"url":"https://custom.example.com:8443/api"}'
        )
        results = ReconParser.parse_httpx(output)
        assert len(results) == 4

        assert results[0]["scheme"] == "https"
        assert results[0]["host"] == "secure.example.com"
        assert results[0]["port"] == 443

        assert results[1]["scheme"] == "http"
        assert results[1]["host"] == "insecure.example.com"
        assert results[1]["port"] == 80

        assert results[2]["scheme"] == "http"
        assert results[2]["host"] == "custom.example.com"
        assert results[2]["port"] == 8080

        assert results[3]["scheme"] == "https"
        assert results[3]["host"] == "custom.example.com"
        assert results[3]["port"] == 8443

    def test_parse_httpx_aliases(self):
        # Test status-code and webserver
        output1 = '{"url":"http://example.com","status-code":301,"webserver":"cloudflare"}'
        results1 = ReconParser.parse_httpx(output1)
        assert results1[0]["status"] == 301
        assert results1[0]["server"] == "cloudflare"

        # Test status and server
        output2 = '{"url":"http://example.com","status":500,"server":"gunicorn"}'
        results2 = ReconParser.parse_httpx(output2)
        assert results2[0]["status"] == 500
        assert results2[0]["server"] == "gunicorn"

    def test_parse_httpx_technologies_normalization(self):
        # Comma-separated string in "tech"
        output1 = '{"url":"http://example.com","tech":"Nginx, React, Node.js"}'
        results1 = ReconParser.parse_httpx(output1)
        assert results1[0]["technologies"] == ["Nginx", "React", "Node.js"]

        # List with whitespace and empty entries
        output2 = '{"url":"http://example.com","technologies":["Nginx", "  ", "", "React"]}'
        results2 = ReconParser.parse_httpx(output2)
        assert results2[0]["technologies"] == ["Nginx", "React"]

        # None or missing tech
        output3 = '{"url":"http://example.com"}'
        results3 = ReconParser.parse_httpx(output3)
        assert results3[0]["technologies"] == []

    def test_parse_httpx_plain_urls_fallback(self):
        output = "http://plain.example.com:8000/test\nhttps://api.example.com"
        results = ReconParser.parse_httpx(output)
        assert len(results) == 2
        assert results[0]["url"] == "http://plain.example.com:8000/test"
        assert results[0]["scheme"] == "http"
        assert results[0]["host"] == "plain.example.com"
        assert results[0]["port"] == 8000
        assert results[0]["technologies"] == []

        assert results[1]["url"] == "https://api.example.com"
        assert results[1]["scheme"] == "https"
        assert results[1]["host"] == "api.example.com"
        assert results[1]["port"] == 443

    def test_parse_httpx_empty_and_malformed(self):
        assert ReconParser.parse_httpx("") == []
        assert ReconParser.parse_httpx(None) == []
        assert ReconParser.parse_httpx("   \n\n  ") == []

        # Malformed lines should be skipped without crashing
        output = "not a valid line\n[1, 2, 3]\n{\"valid\": true, \"url\": \"http://ok.com\"}"
        results = ReconParser.parse_httpx(output)
        assert len(results) == 1
        assert results[0]["url"] == "http://ok.com"


class TestReconParserKatana:
    """Comprehensive tests for ReconParser.parse_katana."""

    def test_parse_katana_plain_text(self):
        output = "http://api.example.com/v1/users\nhttp://api.example.com/v1/login"
        results = ReconParser.parse_katana(output)
        assert len(results) == 2
        assert results[0] == {
            "url": "http://api.example.com/v1/users",
            "path": "/v1/users",
            "host": "api.example.com",
            "method": "GET",
            "params": {},
        }
        assert results[1] == {
            "url": "http://api.example.com/v1/login",
            "path": "/v1/login",
            "host": "api.example.com",
            "method": "GET",
            "params": {},
        }

    def test_parse_katana_jsonl(self):
        output = (
            '{"request":{"endpoint":"https://api.example.com/v2/orders","method":"POST"},"params":{"id":"123"}}\n'
            '{"url":"https://api.example.com/v2/items","path":"/v2/items","host":"api.example.com","method":"GET"}'
        )
        results = ReconParser.parse_katana(output)
        assert len(results) == 2
        assert results[0]["url"] == "https://api.example.com/v2/orders"
        assert results[0]["path"] == "/v2/orders"
        assert results[0]["host"] == "api.example.com"
        assert results[0]["method"] == "POST"
        assert results[0]["params"] == {"id": "123"}

        assert results[1]["url"] == "https://api.example.com/v2/items"
        assert results[1]["path"] == "/v2/items"
        assert results[1]["host"] == "api.example.com"
        assert results[1]["method"] == "GET"

    def test_parse_katana_query_params(self):
        output = "http://api.example.com/search?query=test&page=1"
        results = ReconParser.parse_katana(output)
        assert len(results) == 1
        assert results[0]["params"] == {"query": ["test"], "page": ["1"]}
        assert results[0]["path"] == "/search"

    def test_parse_katana_url_without_path(self):
        output = "http://api.example.com"
        results = ReconParser.parse_katana(output)
        assert len(results) == 1
        assert results[0]["path"] == "/"
        assert results[0]["host"] == "api.example.com"

    def test_parse_katana_deduplication(self):
        output = "http://api.example.com/v1\nhttp://api.example.com/v1\nhttp://api.example.com/v2"
        results = ReconParser.parse_katana(output)
        assert len(results) == 2
        assert [r["url"] for r in results] == ["http://api.example.com/v1", "http://api.example.com/v2"]

    def test_parse_katana_empty_and_whitespace(self):
        assert ReconParser.parse_katana("") == []
        assert ReconParser.parse_katana(None) == []
        assert ReconParser.parse_katana("   \n\n  \t") == []


class TestReconParserNuclei:
    """Comprehensive tests for ReconParser.parse_nuclei."""

    def test_parse_nuclei_standard_jsonl(self):
        output = (
            '{"template-id":"CVE-2023-XXXX","info":{"name":"Example CVE","severity":"high",'
            '"description":"A test CVE","tags":["cve","rce"]},"host":"http://api.example.com",'
            '"matched-at":"http://api.example.com/login","extracted-results":["admin:admin"]}'
        )
        results = ReconParser.parse_nuclei(output)
        assert len(results) == 1
        r = results[0]
        expected_keys = {"template_id", "name", "severity", "host", "matched_at", "description", "tags", "extracted_results"}
        assert set(r.keys()) == expected_keys
        assert r["template_id"] == "CVE-2023-XXXX"
        assert r["name"] == "Example CVE"
        assert r["severity"] == "high"
        assert r["host"] == "http://api.example.com"
        assert r["matched_at"] == "http://api.example.com/login"
        assert r["description"] == "A test CVE"
        assert r["tags"] == ["cve", "rce"]
        assert r["extracted_results"] == ["admin:admin"]

    def test_parse_nuclei_key_variations(self):
        output = (
            '{"template_id":"cve-2024-0001","name":"Direct Name","severity":"critical",'
            '"host":"http://api.example.com","matched_at":"http://api.example.com/api",'
            '"description":"Desc","tags":"auth,bypass","extracted_results":"token123"}'
        )
        results = ReconParser.parse_nuclei(output)
        assert len(results) == 1
        r = results[0]
        assert r["template_id"] == "cve-2024-0001"
        assert r["name"] == "Direct Name"
        assert r["severity"] == "critical"
        assert r["tags"] == ["auth", "bypass"]
        assert r["extracted_results"] == ["token123"]

    def test_parse_nuclei_defensive_null_info(self):
        # info is None or missing or non-dict
        output1 = '{"template-id":"cve-null-info","info":null,"host":"http://api.example.com"}'
        results1 = ReconParser.parse_nuclei(output1)
        assert len(results1) == 1
        assert results1[0]["template_id"] == "cve-null-info"
        assert results1[0]["name"] == "cve-null-info"
        assert results1[0]["severity"] == "info"
        assert results1[0]["tags"] == []
        assert results1[0]["extracted_results"] == []

        output2 = '{"id":"cve-string-info","info":"invalid","host":"http://api.example.com"}'
        results2 = ReconParser.parse_nuclei(output2)
        assert len(results2) == 1
        assert results2[0]["template_id"] == "cve-string-info"

    def test_parse_nuclei_empty_and_malformed(self):
        assert ReconParser.parse_nuclei("") == []
        assert ReconParser.parse_nuclei(None) == []
        assert ReconParser.parse_nuclei("   \n\n  ") == []

        # Malformed lines skipped
        output = "not json\n[1,2,3]\n{\"template-id\":\"valid-id\",\"host\":\"http://valid.com\"}"
        results = ReconParser.parse_nuclei(output)
        assert len(results) == 1
        assert results[0]["template_id"] == "valid-id"


class TestOriginalRequestVerificationScript:
    """Exact 4-step verification script from ORIGINAL_REQUEST.md (lines 99-133)."""

    def test_authoritative_4_step_verification_script(self):
        SUBFINDER_OUTPUT = "api.example.com\nadmin.example.com"
        HTTPX_OUTPUT = '{"url":"http://api.example.com","host":"api.example.com","status_code":200,"webserver":"nginx","tech":["Nginx","React"]}\n{"url":"http://admin.example.com","host":"admin.example.com","status_code":403}'
        KATANA_OUTPUT = "http://api.example.com/v1/users\nhttp://api.example.com/v1/login"
        NUCLEI_OUTPUT = '{"template-id":"CVE-2023-XXXX","info":{"name":"Example CVE","severity":"high","description":"A test CVE","tags":["cve"]},"host":"http://api.example.com","matched-at":"http://api.example.com/login","extracted-results":[]}'

        checks = []

        # R1 — Subfinder
        subs = ReconParser.parse_subfinder(SUBFINDER_OUTPUT)
        assert isinstance(subs[0], dict) and "hostname" in subs[0], "FAIL R1: subfinder not dict with hostname"
        checks.append("PASS R1 subfinder")

        # R2 — HTTPX
        hosts = ReconParser.parse_httpx(HTTPX_OUTPUT)
        assert "technologies" in hosts[0] and "status" in hosts[0], "FAIL R2: httpx missing fields"
        checks.append("PASS R2 httpx")

        # R3 — Katana
        eps = ReconParser.parse_katana(KATANA_OUTPUT)
        assert isinstance(eps[0], dict) and "url" in eps[0] and "path" in eps[0], "FAIL R3: katana not dict with url+path"
        checks.append("PASS R3 katana")

        # R4 — Nuclei
        vulns = ReconParser.parse_nuclei(NUCLEI_OUTPUT)
        assert "template_id" in vulns[0] and "severity" in vulns[0], "FAIL R4: nuclei missing fields"
        checks.append("PASS R4 nuclei")

        assert len(checks) == 4
        assert checks == [
            "PASS R1 subfinder",
            "PASS R2 httpx",
            "PASS R3 katana",
            "PASS R4 nuclei",
        ]
