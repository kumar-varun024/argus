"""
Adversarial Evasion, Protocol Fuzzing, and Stress Tests for WebSocket Security Module.

Covers adversarial origin mutations, HTTP smuggling headers, malformed key handling,
frame injection evasion vectors, protocol boundary fuzzing, and noisy response resilience.
"""
import base64
import urllib.parse
from typing import Any, Dict, List, Optional
import pytest

from argus.collectors.websocket import (
    WebSocketSecurityCollector,
    WebSocketCollector,
    WebSocketPayloadGenerator,
    WebSocketSecurityAnalyzer,
    WebSocketSecurityResult,
    WebSocketSeverity,
    WebSocketTechnique,
    WebSocketMutationStrategy,
    HARDENED_WS_DEFENSE_SIGNATURES,
    SQL_ERROR_SIGNATURES,
    COMMAND_OUTPUT_SIGNATURES,
    XSS_OUTPUT_SIGNATURES,
    PROTOTYPE_POLLUTION_SIGNATURES,
)
from argus.evidence.store import EvidenceStore
from argus.graph.graph import KnowledgeGraph
from argus.http.client import HttpResponse
from argus.runtime.mission import Mission


class TestWebSocketAdversarialOrigins:
    """Tests origin manipulation edge cases, punycode, and evasion patterns."""

    def test_unicode_and_punycode_origin_spoofing(self):
        # Cyrillic 'а' (U+0430) spoofing 'a' in target.com -> xn--trget-e1a.com
        punycode_origin = "https://xn--trget-e1a.com"
        key = WebSocketPayloadGenerator.generate_sec_websocket_key()
        accept = WebSocketPayloadGenerator.compute_sec_websocket_accept(key)

        resp = HttpResponse(
            success=True,
            status_code=101,
            body="",
            headers={"sec-websocket-accept": accept, "upgrade": "websocket"},
            url="https://target.com/ws",
        )
        res = WebSocketSecurityAnalyzer.analyze_cswsh(
            "https://target.com/ws",
            WebSocketMutationStrategy.ORIGIN_MANIPULATION,
            punycode_origin,
            key,
            resp,
        )
        assert res is not None
        assert res.technique == WebSocketTechnique.CSWSH.value
        assert "xn--trget-e1a.com" in res.evidence_snippet

    def test_port_spoofing_origin_cross_origin(self):
        # Target is on standard 443, origin specifies non-standard port 8443
        port_origin = "https://target.com:8443"
        key = WebSocketPayloadGenerator.generate_sec_websocket_key()
        accept = WebSocketPayloadGenerator.compute_sec_websocket_accept(key)

        resp = HttpResponse(
            success=True,
            status_code=101,
            body="",
            headers={"sec-websocket-accept": accept},
            url="https://target.com/ws",
        )
        res = WebSocketSecurityAnalyzer.analyze_cswsh(
            "https://target.com/ws",
            WebSocketMutationStrategy.ORIGIN_MANIPULATION,
            port_origin,
            key,
            resp,
        )
        assert res is not None
        assert res.technique == WebSocketTechnique.CSWSH.value

    def test_scheme_downgrade_on_https_target(self):
        http_origin = "http://target.com"
        key = WebSocketPayloadGenerator.generate_sec_websocket_key()
        accept = WebSocketPayloadGenerator.compute_sec_websocket_accept(key)

        resp = HttpResponse(
            success=True,
            status_code=101,
            body="",
            headers={"sec-websocket-accept": accept},
            url="https://target.com/ws",
        )
        res = WebSocketSecurityAnalyzer.analyze_cswsh(
            "https://target.com/ws",
            WebSocketMutationStrategy.ORIGIN_MANIPULATION,
            http_origin,
            key,
            resp,
        )
        assert res is not None
        assert res.technique == WebSocketTechnique.CSWSH.value


class TestWebSocketProtocolSmugglingAndFuzzing:
    """Tests protocol smuggling headers, malformed nonce keys, and whitespace fuzzing."""

    def test_malformed_base64_sec_websocket_key_verification(self):
        # Invalid base64 key
        invalid_key = "###NOT_BASE64###"
        accept = WebSocketPayloadGenerator.compute_sec_websocket_accept(invalid_key)
        assert isinstance(accept, str)

        # Mismatched accept header must fail verification
        assert WebSocketSecurityAnalyzer.verify_sec_websocket_accept(invalid_key, "wrong_hash") is False

    def test_hop_by_hop_casing_and_trailing_whitespace(self):
        mutations = WebSocketPayloadGenerator.generate_hop_by_hop_mutations("https://target.com/ws")
        for strategy, headers, desc in mutations:
            assert "Sec-WebSocket-Key" in headers
            assert "Host" in headers

    def test_subprotocol_delimiter_and_wildcard_fuzzing(self):
        mutations = WebSocketPayloadGenerator.generate_subprotocol_mutations("https://target.com/ws")
        protocols = [m[2] for m in mutations]
        assert any("*" in p for p in protocols)
        assert any("\t" in p for p in protocols)

    def test_extension_deflate_extreme_window_bits(self):
        mutations = WebSocketPayloadGenerator.generate_extension_deflate_mutations("https://target.com/ws")
        exts = [m[2] for m in mutations]
        assert any("client_max_window_bits=99999" in e for e in exts)


class TestWebSocketFrameFuzzingAdversarial:
    """Tests frame injection payloads, SQL error signatures, command injection variants, and proto pollution."""

    def test_sql_error_signatures_comprehensive(self):
        url = "https://target.com/ws"
        test_errors = [
            ("PostgreSQL query failed: syntax error at or near 'admin'", "postgresql"),
            ("MySQLSyntaxErrorException: You have an error in your SQL syntax", "mysql"),
            ("SQLite3::SQLException: near 'admin': syntax error", "sqlite"),
            ("ORA-01756: quoted string not properly terminated", "oracle"),
            ("Microsoft OLE DB Provider for SQL Server: Unclosed quotation mark", "mssql"),
            ("SQLSTATE[42000]: Syntax error or access violation: SQL syntax error", "generic_sql"),
        ]
        for err_snippet, engine in test_errors:
            body = f'{{"status": "error", "message": "{err_snippet}"}}'
            res = WebSocketSecurityAnalyzer.analyze_frame_response(
                url, WebSocketTechnique.INJECTION_SQLI, "1' OR '1'='1", body
            )
            assert res is not None, f"Failed to detect SQL error for {engine}: {err_snippet}"
            assert res.technique == WebSocketTechnique.INJECTION_SQLI.value
            assert res.severity == "critical"

    def test_command_injection_signatures_comprehensive(self):
        url = "https://target.com/ws"
        test_outputs = [
            ("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin", "passwd"),
            ("uid=1000(appuser) gid=1000(appgroup) groups=1000(appgroup)", "id_command"),
            ("Windows IP Configuration\n   Host Name . . . . . . . . . : WIN-SERVER", "windows_system"),
            ("Directory of C:\\Windows\\System32", "windows_dir"),
        ]
        for out_snippet, sig_type in test_outputs:
            body = f'{{"output": "{out_snippet}"}}'
            res = WebSocketSecurityAnalyzer.analyze_frame_response(
                url, WebSocketTechnique.INJECTION_CMDI, "; id", body
            )
            assert res is not None, f"Failed to detect CMDi for {sig_type}: {out_snippet}"
            assert res.technique == WebSocketTechnique.INJECTION_CMDI.value
            assert res.severity == "critical"

    def test_xss_signatures_comprehensive(self):
        url = "https://target.com/ws"
        test_xss = [
            ("<script>alert('ARGUS_WS_XSS')</script>", "script"),
            ("<script>alert(1)</script>", "script_num"),
            ("<img src=x onerror=alert(1)>", "img_onerror"),
            ("<svg onload=alert(1)>", "svg_onload"),
        ]
        for payload, xss_type in test_xss:
            body = f'{{"echo": "{payload}"}}'
            res = WebSocketSecurityAnalyzer.analyze_frame_response(
                url, WebSocketTechnique.INJECTION_XSS, payload, body
            )
            assert res is not None, f"Failed to detect XSS for {xss_type}: {payload}"
            assert res.technique == WebSocketTechnique.INJECTION_XSS.value

    def test_prototype_pollution_signatures_comprehensive(self):
        url = "https://target.com/ws"
        test_proto = [
            ('{"polluted": true, "result": "ok"}', "polluted_prop"),
            ('{"isAdmin": true, "role": "admin"}', "is_admin"),
            ('{"prototype_polluted": true}', "proto_polluted"),
        ]
        for body, proto_type in test_proto:
            res = WebSocketSecurityAnalyzer.analyze_frame_response(
                url, WebSocketTechnique.PROTOTYPE_POLLUTION, '{"__proto__": {"admin": true}}', body
            )
            assert res is not None, f"Failed to detect Prototype Pollution for {proto_type}: {body}"
            assert res.technique == WebSocketTechnique.PROTOTYPE_POLLUTION.value


class TestWebSocketStressAndAbuseResilience:
    """Stress tests, rate limit boundaries, and noisy response resilience."""

    def test_rate_limit_flood_threshold_boundaries(self):
        url = "https://target.com/ws"
        # Below threshold (49 frames) -> No finding
        res_below = WebSocketSecurityAnalyzer.analyze_protocol_abuse(
            url, WebSocketTechnique.RATE_LIMIT_FLOOD, flood_processed=49, flood_limit=50
        )
        assert res_below is None

        # At threshold (50 frames) -> Finding triggered
        res_at = WebSocketSecurityAnalyzer.analyze_protocol_abuse(
            url, WebSocketTechnique.RATE_LIMIT_FLOOD, flood_processed=50, flood_limit=50
        )
        assert res_at is not None
        assert res_at.technique == WebSocketTechnique.RATE_LIMIT_FLOOD.value

        # Throttled with HTTP 429 -> Suppressed
        res_throttled = WebSocketSecurityAnalyzer.analyze_protocol_abuse(
            url, WebSocketTechnique.RATE_LIMIT_FLOOD, status_code=429, flood_processed=50, flood_limit=50
        )
        assert res_throttled is None

    def test_unusual_http_status_codes_handling(self):
        # 404 Not Found, 405 Method Not Allowed, 503 Service Unavailable
        for sc in (400, 401, 403, 404, 405, 426):
            assert WebSocketSecurityAnalyzer.is_hardened_rejection(sc) is True

    def test_noisy_garbage_response_does_not_crash_analyzer(self):
        url = "https://target.com/ws"
        garbage_bodies = [
            "",
            "   ",
            "\x00\x01\x02\xFF\xFE",
            "<html><head><title>500 Internal Error</title></head><body>Server error</body></html>",
            "<!DOCTYPE html><html><body>Welcome to WebSocket Gateway</body></html>",
            "1234567890" * 100,
        ]
        for gb in garbage_bodies:
            res_sqli = WebSocketSecurityAnalyzer.analyze_frame_response(
                url, WebSocketTechnique.INJECTION_SQLI, "probe", gb
            )
            assert res_sqli is None

            res_cmdi = WebSocketSecurityAnalyzer.analyze_frame_response(
                url, WebSocketTechnique.INJECTION_CMDI, "probe", gb
            )
            assert res_cmdi is None

    def test_concurrent_multiple_candidate_paths_profiling(self):
        collector = WebSocketSecurityCollector()
        mission = Mission(target="large-target.com")
        mission.endpoints = [
            "https://large-target.com/ws",
            "https://large-target.com/api/v1/ws",
            "https://large-target.com/cable",
            "https://large-target.com/socket.io/",
            "https://large-target.com/graphql-ws",
        ]
        candidates = collector._discover_candidate_endpoints(mission)
        assert len(candidates) >= 20
        # Check deduplication
        assert len(candidates) == len(set(candidates))
