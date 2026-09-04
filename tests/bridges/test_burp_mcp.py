"""Comprehensive test suite for Burp Suite MCP Integration in ARGUS."""

import base64
import io
import json
import subprocess
import sys
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import httpx
import pytest

from argus.bridges.burp import (
    BurpCollaboratorClient,
    BurpMCPServer,
    BurpScanImporter,
    BurpScannerClient,
    burp_configure_proxy,
    get_burp_http_client,
)
from argus.bridges.burp.__main__ import main as burp_main
from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.runtime.mission import Mission


# ============================================================================
# 1. Proxy Configuration Tests
# ============================================================================


def test_burp_configure_proxy_enabled():
    res = burp_configure_proxy("http://127.0.0.1:8080", enabled=True)
    assert res["status"] == "configured"
    assert res["proxy_url"] == "http://127.0.0.1:8080"
    assert res["enabled"] is True


def test_burp_configure_proxy_disabled():
    res = burp_configure_proxy(enabled=False)
    assert res["status"] == "disabled"
    assert res["proxy_url"] is None
    assert res["enabled"] is False


def test_get_burp_http_client_factory():
    client = get_burp_http_client(proxy_url="http://127.0.0.1:8080", timeout=5.0)
    assert client.proxy == "http://127.0.0.1:8080"
    assert client.verify_ssl is False
    assert client.default_timeout == 5.0
    client.close()


# ============================================================================
# 2. Burp Scan Importer Tests (XML & JSON)
# ============================================================================

SAMPLE_BURP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<issues burpVersion="2023.12.1" exportTime="Wed Sep 02 23:00:00 UTC 2026">
  <issue>
    <serialNumber>1001</serialNumber>
    <type>1048832</type>
    <name>SQL injection</name>
    <host ip="192.168.1.50">https://target.local</host>
    <path>/items</path>
    <location>https://target.local/items?id=1</location>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground><![CDATA[SQL injection vulnerability occurs when...]]></issueBackground>
    <remediationBackground><![CDATA[Use parameterized queries.]]></remediationBackground>
    <issueDetail><![CDATA[The parameter id was manipulated to sleep 5 seconds.]]></issueDetail>
    <remediationDetail><![CDATA[Sanitize input.]]></remediationDetail>
    <requestresponse>
      <request base64="true">R0VUIC9pdGVtcz9pZD0xIEhUVFAvMS4xDQpIb3N0OiB0YXJnZXQubG9jYWwNCg==</request>
      <response base64="true">SFRUUC8xLjEgMjAwIE9LDQpDb250ZW50LVR5cGU6IHRleHQvaHRtbA0KDQo8aDFPazwvaDE+</response>
    </requestresponse>
  </issue>
  <issue>
    <serialNumber>1002</serialNumber>
    <type>2097408</type>
    <name>Information disclosure</name>
    <host ip="192.168.1.50">https://target.local</host>
    <path>/robots.txt</path>
    <location>https://target.local/robots.txt</location>
    <severity>Information</severity>
    <confidence>Firm</confidence>
    <issueBackground>Disclosing robots.txt</issueBackground>
    <requestresponse>
      <request base64="false">GET /robots.txt HTTP/1.1</request>
      <response base64="false">HTTP/1.1 200 OK</response>
    </requestresponse>
  </issue>
</issues>
"""

SAMPLE_BURP_JSON = json.dumps({
    "issues": [
        {
            "name": "Cross-site scripting (reflected)",
            "serialNumber": "2001",
            "type": "1048576",
            "host": "https://target.local",
            "path": "/search",
            "location": "https://target.local/search?q=test",
            "severity": "Medium",
            "confidence": "Tentative",
            "issue_detail": "Reflected payload found in DOM.",
            "http_messages": [
                {
                    "request": base64.b64encode(b"GET /search?q=test HTTP/1.1").decode("ascii"),
                    "response": base64.b64encode(b"HTTP/1.1 200 OK\n\nsearch results").decode("ascii"),
                    "request_base64": True,
                    "response_base64": True,
                }
            ],
        }
    ]
})


def test_burp_scan_importer_xml():
    importer = BurpScanImporter()
    issues = importer.parse_xml(SAMPLE_BURP_XML)
    assert len(issues) == 2

    sqli = issues[0]
    assert sqli["name"] == "SQL injection"
    assert sqli["host"] == "https://target.local"
    assert sqli["host_ip"] == "192.168.1.50"
    assert sqli["path"] == "/items"
    assert sqli["severity"] == "High"
    assert sqli["confidence"] == "Certain"
    assert len(sqli["http_interactions"]) == 1
    assert "GET /items?id=1 HTTP/1.1" in sqli["http_interactions"][0]["request"]
    assert "HTTP/1.1 200 OK" in sqli["http_interactions"][0]["response"]

    info_issue = issues[1]
    assert info_issue["name"] == "Information disclosure"
    assert info_issue["severity"] == "Information"
    assert info_issue["confidence"] == "Firm"


def test_burp_scan_importer_json():
    importer = BurpScanImporter()
    issues = importer.parse_json(SAMPLE_BURP_JSON)
    assert len(issues) == 1
    xss = issues[0]
    assert xss["name"] == "Cross-site scripting (reflected)"
    assert xss["severity"] == "Medium"
    assert xss["confidence"] == "Tentative"
    assert len(xss["http_interactions"]) == 1
    assert "GET /search?q=test" in xss["http_interactions"][0]["request"]


def test_burp_scan_importer_attach_to_mission():
    mission = Mission(target="https://target.local")
    importer = BurpScanImporter(mission=mission)

    result = importer.import_scan(content=SAMPLE_BURP_XML, format="xml")
    assert result["status"] == "success"
    assert result["imported_count"] == 2
    assert len(result["evidence_ids"]) == 2

    # Verify Evidence attached to mission.evidence
    evidences = mission.evidence.all()
    assert len(evidences) == 2

    sqli_evidence = [e for e in evidences if "SQL" in e.title][0]
    assert sqli_evidence.category == "burp_scan"
    assert sqli_evidence.severity == "high"
    assert sqli_evidence.confidence == 1.0
    assert sqli_evidence.source_type == "TOOL"
    assert sqli_evidence.provenance.step_id == "burp_import_scan"

    # Verify findings and vulnerabilities populated
    assert len(mission.findings) == 2
    assert len(mission.vulnerabilities) == 2
    assert mission.vulnerabilities[0]["severity"] == "high"


def test_burp_scan_importer_file_import(tmp_path):
    xml_file = tmp_path / "burp_export.xml"
    xml_file.write_text(SAMPLE_BURP_XML, encoding="utf-8")

    importer = BurpScanImporter()
    result = importer.import_scan(file_path=str(xml_file), format="auto")
    assert result["status"] == "success"
    assert result["imported_count"] == 2
    assert result["format"] == "xml"


def test_burp_scan_importer_invalid_inputs():
    importer = BurpScanImporter()

    # Empty content and missing file
    res1 = importer.import_scan()
    assert res1["status"] == "error"
    assert res1["imported_count"] == 0

    # Non-existent file
    res2 = importer.import_scan(file_path="/nonexistent/burp_scan.xml")
    assert res2["status"] == "error"

    # Invalid XML
    res3 = importer.import_scan(content="<unclosed_tag", format="xml")
    assert res3["status"] == "error"

    # Invalid JSON
    res4 = importer.import_scan(content="{invalid_json", format="json")
    assert res4["status"] == "error"


# ============================================================================
# 3. Burp Scanner Client Tests (Active Scan REST API)
# ============================================================================


def test_burp_scanner_launch_scan_success():
    client = BurpScannerClient(api_url="http://127.0.0.1:1337", api_key="secret-key")

    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.headers = {"Location": "/v0.1/scan/42"}
    mock_resp.json.return_value = {"scan_id": "42"}

    with patch.object(httpx.Client, "post", return_value=mock_resp) as mock_post:
        result = client.launch_scan(urls=["https://example.com"])
        assert result["status"] == "initiated"
        assert result["scan_id"] == "42"

        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert args[0] == "http://127.0.0.1:1337/v0.1/scan"
        assert kwargs["json"]["urls"] == ["https://example.com"]
        assert kwargs["headers"]["X-API-Key"] == "secret-key"


def test_burp_scanner_launch_scan_connection_error():
    client = BurpScannerClient(api_url="http://127.0.0.1:1337")

    with patch.object(
        httpx.Client,
        "post",
        side_effect=httpx.ConnectError("Connection refused"),
    ):
        result = client.launch_scan(urls=["https://example.com"])
        assert result["status"] == "error"
        assert "Connection error" in result["error"]


def test_burp_scanner_poll_scan_success():
    client = BurpScannerClient(api_url="http://127.0.0.1:1337")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "scan_status": "succeeded",
        "progress_percentage": 100,
        "issue_events": [
            {
                "issue": {
                    "name": "SQL injection",
                    "severity": "high",
                    "confidence": "certain",
                }
            }
        ],
    }

    with patch.object(httpx.Client, "get", return_value=mock_resp):
        result = client.poll_scan(scan_id="42")
        assert result["status"] == "success"
        assert result["scan_status"] == "succeeded"
        assert result["progress_percentage"] == 100
        assert result["issue_count"] == 1
        assert result["issues"][0]["name"] == "SQL injection"


def test_burp_scanner_cancel_scan():
    client = BurpScannerClient(api_url="http://127.0.0.1:1337")

    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch.object(httpx.Client, "delete", return_value=mock_resp):
        result = client.cancel_scan(scan_id="42")
        assert result["status"] == "cancelled"


# ============================================================================
# 4. Burp Collaborator Client Tests (OAST)
# ============================================================================


def test_burp_collaborator_generate_payload():
    client = BurpCollaboratorClient(server_domain="custom-oast.org")
    result = client.generate_payload()
    assert result["status"] == "generated"
    assert result["server_domain"] == "custom-oast.org"
    assert result["payload_domain"].endswith(".custom-oast.org")
    assert len(result["token"]) == 30


def test_burp_collaborator_poll_interactions_via_api():
    client = BurpCollaboratorClient(api_url="http://127.0.0.1:1337")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "interactions": [
            {
                "type": "DNS",
                "client": "8.8.8.8",
                "time": "2026-09-02T23:00:00Z",
            },
            {
                "type": "HTTP",
                "client": "1.2.3.4",
                "time": "2026-09-02T23:00:05Z",
            },
        ]
    }

    with patch.object(httpx.Client, "get", return_value=mock_resp):
        result = client.poll_interactions(
            payload_domain="test.custom-oast.org",
            api_url="http://127.0.0.1:1337",
            secret_key="collab-key",
        )
        assert result["status"] == "success"
        assert result["count"] == 2
        assert result["interactions"][0]["type"] == "DNS"


# ============================================================================
# 5. Burp MCP Server Protocol & Tool Dispatch Tests
# ============================================================================


def test_mcp_server_initialize():
    server = BurpMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0"},
        },
    }

    resp_str = server.handle_jsonrpc(json.dumps(req))
    resp = json.loads(resp_str)

    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 1
    assert resp["result"]["protocolVersion"] == "2024-11-05"
    assert resp["result"]["serverInfo"]["name"] == "argus-burp-bridge"


def test_mcp_server_notifications():
    server = BurpMCPServer()
    req = {
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    }
    resp_str = server.handle_jsonrpc(json.dumps(req))
    assert resp_str == ""


def test_mcp_server_ping():
    server = BurpMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": "req-ping",
        "method": "ping",
    }
    resp = json.loads(server.handle_jsonrpc(json.dumps(req)))
    assert resp["id"] == "req-ping"
    assert resp["result"] == {}


def test_mcp_server_tools_list():
    server = BurpMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
    }
    resp = json.loads(server.handle_jsonrpc(json.dumps(req)))
    tools = resp["result"]["tools"]
    tool_names = [t["name"] for t in tools]

    expected_tools = [
        "burp_configure_proxy",
        "burp_import_scan",
        "burp_launch_scan",
        "burp_poll_scan",
        "burp_collaborator_generate",
        "burp_collaborator_poll",
    ]
    for expected in expected_tools:
        assert expected in tool_names

    # Check schemas
    for t in tools:
        assert "name" in t
        assert "description" in t
        assert "inputSchema" in t


def test_mcp_server_tools_call_configure_proxy():
    server = BurpMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "burp_configure_proxy",
            "arguments": {
                "proxy_url": "http://127.0.0.1:8888",
                "enabled": True,
            },
        },
    }
    resp = json.loads(server.handle_jsonrpc(json.dumps(req)))
    assert resp["id"] == 3
    assert resp["result"]["isError"] is False
    assert "content" in resp["result"]
    assert "http://127.0.0.1:8888" in resp["result"]["content"][0]["text"]


def test_mcp_server_tools_call_import_scan():
    server = BurpMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "burp_import_scan",
            "arguments": {
                "content": SAMPLE_BURP_XML,
                "format": "xml",
            },
        },
    }
    resp = json.loads(server.handle_jsonrpc(json.dumps(req)))
    assert resp["id"] == 4
    assert resp["result"]["isError"] is False
    assert "imported_count" in resp["result"]["content"][0]["text"]


def test_mcp_server_tools_call_unknown_tool():
    server = BurpMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "non_existent_tool",
            "arguments": {},
        },
    }
    resp = json.loads(server.handle_jsonrpc(json.dumps(req)))
    assert resp["id"] == 5
    assert "error" in resp
    assert resp["error"]["code"] == -32601


def test_mcp_server_invalid_json():
    server = BurpMCPServer()
    resp = json.loads(server.handle_jsonrpc("invalid-json{"))
    assert resp["error"]["code"] == -32700


def test_mcp_server_method_not_found():
    server = BurpMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 6,
        "method": "unknown_rpc_method",
    }
    resp = json.loads(server.handle_jsonrpc(json.dumps(req)))
    assert resp["error"]["code"] == -32601


def test_mcp_server_execute_tool_programmatic():
    server = BurpMCPServer()
    result = server.execute_tool(
        "burp_collaborator_generate",
        {"server_domain": "test-oast.net"},
    )
    assert result["status"] == "generated"
    assert result["server_domain"] == "test-oast.net"


# ============================================================================
# 6. Stdio Runner & CLI Entry Point Tests
# ============================================================================


def test_mcp_server_stdio_stream():
    server = BurpMCPServer()

    requests = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    ]
    stdin_data = "\n".join(requests) + "\n"

    in_stream = io.StringIO(stdin_data)
    out_stream = io.StringIO()

    server.run_stdio(stdin=in_stream, stdout=out_stream)

    output = out_stream.getvalue().strip().split("\n")
    assert len(output) == 2

    resp1 = json.loads(output[0])
    assert resp1["id"] == 1
    assert resp1["result"] == {}

    resp2 = json.loads(output[1])
    assert resp2["id"] == 2
    assert len(resp2["result"]["tools"]) == 6


def test_cli_main_version(capsys):
    test_args = ["burp_mcp", "--version"]
    with patch.object(sys, "argv", test_args):
        with pytest.raises(SystemExit) as excinfo:
            burp_main()
        assert excinfo.value.code == 0
    captured = capsys.readouterr()
    assert "argus-burp-bridge" in captured.out


def test_cli_subprocess_execution():
    req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}) + "\n"
    proc = subprocess.run(
        [sys.executable, "-m", "argus.bridges.burp"],
        input=req,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert proc.returncode == 0
    resp = json.loads(proc.stdout.strip())
    assert resp["id"] == 1
    assert resp["result"] == {}


# ============================================================================
# 7. Extended Protocol & Tool Call Coverage Tests
# ============================================================================


def test_mcp_server_tools_call_launch_scan():
    server = BurpMCPServer()
    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.headers = {"Location": "/v0.1/scan/101"}
    mock_resp.json.return_value = {"scan_id": "101"}

    with patch.object(httpx.Client, "post", return_value=mock_resp):
        req = {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "burp_launch_scan",
                "arguments": {"urls": ["https://target.local"]},
            },
        }
        resp = json.loads(server.handle_jsonrpc(json.dumps(req)))
        assert resp["id"] == 10
        assert resp["result"]["isError"] is False
        assert "101" in resp["result"]["content"][0]["text"]


def test_mcp_server_tools_call_poll_scan():
    server = BurpMCPServer()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "scan_status": "auditing",
        "progress_percentage": 55,
        "issue_events": [],
    }

    with patch.object(httpx.Client, "get", return_value=mock_resp):
        req = {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "burp_poll_scan",
                "arguments": {"scan_id": "101"},
            },
        }
        resp = json.loads(server.handle_jsonrpc(json.dumps(req)))
        assert resp["id"] == 11
        assert resp["result"]["isError"] is False
        assert "auditing" in resp["result"]["content"][0]["text"]


def test_mcp_server_tools_call_collaborator_generate():
    server = BurpMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 12,
        "method": "tools/call",
        "params": {
            "name": "burp_collaborator_generate",
            "arguments": {"server_domain": "custom-domain.net"},
        },
    }
    resp = json.loads(server.handle_jsonrpc(json.dumps(req)))
    assert resp["id"] == 12
    assert resp["result"]["isError"] is False
    assert "custom-domain.net" in resp["result"]["content"][0]["text"]


def test_mcp_server_tools_call_collaborator_poll():
    server = BurpMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 13,
        "method": "tools/call",
        "params": {
            "name": "burp_collaborator_poll",
            "arguments": {"payload_domain": "abc123.oastify.com"},
        },
    }
    resp = json.loads(server.handle_jsonrpc(json.dumps(req)))
    assert resp["id"] == 13
    assert resp["result"]["isError"] is False
    assert "abc123.oastify.com" in resp["result"]["content"][0]["text"]


def test_mcp_server_tools_call_missing_required_params():
    server = BurpMCPServer()
    # Missing urls for launch_scan
    req = {
        "jsonrpc": "2.0",
        "id": 14,
        "method": "tools/call",
        "params": {
            "name": "burp_launch_scan",
            "arguments": {"urls": []},
        },
    }
    resp = json.loads(server.handle_jsonrpc(json.dumps(req)))
    assert resp["id"] == 14
    assert resp["result"]["isError"] is True
    assert "Error executing tool" in resp["result"]["content"][0]["text"]


def test_mcp_server_invalid_request_structures():
    server = BurpMCPServer()

    # Request is not a dict
    resp1 = server.handle_request("not-a-dict")  # type: ignore
    assert resp1["error"]["code"] == -32600

    # Missing jsonrpc version or not "2.0"
    resp2 = server.handle_request({"jsonrpc": "1.0", "id": 1, "method": "ping"})
    assert resp2["error"]["code"] == -32600

    # Invalid params type in tools/call
    resp3 = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": "invalid"})
    assert resp3["error"]["code"] == -32602

    # Missing tool name in tools/call params
    resp4 = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}})
    assert resp4["error"]["code"] == -32602


def test_burp_scan_importer_single_root_issue_xml():
    xml_single = """<?xml version="1.0" encoding="UTF-8"?>
    <issue>
      <name>Single XML Issue</name>
      <host>https://single.target</host>
      <severity>Low</severity>
      <confidence>Tentative</confidence>
    </issue>
    """
    importer = BurpScanImporter()
    issues = importer.parse_xml(xml_single)
    assert len(issues) == 1
    assert issues[0]["name"] == "Single XML Issue"
    assert issues[0]["severity"] == "Low"


def test_burp_scan_importer_json_issue_events():
    json_events = json.dumps({
        "issue_events": [
            {
                "issue": {
                    "name": "Issue from REST API event",
                    "origin": "https://api.target",
                    "severity": "medium",
                    "confidence": "certain",
                    "request": "R0VUIC8gSFRUUC8xLjE=",
                    "request_base64": True,
                }
            }
        ]
    })
    importer = BurpScanImporter()
    issues = importer.parse_json(json_events)
    assert len(issues) == 1
    assert issues[0]["name"] == "Issue from REST API event"
    assert issues[0]["host"] == "https://api.target"
    assert "GET / HTTP/1.1" in issues[0]["http_interactions"][0]["request"]


def test_burp_scanner_http_error_responses():
    client = BurpScannerClient(api_url="http://127.0.0.1:1337")

    mock_err_resp = MagicMock()
    mock_err_resp.status_code = 500
    mock_err_resp.text = "Internal Server Error"

    # Launch error
    with patch.object(httpx.Client, "post", return_value=mock_err_resp):
        res = client.launch_scan(urls=["https://fail.target"])
        assert res["status"] == "error"
        assert res["status_code"] == 500

    # Poll error
    with patch.object(httpx.Client, "get", return_value=mock_err_resp):
        res2 = client.poll_scan(scan_id="99")
        assert res2["status"] == "error"
        assert res2["status_code"] == 500


def test_burp_collaborator_direct_polling():
    client = BurpCollaboratorClient(server_domain="collab-server.net", secret_key="mysecret")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "responses": [
            {"protocol": "dns", "interaction_id": "1"},
        ]
    }

    with patch.object(httpx.Client, "get", return_value=mock_resp) as mock_get:
        result = client.poll_interactions(
            payload_domain="tok123.collab-server.net",
            secret_key="mysecret",
            server_domain="collab-server.net",
        )
        assert result["status"] == "success"
        assert result["count"] == 1
        mock_get.assert_called_once()

