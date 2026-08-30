import pytest
import json
from unittest.mock import MagicMock

from argus.tools.dnsx import DNSXTool, DNSResult
from argus.runtime.parser import ReconParser
from argus.runtime.registry import registry
from argus.runtime.base import Runtime


def test_dns_result_dataclass_and_to_dict():
    result = DNSResult(
        host="sub.example.com",
        cname=["service.github.io"],
        a=["192.0.2.1"],
        aaaa=["2001:db8::1"],
        status_code="NOERROR",
        resolver=["1.1.1.1"],
        raw={"host": "sub.example.com"},
    )
    d = result.to_dict()
    assert d["host"] == "sub.example.com"
    assert d["cname"] == ["service.github.io"]
    assert d["a"] == ["192.0.2.1"]
    assert d["aaaa"] == ["2001:db8::1"]
    assert d["status_code"] == "NOERROR"
    assert d["resolver"] == ["1.1.1.1"]
    assert d["raw"] == {"host": "sub.example.com"}


def test_dnsx_tool_build_args_defaults():
    tool = DNSXTool()
    args = tool.build_args()
    assert "-silent" in args
    assert "-json" in args
    assert "-cname" in args
    assert "-resp" in args
    assert "-rcode" in args


def test_dnsx_tool_build_args_custom():
    tool = DNSXTool()
    args = tool.build_args(
        cname=False,
        resp=False,
        json_output=False,
        silent=False,
        rcode=False,
        extra_args=["-t", "10", "-r", "8.8.8.8"],
    )
    assert "-cname" not in args
    assert "-resp" not in args
    assert "-json" not in args
    assert "-silent" not in args
    assert "-rcode" not in args
    assert "-t" in args
    assert "10" in args
    assert "-r" in args
    assert "8.8.8.8" in args


def test_recon_parser_parse_dnsx_jsonl():
    jsonl_output = """{"host":"app.example.com","cname":["app.herokuapp.com."],"a":["54.23.1.2"],"status_code":"NOERROR","resolver":["1.1.1.1"]}
{"host":"docs.example.com","cname":["custom.readme.io"],"status_code":"NXDOMAIN"}"""
    parsed = ReconParser.parse_dnsx(jsonl_output)
    assert len(parsed) == 2
    assert parsed[0]["host"] == "app.example.com"
    assert parsed[0]["cname"] == ["app.herokuapp.com"]  # Trailing dot stripped
    assert parsed[0]["a"] == ["54.23.1.2"]
    assert parsed[0]["status_code"] == "NOERROR"

    assert parsed[1]["host"] == "docs.example.com"
    assert parsed[1]["cname"] == ["custom.readme.io"]
    assert parsed[1]["status_code"] == "NXDOMAIN"


def test_recon_parser_parse_dnsx_plain_text():
    plain_text = """blog.example.com [CNAME] domains.tumblr.com.
test.example.com [A] 93.184.216.34
alias.example.com aws-s3.s3.amazonaws.com"""
    parsed = ReconParser.parse_dnsx(plain_text)
    assert len(parsed) == 3
    assert parsed[0]["host"] == "blog.example.com"
    assert "domains.tumblr.com" in parsed[0]["cname"]
    assert parsed[1]["host"] == "test.example.com"
    assert parsed[1]["a"] == ["93.184.216.34"]
    assert parsed[2]["host"] == "alias.example.com"
    assert "aws-s3.s3.amazonaws.com" in parsed[2]["cname"]


def test_recon_parser_parse_dnsx_empty_and_malformed():
    assert ReconParser.parse_dnsx("") == []
    assert ReconParser.parse_dnsx(None) == []
    malformed = "{not json}\n"
    res = ReconParser.parse_dnsx(malformed)
    assert len(res) == 1
    assert res[0]["host"] == "{not"


def test_dnsx_tool_resolve_with_mock_runtime():
    mock_runtime = MagicMock(spec=Runtime)
    mock_runtime.run_command.return_value = {
        "stdout": json.dumps({
            "host": "shop.target.com",
            "cname": ["shops.myshopify.com"],
            "status_code": "NOERROR",
        }) + "\n",
        "stderr": "",
        "returncode": 0,
    }
    tool = DNSXTool(runtime=mock_runtime)
    results = tool.resolve(["shop.target.com"])

    assert len(results) == 1
    assert isinstance(results[0], DNSResult)
    assert results[0].host == "shop.target.com"
    assert results[0].cname == ["shops.myshopify.com"]
    assert results[0].status_code == "NOERROR"
    mock_runtime.run_command.assert_called_once()


def test_dnsx_tool_resolve_empty_hosts():
    mock_runtime = MagicMock(spec=Runtime)
    tool = DNSXTool(runtime=mock_runtime)
    assert tool.resolve([]) == []
    mock_runtime.run_command.assert_not_called()


def test_dnsx_tool_resolve_runtime_exception():
    mock_runtime = MagicMock(spec=Runtime)
    mock_runtime.run_command.side_effect = RuntimeError("Execution failed")
    tool = DNSXTool(runtime=mock_runtime)
    results = tool.resolve(["error.com"])
    assert results == []


def test_dnsx_tool_registry_registration():
    tool = registry.get("dns_resolver")
    assert tool is not None
    assert tool.id == "dnsx"
    assert tool.capability == "dns_resolver"
    assert "dns_records" in tool.produced_outputs
