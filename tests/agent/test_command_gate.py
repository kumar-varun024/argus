"""Spec tests for the deterministic command gate (commandGate).

Uses the REAL authorization_gate + mission_manager so scope enforcement is
genuine. Proves: passive in-scope -> ALLOW; active in-scope -> NEEDS_CONFIRMATION;
out-of-scope / bad args / unknown tool / no target -> DENY.
"""
from __future__ import annotations

from argus.agent.commandGate import GateOutcome, authorizeCommand
from argus.runtime.manager import mission_manager


def _mission(target: str, scope: list[str]):
    m = mission_manager.create_mission(target)
    m.scope = scope
    return m


def test_passive_in_scope_auto_allows():
    m = _mission("example.com", ["example.com", "*.example.com"])
    d = authorizeCommand("httpx", ["-u", "https://example.com", "-json"], m.id)
    assert d.outcome == GateOutcome.ALLOW
    assert d.targets == ("https://example.com",)


def test_active_in_scope_needs_confirmation():
    m = _mission("example.com", ["example.com", "*.example.com"])
    d = authorizeCommand("nuclei", ["-u", "https://example.com", "-severity", "high"], m.id)
    assert d.outcome == GateOutcome.NEEDS_CONFIRMATION


def test_out_of_scope_denied():
    m = _mission("example.com", ["example.com"])
    d = authorizeCommand("httpx", ["-u", "https://evil.com"], m.id)
    assert d.outcome == GateOutcome.DENY
    assert "out of scope" in d.reason.lower()


def test_multi_target_one_out_of_scope_denies_whole():
    m = _mission("example.com", ["example.com", "*.example.com"])
    d = authorizeCommand("nmap", ["app.example.com", "evil.com"], m.id)
    assert d.outcome == GateOutcome.DENY


def test_bad_args_denied():
    m = _mission("example.com", ["example.com"])
    d = authorizeCommand("nmap", ["--script", "http-shellshock", "example.com"], m.id)
    assert d.outcome == GateOutcome.DENY


def test_unknown_tool_denied():
    m = _mission("example.com", ["example.com"])
    d = authorizeCommand("bash", ["-c", "id"], m.id)
    assert d.outcome == GateOutcome.DENY


def test_no_target_denied_fail_closed():
    m = _mission("example.com", ["example.com"])
    d = authorizeCommand("nmap", ["-sV"], m.id)
    assert d.outcome == GateOutcome.DENY
    assert "no scope-checkable target" in d.reason.lower()


def test_no_mission_denied():
    d = authorizeCommand("httpx", ["-u", "https://example.com"], None)
    assert d.outcome == GateOutcome.DENY


def test_injection_arg_denied():
    m = _mission("example.com", ["example.com"])
    d = authorizeCommand("curl", ["-H", "X: $(rm -rf /)", "https://example.com"], m.id)
    assert d.outcome == GateOutcome.DENY
