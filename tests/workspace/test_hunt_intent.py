"""Spec tests for the deterministic hunt-intent parser (huntIntent.py).

These assert the external contract (a hunt command must yield a structured
request; questions and target-less messages must not), not implementation
detail -- so they are not characterization tests.
"""
from __future__ import annotations

import pytest

from argus.workspace.huntIntent import HUNT_ACTION, DEFAULT_PROFILE, HuntRequest, parseHuntRequest


@pytest.mark.parametrize("message,expected_target", [
    ("scan example.com", "example.com"),
    ("please hunt app.staging.example.co.uk now", "app.staging.example.co.uk"),
    ("run a scan of https://shop.example.com/login?next=1", "https://shop.example.com/login?next=1"),
    ("enumerate 10.0.0.5", "10.0.0.5"),
    ("pentest 192.168.1.0/24", "192.168.1.0/24"),
])
def test_extracts_target(message, expected_target):
    req = parseHuntRequest(message)
    assert req is not None
    assert req.action == HUNT_ACTION
    assert req.target == expected_target


def test_url_preferred_over_bare_domain_in_same_message():
    req = parseHuntRequest("scan https://real.example.com but not other.example.com")
    assert req is not None
    assert req.target == "https://real.example.com"


def test_trailing_punctuation_stripped_from_url():
    req = parseHuntRequest("scan https://example.com/path.")
    assert req is not None
    assert req.target == "https://example.com/path"


@pytest.mark.parametrize("message,expected_profile", [
    ("scan example.com", DEFAULT_PROFILE),
    ("run a quick scan of example.com", "quick"),
    ("hunt example.com for vulnerabilities", "vuln"),
    ("do a full pentest of example.com", "full"),
    ("recon example.com", "recon"),
])
def test_extracts_profile(message, expected_profile):
    req = parseHuntRequest(message)
    assert req is not None
    assert req.profile == expected_profile


@pytest.mark.parametrize("message", [
    "what did the scan of example.com find?",
    "why is example.com vulnerable",
    "how do I scan example.com",
    "did the hunt on example.com complete?",
])
def test_questions_are_not_hunt_commands(message):
    assert parseHuntRequest(message) is None


@pytest.mark.parametrize("message", [
    "tell me about example.com",            # target but no hunt verb
    "summarize the evidence for example.com",
    "run a scan",                            # verb but no target
    "start the recon please",
    "",                                      # empty
    "   ",
])
def test_non_commands_return_none(message):
    assert parseHuntRequest(message) is None


def test_result_is_frozen():
    req = parseHuntRequest("scan example.com")
    assert isinstance(req, HuntRequest)
    with pytest.raises(Exception):
        req.target = "evil.com"  # frozen dataclass
