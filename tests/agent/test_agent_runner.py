"""Spec tests for the background runner + per-command approval channel.

No real agent/LLM/container: a fake agent factory drives the runner, and the
approval channel is tested directly with threads.
"""
from __future__ import annotations

import threading
import time

from argus.agent.agentRunner import (
    AgentHuntEngine,
    HuntAgentRunner,
    requestCommandApproval,
    resolveCommandApproval,
)
from argus.agent.commandGate import CommandDecision, GateOutcome
from argus.runtime.events import EventBus, RuntimeEventType


def _decision():
    return CommandDecision(GateOutcome.NEEDS_CONFIRMATION, "active", "nuclei", ("-u", "https://example.com"), ("https://example.com",))


def test_approval_approved_within_timeout():
    bus = EventBus()
    seen = []
    bus.subscribe(seen.append)
    results = {}

    def ask():
        results["approved"] = requestCommandApproval(_decision(), "m1", bus, timeout=5.0)

    t = threading.Thread(target=ask)
    t.start()
    time.sleep(0.1)
    # find the published nonce and approve it
    nonce = next(e.details["nonce"] for e in seen if e.details.get("kind") == "command_approval")
    assert resolveCommandApproval(nonce, True) is True
    t.join(2.0)
    assert results["approved"] is True


def test_approval_denied():
    bus = EventBus()
    seen = []
    bus.subscribe(seen.append)
    results = {}
    t = threading.Thread(target=lambda: results.__setitem__("r", requestCommandApproval(_decision(), "m1", bus, timeout=5.0)))
    t.start()
    time.sleep(0.1)
    nonce = next(e.details["nonce"] for e in seen if e.details.get("kind") == "command_approval")
    resolveCommandApproval(nonce, False)
    t.join(2.0)
    assert results["r"] is False


def test_approval_times_out_to_false():
    bus = EventBus()
    approved = requestCommandApproval(_decision(), "m1", bus, timeout=0.2)
    assert approved is False


def test_resolve_unknown_nonce_returns_false():
    assert resolveCommandApproval("nope", True) is False


def test_command_approval_event_published():
    bus = EventBus()
    seen = []
    bus.subscribe(seen.append)
    threading.Thread(target=lambda: requestCommandApproval(_decision(), "mX", bus, timeout=0.2)).start()
    time.sleep(0.1)
    evs = [e for e in seen if e.event_type == RuntimeEventType.CHECKPOINT_REACHED]
    assert evs and evs[0].details["kind"] == "command_approval"
    assert evs[0].details["tool"] == "nuclei"


class _FakeAgent:
    def __init__(self, recorder):
        self._recorder = recorder

    def run(self, mission, objective, user_id="local_user", confirm_hook=None, cancel_check=None):
        self._recorder["ran"] = {"objective": objective, "mission": mission.id, "cancelled": bool(cancel_check and cancel_check())}


class _M:
    id = "m-run"
    target = "example.com"
    scope = ["example.com"]


def test_runner_starts_agent_thread():
    rec = {}
    runner = HuntAgentRunner(agent_factory=lambda: _FakeAgent(rec), bus=EventBus())
    runner.start(_M(), "probe example.com")
    time.sleep(0.2)
    assert rec["ran"]["mission"] == "m-run"
    assert "example.com" in rec["ran"]["objective"]


class _BlockingAgent:
    """Polls cancel_check until cancelled (simulates a long-running hunt)."""

    def __init__(self, recorder):
        self._recorder = recorder

    def run(self, mission, objective, user_id="local_user", confirm_hook=None, cancel_check=None):
        for _ in range(500):
            if cancel_check and cancel_check():
                self._recorder["cancelled"] = True
                return
            time.sleep(0.01)
        self._recorder["cancelled"] = False


def test_cancel_stops_a_running_agent():
    rec = {}
    runner = HuntAgentRunner(agent_factory=lambda: _BlockingAgent(rec), bus=EventBus())
    runner.start(_M(), "probe")
    time.sleep(0.1)
    runner.cancel("m-run")
    time.sleep(0.3)
    assert rec.get("cancelled") is True


def test_engine_start_derives_objective():
    captured = {}

    class _Runner:
        def start(self, mission, objective, user_id="local_user"):
            captured["objective"] = objective
            captured["mission"] = mission.id

    AgentHuntEngine(runner=_Runner()).start(_M())
    assert captured["mission"] == "m-run"
    assert "example.com" in captured["objective"]
