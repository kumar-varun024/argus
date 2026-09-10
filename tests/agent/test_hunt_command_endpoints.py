"""Integration tests for the mid-hunt command-approval + cancel endpoints."""
from __future__ import annotations

import threading
import time

from fastapi.testclient import TestClient

from argus.agent.agentRunner import requestCommandApproval
from argus.agent.commandGate import CommandDecision, GateOutcome
from argus.runtime.events import get_event_bus
import argus.workspace.web.app as webapp


def test_command_confirm_unknown_nonce():
    client = TestClient(webapp.app)
    resp = client.post("/hunt/command/confirm", data={"nonce": "nope", "approve": "true"})
    assert resp.status_code == 200
    assert resp.json() == {"resolved": False}


def test_cancel_endpoint():
    client = TestClient(webapp.app)
    resp = client.post("/hunt/cancel", data={"mission_id": "m-any"})
    assert resp.json() == {"cancelled": True}


def test_command_confirm_resolves_pending_approval():
    client = TestClient(webapp.app)
    bus = get_event_bus()
    seen = []
    bus.subscribe(seen.append)
    decision = CommandDecision(GateOutcome.NEEDS_CONFIRMATION, "active", "nuclei", ("-u", "https://example.com"), ("https://example.com",))
    result = {}
    t = threading.Thread(target=lambda: result.__setitem__("approved", requestCommandApproval(decision, "m-ep", bus, timeout=5.0)))
    t.start()
    time.sleep(0.1)
    nonce = next(e.details["nonce"] for e in seen if e.details.get("kind") == "command_approval")

    resp = client.post("/hunt/command/confirm", data={"nonce": nonce, "approve": "true"})
    assert resp.json() == {"resolved": True}
    t.join(2.0)
    assert result["approved"] is True
