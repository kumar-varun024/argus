"""Integration tests for the hunt web endpoints + SSE event stream.

The web module's `hunt_bridge` is monkeypatched to one with a FAKE controller,
so /hunt/confirm never launches a real hunt.
"""
from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from argus.runtime.events import EventBus, RuntimeEventType
from argus.runtime.manager import mission_manager
from argus.workspace import huntOrchestrator
from argus.workspace.huntBridge import HuntBridge
from argus.workspace.models import Conversation
import argus.workspace.web.app as webapp


class FakeController:
    def __init__(self):
        self.started = []

    def start(self, mission):
        self.started.append(mission)


@pytest.fixture
def client_with_fake_bridge(monkeypatch):
    fake = FakeController()
    bridge = HuntBridge(controller=fake)
    monkeypatch.setattr(webapp, "hunt_bridge", bridge)
    return TestClient(webapp.app), bridge, fake


def test_propose_non_hunt_message(client_with_fake_bridge):
    client, _, _ = client_with_fake_bridge
    resp = client.post("/hunt/propose", data={"message": "tell me about the evidence"})
    assert resp.status_code == 200
    assert resp.json() == {"is_hunt": False}


def test_propose_and_confirm_unbound_roundtrip(client_with_fake_bridge):
    client, _, fake = client_with_fake_bridge
    proposal = client.post("/hunt/propose", data={"message": "scan roundtrip.example.com"}).json()
    assert proposal["is_hunt"] is True
    assert proposal["allowed"] is True
    assert proposal["establishes_scope"] is True
    assert proposal["nonce"]

    confirm = client.post("/hunt/confirm", data={"nonce": proposal["nonce"]}).json()
    assert confirm["started"] is True
    assert confirm["mission_id"]
    assert len(fake.started) == 1
    assert mission_manager.get_mission(confirm["mission_id"]).target == "roundtrip.example.com"


def test_confirm_replay_rejected_via_endpoint(client_with_fake_bridge):
    client, _, fake = client_with_fake_bridge
    nonce = client.post("/hunt/propose", data={"message": "scan replay-ep.example.com"}).json()["nonce"]
    first = client.post("/hunt/confirm", data={"nonce": nonce}).json()
    second = client.post("/hunt/confirm", data={"nonce": nonce}).json()
    assert first["started"] is True
    assert second["started"] is False
    assert len(fake.started) == 1


def test_propose_bound_out_of_scope(client_with_fake_bridge):
    client, _, _ = client_with_fake_bridge
    mission = mission_manager.create_mission("inscope.example.com")
    mission.scope = ["inscope.example.com"]
    conv = Conversation(title="c", user_id="local_user", mission_id=mission.id)
    webapp.repository.save(conv)

    resp = client.post("/hunt/propose", data={"cid": conv.conversation_id, "message": "scan outofscope.example.net"}).json()
    assert resp["is_hunt"] is True
    assert resp["allowed"] is False
    assert resp["scope_state"] == "OUT_OF_SCOPE"
    assert resp["nonce"] is None


def test_event_bus_unsubscribe():
    bus = EventBus()
    baseline = len(bus.subscribers)
    cb = lambda e: None
    bus.subscribe(cb)
    assert len(bus.subscribers) == baseline + 1
    bus.unsubscribe(cb)
    assert len(bus.subscribers) == baseline
    bus.unsubscribe(cb)  # no error when absent


def test_stream_replays_history_filters_and_stops_at_terminal():
    bus = EventBus()
    bus.publish(RuntimeEventType.MISSION_CREATED, "m1", {"target": "x"})
    bus.publish(RuntimeEventType.PLAN_CREATED, "m1", {"steps_count": 3})
    bus.publish(RuntimeEventType.MISSION_STARTED, "other-mission", {})
    bus.publish(RuntimeEventType.MISSION_COMPLETED, "m1", {})
    bus.publish(RuntimeEventType.PLAN_CREATED, "m1", {"after": "terminal"})

    async def drain():
        frames = []
        async for frame in huntOrchestrator.streamMissionEvents("m1", bus=bus, idle_timeout=0.05):
            frames.append(frame)
        return frames

    joined = "".join(asyncio.run(drain()))
    assert "MissionCreated" in joined
    assert "MissionCompleted" in joined
    assert "other-mission" not in joined            # other mission filtered out
    assert joined.count("PlanCreated") == 1          # post-terminal event never emitted
    assert len(bus.subscribers) == 1                 # stream unsubscribed on exit (only observability logger left)
