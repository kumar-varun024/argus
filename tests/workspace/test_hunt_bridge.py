"""Spec tests for the hunt executor bridge (huntBridge.py).

Exercises the authorization boundary end-to-end with the REAL AuthorizationGate
and mission_manager (so scope checks are genuine) but a FAKE controller, so no
real hunt is ever launched.
"""
from __future__ import annotations

import pytest

from argus.authorization.scope import ScopeState
from argus.runtime.manager import mission_manager
from argus.workspace.huntBridge import HuntBridge
from argus.workspace.huntIntent import HuntRequest


class FakeController:
    def __init__(self):
        self.started = []

    def start(self, mission):
        self.started.append(mission)


def _request(target: str, profile: str = "recon") -> HuntRequest:
    return HuntRequest(action="hunt", target=target, profile=profile, raw_message=f"scan {target}")


def _bound_mission(target: str, scope: list[str]):
    mission = mission_manager.create_mission(target)
    mission.scope = scope
    return mission


def test_bound_in_scope_proposes_then_dispatches():
    fake = FakeController()
    bridge = HuntBridge(controller=fake)
    mission = _bound_mission("example.com", ["example.com", "*.example.com"])

    proposal = bridge.proposeHunt(_request("example.com"), mission.id, "local_user")
    assert proposal.allowed is True
    assert proposal.nonce
    assert proposal.scope_state == ScopeState.IN_SCOPE.value

    dispatch = bridge.confirmHunt(proposal.nonce, "local_user")
    assert dispatch.started is True
    assert dispatch.mission_id == mission.id
    assert fake.started == [mission]


def test_bound_out_of_scope_is_denied_without_nonce():
    fake = FakeController()
    bridge = HuntBridge(controller=fake)
    mission = _bound_mission("example.com", ["example.com"])

    proposal = bridge.proposeHunt(_request("evil.com"), mission.id, "local_user")
    assert proposal.allowed is False
    assert proposal.nonce is None
    assert proposal.scope_state == ScopeState.OUT_OF_SCOPE.value
    assert fake.started == []


def test_unbound_confirmation_creates_scoped_mission_and_dispatches():
    fake = FakeController()
    bridge = HuntBridge(controller=fake)

    proposal = bridge.proposeHunt(_request("newtarget.example.org"), None, "local_user")
    assert proposal.allowed is True
    assert proposal.establishes_scope is True
    assert proposal.nonce

    dispatch = bridge.confirmHunt(proposal.nonce, "local_user")
    assert dispatch.started is True
    assert dispatch.mission_id
    created = mission_manager.get_mission(dispatch.mission_id)
    assert created.target == "newtarget.example.org"
    assert fake.started == [created]


def test_nonce_is_single_use_replay_rejected():
    fake = FakeController()
    bridge = HuntBridge(controller=fake)
    proposal = bridge.proposeHunt(_request("replay.example.com"), None, "local_user")

    first = bridge.confirmHunt(proposal.nonce, "local_user")
    second = bridge.confirmHunt(proposal.nonce, "local_user")

    assert first.started is True
    assert second.started is False
    assert "already been used" in second.reason
    assert len(fake.started) == 1  # dispatched exactly once


def test_unknown_nonce_rejected():
    bridge = HuntBridge(controller=FakeController())
    dispatch = bridge.confirmHunt("does-not-exist", "local_user")
    assert dispatch.started is False
    assert "Unknown" in dispatch.reason


def test_expired_nonce_rejected():
    fake = FakeController()
    clock = {"t": 1000.0}
    bridge = HuntBridge(controller=fake, now_fn=lambda: clock["t"], ttl_seconds=300.0)
    proposal = bridge.proposeHunt(_request("expire.example.com"), None, "local_user")

    clock["t"] = 1000.0 + 301.0
    dispatch = bridge.confirmHunt(proposal.nonce, "local_user")
    assert dispatch.started is False
    assert "expired" in dispatch.reason.lower()
    assert fake.started == []


def test_confirmation_bound_to_issuing_user():
    fake = FakeController()
    bridge = HuntBridge(controller=fake)
    proposal = bridge.proposeHunt(_request("userbound.example.com"), None, "alice")

    dispatch = bridge.confirmHunt(proposal.nonce, "bob")
    assert dispatch.started is False
    assert "does not belong" in dispatch.reason
    assert fake.started == []
