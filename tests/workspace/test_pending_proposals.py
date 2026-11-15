"""Exercise the pending-proposal feed with a recording-only controller."""

from copy import deepcopy
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

from argus.workspace.huntBridge import HuntBridge
from argus.workspace.huntIntent import HuntRequest
from argus.workspace.models import Conversation
import argus.workspace.web.app as webapp


AUTH = {"Authorization": "Bearer fixture-operator"}


@pytest.fixture
def pending_workspace(monkeypatch):
    now = [1_800_000_000.0]
    start_signals = []
    bridge = HuntBridge(
        gate=SimpleNamespace(can_execute_action=lambda *_: SimpleNamespace(allowed=True)),
        controller=SimpleNamespace(start=start_signals.append),
        now_fn=lambda: now[0],
    )
    monkeypatch.setattr(webapp, "hunt_bridge", bridge)
    monkeypatch.setenv("ARGUS_ALLOWED_HOSTS", "127.0.0.1:8000")
    monkeypatch.setenv("ARGUS_OPERATOR_TOKENS", "local_user:fixture-operator,bob:fixture-bob")
    with TestClient(webapp.app, base_url="http://127.0.0.1:8000") as client:
        yield client, bridge, now, start_signals


def propose(bridge, target, *, operator_id="local_user", mission_id=None):
    proposal = bridge.proposeHunt(HuntRequest("hunt", target, "recon", "fixture"), mission_id, operator_id)
    assert proposal.allowed and proposal.nonce
    return proposal.nonce


@pytest.mark.parametrize("headers, status", [
    ({}, 401),
    ({"Authorization": "Bearer wrong"}, 401),
    ([*AUTH.items(), ("Authorization", "Bearer duplicated")], 401),
    ({**AUTH, "Host": "untrusted.example.test"}, 403),
])
def test_pending_feed_checks_host_and_bearer(pending_workspace, headers, status):
    client, _, _, _ = pending_workspace
    response = client.get("/hunt/pending", headers=headers)
    assert response.status_code == status
    assert response.headers["cache-control"] == "no-store"
    assert "proposals" not in response.json()


def test_pending_feed_refuses_ambiguous_operator_configuration(pending_workspace, monkeypatch):
    client, _, _, _ = pending_workspace
    monkeypatch.setenv("ARGUS_OPERATOR_TOKENS", "local_user:fixture-operator,bob:fixture-operator")
    assert client.get("/hunt/pending", headers=AUTH).status_code == 401


def test_pending_feed_is_read_only_and_hides_expired_consumed_and_other_owner_rows(pending_workspace):
    client, bridge, now, start_signals = pending_workspace
    expired = propose(bridge, "expired.example.test")
    now[0] += 300
    consumed = propose(bridge, "consumed.example.test")
    assert bridge._claim(consumed, "local_user")[0] is not None
    other_owner = propose(bridge, "other-owner.example.test", operator_id="bob")
    active = propose(bridge, "https://user:credential@active.example.test:8443/private?token=secret#fragment")
    before = deepcopy(bridge._pending)

    response = client.get("/hunt/pending", headers=AUTH)
    repeated = client.get("/hunt/pending", headers=AUTH)
    assert response.status_code == repeated.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == repeated.json()
    (row,) = response.json()["proposals"]
    assert row == {
        "proposal_id": row["proposal_id"],
        "target": "https://active.example.test:8443",
        "profile": "recon",
        "mission_id": None,
        "expires_at": now[0] + 300,
        "review": None,
        "conversation_id": "",
    }
    assert row["proposal_id"].startswith("review-")
    assert all(nonce not in response.text for nonce in (expired, consumed, other_owner, active))
    assert all(secret not in response.text for secret in ("credential", "/private", "token=", "fragment"))
    assert client.post("/hunt/pending", headers=AUTH).status_code == 405
    assert bridge._pending == before
    assert start_signals == []


def test_pending_feed_filters_by_owned_conversation_mission(pending_workspace):
    client, bridge, _, start_signals = pending_workspace
    owned = Conversation(title="Owned", user_id="local_user", mission_id="fixture-mission")
    foreign = Conversation(title="Foreign", user_id="bob", mission_id=owned.mission_id)
    unbound = Conversation(title="Unbound", user_id="local_user")
    for conversation in (owned, foreign, unbound):
        webapp.repository.save(conversation)
    propose(bridge, "different-mission.example.test", mission_id="different-mission")
    propose(bridge, "home.example.test")
    response = client.post("/hunt/propose", data={
        "cid": owned.conversation_id, "message": "scan pending.example.test",
    })
    assert response.json()["allowed"] is True

    home = client.get("/hunt/pending", headers=AUTH).json()["proposals"]
    scoped = client.get("/hunt/pending", headers=AUTH, params={"cid": owned.conversation_id})
    assert [item["target"] for item in home] == ["home.example.test"]
    assert [item["target"] for item in scoped.json()["proposals"]] == ["pending.example.test"]
    assert client.get("/hunt/pending", headers=AUTH, params={"cid": foreign.conversation_id}).status_code == 404
    assert client.get("/hunt/pending", headers=AUTH, params={"cid": unbound.conversation_id}).json() == {"proposals": []}
    assert start_signals == []


@pytest.mark.parametrize("change, status", [("credential", 401), ("conversation", 404)])
def test_pending_feed_rechecks_access_before_sending_data(pending_workspace, monkeypatch, change, status):
    client, bridge, _, _ = pending_workspace
    conversation = Conversation(title="Owned", user_id="local_user", mission_id="fixture-mission")
    webapp.repository.save(conversation)
    propose(bridge, "pending.example.test", mission_id=conversation.mission_id)
    read_pending = bridge.pending_proposals

    def read_then_change(operator_id, mission_id):
        proposals = read_pending(operator_id, mission_id)
        assert len(proposals) == 1
        if change == "credential":
            monkeypatch.setenv("ARGUS_OPERATOR_TOKENS", "local_user:rotated-operator")
        else:
            conversation.mission_id = "replacement-mission"
        return proposals

    monkeypatch.setattr(bridge, "pending_proposals", read_then_change)
    response = client.get("/hunt/pending", headers=AUTH, params={"cid": conversation.conversation_id})
    assert response.status_code == status
    assert response.headers["cache-control"] == "no-store"
    assert "pending.example.test" not in response.text
