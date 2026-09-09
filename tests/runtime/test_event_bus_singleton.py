"""Tests for the shared runtime event bus (argus/runtime/events.py).

These pin the contract the workspace hunt-console SSE stream depends on:
lifecycle publishers route through ONE shared EventBus so a subscriber can
observe them. Prior to the shared instance, publishers created throwaway
EventBus() objects whose subscribers/history went nowhere.
"""
from __future__ import annotations

from argus.runtime.events import EventBus, RuntimeEvent, RuntimeEventType, get_event_bus
from argus.runtime.manager import mission_manager


def test_get_event_bus_returns_shared_instance():
    assert get_event_bus() is get_event_bus()
    assert isinstance(get_event_bus(), EventBus)


def test_subscriber_receives_published_event():
    received: list[RuntimeEvent] = []
    get_event_bus().subscribe(received.append)
    get_event_bus().publish(RuntimeEventType.MISSION_STARTED, "mission-abc", details={"k": "v"})
    assert any(e.mission_id == "mission-abc" and e.event_type == RuntimeEventType.MISSION_STARTED for e in received)


def test_create_mission_publishes_on_shared_bus():
    """mission_manager.create_mission was repointed to get_event_bus(); a
    subscriber on the shared bus must now see MISSION_CREATED (it saw nothing
    when create_mission used a throwaway EventBus())."""
    seen: list[RuntimeEvent] = []
    get_event_bus().subscribe(seen.append)
    mission = mission_manager.create_mission("shared-bus-target.example.com")
    matches = [e for e in seen if e.event_type == RuntimeEventType.MISSION_CREATED and e.mission_id == mission.id]
    assert len(matches) == 1
    assert matches[0].details.get("target") == "shared-bus-target.example.com"
