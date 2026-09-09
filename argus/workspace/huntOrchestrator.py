"""Glue between the chat turn and the hunt bridge, plus the live event stream.

Keeps the web layer and ConversationEngine thin: given a chat message, decide
whether it is a hunt command and, if so, produce an approval-card proposal;
and stream a mission's lifecycle events (from the shared runtime event bus) as
Server-Sent Events for the hunt console.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, AsyncGenerator, Dict, Optional

from argus.runtime.events import RuntimeEvent, RuntimeEventType, get_event_bus
from argus.workspace.huntBridge import HuntDispatch, HuntProposal, hunt_bridge
from argus.workspace.huntIntent import parseHuntRequest

TERMINAL_EVENTS = frozenset({
    RuntimeEventType.MISSION_COMPLETED,
    RuntimeEventType.MISSION_FAILED,
    RuntimeEventType.MISSION_CANCELLED,
})
DEFAULT_IDLE_TIMEOUT_SECONDS: float = 15.0


def maybeProposeHunt(message: str, mission_id: Optional[str], user_id: str, bridge=None) -> Optional[HuntProposal]:
    """Return a HuntProposal iff the message is a hunt command, else None."""
    request = parseHuntRequest(message)
    if request is None:
        return None
    return (bridge or hunt_bridge).proposeHunt(request, mission_id or None, user_id)


def proposalToDict(proposal: HuntProposal) -> Dict[str, Any]:
    return {
        "is_hunt": True,
        "allowed": proposal.allowed,
        "reason": proposal.reason,
        "target": proposal.target,
        "profile": proposal.profile,
        "nonce": proposal.nonce,
        "scope_state": proposal.scope_state,
        "establishes_scope": proposal.establishes_scope,
    }


def dispatchToDict(dispatch: HuntDispatch) -> Dict[str, Any]:
    return {"started": dispatch.started, "reason": dispatch.reason, "mission_id": dispatch.mission_id}


def _sseFrame(event: RuntimeEvent) -> str:
    payload = {
        "type": event.event_type.value,
        "mission_id": event.mission_id,
        "timestamp": event.timestamp,
        "details": event.details,
    }
    return f"data: {json.dumps(payload)}\n\n"


async def streamMissionEvents(
    mission_id: str,
    bus=None,
    request=None,
    idle_timeout: float = DEFAULT_IDLE_TIMEOUT_SECONDS,
) -> AsyncGenerator[str, None]:
    """Yield SSE frames for one mission's events: replay matching history, then
    live events until a terminal event or client disconnect. Detaches its bus
    subscription on exit."""
    bus = bus or get_event_bus()
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()
    seen: set = set()

    def _onEvent(event: RuntimeEvent) -> None:
        if event.mission_id == mission_id:
            loop.call_soon_threadsafe(queue.put_nowait, event)

    bus.subscribe(_onEvent)
    try:
        for event in list(bus.get_history()):
            if event.mission_id != mission_id or event.id in seen:
                continue
            seen.add(event.id)
            yield _sseFrame(event)
            if event.event_type in TERMINAL_EVENTS:
                return
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=idle_timeout)
            except asyncio.TimeoutError:
                if request is not None and await request.is_disconnected():
                    return
                yield ": keepalive\n\n"
                continue
            if event.id in seen:
                continue
            seen.add(event.id)
            yield _sseFrame(event)
            if event.event_type in TERMINAL_EVENTS:
                return
    finally:
        bus.unsubscribe(_onEvent)
