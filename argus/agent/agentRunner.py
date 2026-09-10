"""Runs the HuntAgent loop in a background thread and brokers per-command
human approvals for active tools.

When the agent hits a NEEDS_CONFIRMATION command its background thread blocks on
a one-shot approval keyed by a single-use nonce, after publishing a
command-approval event to the shared bus (the hunt console renders it as an
inline card). The human POSTs the nonce to resolve it; on timeout the command
is skipped. `start(mission)` is the engine interface huntBridge dispatches to —
so confirming a hunt now launches the agent.
"""
from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from argus.agent.commandGate import CommandDecision
from argus.agent.huntAgent import HuntAgent
from argus.runtime.events import RuntimeEventType, get_event_bus

APPROVAL_TIMEOUT_SECONDS: float = 180.0


@dataclass
class _PendingApproval:
    event: threading.Event
    mission_id: str
    tool_id: str
    approved: bool = False


_approvals: Dict[str, _PendingApproval] = {}
_approvals_lock = threading.Lock()


def requestCommandApproval(decision: CommandDecision, mission_id: str, bus=None,
                           timeout: float = APPROVAL_TIMEOUT_SECONDS) -> bool:
    """Publish a command-approval request and block until resolved or timed out.
    Returns True only if a human explicitly approved within the timeout."""
    bus = bus or get_event_bus()
    nonce = uuid.uuid4().hex
    event = threading.Event()
    with _approvals_lock:
        _approvals[nonce] = _PendingApproval(event, mission_id, decision.tool_id)
    bus.publish(RuntimeEventType.CHECKPOINT_REACHED, mission_id, details={
        "kind": "command_approval",
        "nonce": nonce,
        "tool": decision.tool_id,
        "args": list(decision.args),
        "targets": list(decision.targets),
        "reason": decision.reason,
    })
    resolved = event.wait(timeout)
    with _approvals_lock:
        pending = _approvals.pop(nonce, None)
    return bool(resolved and pending and pending.approved)


def resolveCommandApproval(nonce: str, approve: bool) -> bool:
    """Resolve a pending command approval (from the UI). Returns True if the
    nonce was pending (single-use); False if unknown/already resolved."""
    with _approvals_lock:
        pending = _approvals.get(nonce)
        if pending is None:
            return False
        pending.approved = bool(approve)
        pending.event.set()
    return True


class HuntAgentRunner:
    """Owns the background agent threads and the cancel (kill-switch) events."""

    def __init__(self, agent_factory: Optional[Callable[[], HuntAgent]] = None, bus=None):
        self._agent_factory = agent_factory or (lambda: HuntAgent())
        self._bus = bus or get_event_bus()
        self._cancels: Dict[str, threading.Event] = {}

    def start(self, mission: Any, objective: str, user_id: str = "local_user") -> None:
        mission_id = getattr(mission, "id", "unknown")
        cancel = threading.Event()
        self._cancels[mission_id] = cancel

        def _run():
            agent = self._agent_factory()
            agent.run(
                mission, objective, user_id,
                confirm_hook=lambda decision: requestCommandApproval(decision, mission_id, self._bus),
                cancel_check=cancel.is_set,
            )

        thread = threading.Thread(target=_run, name=f"HuntAgent-{mission_id}", daemon=True)
        thread.start()

    def cancel(self, mission_id: str) -> None:
        event = self._cancels.get(mission_id)
        if event:
            event.set()


hunt_agent_runner = HuntAgentRunner()


class AgentHuntEngine:
    """Adapter exposing the `.start(mission)` interface huntBridge dispatches to,
    so confirming a hunt launches the agent loop."""

    def __init__(self, runner: Optional[HuntAgentRunner] = None):
        self._runner = runner or hunt_agent_runner

    def start(self, mission: Any) -> None:
        target = getattr(mission, "target", "") or "the target"
        objective = f"Find and validate security vulnerabilities on {target}, strictly within the authorized scope."
        self._runner.start(mission, objective)
