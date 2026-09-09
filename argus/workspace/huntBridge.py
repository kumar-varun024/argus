"""Executor bridge: the authorization boundary between the chat AI and the
autonomous hunter.

The chat may PROPOSE a hunt (via huntIntent), but only deterministic code here
authorizes and dispatches it (house rule 2.6 — the model is an untrusted
actor):

  * proposeHunt runs the deterministic AuthorizationGate against the target.
    - Bound conversation (has a mission): the target must be IN_SCOPE for that
      operator-defined mission, else denied — chat cannot widen a mission's
      scope.
    - Unbound conversation: there is no scope yet, so the human's explicit
      confirmation IS the authorization; confirming creates a fresh mission
      scoped to exactly that target (no widening).
  * A single-use, TTL-bound nonce is minted on propose and atomically consumed
    on confirm, so an approval cannot be replayed.
  * confirmHunt re-verifies the gate (bound mode) before dispatching via the
    MissionController — never trusting the earlier decision.

Dependencies are injected so tests never start a real hunt.
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple

from argus.authorization.gate import authorization_gate
from argus.authorization.scope import ScopeState
from argus.runtime.manager import mission_manager
from argus.workspace.huntIntent import HuntRequest

HUNT_ACTION: str = "hunt"
DEFAULT_NONCE_TTL_SECONDS: float = 300.0


@dataclass(frozen=True)
class HuntProposal:
    """The result of proposing a hunt: either denied (with a reason) or allowed
    with a single-use nonce the human must confirm."""

    allowed: bool
    reason: str
    target: str
    profile: str
    nonce: Optional[str] = None
    scope_state: Optional[str] = None
    establishes_scope: bool = False


@dataclass(frozen=True)
class HuntDispatch:
    """The result of confirming a hunt."""

    started: bool
    reason: str
    mission_id: Optional[str] = None


@dataclass
class _PendingHunt:
    target: str
    profile: str
    mission_id: Optional[str]
    user_id: str
    created_at: float
    establishes_scope: bool
    consumed: bool = False


def _scopeStateOf(decision) -> Optional[str]:
    scope_decision = getattr(decision, "scope_decision", None)
    state = getattr(scope_decision, "decision", None)
    if state is None:
        return None
    return state.value if hasattr(state, "value") else str(state)


class HuntBridge:
    """Authorizes and dispatches chat-initiated hunts. All external
    collaborators are injectable; defaults are the process singletons."""

    def __init__(
        self,
        gate=None,
        manager=None,
        controller=None,
        now_fn: Callable[[], float] = time.time,
        ttl_seconds: float = DEFAULT_NONCE_TTL_SECONDS,
    ):
        self._gate = gate or authorization_gate
        self._manager = manager or mission_manager
        self._controller = controller
        self._now = now_fn
        self._ttl = ttl_seconds
        self._pending: Dict[str, _PendingHunt] = {}
        self._lock = threading.Lock()

    def _getController(self):
        if self._controller is None:
            from argus.runtime.checkpoint import MissionCheckpointer
            from argus.runtime.controller import MissionController
            self._controller = MissionController(MissionCheckpointer())
        return self._controller

    def _mint(self, request: HuntRequest, mission_id: Optional[str], user_id: str, establishes_scope: bool) -> str:
        nonce = uuid.uuid4().hex
        with self._lock:
            self._pending[nonce] = _PendingHunt(
                target=request.target,
                profile=request.profile,
                mission_id=mission_id,
                user_id=user_id,
                created_at=self._now(),
                establishes_scope=establishes_scope,
            )
        return nonce

    def _claim(self, nonce: str, user_id: str) -> Tuple[Optional[_PendingHunt], str]:
        """Atomically validate and consume a nonce (single-use, replay-proof)."""
        with self._lock:
            pending = self._pending.get(nonce)
            if pending is None:
                return None, "Unknown or expired confirmation."
            if pending.consumed:
                return None, "This confirmation has already been used."
            if pending.user_id != user_id:
                return None, "Confirmation does not belong to this user."
            if self._now() - pending.created_at > self._ttl:
                pending.consumed = True
                return None, "Confirmation expired; please re-issue the hunt."
            pending.consumed = True
            return pending, ""

    def proposeHunt(self, request: HuntRequest, mission_id: Optional[str], user_id: str) -> HuntProposal:
        target = request.target
        if mission_id:
            decision = self._gate.can_execute_action(user_id, HUNT_ACTION, target, mission_id)
            if not decision.allowed:
                return HuntProposal(False, decision.reason, target, request.profile, scope_state=_scopeStateOf(decision))
            nonce = self._mint(request, mission_id, user_id, establishes_scope=False)
            return HuntProposal(
                True, "Target is in scope for the bound mission; awaiting confirmation.",
                target, request.profile, nonce=nonce, scope_state=ScopeState.IN_SCOPE.value,
            )
        nonce = self._mint(request, None, user_id, establishes_scope=True)
        return HuntProposal(
            True, "No mission bound; confirming authorizes a new mission scoped to this target.",
            target, request.profile, nonce=nonce, establishes_scope=True,
        )

    def confirmHunt(self, nonce: str, user_id: str) -> HuntDispatch:
        pending, error = self._claim(nonce, user_id)
        if pending is None:
            return HuntDispatch(False, error)
        if pending.establishes_scope:
            mission = self._manager.create_mission(pending.target)
        else:
            decision = self._gate.can_execute_action(user_id, HUNT_ACTION, pending.target, pending.mission_id)
            if not decision.allowed:
                return HuntDispatch(False, f"Re-verification failed: {decision.reason}")
            mission = self._manager.get_mission(pending.mission_id)
            if mission is None:
                return HuntDispatch(False, "Bound mission no longer exists.")
        self._getController().start(mission)
        return HuntDispatch(True, "Hunt dispatched.", mission_id=mission.id)


hunt_bridge = HuntBridge()
