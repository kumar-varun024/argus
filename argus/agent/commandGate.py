"""The deterministic command gate: the single authority on whether a proposed
command may run. Combines the tool allowlist + argument policy (toolCatalog)
with per-target mission-scope verification (authorization_gate) and the autonomy
policy (which allowlisted+in-scope tools auto-run vs. require human confirmation).

This runs OUTSIDE the model prompt. The LLM proposes {tool, args}; this code —
never the model — decides. Fail-closed: no allowlisted tool, a bad argument, a
command with no scope-checkable target, or any target out of scope => DENY.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple

from argus.agent.toolCatalog import extractTargets, isAllowedTool, validateArgs
from argus.authorization.gate import authorization_gate

HUNT_ACTION: str = "hunt"

# Allowlisted+in-scope tools that run without per-command confirmation: passive
# recon / fingerprinting only. Everything else that passes the gate is returned
# as NEEDS_CONFIRMATION so a human approves each active/noisy command.
AUTO_TOOLS = frozenset({"dig", "whois", "whatweb", "wafw00f", "httpx"})


class GateOutcome(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    NEEDS_CONFIRMATION = "NEEDS_CONFIRMATION"


@dataclass(frozen=True)
class CommandDecision:
    outcome: GateOutcome
    reason: str
    tool_id: str
    args: Tuple[str, ...]
    targets: Tuple[str, ...]


def _deny(reason: str, tool_id: str, args: List[str], targets: Tuple[str, ...] = ()) -> CommandDecision:
    return CommandDecision(GateOutcome.DENY, reason, tool_id, tuple(args), targets)


def authorizeCommand(
    tool_id: str,
    args: List[str],
    mission_id: Optional[str],
    user_id: str = "local_user",
    gate=None,
) -> CommandDecision:
    """Authorize one proposed command. Returns ALLOW (auto-run),
    NEEDS_CONFIRMATION (in scope, human must approve), or DENY (with reason)."""
    gate = gate or authorization_gate
    args = list(args)

    if not isAllowedTool(tool_id):
        return _deny(f"Tool '{tool_id}' is not on the allowlist.", tool_id, args)

    ok, reason = validateArgs(tool_id, args)
    if not ok:
        return _deny(reason, tool_id, args)

    targets = extractTargets(tool_id, args)
    if not targets:
        return _deny("Command has no scope-checkable target; refusing (fail-closed).", tool_id, args)

    if not mission_id:
        return _deny("No mission bound; cannot verify scope.", tool_id, args, tuple(targets))

    for target in targets:
        decision = gate.can_execute_action(user_id, HUNT_ACTION, target, mission_id)
        if not decision.allowed:
            return _deny(f"Target '{target}' is out of scope: {decision.reason}", tool_id, args, tuple(targets))

    if tool_id in AUTO_TOOLS:
        return CommandDecision(GateOutcome.ALLOW, "Passive tool, all targets in scope.", tool_id, tuple(args), tuple(targets))
    return CommandDecision(
        GateOutcome.NEEDS_CONFIRMATION,
        "In scope, but an active tool that requires confirmation.",
        tool_id, tuple(args), tuple(targets),
    )
