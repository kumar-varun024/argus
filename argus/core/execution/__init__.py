"""
Shared execution core.

Machinery common to both execution tiers (the deterministic scan engine and the
autonomous mission runtime): collector/tool resolution today, with the task
model, capability registry, and state machine to follow. Modules here must not
import the engines (``argus.scanning`` / ``argus.runtime`` orchestrators) — the
dependency direction is engines -> core, never the reverse.
"""
