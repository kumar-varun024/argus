"""Gated agentic command executor for authorized hunting.

An LLM plans -> a deterministic gate authorizes -> an isolated sandbox runs.
The model never gets raw shell: every command is checked against a tool
allowlist, an argument policy, and per-target mission scope BEFORE execution
(house rule 2.6 -- the model is untrusted).
"""
