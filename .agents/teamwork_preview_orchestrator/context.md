# Context — ARGUS Sprint 1 Recon Intelligence

## Background
ARGUS is an autonomous offensive-security research orchestrator. Sprint 0 established a working E2E execution loop:
`Mission → Planner → TaskScheduler → ToolOrchestrator → ExternalToolExecutor → Parser → Evidence → Completion`

Sprint 1 Goal:
Upgrade the four recon tool parsers (`Subfinder`, `HTTPX`, `Katana`, `Nuclei`) and the executor's evidence creation so that raw output becomes rich, structured, queryable attack-surface data stored consistently in `EvidenceStore` and `Mission` state fields.

## Key Files to Investigate:
- `argus/runtime/parser.py`
- `argus/runtime/executor.py`
- `argus/runtime/mission.py`
- `argus/evidence/model.py`
- `argus/evidence/store.py`
- `tests/runtime/test_e2e_mission.py`
- `tests/planning/test_recon_task_generation.py`
- `ARGUS_CLAUDE_HANDOFF_COMPLETE.md`
