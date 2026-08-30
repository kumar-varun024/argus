# DISPATCH LOG

## 2026-08-26T12:32:19Z
Refactor the ARGUS `TaskGenerator` to produce concrete, dependency-aware recon tasks that use explicit `metadata.tool_id` routing instead of legacy specialist references, so the existing dispatcher and registry can execute them end-to-end.

Reference material: Read `/home/varun/argus/ARGUS_CLAUDE_HANDOFF_COMPLETE.md` sections 52-54 for full context on the problem and desired solution. Also read sections 21-26 for dispatcher/scheduler/gap-analyzer context.

## Requirements
1. R1. Concrete recon task generation:
   - `TaskGenerator` must produce recon tasks that each specify an explicit `metadata.tool_id` matching a registered tool in the registry (`subfinder`, `httpx`, `katana_crawler`, `nuclei`), and that declare correct dependency chains so they execute in the right order: subdomain discovery -> live host detection -> endpoint crawling -> vulnerability scanning.
   - No task references `"ReconAgent"` or any other non-existent specialist in `required_specialists`.
2. R2. GapAnalyzer recon-state awareness:
   - `GapAnalyzer` (`argus/planning/gap_analysis.py`) must distinguish between distinct recon states (no subdomains, no live hosts, no endpoints, no vulnerability scan) rather than collapsing all of them into a single "no technologies" gap. It should produce the appropriate gap for the current state so `TaskGenerator` can emit the correct next recon task.
3. R3. Zero regression & test verification:
   - All currently passing tests in the repository must continue to pass (`python -m pytest tests/ --ignore=tests/workspace -x -q`).
   - Add comprehensive unit tests verifying the task generator produces correctly routed, dependency-aware recon tasks and gap analyzer behavior.
   - Verify the dispatcher routing test from the acceptance criteria passes.
