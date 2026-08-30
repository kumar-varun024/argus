# TaskGenerator & GapAnalyzer Refactoring Progress

## Status: COMPLETED

### Milestones
- [x] Initial codebase and test suite survey (401 existing tests passing).
- [x] Verification of explicit dispatcher tool_id routing test from acceptance criteria.
- [x] Architecture design for concrete recon task templates (`subfinder`, `httpx`, `katana_crawler`, `nuclei`) and dependency chains.
- [x] Architecture design for state-aware `GapAnalyzer` (subdomains -> live hosts -> endpoints -> vulnerability scan).
- [x] Implement changes in `argus/planning/task_generator.py`.
- [x] Implement changes in `argus/planning/gap_analysis.py`.
- [x] Write comprehensive unit tests for `TaskGenerator`, `GapAnalyzer`, dispatcher routing, and execution ordering (`tests/planning/test_recon_task_generation.py`).
- [x] Run full regression suite (`python -m pytest tests/ --ignore=tests/workspace -x -q` -> 416 passed).
- [x] Final handoff report written to `handoff.md`.
