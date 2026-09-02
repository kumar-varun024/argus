## 2026-08-30T20:17:07Z
You are the Verification & QA Specialist for Sprint 16: Insecure Deserialization Detection Module.

Working directory: /home/varun/argus
Your agent directory: /home/varun/argus/.agents/worker_qa/
Please read:
- /home/varun/argus/ORIGINAL_REQUEST.md
- /home/varun/argus/PROJECT.md
- /home/varun/argus/.agents/orchestrator/implementation_plan.md

### Mandate
1. Run pytest on the new deserialization test suites:
   `python -m pytest tests/collectors/test_deserialization.py tests/collectors/test_deserialization_adversarial.py -v`
2. Run the full regression test suite:
   `python -m pytest tests/ --ignore=tests/workspace -x -q`
3. Verify that all Acceptance Criteria are met:
   - Java deserialization error signatures produce critical Evidence.
   - Python pickle / PHP unserialize error signatures produce Evidence.
   - Normal responses with base64 data do NOT produce false positives.
   - At least 5 distinct serialization format bypass strategies are implemented and tested.
   - Tool is registered in `registry.py` and scheduled in `TaskGenerator` DAG.
   - Confirmed findings create `HAS_VULNERABILITY` and `HAS_ENDPOINT` edges in `AttackSurfaceGraph`.
   - All 1,307+ existing tests continue to pass (zero regressions) and at least 20 new tests added.
4. If any test fails or any edge case is missing, make the necessary fixes in `argus/collectors/deserialization.py`, `tests/collectors/test_deserialization.py`, or integration files until 100% passing.
5. Write a comprehensive Victory Audit and verification report to `/home/varun/argus/.agents/worker_qa/handoff.md`.
6. Send a completion message to the caller when done.
