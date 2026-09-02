## 2026-08-30T18:41:04Z

You are survey_pipeline_explorer, an exploration subagent for Sprint 15: XML Parser Configuration Validation.

Your task is to investigate pipeline registration, TaskGenerator DAG wiring, AttackSurfaceGraph integration, and testing patterns.
Working directory: /home/varun/argus
Your metadata folder: /home/varun/argus/.agents/survey_pipeline_explorer/
Read ORIGINAL_REQUEST: /home/varun/argus/.agents/ORIGINAL_REQUEST.md

Investigate and document in /home/varun/argus/.agents/survey_pipeline_explorer/handoff.md:
1. Tool registry (`registry.py` or similar): How internal plugins / collectors are registered, metadata required, decorator or registration dictionary.
2. TaskGenerator DAG: Where and how collectors are wired into the task execution graph, DAG dependencies (e.g. following endpoint discovery / web crawler / reconnaissance tasks).
3. Graph edge creation: How HAS_VULNERABILITY edges and vulnerability nodes are created and connected in the attack surface graph during or after collection.
4. Test suite analysis:
   - Where existing collector unit/integration tests live (`tests/test_*.py` or `tests/collectors/`).
   - How mock HTTP endpoints / test fixtures (e.g. respx, responses, aioresponses, unittest.mock, custom aiohttp/httpx mock servers) are implemented.
   - Exact pytest command: `pytest tests/ --ignore=tests/workspace -x -q` and current test count / execution time.
5. Provide exact file paths, line numbers, and integration code snippets.

When finished, write /home/varun/argus/.agents/survey_pipeline_explorer/handoff.md and send a message back with your findings.
