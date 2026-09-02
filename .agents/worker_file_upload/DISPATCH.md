## 2026-09-01T20:33:00Z

You are the Lead Security Implementation Engineer & QA Specialist for ARGUS Sprint 26.
Your working directory for metadata and progress is: `/home/varun/argus/.agents/worker_file_upload/`.

MANDATORY FIRST STEP:
Read the following authoritative specification files on disk before starting:
1. `/home/varun/argus/.agents/ORIGINAL_REQUEST.md`
2. `/home/varun/argus/.agents/orchestrator/PROJECT.md`
3. `/home/varun/argus/.agents/orchestrator/implementation_plan.md`
4. `/home/varun/argus/.agents/survey_explorer_3/handoff.md`

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine defensive security scanning logic. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A forensic auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Core Tasks:
1. Implement the defensive `FileUploadCollector` module in `/home/varun/argus/argus/collectors/file_upload.py` with all required enums, dataclasses, generator, analyzer, prober (using `AuthenticatedHttpClient`), and `FileUploadCollector(BaseCollector)` supporting quadruple state publishing (`mission.evidence`, `mission.vulnerabilities`, `mission.attack_surface_graph` with `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges, and `mission.publish_finding`).
2. Update `/home/varun/argus/argus/http/client.py` to ensure multipart `files` argument is supported in `request()` and `post()`.
3. Export all public collector classes in `/home/varun/argus/argus/collectors/__init__.py`.
4. Register the tool and fallback in `/home/varun/argus/argus/runtime/registry.py` and `/home/varun/argus/argus/runtime/plugins.py`.
5. Wire the DAG task template and gap resolver in `/home/varun/argus/argus/planning/task_generator.py`.
6. Add the graph builder section in `/home/varun/argus/argus/graph/attack_surface.py`.
7. Add CWE-434 and CWE-436 definitions and CVSS rules in `/home/varun/argus/argus/reporting/cvss.py`.
8. Implement comprehensive test suites:
   - `tests/collectors/test_file_upload.py` (functional & integration tests)
   - `tests/collectors/test_file_upload_adversarial.py` (adversarial, evasion, and false-positive rejection tests)
9. Verify all new tests and full test suite with zero regressions:
   - `python -m pytest tests/collectors/test_file_upload.py tests/collectors/test_file_upload_adversarial.py -v`
   - `python -m pytest tests/ --ignore=tests/workspace -x -q` (must pass 1,814+ tests with 0 failures).
10. Write your victory audit and detailed handoff report to `/home/varun/argus/.agents/worker_file_upload/handoff.md` and send a final completion message to parent.
