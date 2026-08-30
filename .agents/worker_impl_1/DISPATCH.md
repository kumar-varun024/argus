## 2026-08-28T12:15:10Z

You are the Lead Implementation Worker for Sprint 5 of ARGUS: Information Disclosure Engine (Phase 6 Roadmap).
Your working directory is: /home/varun/argus/.agents/worker_impl_1/
Please read the original request at /home/varun/argus/.agents/ORIGINAL_REQUEST.md and the project specification at /home/varun/argus/.agents/PROJECT.md.

Also read the survey reports:
- /home/varun/argus/.agents/explorer_survey_1/survey_collector.md
- /home/varun/argus/.agents/explorer_survey_2/survey_parsing_graph.md
- /home/varun/argus/.agents/explorer_survey_3/survey_dag_testing.md

## MANDATORY INTEGRITY WARNING
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

## Tasks to Implement:
1. **R1 & R2: Collector & Wordlist Probing**:
   - Create `argus/collectors/information_disclosure.py` with `InformationDisclosureCollector(BaseCollector)`:
     - `__init__(self, http_client=None, wordlist=None, secret_extractor=None)`
     - Export `InformationDisclosureCollector` in `argus/collectors/__init__.py`.
     - Ingest discovered endpoints (`mission.endpoints`), subdomains (`mission.subdomains`), and live hosts (`mission.live_hosts`).
     - Use `AuthenticatedHttpClient` (`argus/http/client.py`) to actively probe high-value wordlist paths:
       `.git/config`, `.env`, `phpinfo.php`, `.js.map`, `/actuator/env`, `/actuator/heapdump`, plus variations like `.env.local`, `.git/HEAD`, `/actuator/configprops`.
     - Ensure requests respect mission scope and handle non-200 responses gracefully.
2. **R3: Secret Extraction & Artifact Parsing**:
   - Implement comprehensive parsing on HTTP 200 responses:
     - API keys (Google `AIza...`, Stripe `sk_live_...`, GitHub `ghp_...`, Slack tokens/webhooks, generic API keys).
     - AWS keys (`AKIA...`, `aws_secret_access_key`).
     - JWT tokens (`eyJ...`).
     - Passwords / credentials (`DB_PASSWORD=...`, cleartext passwords).
     - Database connection strings (`postgres://...`, `mysql://...`, `mongodb://...`, `redis://...`).
     - Private RFC 1918 IPs (`10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`).
     - Internal hostnames/domains (`*.internal`, `*.corp`, `*.local`, `*.lan`, `*.cluster.local`, and subdomains of `mission.target`).
   - Emit `Evidence(category="information_disclosure", severity="high")` with complete metadata (url, path, status_code=200, secrets, internal_domains).
   - Append finding to `mission.vulnerabilities` and `mission.evidence`.
3. **R4: DAG Integration & Attack Surface Graph Expansion**:
   - Register `Tool(id="info_disclosure", capability="information_disclosure_detector", ...)` in `argus/runtime/registry.py`.
   - Update `argus/planning/task_generator.py`: add `"info_disclosure"` recon task template (priority 0.82, dependency on `"Fingerprint Live Hosts"`), update `generate_recon_tasks()` and `from_gaps()`.
   - Update `argus/planning/gap_analysis.py` (and `steps.py` if applicable) for Information Disclosure gap detection.
   - Attack surface graph feedback loop:
     - Discovered internal domains/subdomains are added to `mission.subdomains` (if new).
     - Emit `Evidence(category="subdomain", value=domain)`.
     - Add nodes and edges in `KnowledgeGraph` (`endpoint`, `vulnerability`, `subdomain`, `secret`) and connect via `HAS_VULNERABILITY`, `DISCLOSED_SUBDOMAIN`, `RESOLVES_TO`.
4. **R5: Comprehensive Tests & Zero Regression**:
   - Implement at least 10 new high-quality tests across:
     - `tests/collectors/test_information_disclosure.py`
     - `tests/planning/test_info_disclosure_task_generation.py`
     - `tests/runtime/test_e2e_info_disclosure.py`
   - Include an E2E integration test mocking `.env` discovery with assertions for collector invocation, Evidence generation, and graph loop feedback.
   - Execute verification: `python -m pytest tests/ --ignore=tests/workspace -x -q` and verify all 646+ existing tests pass with 0 failures and all new tests pass.

5. **Handoff Documentation**:
   - Write comprehensive implementation report and handoff to BOTH:
     - `/home/varun/argus/.agents/sprint5_impl/handoff.md`
     - `/home/varun/argus/.agents/worker_impl_1/handoff.md`
   - Send completion message to orchestrator when finished.
