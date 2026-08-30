# Orchestration Plan — ARGUS Sprint 1 Recon Intelligence

## Milestone Sequence
1. **M1: R1 Subfinder Normalization**
   - Files: `argus/runtime/parser.py`, `argus/runtime/executor.py`, `argus/collectors/subfinder.py`
   - Scope: Update `ReconParser.parse_subfinder` to return `list[dict]` with `"hostname"` and `"source"`. Update `ExternalToolExecutor.execute()` to preserve `mission.subdomains` as `list[str]` and store `Evidence(category="subdomain", metadata={"source": "subfinder", "hostname": hostname})`.
   - Gate: Worker -> Reviewer -> Challenger -> Auditor.

2. **M2: R2 HTTPX Normalization**
   - Files: `argus/runtime/parser.py`, `argus/runtime/executor.py`
   - Scope: Update `ReconParser.parse_httpx` to return all 8 required keys, derive missing fields from URL, normalize technologies. Update `ExternalToolExecutor.execute()` to store dicts in `mission.live_hosts`, create `category="live_host"` Evidence with full metadata, create separate `category="technology"` Evidence items, and populate `mission.technologies`.
   - Gate: Worker -> Reviewer -> Challenger -> Auditor.

3. **M3: R3 Katana Normalization**
   - Files: `argus/runtime/parser.py`, `argus/runtime/executor.py`, `argus/collectors/katana.py`
   - Scope: Update `ReconParser.parse_katana` to parse plain URLs and JSONL into `list[dict]` with `url`, `path`, `host`, `method`, `params`. Update `ExternalToolExecutor.execute()` to store dicts in `mission.endpoints` and create `category="endpoint"` Evidence with metadata. Update `KatanaCollector` set deduplication to use URL strings.
   - Gate: Worker -> Reviewer -> Challenger -> Auditor.

4. **M4: R4 Nuclei Normalization**
   - Files: `argus/runtime/parser.py`, `argus/runtime/executor.py`, `argus/runtime/mission.py`
   - Scope: Update `ReconParser.parse_nuclei` to return full vulnerability dicts, handle null info defensively. Add `vulnerabilities` field to `Mission` dataclass. Update `ExternalToolExecutor.execute()` to store dicts in `mission.vulnerabilities` and create `category="vulnerability"` Evidence with `severity=vuln.severity.lower()` and full metadata.
   - Gate: Worker -> Reviewer -> Challenger -> Auditor.

5. **M5: R5 Testing & Regression Verification**
   - Files: `tests/runtime/test_recon_parsers.py`, `tests/runtime/test_e2e_mission.py`
   - Scope: Create comprehensive parser unit tests and verification script test. Update E2E assertions for evidence categories, metadata, and mission state fields. Run full 427+ regression test suite.
   - Gate: Worker -> Reviewer -> Challenger -> Auditor.
