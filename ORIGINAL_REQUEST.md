# Original User Request

## Initial Request — 2026-08-30T17:18:35+05:30

You are the Project Orchestrator for ARGUS Sprint 12: SSRF Validation Collector.

Working directory: /home/varun/argus
Your agent directory: /home/varun/argus/.agents/orchestrator
Original request file: /home/varun/argus/ORIGINAL_REQUEST.md (and /home/varun/argus/.agents/ORIGINAL_REQUEST.md)

## Objective & Requirements
ARGUS is an authorized defensive security assessment platform. This sprint adds a defensive validation module to detect misconfigured server-side URL fetching behavior (SSRF), following the same architecture as existing SQLInjectionCollector, XSSCollector, PathTraversalCollector, and CommandInjectionCollector modules.

### R1. SSRF Validation Collector
Implement a defensive validation collector module that uses the AuthenticatedHttpClient to test discovered endpoint parameters for server-side request forgery (SSRF) misconfigurations. Test injection points include URL/webhook parameters in GET query strings, POST body fields (JSON & form-urlencoded), and HTTP headers (Referer, X-Forwarded-For). Probing for access to internal network addresses (localhost/loopback variants, RFC 1918 private subnets) and cloud metadata service endpoints (AWS IMDSv1/v2, GCP metadata, Azure IMDS).

### R2. Multi-Technique Detection
1. Cloud Metadata Response Detection (AWS IAM role names, GCP instance identifiers, Azure VM metadata JSON).
2. Internal Service Response Detection (Redis PONG, database handshake banners, internal admin page HTML titles).
3. Differential Timing (latency differences internal vs external >= 4s).

### R3. Input Validation Bypass Mutations
Include mutations for server-side URL validation filters: decimal IP notation (2130706433), hexadecimal IP (0x7f000001), octal IP (0177.0.0.1), shortened IP (127.1), URL encoding & double URL encoding, alternative URI schemes (dict, gopher, file), IPv6 representations (::1, ::ffff:127.0.0.1), DNS rebinding patterns. At least 6 distinct bypass strategies.

### R4. Pipeline Connectivity
Wire collector into TaskGenerator DAG after endpoint discovery. Register as internal plugin in tool registry. Confirmed findings must create HAS_VULNERABILITY edges on the attack surface graph.

### R5. Zero Regression & E2E Validation
All 1071+ currently passing tests must continue to pass (`python -m pytest tests/ --ignore=tests/workspace -x -q` exits 0). Write at least 20 new tests.
Write detailed handoff to `/home/varun/argus/.agents/sprint12_ssrf/handoff.md` and `/home/varun/argus/.agents/orchestrator/handoff.md`.

## Execution Instructions
- Maintain your own BRIEFING.md, plan.md, progress.md in your agent directory.
- Use specialists/workers to inspect the codebase, implement modules, and write tests per the Sub-Agent Orchestration Protocol.
- Verify full test suite passing with zero regressions.
- When 100% complete, send completion message with summary.
