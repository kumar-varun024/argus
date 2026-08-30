# ARGUS Sprint 12 Orchestration Plan

## Objectives
Deliver the SSRF Validation Collector module adhering to all requirements R1-R5:
- R1: SSRF Validation Collector with AuthenticatedHttpClient, testing GET query, POST JSON/form, headers (Referer, X-Forwarded-For), probing localhost, RFC 1918, cloud metadata.
- R2: Multi-technique detection (AWS/GCP/Azure metadata, internal service Redis/DB/admin responses, differential timing >= 4s).
- R3: Bypass mutations (decimal, hex, octal, shortened IP, URL & double URL encoding, alt schemes dict/gopher/file, IPv6, DNS rebinding patterns, >=6 strategies).
- R4: Pipeline connectivity (TaskGenerator DAG wiring after endpoint discovery, tool registry registration, HAS_VULNERABILITY edges on graph).
- R5: Zero regressions (all 1071+ tests pass) + >=20 comprehensive new tests. Detailed handoffs written to `.agents/sprint12_ssrf/handoff.md` and `.agents/orchestrator/handoff.md`.

## Workflow Phases
1. **Phase 1: Codebase Survey**: Spawn Explorer to analyze existing collectors (`SQLInjectionCollector`, `XSSCollector`, `PathTraversalCollector`, `CommandInjectionCollector`), `AuthenticatedHttpClient`, `TaskGenerator`, DAG wiring, Tool Registry, Graph node/edge definitions, and test structure.
2. **Phase 2: Project Architecture Specification**: Create `PROJECT.md` documenting architecture, feature inventory, contracts, and test targets.
3. **Phase 3: Implementation**: Spawn Worker(s) to implement `SSRFCollector` (or matching naming convention), payloads/mutations/detection techniques, tool registry entry, DAG wiring, and graph edges.
4. **Phase 4: Test Suite Development & Verification**: Spawn Worker / Test Writer to implement unit & integration tests, verifying all 1071+ existing tests pass and >= 20 new tests pass.
5. **Phase 5: Review & Forensic Audit**: Spawn Reviewers, Challenger, and Forensic Auditor to independently verify functionality, robustness, and genuine implementation integrity.
6. **Phase 6: Final Handoff**: Write handoff reports and notify parent/user.
