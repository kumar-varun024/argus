# BRIEFING — 2026-09-01T01:17:00+05:30

## Mission
Investigate requirements and technical specifications for Web Cache Poisoning & Cache Deception Detection Module in ARGUS (R1-R5: Cache Security Collector & Prober, Multi-Vector Detection Modes, Mutation & Evasion Strategies, Pipeline/Graph connectivity, and False Positive Rejection Rules).

## 🔒 My Identity
- Archetype: specification_miner
- Roles: Specification Mining Specialist, Concurrency Testing & Security Specification Specialist
- Working directory: /home/varun/argus/.agents/survey_spec_miner
- Original parent: bd1437ca-69f9-48ac-a1a2-96f044de54e2
- Milestone: Sprint 20 Race Conditions & Concurrency Vulnerabilities Specification Mining
- [Sprint 23 Identity]: Web Cache Poisoning & Cache Deception Specification Specialist; Parent: 14e0efdd-8b68-4210-b30c-f8f6e3106536

## 🔒 Key Constraints
- Read-only probe; do NOT modify any codebase files.
- Discover and document technical specifications thoroughly for HTTP Request Smuggling validation.
- Cover all desynchronization variants (CL.TE, TE.CL, TE.TE, H2.CL, H2.TE, H2 CRLF downgrading), at least 5 distinct obfuscation strategies, differential response time analysis, sequential 2-request confirmation pipelines, false positive rejection, defensive safe assessment guidelines, and mock server / test fixture architecture.
- Ensure strict alignment with ARGUS architecture (BaseCollector, Evidence, AttackSurfaceGraph, registry, TaskGenerator, CVSS/CWE).
- [Sprint 20]: Analyze and document detection and verification models for 5 concurrency scenarios (Limit Overrun, TOCTOU, Session & State Concurrency, Multi-Endpoint Concurrency, Differential State Verification Pipeline).
- [Sprint 20]: Document at least 5 distinct synchronization & concurrency mechanisms (HTTP/2 Single-Packet Multiplexing, Connection Pre-Warming, Microsecond Barrier Synchronization, Header/Body Padding for TCP Alignment, Dynamic Concurrency Scaling).
- [Sprint 20]: Document CWE-362 and CWE-367 classification, CVSS v3.1 scoring formulas, and test payload generation requirements.
- [Sprint 23]: Read-only probe. Discover and formalize all requirements for Web Cache Poisoning & Cache Deception: R1 (Collector & Prober with AuthenticatedHttpClient, baseline vs perturbed requests), R2 (Unkeyed headers, unkeyed params, WCD, normalization flaws, cache fingerprinting), R3 (5+ mutation & evasion strategies), R4 (Pipeline & Graph connectivity), R5 (False positive rejection rules).

## Current Parent
- Conversation ID: 14e0efdd-8b68-4210-b30c-f8f6e3106536
- Updated: 2026-09-01T01:17:00+05:30

## Task Summary
- **What to build/document**: Comprehensive specification for Web Cache Poisoning & Web Cache Deception detection collector (`CacheSecurityCollector` / `CacheSecurityAnalyzer` / `CacheSecurityPayloadGenerator`), probers (`CacheProber`, `AuthenticatedHttpClient`), lifecycle fingerprinting (`CF-Cache-Status`, `X-Cache`, `Age`, `Cache-Control`, Akamai/CloudFront/Fastly/Varnish/Nginx/ATS), 5+ mutation/evasion strategies, multi-vector detection matrices, verification oracle logic, false positive rejection rules, and graph integration.
- **Success criteria**: Detailed `handoff.md` covering all requirements R1-R5, exhaustive tables, payload matrices, oracle logic, fingerprinting signatures, and verification methods.
- **Interface contracts**: Argus tripartite collector pattern (`CacheSecurityCollector`), `Evidence`, `AttackSurfaceGraph` (`HAS_VULNERABILITY` edges), `registry.py`, `TaskGenerator`, `CVSSCalculator` (CWE-444, CWE-524, CWE-525, CWE-613, etc.).

## Key Decisions Made
- Investigating codebase architecture: `BaseCollector`, `AuthenticatedHttpClient`, `Evidence`, `TaskGenerator`, `registry.py`, `AttackSurfaceGraph`, existing collectors (e.g. `ssti`, `request_smuggling`, `race_conditions`, `business_logic`).
- Structuring 5 multi-vector detection modes: Unkeyed Header Poisoning, Unkeyed Query Parameter Poisoning, Web Cache Deception, Cache Key Normalization Flaws, and Cache Header & Lifecycle Fingerprinting.
- Defining precise oracle verification logic: Baseline Request -> Perturbed Probe Request (with unique cache buster) -> Cache Validation / Replay Request (confirming poisoned state without probe header) -> Second Cache Buster Control Request (confirming isolation).

## Artifact Index
- /home/varun/argus/.agents/survey_spec_miner/DISPATCH.md — Dispatch log
- /home/varun/argus/.agents/survey_spec_miner/BRIEFING.md — Situational awareness
- /home/varun/argus/.agents/survey_spec_miner/progress.md — Liveness & progress tracker
- /home/varun/argus/.agents/survey_spec_miner/handoff.md — Final spec mining report

