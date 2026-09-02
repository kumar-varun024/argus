# BRIEFING — 2026-08-31T12:05:00Z

## Mission
Analyze exact technical specifications, detection logic, bypass/mutation strategies, evidence models, and test requirements for Sprint 17 (GraphQL Security Detection Module for ARGUS).

## 🔒 My Identity
- Archetype: Specification Miner
- Roles: GraphQL Security Spec Miner, Technical Researcher
- Working directory: /home/varun/argus/.agents/spec_miner_graphql
- Original parent: c31d2366-ae81-4c67-9496-705f0f44ae59
- Milestone: Sprint 17 - GraphQL Security Specification Mining

## 🔒 Key Constraints
- Authoritative specification mining only; do NOT implement code changes directly.
- Fully probe all required and discovered features (R1 Endpoint/Injection Discovery, R2.1 Introspection/Field Suggestion, R2.2 Query Depth/Complexity DoS, R2.3 Batching/Alias Multiplexing, R2.4 Field-Level Access Control & Injection, R3 5+ Bypass/Mutation Strategies).
- Adhere strictly to Argus architecture: BaseCollector, AuthenticatedHttpClient, Evidence model, AttackSurfaceGraph (HAS_VULNERABILITY edges), TaskGenerator DAG wiring, tool registry, and zero regressions (1,352+ passing tests).
- Communication hygiene: zero intermediate pings to orchestrator. Self-contained handoff.md.

## Current Parent
- Conversation ID: c31d2366-ae81-4c67-9496-705f0f44ae59
- Updated: 2026-08-31T12:05:00Z

## Task Summary
- **What to build**: Complete GraphQL Security Collector specification & detection blueprint.
- **Success criteria**: Comprehensive handoff report covering all requirements (R1, R2.1-R2.4, R3, R4, R5), payload specifications, AST/query generation, signatures, error behavior, edge cases, evidence schema, and false positive controls.
- **Interface contracts**: BaseCollector, AuthenticatedHttpClient, Evidence(category="graphql_security"), AttackSurfaceGraph.
- **Code layout**: /home/varun/argus/argus/collectors/graphql.py, tests/collectors/test_graphql.py.

## Key Decisions Made
- Specification structured around 4 major vulnerability pillars (Introspection/Leakage, Depth/DoS, Batching/Multiplexing, Field Authorization/Injection) and 6 bypass mutation strategies.
- Defined precise AST/query payload schemas, signature regex catalogs, response heuristics, and safe non-destructive probing rules.

## Artifact Index
- /home/varun/argus/.agents/spec_miner_graphql/DISPATCH.md — Dispatch log
- /home/varun/argus/.agents/spec_miner_graphql/BRIEFING.md — Situational awareness
- /home/varun/argus/.agents/spec_miner_graphql/progress.md — Progress and liveness log
- /home/varun/argus/.agents/spec_miner_graphql/handoff.md — Final specification report

## Loaded Skills
- None explicitly loaded
