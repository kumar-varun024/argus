# DISPATCH — Cluster 3 Auditor (Sections 26–37)

## Working Directory
`/home/varun/argus/.agents/audit_cluster3`

## Original Request & Spec
`/home/varun/argus/.agents/ORIGINAL_REQUEST.md` (Read sections 26 to 37)

## Scope: Sections 26–37
26: AI Research
27: Security Research RAG / Intelligence Fabric (Must detail 27.1–27.16)
28: Research Cards
29: Vulnerability Intelligence Engine
30: Methodology Engine & Playbooks
31: Authorization Specialist
32: Business Logic Specialist
33: API Intelligence Specialist
34: GraphQL Specialist
35: JavaScript Intelligence
36: Authentication Specialist
37: File Upload Specialist

## Instructions
For EVERY one of the 12 sections:
1. Locate source files in `argus/` (e.g. `argus/ai/`, `argus/vector/`, `argus/rag/`, `argus/cards/`, `argus/intelligence/`, `argus/methodology/`, `argus/specialists/`, `argus/api/`, `argus/graphql/`, `argus/js/`, `argus/javascript/`, `argus/auth/`, `argus/upload/`, etc.).
2. For Section 27, analyze all subsections (27.1 Research Sources, 27.2 Ingestion, 27.3 Representations, 27.4 Retrieval Modes, 27.5 Hybrid, 27.6 Graph RAG, 27.7 Evidence RAG, 27.8 Context Builder, 27.9 Reranking, 27.10 Grounding/Citations, 27.11 Confidence, 27.12 Freshness, 27.13 Privacy/Scope-Aware, 27.14 Pluggable Providers, 27.15 Evaluation, 27.16 Failure Handling).
3. Check CLI wiring (e.g. `argus api ...`, `argus graphql`, `argus javascript`, `argus search`).
4. Assign status: ✅ Implemented, ⚠️ Partial, ❌ Missing, 🔴 Broken.
5. Record:
   - Status
   - Source Files (exact relative paths)
   - Implementation Evidence (specific classes, functions, mechanisms)
   - Gaps (discrepancies, missing features from spec)
   - Test Coverage (matching tests in `tests/`)
   - Notes (architectural notes, technical debt)
6. Write complete section-by-section findings to `/home/varun/argus/.agents/audit_cluster3/handoff.md`.
7. Notify parent when done.
