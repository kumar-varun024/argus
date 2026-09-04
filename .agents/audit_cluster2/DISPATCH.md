# DISPATCH — Cluster 2 Auditor (Sections 16–25)

## Working Directory
`/home/varun/argus/.agents/audit_cluster2`

## Original Request & Spec
`/home/varun/argus/.agents/ORIGINAL_REQUEST.md` (Read sections 16 to 25)

## Scope: Sections 16–25
16: Reconnaissance
17: Recon Parser
18: Nuclei Integration
19: Evidence Store
20: Provenance Engine
21: Observations & Correlations
22: Knowledge Graph
23: Workflow Intelligence
24: Authorization Graph
25: Business Objects

## Instructions
For EVERY one of the 10 sections:
1. Locate source files in `argus/` (e.g. `argus/recon/`, `argus/evidence/`, `argus/provenance/`, `argus/observation/`, `argus/correlation/`, `argus/graph/`, `argus/workflow/`, `argus/authz/`, `argus/authorization/`, `argus/objects/`, `argus/business/`, etc.).
2. Inspect code logic (classes, functions, data structures, workflows, stubs/placeholders).
3. Check CLI wiring (e.g. `argus trace`, `argus observations`, `argus correlations`, `argus evidence`).
4. Assign status: ✅ Implemented, ⚠️ Partial, ❌ Missing, 🔴 Broken.
5. Record:
   - Status
   - Source Files (exact relative paths)
   - Implementation Evidence (specific classes, functions, mechanisms)
   - Gaps (discrepancies, missing features from spec)
   - Test Coverage (matching tests in `tests/`)
   - Notes (architectural notes, technical debt)
6. Write complete section-by-section findings to `/home/varun/argus/.agents/audit_cluster2/handoff.md`.
7. Notify parent when done.
