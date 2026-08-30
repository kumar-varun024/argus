## 2026-08-27T09:27:47Z
You are an Explorer investigating the Graph and Evidence subsystems for Sprint 2.
Your working directory: /home/varun/argus/.agents/explorer_graph
Original request path: /home/varun/argus/.agents/ORIGINAL_REQUEST.md

Investigate:
1. `argus/graph/graph.py`, `argus/graph/node.py`, `argus/graph/edge.py` — how KnowledgeGraph works, methods available, node/edge structure, immutability/mutability, deduplication.
2. `argus/evidence/store.py`, `argus/evidence/model.py`, and any evidence-related files — how Evidence is structured, categories used (SUBDOMAIN, LIVE_HOST, ENDPOINT, TECHNOLOGY, VULNERABILITY, etc.), metadata keys, how tools store evidence.
3. How to build an idempotent Attack-Surface Graph Builder that turns EvidenceStore contents into a populated KnowledgeGraph with node types: target, subdomain, live_host, endpoint, technology, vulnerability, and edge types: RESOLVES_TO, HOSTS, HAS_ENDPOINT, RUNS_TECHNOLOGY, HAS_VULNERABILITY.
4. Detail the exact ID conventions, node properties, and edge connection logic for each entity type.

Write your findings and recommendations to `/home/varun/argus/.agents/explorer_graph/handoff.md` and send a message when complete.
