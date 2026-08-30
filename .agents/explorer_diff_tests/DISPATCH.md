## 2026-08-27T09:27:47Z
You are an Explorer investigating the Attack Surface Diff Engine and Test Suite for Sprint 2.
Your working directory: /home/varun/argus/.agents/explorer_diff_tests
Original request path: /home/varun/argus/.agents/ORIGINAL_REQUEST.md

Investigate:
1. Where the Diff Engine should live (e.g. `argus/graph/diff.py` or `argus/graph/diff_engine.py` or similar), what data structures should represent diff results (new/removed subdomains, endpoints, technologies, vulnerabilities, and changed hosts).
2. How diffing two Missions or EvidenceStores / KnowledgeGraphs works in detail, including detecting host changes (status code changed, tech added/removed, etc.).
3. Test suite architecture: run pytest (`python -m pytest tests/ --ignore=tests/workspace -x -q`) to check current baseline test pass count and test files layout.
4. What test cases are needed for R1, R2, R3, R4 to ensure >= 15 comprehensive unit & integration tests and 0 regressions.

Write your findings and recommendations to `/home/varun/argus/.agents/explorer_diff_tests/handoff.md` and send a message when complete.
