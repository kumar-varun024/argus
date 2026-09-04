## 2026-09-03T05:16:40+05:30
You are Worker 2: Scan Semantic Search & CVE Knowledge Base Specialist.
Your working directory is: /home/varun/argus/.agents/worker_m2/
Read these files carefully before writing code:
- /home/varun/argus/.agents/ORIGINAL_REQUEST.md
- /home/varun/argus/PROJECT.md
- /home/varun/argus/.agents/explorer_2/handoff.md
- /home/varun/argus/.agents/worker_m1/handoff.md

Your task is to implement Milestone 2 (Requirements R2 & R3):
1. `argus/knowledge/cve_models.py`:
   - `CVEEntry`: structured dataclass (`cve_id`, `description`, `title`, `severity`, `cvss_score`, `cvss_vector`, `cwes`, `affected_products`, `references`, `published_date`, `last_modified_date`, `metadata`, `to_dict()`, `from_dict()`, `to_embedding_text()`).
   - `CVECorrelationSuggestion`: structured dataclass (`cve_id`, `cve_title`, `cve_description`, `finding_id`, `finding_title`, `correlation_score`, `vector_similarity`, `cwe_match`, `tech_match`, `category_match`, `rationale`, `to_dict()`).
2. `argus/knowledge/cve_kb.py`:
   - `CVEKnowledgeBase`: Manages ingestion of CVE data from dicts, JSON files, or CVEEntry lists into `VectorStore` (source_type="cve"). Supports semantic search by description similarity (`search_cves`), filtering by severity/CWE/affected product, `get_cve`, `count`, `clear`.
3. `argus/knowledge/cve_correlator.py`:
   - `CVECorrelator`: Finding-to-CVE hybrid correlation engine using vector similarity, CWE match, technology match, and category match. Returns sorted `CVECorrelationSuggestion` objects.
4. `argus/reporting/vector_indexer.py`:
   - `ScanEvidenceIndexer`: Indexes `Evidence` objects and `Finding` objects from scans into `VectorStore` (`source_type="evidence"` or `"finding"`), plus historical scan reports in `.argus/reports/`.
   - `FindingSemanticSearchEngine`: High-level semantic search API over indexed findings and evidence with filtering by `mission_id`, `severity`, `category`, `target`/`host`, and `min_score`.
5. Integrate post-scan indexing into `argus/scanning/engine.py` (after report generation) and `argus/runtime/lifecycle.py` wrapped safely with exception handling so scan execution never fails if indexing is skipped.
6. Cleanly export new classes in `argus/knowledge/__init__.py` and `argus/reporting/__init__.py`.
7. Create comprehensive test suites:
   - `tests/test_semantic_search.py` (evidence & finding indexing, semantic search queries e.g. "authentication bypass via parameter tampering", historical reports, metadata filtering).
   - `tests/test_cve_kb.py` (CVE ingestion, semantic search, finding-to-CVE correlation, scoring logic).
8. Run tests: `python3 -m pytest tests/test_semantic_search.py tests/test_cve_kb.py tests/test_vector_store.py -v` and verify 100% pass, plus `python3 -m pytest tests/ --ignore=tests/workspace -q` with zero regressions.
