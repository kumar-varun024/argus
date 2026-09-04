## 2026-09-03T16:49:29Z

You are the SWE Orchestrator for Sprint 31b: CLI Search Command & Vector RAG Integration Tests for the ARGUS security scanner.

Working directory: /home/varun/argus/.agents/swe_sprint31b
Workspace root: /home/varun/argus
Original request: /home/varun/argus/.agents/ORIGINAL_REQUEST.md
Handoff destination: /home/varun/argus/.agents/swe_sprint31b/handoff.md
Integrity mode: development

Your mission is to implement the `argus search` CLI command group (`argus/cli/search_cli.py`), register it in `argus/cli/app.py`, write comprehensive end-to-end integration tests connecting all Vector RAG components (`tests/vector/test_rag_integration.py` and `tests/cli/test_search_cli.py`), verify zero regressions across the codebase (>= 2,261 tests passing), update `/home/varun/argus/.agents/sprint_handoff.md`, and deliver a clean handoff.

## Detailed Requirements

### R1. CLI `argus search` Command
Add a new `search` CLI command group to ARGUS (`argus/cli/search_cli.py`) registered in `argus/cli/app.py`. The CLI must use Typer (already a dependency) and Rich (already a dependency) for output formatting. Commands:

- **`argus search <query>`**: Semantic search across all indexed sources (findings, evidence, CVEs, memory). Displays results in a Rich table with columns: Score, Type, Severity, Title/Content (truncated), Category. Supports these options:
  - `--type` / `-t`: Filter by source type (`finding`, `evidence`, `cve`, `memory`, or `all` default)
  - `--severity` / `-s`: Filter by severity (`critical`, `high`, `medium`, `low`, `info`)
  - `--category` / `-c`: Filter by category
  - `--mission` / `-m`: Filter by mission ID
  - `--top-k` / `-k`: Number of results (default 10)
  - `--min-score`: Minimum similarity threshold (default 0.0)
  - `--json`: Output raw JSON instead of Rich table
  - `--verbose` / `-v`: Show additional fields (full content, metadata, embeddings info)

- **`argus search cves <query>`**: Shortcut for CVE-specific semantic search. Same options as above but defaults to `--type cve`. Adds `--cwe` filter and `--product` filter.

- **`argus search memory <query>`**: Shortcut for memory-specific search. Same base options. Adds `--memory-type` filter (attack_pattern, user_correction, strategic_decision, session_context, note).

- **`argus search stats`**: Display index statistics — counts by source_type, total documents, vector store path, embedding provider name.

### R2. End-to-End Integration Tests
Write integration tests that verify the complete Vector RAG pipeline works end-to-end across all components:

- **`tests/vector/test_rag_integration.py`**: Tests covering:
  - Index findings via `ScanEvidenceIndexer` → search via `FindingSemanticSearchEngine` → verify results
  - Ingest CVEs via `CVEKnowledgeBase` → search via `search_cves()` → verify correlation
  - Store memories via `MemoryManager` → recall via `recall()` → verify semantic relevance
  - Cross-source search via `VectorStore.search()` spanning findings + CVEs + memory in single query
  - `ResearchContextEngine.resolve()` returning blended results from all sources
  - Round-trip persistence: add → close store → reopen → search → verify results survive
  - Filter composition: combining source_type + severity + mission_id + category filters
  - Minimum 25 test cases

- **`tests/cli/test_search_cli.py`**: CLI integration tests using Typer's `CliRunner`:
  - Basic search returns formatted output
  - `--json` flag produces valid JSON
  - `--type`, `--severity`, `--category` filters work
  - `search cves` and `search memory` subcommands work
  - `search stats` returns counts
  - Empty results handled gracefully
  - Minimum 15 test cases

### R3. CLI Registration
Register the search CLI in `argus/cli/app.py` by adding the search_app typer as a subcommand named "search".

## Existing Architecture Reference
These modules are already fully implemented and should be used as-is:
- `argus/vector/store.py` — `VectorStore`, `get_vector_store()`
- `argus/vector/embeddings.py` — `EmbeddingEngine`, `get_embedding_engine()`
- `argus/vector/models.py` — `VectorDocument`, `SearchResult`, `VectorFilter`
- `argus/reporting/vector_indexer.py` — `ScanEvidenceIndexer`, `FindingSemanticSearchEngine`
- `argus/knowledge/cve_kb.py` — `CVEKnowledgeBase`
- `argus/knowledge/cve_correlator.py` — `CVECorrelator`
- `argus/memory/store.py` — `MemoryStore`
- `argus/memory/manager.py` — `MemoryManager`, `get_memory_manager()`
- `argus/memory/models.py` — `MemoryEntry`, `MemoryType`, `MemorySearchResult`
- `argus/workspace/context/engine.py` — `ResearchContextEngine`
- `argus/cli/app.py` — Main Typer app with existing subcommand pattern

Follow the existing CLI patterns in `argus/cli/` — use Typer for commands, Rich for formatting.

## Post-Sprint Handoff
After all tests pass, update `/home/varun/argus/.agents/sprint_handoff.md`:
- Add Sprint 31b row to the completed sprints table
- Update the test baseline count
- Update the "Remaining Roadmap" section (Sprint 31c: Adversarial RAG pipeline tests)
- Add a Sprint 31b section with results summary

## Acceptance Criteria
- [ ] `python -m pytest tests/vector/test_rag_integration.py tests/cli/test_search_cli.py -x -q` passes completely
- [ ] `python -m pytest tests/ --ignore=tests/workspace -x -q` passes with >= 2,261 tests (zero regressions)
- [ ] Minimum 40 new test cases across the 2 test files
- [ ] Functional CLI validation:
  - `python -m argus search "SQL injection"` returns formatted results when findings are indexed
  - `python -m argus search --json "XSS"` returns valid JSON array
  - `python -m argus search cves "buffer overflow" --severity critical` filters correctly
  - `python -m argus search memory "attack pattern" --memory-type attack_pattern` filters correctly
  - `python -m argus search stats` displays document counts by source type
  - Cross-source search returns results from findings, CVEs, and memory in a single query
  - `ResearchContextEngine.resolve()` integration test returns blended multi-source results
- [ ] Architecture compliance: Typer + Rich only, no modifications to existing vector store/embedding engine/CVE KB/memory internals, search CLI registered in `argus/cli/app.py`.

In your working directory `/home/varun/argus/.agents/swe_sprint31b`, maintain `progress.md` and write `handoff.md` upon completion.
When 100% complete with all tests passing and handoff written, send your completion report with a victory claim.
