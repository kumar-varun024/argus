# Dispatch Record

## 2026-09-03T01:52:07+05:30
You are the Project Orchestrator for the ARGUS platform sprint: Vector RAG & Semantic Search.

Working directory: /home/varun/argus
Agent working directory: /home/varun/argus/.agents/orchestrator
Original request: /home/varun/argus/.agents/ORIGINAL_REQUEST.md
Final handoff location: /home/varun/argus/.agents/sprint31_vector_rag/handoff.md
Integrity mode: development

Your mission is to orchestrate and execute the complete implementation of Sprint 31: Vector RAG & Semantic Search across the codebase, adhering strictly to the multi-agent orchestration protocol and zero-regression requirement (2,089+ passing tests).

## Requirements Overview
- R1: Embedding & Vector Store Engine — Build a vector store backed by SQLite-vec that can generate embeddings, store them, and perform semantic similarity search. File-based, zero external services, local lightweight embedding generation (e.g. sentence-transformers or lightweight embedding model). Support inserting documents with metadata, querying by semantic similarity with configurable top-k, and filtering by metadata fields (source_type, mission_id, severity, etc.). Store persists to disk and survives process restarts.
- R2: Semantic Search Over Scan Evidence & Findings — Index all collected evidence and confirmed findings from ARGUS scans into vector store after scan completion. Enable semantic searching over findings (e.g., "authentication bypass via parameter tampering" retrieving relevant SQLi, IDOR, auth bypass findings even without exact keyword match). Historical scan reports indexable and searchable.
- R3: CVE & Vulnerability Knowledge Base — Indexable knowledge base for CVE data and vulnerability intelligence. Ingest CVE records from JSON feeds/local files, embed descriptions, semantic search by description similarity. Finding-to-CVE correlation suggestions.
- R4: Enhanced Workspace Copilot Integration — Upgrade `ResearchContextEngine` in `argus/workspace/context/` to use semantic retrieval alongside existing keyword/graph retrieval. Blended context ranker (vector similarity + lexical scores). Rich contextual retrieval of semantically relevant evidence, findings, and knowledge base entries.
- R5: Conversational Learning & Growth — Memory system in `argus/memory/` that learns from conversations and scans. Key interactions, decisions, attack patterns, user corrections embedded and stored. Recall past experiences across sessions.
- R6: Zero Regression & Validation — All 2,089+ currently passing tests must pass (`python -m pytest tests/ --ignore=tests/workspace -x -q`). At least 20 new tests added covering vector store, semantic search, CVE indexing, copilot integration, and memory. Add `sqlite-vec` and embedding dependencies to `pyproject.toml`. Write handoff to `.agents/sprint31_vector_rag/handoff.md`.
