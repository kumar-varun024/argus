# Subagent Prompt Drafts

## Milestone 1: Vector Store & Embedding Engine Specialist (Worker 1)
- Role: Vector Store Specialist (`teamwork_preview_worker`)
- Working Directory: `/home/varun/argus/.agents/worker_m1/`
- Target Files:
  - `pyproject.toml`
  - `argus/vector/__init__.py`
  - `argus/vector/models.py`
  - `argus/vector/embeddings.py`
  - `argus/vector/store.py`
  - `argus/vector/exceptions.py`
  - `tests/test_vector_store.py`
- Mandatory Warnings & Integrity Constraints:
  - DO NOT CHEAT. All implementations must be genuine.
  - Zero external cloud services, 100% local/offline embedding & storage.
  - Dual-engine `VectorStore` (native `sqlite-vec` + pure Python/NumPy fallback).
  - Add `"sqlite-vec>=0.1.6"` to `pyproject.toml`.
  - Pass all tests in `tests/test_vector_store.py`.
