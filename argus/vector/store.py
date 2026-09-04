"""
Persistent Vector Store for ARGUS.

Provides dual-engine similarity search:
1. Native sqlite-vec virtual table acceleration (vec0) when sqlite-vec is available.
2. High-performance vectorized pure-Python/NumPy fallback over relational SQLite blobs.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid

import numpy as np

from argus.vector.embeddings import EmbeddingEngine, get_embedding_engine
from argus.vector.exceptions import (
    DimensionMismatchError,
    DocumentNotFoundError,
    ExtensionLoadError,
    VectorStoreError,
)
from argus.vector.models import (
    DistanceMetric,
    SearchResult,
    VectorDocument,
    VectorFilter,
    VectorStoreConfig,
)


class VectorStore:
    """
    Dual-engine persistent vector database for ARGUS documents, evidence, findings, CVEs, and memory.
    """

    def __init__(
        self,
        config: Optional[VectorStoreConfig] = None,
        db_path: Optional[str] = None,
        embedding_engine: Optional[EmbeddingEngine] = None,
        use_sqlite_vec: Optional[bool] = None,
    ):
        if config is None:
            config = VectorStoreConfig()
        self.config = config

        # Allow db_path override
        if db_path is not None:
            self.db_path = db_path
        else:
            env_path = os.environ.get("ARGUS_VECTOR_STORE_PATH")
            self.db_path = env_path if env_path else self.config.db_path

        # Allow use_sqlite_vec override
        self._use_sqlite_vec_requested = (
            use_sqlite_vec if use_sqlite_vec is not None else self.config.use_sqlite_vec
        )

        self.dimension = self.config.dimension
        self.distance_metric = self.config.distance_metric
        self.table_name = self.config.table_name

        self.embedding_engine = embedding_engine or get_embedding_engine(
            provider=self.config.embedding_provider,
            dimension=self.dimension,
        )

        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None
        self.is_sqlite_vec_available: bool = False

        self._initialize_database()

    def _get_resolved_path(self) -> str:
        """Resolve database path, expanding home dir and handling in-memory instances."""
        if self.db_path == ":memory:":
            return ":memory:"
        expanded = os.path.expanduser(self.db_path)
        resolved = Path(expanded).resolve()
        resolved.parent.mkdir(parents=True, exist_ok=True)
        return str(resolved)

    def _initialize_database(self) -> None:
        """Connect to SQLite database, load sqlite-vec if available, and create schemas."""
        with self._lock:
            target_path = self._get_resolved_path()
            self._conn = sqlite3.connect(
                target_path,
                check_same_thread=False,
                timeout=10.0,
            )
            self._conn.row_factory = sqlite3.Row

            if target_path != ":memory:":
                self._conn.execute("PRAGMA journal_mode = WAL;")
                self._conn.execute("PRAGMA busy_timeout = 5000;")
                self._conn.execute("PRAGMA synchronous = NORMAL;")

            # Attempt to load sqlite-vec extension if requested
            self.is_sqlite_vec_available = False
            if self._use_sqlite_vec_requested:
                try:
                    import sqlite_vec
                    self._conn.enable_load_extension(True)
                    sqlite_vec.load(self._conn)
                    self.is_sqlite_vec_available = True
                except Exception:
                    self.is_sqlite_vec_available = False

            if self.config.auto_create_tables:
                self._create_tables()

    def _create_tables(self) -> None:
        """Create relational document store and sqlite-vec virtual table if supported."""
        with self._lock, self._conn:
            # 1. Primary relational documents table
            self._conn.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {self.table_name} (
                    id TEXT PRIMARY KEY,
                    content TEXT NOT NULL,
                    source_type TEXT NOT NULL DEFAULT 'general',
                    mission_id TEXT,
                    severity TEXT,
                    category TEXT,
                    metadata_json TEXT,
                    embedding_blob BLOB,
                    created_at TEXT,
                    updated_at TEXT
                );
                """
            )
            self._conn.execute(
                f"CREATE INDEX IF NOT EXISTS idx_{self.table_name}_source_type ON {self.table_name}(source_type);"
            )
            self._conn.execute(
                f"CREATE INDEX IF NOT EXISTS idx_{self.table_name}_mission_id ON {self.table_name}(mission_id);"
            )
            self._conn.execute(
                f"CREATE INDEX IF NOT EXISTS idx_{self.table_name}_severity ON {self.table_name}(severity);"
            )
            self._conn.execute(
                f"CREATE INDEX IF NOT EXISTS idx_{self.table_name}_category ON {self.table_name}(category);"
            )
            self._conn.execute(
                f"CREATE INDEX IF NOT EXISTS idx_{self.table_name}_created_at ON {self.table_name}(created_at);"
            )

            # 2. Virtual sqlite-vec table if extension is active
            if self.is_sqlite_vec_available:
                metric_name = "cosine"
                if self.distance_metric == DistanceMetric.L2:
                    metric_name = "l2"
                elif self.distance_metric == DistanceMetric.DOT:
                    metric_name = "cosine"

                self._conn.execute(
                    f"""
                    CREATE VIRTUAL TABLE IF NOT EXISTS vec_{self.table_name} USING vec0(
                        id TEXT PRIMARY KEY,
                        embedding float[{self.dimension}] distance_metric={metric_name}
                    );
                    """
                )

    def _serialize_embedding(self, embedding: List[float]) -> bytes:
        """Convert float list into compact float32 binary blob."""
        if len(embedding) != self.dimension:
            raise DimensionMismatchError(
                f"Embedding dimension {len(embedding)} does not match store dimension {self.dimension}"
            )
        arr = np.array(embedding, dtype=np.float32)
        return arr.tobytes()

    def _deserialize_embedding(self, blob: bytes) -> List[float]:
        """Convert float32 binary blob back to float list."""
        if not blob:
            return []
        arr = np.frombuffer(blob, dtype=np.float32)
        return arr.tolist()

    def add_document(self, doc: VectorDocument) -> str:
        """
        Add or replace a single VectorDocument. Computes embedding if missing.
        """
        self.add_documents([doc])
        return doc.id

    def add_documents(self, docs: List[VectorDocument]) -> List[str]:
        """
        Add or replace a batch of VectorDocuments in a single transaction.
        Generates embeddings for any documents where doc.embedding is None.
        """
        if not docs:
            return []

        # Find documents requiring embedding generation
        missing_indices = []
        texts_to_embed = []
        for i, doc in enumerate(docs):
            if doc.embedding is None:
                missing_indices.append(i)
                texts_to_embed.append(doc.content)

        if texts_to_embed:
            generated_embeddings = self.embedding_engine.embed_batch(texts_to_embed)
            for idx, emb in zip(missing_indices, generated_embeddings):
                docs[idx].embedding = emb

        now_str = datetime.now(timezone.utc).isoformat()
        doc_rows = []
        vec_rows = []
        ids = []

        for doc in docs:
            if not doc.id:
                doc.id = str(uuid.uuid4())
            ids.append(doc.id)

            if not doc.created_at:
                doc.created_at = now_str
            doc.updated_at = now_str

            emb_blob = self._serialize_embedding(doc.embedding)
            meta_json = json.dumps(doc.metadata or {})

            doc_rows.append((
                doc.id,
                doc.content,
                doc.source_type,
                doc.mission_id,
                doc.severity,
                doc.category,
                meta_json,
                emb_blob,
                doc.created_at,
                doc.updated_at,
            ))

            if self.is_sqlite_vec_available:
                vec_rows.append((doc.id, emb_blob))

        with self._lock, self._conn:
            self._conn.executemany(
                f"""
                INSERT OR REPLACE INTO {self.table_name} (
                    id, content, source_type, mission_id, severity, category,
                    metadata_json, embedding_blob, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                doc_rows,
            )

            if self.is_sqlite_vec_available and vec_rows:
                # In sqlite-vec, delete existing id from vec table before insert or use replace
                self._conn.executemany(
                    f"DELETE FROM vec_{self.table_name} WHERE id = ?;",
                    [(vid,) for vid, _ in vec_rows],
                )
                self._conn.executemany(
                    f"INSERT INTO vec_{self.table_name}(id, embedding) VALUES (?, ?);",
                    vec_rows,
                )

        return ids

    def add_texts(
        self,
        texts: List[str],
        metadatas: Optional[List[Dict[str, Any]]] = None,
        ids: Optional[List[str]] = None,
        source_type: str = "general",
        mission_id: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        **kwargs: Any,
    ) -> List[str]:
        """
        Convenience method to embed and store raw text strings.
        """
        if not texts:
            return []

        docs: List[VectorDocument] = []
        for i, text in enumerate(texts):
            doc_id = ids[i] if (ids and i < len(ids)) else str(uuid.uuid4())
            meta = metadatas[i] if (metadatas and i < len(metadatas)) else {}
            if kwargs:
                meta = {**meta, **kwargs}

            doc = VectorDocument(
                id=doc_id,
                content=text,
                source_type=source_type,
                mission_id=mission_id,
                severity=severity,
                category=category,
                metadata=meta,
            )
            docs.append(doc)

        return self.add_documents(docs)

    def get(self, doc_id: str) -> Optional[VectorDocument]:
        """
        Retrieve a VectorDocument by ID. Returns None if not found.
        """
        with self._lock:
            cur = self._conn.execute(
                f"""
                SELECT id, content, source_type, mission_id, severity, category,
                       metadata_json, embedding_blob, created_at, updated_at
                FROM {self.table_name}
                WHERE id = ?;
                """,
                (doc_id,),
            )
            row = cur.fetchone()
            if not row:
                return None

            metadata = {}
            if row["metadata_json"]:
                try:
                    metadata = json.loads(row["metadata_json"])
                except Exception:
                    metadata = {}

            embedding = self._deserialize_embedding(row["embedding_blob"])

            return VectorDocument(
                id=row["id"],
                content=row["content"],
                embedding=embedding,
                source_type=row["source_type"],
                mission_id=row["mission_id"],
                severity=row["severity"],
                category=row["category"],
                metadata=metadata,
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )

    def delete(self, doc_id: str) -> bool:
        """
        Delete a document by ID. Returns True if deleted, False if not found.
        """
        with self._lock, self._conn:
            cur = self._conn.execute(
                f"DELETE FROM {self.table_name} WHERE id = ?;",
                (doc_id,),
            )
            deleted = cur.rowcount > 0

            if self.is_sqlite_vec_available:
                self._conn.execute(
                    f"DELETE FROM vec_{self.table_name} WHERE id = ?;",
                    (doc_id,),
                )

        return deleted

    def delete_where(self, filters: Union[Dict[str, Any], VectorFilter]) -> int:
        """
        Delete documents matching the specified filter criteria.
        Returns the number of deleted records.
        """
        vec_filter = VectorFilter.from_dict(filters) if not isinstance(filters, VectorFilter) else filters
        where_clause, params = vec_filter.to_sql_conditions()

        with self._lock, self._conn:
            # First find matching IDs to also delete from virtual table and handle metadata_filters
            if where_clause:
                select_sql = f"SELECT id, metadata_json FROM {self.table_name} WHERE {where_clause};"
                cur = self._conn.execute(select_sql, params)
            else:
                select_sql = f"SELECT id, metadata_json FROM {self.table_name};"
                cur = self._conn.execute(select_sql)

            rows = cur.fetchall()
            matching_ids = []
            for row in rows:
                if vec_filter.metadata_filters:
                    meta = {}
                    if row["metadata_json"]:
                        try:
                            meta = json.loads(row["metadata_json"])
                        except Exception:
                            meta = {}
                    if not all(meta.get(k) == v for k, v in vec_filter.metadata_filters.items()):
                        continue
                matching_ids.append(row["id"])

            if not matching_ids:
                return 0

            # Delete in batches
            batch_size = 500
            total_deleted = 0
            for i in range(0, len(matching_ids), batch_size):
                batch = matching_ids[i:i + batch_size]
                placeholders = ", ".join(["?"] * len(batch))
                self._conn.execute(
                    f"DELETE FROM {self.table_name} WHERE id IN ({placeholders});",
                    batch,
                )
                if self.is_sqlite_vec_available:
                    self._conn.execute(
                        f"DELETE FROM vec_{self.table_name} WHERE id IN ({placeholders});",
                        batch,
                    )
                total_deleted += len(batch)

            return total_deleted

    def count(self, filters: Optional[Union[Dict[str, Any], VectorFilter]] = None) -> int:
        """
        Count documents matching the optional filter criteria.
        """
        if filters is None:
            with self._lock:
                cur = self._conn.execute(f"SELECT COUNT(*) FROM {self.table_name};")
                return cur.fetchone()[0]

        vec_filter = VectorFilter.from_dict(filters) if not isinstance(filters, VectorFilter) else filters
        where_clause, params = vec_filter.to_sql_conditions()

        with self._lock:
            if not vec_filter.metadata_filters:
                query = f"SELECT COUNT(*) FROM {self.table_name}"
                if where_clause:
                    query += f" WHERE {where_clause}"
                cur = self._conn.execute(query, params)
                return cur.fetchone()[0]
            else:
                query = f"SELECT metadata_json FROM {self.table_name}"
                if where_clause:
                    query += f" WHERE {where_clause}"
                cur = self._conn.execute(query, params)
                matching = 0
                for row in cur.fetchall():
                    meta = {}
                    if row["metadata_json"]:
                        try:
                            meta = json.loads(row["metadata_json"])
                        except Exception:
                            meta = {}
                    if all(meta.get(k) == v for k, v in vec_filter.metadata_filters.items()):
                        matching += 1
                return matching

    def clear(self) -> None:
        """Clear all stored documents and vectors."""
        with self._lock, self._conn:
            self._conn.execute(f"DELETE FROM {self.table_name};")
            if self.is_sqlite_vec_available:
                self._conn.execute(f"DELETE FROM vec_{self.table_name};")

    def search(
        self,
        query: Union[str, List[float]],
        top_k: int = 10,
        filters: Optional[Union[Dict[str, Any], VectorFilter]] = None,
        metric: Optional[Union[DistanceMetric, str]] = None,
        min_score: Optional[float] = None,
    ) -> List[SearchResult]:
        """
        Perform similarity search using query string or pre-computed embedding vector.
        """
        # Resolve query embedding vector
        if isinstance(query, str):
            query_vector = self.embedding_engine.embed_text(query)
        else:
            query_vector = query

        if len(query_vector) != self.dimension:
            raise DimensionMismatchError(
                f"Query vector dimension {len(query_vector)} does not match store dimension {self.dimension}"
            )

        vec_filter = (
            VectorFilter.from_dict(filters)
            if filters is not None and not isinstance(filters, VectorFilter)
            else (filters or VectorFilter())
        )

        effective_min_score = min_score if min_score is not None else vec_filter.min_score
        target_metric = (
            DistanceMetric.from_str(metric)
            if metric is not None
            else self.distance_metric
        )

        if self.is_sqlite_vec_available and target_metric == DistanceMetric.COSINE:
            return self._search_sqlite_vec(
                query_vector=query_vector,
                top_k=top_k,
                vec_filter=vec_filter,
                min_score=effective_min_score,
            )
        else:
            return self._search_numpy(
                query_vector=query_vector,
                top_k=top_k,
                vec_filter=vec_filter,
                metric=target_metric,
                min_score=effective_min_score,
            )

    def _search_sqlite_vec(
        self,
        query_vector: List[float],
        top_k: int,
        vec_filter: VectorFilter,
        min_score: Optional[float],
    ) -> List[SearchResult]:
        """Search accelerated by native sqlite-vec virtual table."""
        emb_blob = self._serialize_embedding(query_vector)
        where_clause, filter_params = vec_filter.to_sql_conditions(table_prefix="d")

        sql = f"""
            SELECT v.id, v.distance, d.content, d.source_type, d.mission_id,
                   d.severity, d.category, d.metadata_json, d.created_at, d.embedding_blob
            FROM vec_{self.table_name} v
            JOIN {self.table_name} d ON v.id = d.id
            WHERE v.embedding MATCH ?
        """
        params: List[Any] = [emb_blob]

        if where_clause:
            sql += f" AND {where_clause}"

        sql += f" ORDER BY v.distance LIMIT {max(top_k * 3, 50)};"
        params.extend(filter_params)

        with self._lock:
            try:
                cur = self._conn.execute(sql, params)
                rows = cur.fetchall()
            except Exception:
                # If virtual table query fails, fallback safely to numpy
                return self._search_numpy(
                    query_vector=query_vector,
                    top_k=top_k,
                    vec_filter=vec_filter,
                    metric=DistanceMetric.COSINE,
                    min_score=min_score,
                )

        results: List[SearchResult] = []
        for row in rows:
            meta = {}
            if row["metadata_json"]:
                try:
                    meta = json.loads(row["metadata_json"])
                except Exception:
                    meta = {}

            # Apply custom metadata filter if present
            if vec_filter.metadata_filters:
                if not all(meta.get(k) == v for k, v in vec_filter.metadata_filters.items()):
                    continue

            dist = float(row["distance"])
            # In sqlite-vec with distance_metric=cosine, distance is 1.0 - cosine_sim
            score = max(0.0, min(1.0, 1.0 - dist))

            if min_score is not None and score < min_score:
                continue

            doc = VectorDocument(
                id=row["id"],
                content=row["content"],
                embedding=self._deserialize_embedding(row["embedding_blob"]) if "embedding_blob" in row.keys() else None,
                source_type=row["source_type"],
                mission_id=row["mission_id"],
                severity=row["severity"],
                category=row["category"],
                metadata=meta,
                created_at=row["created_at"],
            )

            res = SearchResult(
                id=row["id"],
                content=row["content"],
                score=score,
                distance=dist,
                source_type=row["source_type"],
                mission_id=row["mission_id"],
                severity=row["severity"],
                category=row["category"],
                metadata=meta,
                created_at=row["created_at"],
                document=doc,
            )
            results.append(res)
            if len(results) >= top_k:
                break

        return results

    def _search_numpy(
        self,
        query_vector: List[float],
        top_k: int,
        vec_filter: VectorFilter,
        metric: DistanceMetric,
        min_score: Optional[float],
    ) -> List[SearchResult]:
        """High-performance fallback similarity search using vectorized NumPy operations."""
        where_clause, params = vec_filter.to_sql_conditions()
        sql = f"""
            SELECT id, content, source_type, mission_id, severity, category,
                   metadata_json, embedding_blob, created_at, updated_at
            FROM {self.table_name}
        """
        if where_clause:
            sql += f" WHERE {where_clause}"

        with self._lock:
            cur = self._conn.execute(sql, params)
            rows = cur.fetchall()

        if not rows:
            return []

        # Filter in-memory metadata_filters and load candidate embeddings
        candidate_rows = []
        blobs = []
        for row in rows:
            meta = {}
            if row["metadata_json"]:
                try:
                    meta = json.loads(row["metadata_json"])
                except Exception:
                    meta = {}

            if vec_filter.metadata_filters:
                if not all(meta.get(k) == v for k, v in vec_filter.metadata_filters.items()):
                    continue

            blob = row["embedding_blob"]
            if not blob or len(blob) != self.dimension * 4:
                continue

            candidate_rows.append((row, meta))
            blobs.append(blob)

        if not candidate_rows:
            return []

        # Build contiguous float32 matrix
        matrix = np.frombuffer(b"".join(blobs), dtype=np.float32).reshape(len(blobs), self.dimension)
        q = np.array(query_vector, dtype=np.float32)

        if metric == DistanceMetric.COSINE:
            norm_q = float(np.linalg.norm(q))
            norms_m = np.linalg.norm(matrix, axis=1)
            denominator = norms_m * norm_q
            dots = np.dot(matrix, q)
            cosine_sims = np.where(denominator > 1e-12, dots / denominator, 0.0)
            scores = np.clip(cosine_sims, 0.0, 1.0)
            distances = 1.0 - cosine_sims
        elif metric == DistanceMetric.L2:
            diffs = matrix - q
            distances = np.linalg.norm(diffs, axis=1)
            scores = 1.0 / (1.0 + distances)
        elif metric == DistanceMetric.DOT:
            scores = np.dot(matrix, q)
            distances = -scores
        else:
            raise ValueError(f"Unsupported distance metric: {metric}")

        # Top-K sorting
        sorted_indices = np.argsort(-scores)

        results: List[SearchResult] = []
        for idx in sorted_indices:
            score = float(scores[idx])
            dist = float(distances[idx])

            if min_score is not None and score < min_score:
                continue

            row, meta = candidate_rows[idx]
            doc = VectorDocument(
                id=row["id"],
                content=row["content"],
                embedding=self._deserialize_embedding(row["embedding_blob"]),
                source_type=row["source_type"],
                mission_id=row["mission_id"],
                severity=row["severity"],
                category=row["category"],
                metadata=meta,
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )

            res = SearchResult(
                id=row["id"],
                content=row["content"],
                score=score,
                distance=dist,
                source_type=row["source_type"],
                mission_id=row["mission_id"],
                severity=row["severity"],
                category=row["category"],
                metadata=meta,
                created_at=row["created_at"],
                document=doc,
            )
            results.append(res)
            if len(results) >= top_k:
                break

        return results

    def close(self) -> None:
        """Close database connection."""
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None

    def __enter__(self) -> "VectorStore":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


_GLOBAL_VECTOR_STORE: Optional[VectorStore] = None


def get_vector_store(
    db_path: Optional[str] = None,
    config: Optional[VectorStoreConfig] = None,
    force_new: bool = False,
    **kwargs: Any,
) -> VectorStore:
    """
    Get or create singleton/cached VectorStore instance.
    """
    global _GLOBAL_VECTOR_STORE
    if _GLOBAL_VECTOR_STORE is None or force_new:
        _GLOBAL_VECTOR_STORE = VectorStore(
            config=config,
            db_path=db_path,
            **kwargs,
        )
    return _GLOBAL_VECTOR_STORE
