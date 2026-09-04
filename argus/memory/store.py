"""Vector-backed persistent store for conversational memory entries."""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional, Union

from argus.memory.models import (
    MemoryEntry,
    MemoryQuery,
    MemorySearchResult,
    MemoryStatus,
    MemoryType,
)
from argus.vector.models import SearchResult, VectorDocument, VectorFilter, VectorStoreConfig
from argus.vector.store import VectorStore, get_vector_store

logger = logging.getLogger(__name__)

_UNSET = object()


class MemoryStore:
    """
    Vector-backed storage and semantic retrieval engine for conversational memories.
    
    All documents in the underlying VectorStore are tagged with `source_type='memory'`
    and categorized by their `memory_type`.
    """

    def __init__(
        self,
        vector_store: Optional[VectorStore] = None,
        db_path: Optional[str] = None,
        config: Optional[VectorStoreConfig] = None,
        **kwargs: Any,
    ) -> None:
        if vector_store is not None:
            self.vector_store = vector_store
        elif db_path is not None or config is not None:
            self.vector_store = VectorStore(
                db_path=db_path,
                config=config,
                **kwargs,
            )
        else:
            self.vector_store = get_vector_store(**kwargs)

    def add(self, entry: MemoryEntry) -> str:
        """
        Add or update a MemoryEntry in the vector store.
        
        Returns the entry ID.
        """
        if not isinstance(entry, MemoryEntry):
            raise TypeError(f"Expected MemoryEntry, got {type(entry).__name__}")

        doc = entry.to_vector_document()
        self.vector_store.add_document(doc)
        return entry.id

    def add_batch(self, entries: List[MemoryEntry]) -> List[str]:
        """
        Add or update a batch of MemoryEntries in the vector store.
        
        Returns list of entry IDs.
        """
        if not entries:
            return []
        entry_list = list(entries)
        if not entry_list:
            return []
        for e in entry_list:
            if not isinstance(e, MemoryEntry):
                raise TypeError(f"Expected MemoryEntry in batch, got {type(e).__name__}")
        docs = [e.to_vector_document() for e in entry_list]
        return self.vector_store.add_documents(docs)

    def get(self, entry_id: str) -> Optional[MemoryEntry]:
        """
        Retrieve a MemoryEntry by its unique ID.
        
        Returns None if not found or if the document is not of source_type='memory'.
        """
        if not entry_id or not str(entry_id).strip():
            return None

        doc = self.vector_store.get(str(entry_id))
        if doc is None or doc.source_type != "memory":
            return None

        return MemoryEntry.from_vector_document(doc)

    def search(
        self,
        query: Union[str, List[float], MemoryQuery, None],
        top_k: Optional[int] = None,
        filters: Optional[Union[Dict[str, Any], VectorFilter]] = None,
        min_score: Optional[float] = None,
        memory_type: Optional[Union[str, MemoryType, List[Union[str, MemoryType]]]] = None,
        mission_id: Optional[str] = None,
        project_id: Optional[str] = None,
        status: Optional[Union[str, MemoryStatus, List[Union[str, MemoryStatus]]]] = None,
        tags: Optional[Union[str, List[str]]] = None,
        exact_mission: bool = False,
        exact_project: bool = False,
        global_only: bool = False,
        active_only: bool = False,
        **kwargs: Any,
    ) -> List[MemorySearchResult]:
        """
        Perform semantic similarity search over stored memories.
        
        Ensures returned similarity scores are always bounded in [0.0, 1.0].
        """
        # Unpack parameters if query is a MemoryQuery instance
        target_tags: Optional[List[str]] = None
        target_project_id: Optional[str] = project_id
        target_min_score: Optional[float] = min_score
        target_status: Optional[Union[str, MemoryStatus, List[Union[str, MemoryStatus]]]] = status
        target_memory_type: Optional[Union[str, MemoryType, List[Union[str, MemoryType]]]] = memory_type
        target_mission_id: Optional[str] = mission_id
        query_filters: Optional[Dict[str, Any]] = None

        if isinstance(query, MemoryQuery):
            q_val: Any = query.query
            if top_k is None:
                top_k = query.top_k
            if target_min_score is None:
                target_min_score = query.min_score
            if target_memory_type is None:
                target_memory_type = query.memory_type
            if target_mission_id is None:
                target_mission_id = query.mission_id
            if target_status is None:
                target_status = query.status
            if tags is None:
                tags = query.tags
            if target_project_id is None:
                target_project_id = query.project_id
            if not global_only:
                global_only = getattr(query, "global_only", False)
            if not active_only:
                active_only = getattr(query, "active_only", False)
            query_filters = query.filters
        else:
            q_val = query

        # Validate / coerce top_k
        try:
            top_k_int = int(top_k) if top_k is not None else 10
        except (ValueError, TypeError):
            top_k_int = 10

        if top_k_int <= 0:
            return []

        # Validate / coerce min_score
        min_score_bounded: Optional[float] = None
        if target_min_score is not None:
            try:
                ms_f = float(target_min_score)
                import math
                if not (math.isnan(ms_f) or math.isinf(ms_f)):
                    min_score_bounded = max(0.0, min(1.0, ms_f))
            except (ValueError, TypeError):
                min_score_bounded = None

        # Short-circuit on None, empty, or non-string/non-vector queries
        if q_val is None:
            return []
        if isinstance(q_val, str):
            if not q_val.strip():
                return []
        elif isinstance(q_val, (list, tuple)):
            if len(q_val) == 0:
                return []
            expected_dim = getattr(self.vector_store, "dimension", 384)
            if len(q_val) != expected_dim:
                logger.warning(
                    f"Query vector dimension {len(q_val)} does not match store dimension {expected_dim}"
                )
                return []
        else:
            # Query is neither text nor valid embedding vector (e.g. int, bool, dict, object)
            return []

        # Handle active_only flag
        if active_only and target_status is None:
            target_status = MemoryStatus.ACTIVE

        # Clean string IDs
        if target_mission_id is not None:
            s_mid = str(target_mission_id).strip()
            target_mission_id = s_mid if s_mid else None

        if target_project_id is not None:
            s_pid = str(target_project_id).strip()
            target_project_id = s_pid if s_pid else None

        # Process tags
        if tags is not None:
            if isinstance(tags, str):
                target_tags = [tags.strip()] if tags.strip() else []
            elif isinstance(tags, (list, tuple, set)):
                target_tags = [str(t).strip() for t in tags if t is not None and str(t).strip()]

        # Handle custom / extra filters dict
        metadata_filters: Dict[str, Any] = {}
        base_filters: Dict[str, Any] = {
            "source_type": "memory",
        }

        combined_filters: Dict[str, Any] = {}
        if filters:
            f_dict = filters if isinstance(filters, dict) else (filters.to_dict() if hasattr(filters, "to_dict") else dict(vars(filters)))
            combined_filters.update(f_dict)
        if query_filters:
            combined_filters.update(query_filters)

        # Extract special control flags from combined_filters
        global_only = combined_filters.pop("global_only", global_only)
        active_only = combined_filters.pop("active_only", active_only)
        exact_mission = combined_filters.pop("exact_mission", exact_mission)
        exact_project = combined_filters.pop("exact_project", exact_project)

        if active_only and target_status is None:
            target_status = MemoryStatus.ACTIVE

        # Extract special keys from combined_filters
        if "tags" in combined_filters and target_tags is None:
            raw_t = combined_filters.pop("tags")
            if isinstance(raw_t, str):
                target_tags = [raw_t.strip()] if raw_t.strip() else []
            elif isinstance(raw_t, (list, tuple, set)):
                target_tags = [str(t).strip() for t in raw_t if t is not None and str(t).strip()]

        if "status" in combined_filters and target_status is None:
            target_status = combined_filters.pop("status")

        if ("memory_type" in combined_filters or "category" in combined_filters) and target_memory_type is None:
            target_memory_type = combined_filters.pop("memory_type", None) or combined_filters.pop("category", None)

        if "mission_id" in combined_filters and target_mission_id is None:
            target_mission_id = combined_filters.pop("mission_id")
            if target_mission_id is not None:
                s_mid = str(target_mission_id).strip()
                target_mission_id = s_mid if s_mid else None

        if "project_id" in combined_filters and target_project_id is None:
            target_project_id = combined_filters.pop("project_id")
            if target_project_id is not None:
                s_pid = str(target_project_id).strip()
                target_project_id = s_pid if s_pid else None

        for k, v in combined_filters.items():
            if k in ("source_type", "severity"):
                base_filters[k] = v
            elif k == "metadata_filters" and isinstance(v, dict):
                metadata_filters.update(v)
            elif v is not None:
                metadata_filters[k] = v

        # Prepare categories (memory_types) with canonical normalization
        categories: Optional[Union[str, List[str]]] = None
        if target_memory_type is not None:
            if isinstance(target_memory_type, (list, tuple, set)):
                cats: List[str] = []
                for m in target_memory_type:
                    try:
                        cats.append(MemoryType.from_str(m).value)
                    except ValueError:
                        cats.append(str(m).strip().lower())
                categories = cats
            else:
                try:
                    categories = MemoryType.from_str(target_memory_type).value
                except ValueError:
                    categories = str(target_memory_type).strip().lower()

        if target_mission_id is not None and exact_mission:
            base_filters["mission_id"] = target_mission_id
        if categories is not None:
            base_filters["category"] = categories

        if target_project_id is not None and exact_project:
            metadata_filters["project_id"] = target_project_id

        # Normalize allowed statuses for case-insensitive post-retrieval filtering
        allowed_statuses: Optional[set] = None
        if target_status is not None:
            if isinstance(target_status, (list, tuple, set)):
                allowed_statuses = set()
                for s in target_status:
                    try:
                        allowed_statuses.add(MemoryStatus.from_str(s).value)
                    except ValueError:
                        allowed_statuses.add(str(s).strip().lower())
            else:
                try:
                    s_val = MemoryStatus.from_str(target_status).value
                except ValueError:
                    s_val = str(target_status).strip().lower()
                allowed_statuses = {s_val}

        # Whitelist vector_store kwargs (metric only) and absorb extra filter kwargs into metadata_filters
        vs_kwargs = {}
        # Pop control flags from kwargs if passed
        kwargs.pop("global_only", None)
        kwargs.pop("active_only", None)
        kwargs.pop("exact_mission", None)
        kwargs.pop("exact_project", None)

        for k, v in kwargs.items():
            if k == "metric":
                vs_kwargs[k] = v
            elif v is not None:
                metadata_filters[k] = v

        if metadata_filters:
            base_filters["metadata_filters"] = metadata_filters

        vec_filter = VectorFilter.from_dict(base_filters)

        # Over-sample to account for post-retrieval tag/status/project/mission filtering
        fetch_k = max(top_k_int * 5, 50) if (target_tags or allowed_statuses or global_only or target_project_id or target_mission_id) else max(top_k_int * 3, 20)
        raw_results = self.vector_store.search(
            query=q_val,
            top_k=fetch_k,
            filters=vec_filter,
            min_score=min_score_bounded,
            **vs_kwargs,
        )

        search_results: List[MemorySearchResult] = []
        for res in raw_results:
            doc = res.document
            if doc is None:
                doc = self.vector_store.get(res.id)
            if doc is None or doc.source_type != "memory":
                continue

            entry = MemoryEntry.from_vector_document(doc)

            # Post-filter on status if needed
            if allowed_statuses is not None:
                e_status = (
                    entry.status.value
                    if isinstance(entry.status, MemoryStatus)
                    else str(entry.status).strip().lower()
                )
                if e_status not in allowed_statuses:
                    continue

            # Post-filter on global_only vs mission_id
            if global_only:
                if entry.mission_id is not None:
                    continue
            elif target_mission_id is not None:
                doc_mid = entry.mission_id
                if exact_mission:
                    if doc_mid != target_mission_id:
                        continue
                else:
                    if doc_mid and doc_mid != target_mission_id:
                        continue

            # Post-filter on project_id if specified
            if target_project_id is not None:
                doc_pid = entry.project_id
                if exact_project:
                    if doc_pid != target_project_id:
                        continue
                else:
                    if doc_pid and doc_pid != target_project_id:
                        continue

            # Post-filter on tags if specified
            if target_tags:
                entry_tags_set = set(entry.tags)
                if not any(t in entry_tags_set for t in target_tags):
                    continue

            # Ensure similarity score is strictly bounded in [0.0, 1.0]
            try:
                score_f = float(res.score)
                import math
                if math.isnan(score_f):
                    bounded_score = 0.0
                elif math.isinf(score_f):
                    bounded_score = 1.0 if score_f > 0 else 0.0
                else:
                    bounded_score = max(0.0, min(1.0, score_f))
            except (ValueError, TypeError):
                bounded_score = 0.0

            if min_score_bounded is not None and bounded_score < min_score_bounded:
                continue

            search_results.append(
                MemorySearchResult(
                    entry=entry,
                    score=bounded_score,
                    distance=res.distance,
                )
            )

            if len(search_results) >= top_k_int:
                break

        return search_results

    def list(
        self,
        memory_type: Optional[Union[str, MemoryType, List[Union[str, MemoryType]]]] = None,
        mission_id: Optional[str] = None,
        status: Optional[Union[str, MemoryStatus, List[Union[str, MemoryStatus]]]] = None,
        project_id: Optional[str] = None,
        global_only: bool = False,
        tags: Optional[Union[str, List[str]]] = None,
        limit: Optional[int] = None,
        offset: int = 0,
        **kwargs: Any,
    ) -> List[MemoryEntry]:
        """
        List memory entries matching the criteria.
        
        Entries are returned in reverse chronological order (newest first).
        """
        clauses = ["source_type = 'memory'"]
        params: List[Any] = []

        if global_only:
            clauses.append("mission_id IS NULL")
        elif mission_id is not None:
            clauses.append("mission_id = ?")
            params.append(mission_id)

        if memory_type is not None:
            if isinstance(memory_type, (list, tuple, set)):
                types: List[str] = []
                for m in memory_type:
                    try:
                        types.append(MemoryType.from_str(m).value)
                    except ValueError:
                        types.append(str(m).strip().lower())
                placeholders = ", ".join(["?"] * len(types))
                clauses.append(f"category IN ({placeholders})")
                params.extend(types)
            else:
                try:
                    m_type = MemoryType.from_str(memory_type).value
                except ValueError:
                    m_type = str(memory_type).strip().lower()
                clauses.append("category = ?")
                params.append(m_type)

        where_clause = " WHERE " + " AND ".join(clauses)

        # Prepare status filtering set with canonical normalization
        status_filter_set: Optional[set] = None
        if status is not None:
            if isinstance(status, (list, tuple, set)):
                status_filter_set = set()
                for s in status:
                    try:
                        status_filter_set.add(MemoryStatus.from_str(s).value)
                    except ValueError:
                        status_filter_set.add(str(s).strip().lower())
            else:
                try:
                    s_str = MemoryStatus.from_str(status).value
                except ValueError:
                    s_str = str(status).strip().lower()
                status_filter_set = {s_str}

        # Normalize target tags for filtering
        target_tags_list: Optional[List[str]] = None
        if tags is not None:
            if isinstance(tags, str):
                target_tags_list = [tags.strip()] if tags.strip() else []
            elif isinstance(tags, (list, tuple, set)):
                target_tags_list = [str(t).strip() for t in tags if t is not None and str(t).strip()]

        clean_project_id = str(project_id).strip() if project_id is not None and str(project_id).strip() else None

        with self.vector_store._lock:
            cur = self.vector_store._conn.execute(
                f"""
                SELECT id, content, source_type, mission_id, severity, category,
                       metadata_json, created_at, updated_at
                FROM {self.vector_store.table_name}
                {where_clause}
                ORDER BY created_at DESC;
                """,
                params,
            )
            rows = cur.fetchall()

        entries: List[MemoryEntry] = []
        for row in rows:
            meta = {}
            if row["metadata_json"]:
                try:
                    meta = json.loads(row["metadata_json"])
                except Exception:
                    meta = {}

            # Status check with normalized string comparison
            if status_filter_set is not None:
                row_status = meta.get("status", MemoryStatus.ACTIVE.value)
                if isinstance(row_status, str):
                    row_status = row_status.strip().lower()
                if row_status not in status_filter_set:
                    continue

            # Project ID filtering
            if clean_project_id is not None:
                row_pid = meta.get("project_id")
                if row_pid is not None:
                    row_pid = str(row_pid).strip()
                if row_pid != clean_project_id:
                    continue

            # Tag filtering
            if target_tags_list:
                row_tags = meta.get("tags") or []
                row_tags_set = set(str(t).strip() for t in row_tags if t is not None)
                if not any(t in row_tags_set for t in target_tags_list):
                    continue

            doc = VectorDocument(
                id=row["id"],
                content=row["content"],
                source_type=row["source_type"],
                mission_id=row["mission_id"],
                severity=row["severity"],
                category=row["category"],
                metadata=meta,
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )
            entries.append(MemoryEntry.from_vector_document(doc))

        try:
            offset_val = max(0, int(offset)) if offset is not None else 0
        except (ValueError, TypeError):
            offset_val = 0

        if offset_val > 0:
            entries = entries[offset_val:]

        if limit is not None:
            try:
                limit_val = max(0, int(limit))
                entries = entries[:limit_val]
            except (ValueError, TypeError):
                pass

        return entries

    def update(
        self,
        id: str,
        content: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        confidence: Optional[float] = None,
        status: Optional[Union[str, MemoryStatus]] = None,
        memory_type: Optional[Union[str, MemoryType]] = None,
        mission_id: Any = _UNSET,
        title: Optional[str] = None,
        superseded_by: Optional[str] = None,
        **kwargs: Any,
    ) -> Optional[MemoryEntry]:
        """
        Update an existing memory entry atomically.
        
        Preserves existing vector embedding if content is unchanged.
        Enforces confidence bounds, status normalization, and type normalization.
        Returns the updated MemoryEntry, or None if not found.
        """
        if not id or not str(id).strip():
            return None

        with self.vector_store._lock:
            existing_doc = self.vector_store.get(str(id))
            if existing_doc is None or existing_doc.source_type != "memory":
                return None

            entry = MemoryEntry.from_vector_document(existing_doc)
            old_content = entry.content

            if content is not None:
                entry.content = str(content)
            if metadata is not None:
                entry.metadata = dict(metadata)
            if tags is not None:
                if isinstance(tags, str):
                    s_t = tags.strip()
                    entry.tags = [s_t] if s_t else []
                elif isinstance(tags, (list, tuple, set)):
                    entry.tags = [str(t).strip() for t in tags if t is not None and str(t).strip()]
                else:
                    entry.tags = []
            if confidence is not None:
                entry.confidence = confidence
            if status is not None:
                entry.status = status
            if memory_type is not None:
                entry.memory_type = memory_type
            if mission_id is not _UNSET:
                entry.mission_id = mission_id
                if mission_id is None:
                    entry.metadata.pop("mission_id", None)
                else:
                    entry.metadata["mission_id"] = mission_id
            if title is not None:
                entry.title = title
            if superseded_by is not None:
                entry.superseded_by = superseded_by

            if kwargs:
                for k, v in kwargs.items():
                    if v is None:
                        entry.metadata.pop(k, None)
                    else:
                        entry.metadata[k] = v

            # Re-normalize and enforce invariants
            entry.__post_init__()
            entry.updated_at = datetime.now(timezone.utc).isoformat()

            doc = entry.to_vector_document()
            # Reuse existing embedding if content is unchanged to avoid costly re-embedding
            if (content is None or entry.content == old_content) and existing_doc.embedding is not None:
                doc.embedding = existing_doc.embedding

            self.vector_store.add_document(doc)
            return entry

    def archive(self, id: str) -> bool:
        """
        Archive a memory entry by ID.
        
        Returns True if found and archived, False otherwise.
        """
        if not id or not str(id).strip():
            return False
        entry = self.update(id, status=MemoryStatus.ARCHIVED)
        return entry is not None

    def supersede(self, id: str, superseded_by_id: str) -> bool:
        """
        Mark a memory entry as superseded by another memory entry.
        
        Returns True if found and updated, False otherwise.
        """
        if not id or not str(id).strip():
            return False
        entry = self.update(
            id,
            status=MemoryStatus.SUPERSEDED,
            superseded_by=superseded_by_id,
        )
        return entry is not None

    def delete(self, id: str) -> bool:
        """
        Permanently delete a memory entry by ID.
        
        Returns True if deleted, False if not found.
        """
        if not id or not str(id).strip():
            return False
        with self.vector_store._lock:
            existing = self.get(id)
            if existing is None:
                return False
            return self.vector_store.delete(id)

    def clear(self, mission_id: Optional[str] = None) -> int:
        """
        Clear stored memories.
        
        If mission_id is specified, only memories for that mission are cleared.
        If mission_id is None, all conversational memories are deleted.
        Returns the number of deleted records.
        """
        if mission_id is not None:
            filters = VectorFilter(source_type="memory", mission_id=mission_id)
        else:
            filters = VectorFilter(source_type="memory")
        return self.vector_store.delete_where(filters)

    def count(
        self,
        filters: Optional[Union[Dict[str, Any], VectorFilter]] = None,
        memory_type: Optional[Union[str, MemoryType, List[Union[str, MemoryType]]]] = None,
        mission_id: Optional[str] = None,
        status: Optional[Union[str, MemoryStatus, List[Union[str, MemoryStatus]]]] = None,
        global_only: bool = False,
        **kwargs: Any,
    ) -> int:
        """
        Count total stored memories matching the optional filters or kwargs.
        """
        f_dict: Dict[str, Any] = {}
        if filters is not None:
            if isinstance(filters, VectorFilter):
                f_dict = filters.to_dict() if hasattr(filters, "to_dict") else dict(vars(filters))
            elif isinstance(filters, dict):
                f_dict = dict(filters)

        f_dict.update(kwargs)
        if memory_type is not None:
            f_dict["memory_type"] = memory_type
        if mission_id is not None:
            f_dict["mission_id"] = mission_id
        if status is not None:
            f_dict["status"] = status
        global_only = f_dict.pop("global_only", global_only)

        # Handle global_only count via direct SQL query
        if global_only:
            clauses = ["source_type = 'memory'", "mission_id IS NULL"]
            params: List[Any] = []
            if memory_type is not None:
                m_val = MemoryType.from_str(memory_type).value if isinstance(memory_type, (str, MemoryType)) else str(memory_type)
                clauses.append("category = ?")
                params.append(m_val)
            sql = f"SELECT metadata_json FROM {self.vector_store.table_name} WHERE " + " AND ".join(clauses)
            with self.vector_store._lock:
                cur = self.vector_store._conn.execute(sql, params)
                rows = cur.fetchall()
            if status is None:
                return len(rows)
            # Filter status in Python
            target_s = MemoryStatus.from_str(status).value if isinstance(status, (str, MemoryStatus)) else str(status).strip().lower()
            matching = 0
            for r in rows:
                meta = {}
                if r["metadata_json"]:
                    try:
                        meta = json.loads(r["metadata_json"])
                    except Exception:
                        pass
                if meta.get("status", "active") == target_s:
                    matching += 1
            return matching

        # Handle category / memory_type normalization
        m_type = f_dict.pop("memory_type", None) or f_dict.pop("category", None)
        if m_type is not None:
            if isinstance(m_type, (list, tuple, set)):
                cats: List[str] = []
                for m in m_type:
                    try:
                        cats.append(MemoryType.from_str(m).value)
                    except ValueError:
                        cats.append(str(m).strip().lower())
                f_dict["category"] = cats
            else:
                try:
                    f_dict["category"] = MemoryType.from_str(m_type).value
                except ValueError:
                    f_dict["category"] = str(m_type).strip().lower()

        # Handle status normalization
        stat = f_dict.pop("status", None)
        if stat is not None:
            if isinstance(stat, (list, tuple, set)):
                stats: List[str] = []
                for s in stat:
                    try:
                        stats.append(MemoryStatus.from_str(s).value)
                    except ValueError:
                        stats.append(str(s).strip().lower())
                unique_stats = list(dict.fromkeys(stats))
                if not unique_stats:
                    return 0
                elif len(unique_stats) == 1:
                    existing_meta = dict(f_dict.get("metadata_filters") or {})
                    existing_meta["status"] = unique_stats[0]
                    f_dict["metadata_filters"] = existing_meta
                else:
                    return sum(
                        self.count(
                            filters=dict(f_dict),
                            status=s,
                        )
                        for s in unique_stats
                    )
            else:
                try:
                    s_norm = MemoryStatus.from_str(stat).value
                except ValueError:
                    s_norm = str(stat).strip().lower()
                existing_meta = dict(f_dict.get("metadata_filters") or {})
                existing_meta["status"] = s_norm
                f_dict["metadata_filters"] = existing_meta

        f_dict["source_type"] = "memory"
        vec_filter = VectorFilter.from_dict(f_dict)
        return self.vector_store.count(vec_filter)
