"""High-level facade and lifecycle manager for ARGUS conversational memory."""

import logging
import threading
from typing import Any, Dict, List, Optional, Union
import uuid

from argus.memory.models import (
    MemoryEntry,
    MemoryQuery,
    MemorySearchResult,
    MemoryStatus,
    MemoryType,
)
from argus.memory.store import MemoryStore
from argus.vector.models import VectorStoreConfig
from argus.vector.store import VectorStore

logger = logging.getLogger(__name__)


class MemoryManager:
    """
    High-level facade wrapping MemoryStore.
    
    Provides:
    - Semantic recall (`recall(query, top_k)`) returning ranked memory entries.
    - Memory lifecycle management (create, update, archive, supersede).
    - Cross-mission knowledge transfer (promotion to global, pattern export/import).
    """

    def __init__(
        self,
        store: Optional[MemoryStore] = None,
        vector_store: Optional[VectorStore] = None,
        db_path: Optional[str] = None,
        config: Optional[VectorStoreConfig] = None,
        **kwargs: Any,
    ) -> None:
        if store is not None:
            self.store = store
        elif vector_store is not None:
            self.store = MemoryStore(vector_store=vector_store, **kwargs)
        elif db_path is not None or config is not None:
            self.store = MemoryStore(db_path=db_path, config=config, **kwargs)
        else:
            self.store = MemoryStore(**kwargs)

    # --------------------------------------------------------------------------
    # Semantic Recall
    # --------------------------------------------------------------------------

    def recall(
        self,
        query: Union[str, MemoryQuery],
        top_k: Optional[int] = None,
        min_score: Optional[float] = None,
        mission_id: Optional[str] = None,
        project_id: Optional[str] = None,
        memory_type: Optional[Union[str, MemoryType, List[Union[str, MemoryType]]]] = None,
        status: Optional[Union[str, MemoryStatus, List[Union[str, MemoryStatus]]]] = None,
        tags: Optional[Union[str, List[str]]] = None,
        active_only: bool = False,
        global_only: bool = False,
        **kwargs: Any,
    ) -> List[MemorySearchResult]:
        """
        Recall semantically relevant memories matching query criteria.
        
        Returns ranked list of MemorySearchResult objects whose scores are
        bounded in [0.0, 1.0].
        """
        if active_only and status is None:
            status = MemoryStatus.ACTIVE

        return self.store.search(
            query=query,
            top_k=top_k,
            min_score=min_score,
            memory_type=memory_type,
            mission_id=mission_id,
            project_id=project_id,
            status=status,
            tags=tags,
            global_only=global_only,
            active_only=active_only,
            **kwargs,
        )

    def recall_global(
        self,
        query: Union[str, MemoryQuery],
        top_k: int = 10,
        min_score: Optional[float] = None,
        **kwargs: Any,
    ) -> List[MemorySearchResult]:
        """
        Recall cross-mission / global memories (memories without mission_id).
        """
        if isinstance(query, MemoryQuery):
            query.mission_id = None
            query.global_only = True
            return self.recall(query, top_k=top_k, min_score=min_score, global_only=True, **kwargs)
        return self.recall(
            query=query,
            top_k=top_k,
            min_score=min_score,
            mission_id=None,
            global_only=True,
            **kwargs,
        )

    # --------------------------------------------------------------------------
    # Memory Recording & Lifecycle
    # --------------------------------------------------------------------------

    def record(
        self,
        content: str,
        memory_type: Union[MemoryType, str] = MemoryType.NOTE,
        mission_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
        confidence: float = 1.0,
        title: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        id: Optional[str] = None,
        **kwargs: Any,
    ) -> MemoryEntry:
        """
        Record a generic memory entry into the store.
        """
        meta = dict(metadata or {})
        if kwargs:
            meta.update(kwargs)

        entry = MemoryEntry(
            id=id or str(uuid.uuid4()),
            content=content,
            memory_type=memory_type,
            mission_id=mission_id,
            tags=tags or [],
            confidence=confidence,
            title=title,
            metadata=meta,
        )
        self.store.add(entry)
        return entry

    def record_attack_pattern(
        self,
        content: str,
        mission_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
        confidence: float = 1.0,
        title: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> MemoryEntry:
        """Record an attack pattern learned from scans or manual pentests."""
        return self.record(
            content=content,
            memory_type=MemoryType.ATTACK_PATTERN,
            mission_id=mission_id,
            tags=tags,
            confidence=confidence,
            title=title,
            metadata=metadata,
            **kwargs,
        )

    def record_user_correction(
        self,
        content: str,
        mission_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
        confidence: float = 1.0,
        title: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> MemoryEntry:
        """Record a user correction or manual override."""
        return self.record(
            content=content,
            memory_type=MemoryType.USER_CORRECTION,
            mission_id=mission_id,
            tags=tags,
            confidence=confidence,
            title=title,
            metadata=metadata,
            **kwargs,
        )

    def record_strategic_decision(
        self,
        content: str,
        mission_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
        confidence: float = 1.0,
        title: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> MemoryEntry:
        """Record a strategic decision (e.g., skip host X, prioritize SQLi over XSS)."""
        return self.record(
            content=content,
            memory_type=MemoryType.STRATEGIC_DECISION,
            mission_id=mission_id,
            tags=tags,
            confidence=confidence,
            title=title,
            metadata=metadata,
            **kwargs,
        )

    def record_session_context(
        self,
        content: str,
        mission_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
        confidence: float = 1.0,
        title: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> MemoryEntry:
        """Record active session context (current scan state, active hypotheses)."""
        return self.record(
            content=content,
            memory_type=MemoryType.SESSION_CONTEXT,
            mission_id=mission_id,
            tags=tags,
            confidence=confidence,
            title=title,
            metadata=metadata,
            **kwargs,
        )

    def record_note(
        self,
        content: str,
        mission_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
        confidence: float = 1.0,
        title: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> MemoryEntry:
        """Record a free-form analyst or agent note."""
        return self.record(
            content=content,
            memory_type=MemoryType.NOTE,
            mission_id=mission_id,
            tags=tags,
            confidence=confidence,
            title=title,
            metadata=metadata,
            **kwargs,
        )

    def get_entry(self, entry_id: str) -> Optional[MemoryEntry]:
        """Retrieve a memory entry by ID."""
        return self.store.get(entry_id)

    def update_entry(self, entry_id: str, **kwargs: Any) -> Optional[MemoryEntry]:
        """Update fields of an existing memory entry."""
        return self.store.update(entry_id, **kwargs)

    def archive_entry(self, entry_id: str) -> bool:
        """Archive a memory entry."""
        return self.store.archive(entry_id)

    def supersede_entry(self, old_entry_id: str, new_entry_id: str) -> bool:
        """Mark old memory entry as superseded by new entry."""
        return self.store.supersede(old_entry_id, new_entry_id)

    def supersede_with_new(
        self,
        old_entry_id: str,
        new_content: str,
        memory_type: Optional[Union[MemoryType, str]] = None,
        mission_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
        confidence: float = 1.0,
        title: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Optional[MemoryEntry]:
        """
        Record a replacement memory entry and mark the original as superseded.
        """
        old = self.get_entry(old_entry_id)
        if old is None:
            return None

        m_type = memory_type or old.memory_type
        m_id = mission_id if mission_id is not None else old.mission_id
        t = tags if tags is not None else old.tags
        m_meta = dict(old.metadata)
        if metadata:
            m_meta.update(metadata)

        new_entry = self.record(
            content=new_content,
            memory_type=m_type,
            mission_id=m_id,
            tags=t,
            confidence=confidence,
            title=title,
            metadata=m_meta,
            **kwargs,
        )

        self.supersede_entry(old_entry_id, new_entry.id)
        return new_entry

    def delete_entry(self, entry_id: str) -> bool:
        """Permanently delete a memory entry."""
        return self.store.delete(entry_id)

    def list_entries(
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
        """List entries matching the specified criteria."""
        return self.store.list(
            memory_type=memory_type,
            mission_id=mission_id,
            status=status,
            project_id=project_id,
            global_only=global_only,
            tags=tags,
            limit=limit,
            offset=offset,
            **kwargs,
        )

    def clear_mission(self, mission_id: str) -> int:
        """Clear all memories associated with a specific mission."""
        if not mission_id or not str(mission_id).strip():
            return 0
        return self.store.clear(mission_id=str(mission_id).strip())

    def clear_all(self) -> int:
        """Clear all memories across all missions."""
        return self.store.clear(mission_id=None)

    def count_entries(
        self,
        filters: Optional[Union[Dict[str, Any], Any]] = None,
        **kwargs: Any,
    ) -> int:
        """Count total memory entries matching the filters or keyword arguments."""
        return self.store.count(filters, **kwargs)

    # --------------------------------------------------------------------------
    # Cross-Mission Knowledge Transfer
    # --------------------------------------------------------------------------

    def promote_to_global(self, entry_id: str) -> Optional[MemoryEntry]:
        """
        Promote a mission-scoped memory entry to a global memory by removing
        its mission_id binding.
        """
        entry = self.get_entry(entry_id)
        if entry is None:
            return None

        entry.mission_id = None
        if "mission_id" in entry.metadata:
            del entry.metadata["mission_id"]

        return self.store.update(
            id=entry_id,
            mission_id=None,
            metadata=entry.metadata,
        )

    def transfer_to_mission(
        self,
        entry_id: str,
        target_mission_id: str,
    ) -> Optional[MemoryEntry]:
        """
        Clone a memory entry into a target mission's context.
        """
        if not target_mission_id or not str(target_mission_id).strip():
            return None
        clean_target_mid = str(target_mission_id).strip()

        source = self.get_entry(entry_id)
        if source is None:
            return None

        cloned_meta = dict(source.metadata)
        cloned_meta["transferred_from_entry"] = source.id
        cloned_meta["transferred_from_mission"] = source.mission_id

        return self.record(
            content=source.content,
            memory_type=source.memory_type,
            mission_id=clean_target_mid,
            tags=list(source.tags),
            confidence=source.confidence,
            title=source.title,
            metadata=cloned_meta,
        )

    def export_attack_patterns(
        self,
        mission_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Export learned attack patterns for cross-mission knowledge sharing.
        """
        entries = self.list_entries(
            memory_type=MemoryType.ATTACK_PATTERN,
            mission_id=mission_id,
            status=MemoryStatus.ACTIVE,
        )
        return [e.to_dict() for e in entries]

    def import_attack_patterns(
        self,
        patterns: List[Dict[str, Any]],
        target_mission_id: Optional[str] = None,
    ) -> List[MemoryEntry]:
        """
        Import attack patterns into the store, optionally scoping them to a mission.
        """
        if not patterns:
            return []
        pattern_list = list(patterns)
        if not pattern_list:
            return []
        clean_mid = str(target_mission_id).strip() if target_mission_id and str(target_mission_id).strip() else None
        imported: List[MemoryEntry] = []
        for p in pattern_list:
            if not isinstance(p, dict):
                continue
            p_data = dict(p)
            # Remove id to generate new entry or reuse
            p_data.pop("id", None)
            if clean_mid is not None:
                p_data["mission_id"] = clean_mid
            p_data["memory_type"] = MemoryType.ATTACK_PATTERN
            entry = MemoryEntry.from_dict(p_data)
            imported.append(entry)
        if imported:
            self.store.add_batch(imported)
        return imported


_GLOBAL_MEMORY_MANAGER: Optional[MemoryManager] = None
_MANAGER_LOCK = threading.Lock()


def get_memory_manager(
    store: Optional[MemoryStore] = None,
    vector_store: Optional[VectorStore] = None,
    force_new: bool = False,
    **kwargs: Any,
) -> MemoryManager:
    """
    Get or create singleton/cached MemoryManager instance (thread-safe).
    """
    global _GLOBAL_MEMORY_MANAGER
    with _MANAGER_LOCK:
        curr_vs = getattr(_GLOBAL_MEMORY_MANAGER.store, "vector_store", None) if _GLOBAL_MEMORY_MANAGER and hasattr(_GLOBAL_MEMORY_MANAGER, "store") else None
        should_create = (
            _GLOBAL_MEMORY_MANAGER is None
            or force_new
            or (store is not None and _GLOBAL_MEMORY_MANAGER.store != store)
            or (vector_store is not None and curr_vs != vector_store)
        )
        if should_create:
            _GLOBAL_MEMORY_MANAGER = MemoryManager(
                store=store,
                vector_store=vector_store,
                **kwargs,
            )
        return _GLOBAL_MEMORY_MANAGER
