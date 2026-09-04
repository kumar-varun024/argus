"""Data models for ARGUS conversational memory system."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
import math
import uuid

from argus.vector.models import VectorDocument


class MemoryType(str, Enum):
    """Supported categories of conversational and agentic memories."""
    ATTACK_PATTERN = "attack_pattern"
    USER_CORRECTION = "user_correction"
    STRATEGIC_DECISION = "strategic_decision"
    SESSION_CONTEXT = "session_context"
    NOTE = "note"

    @classmethod
    def from_str(cls, value: Union[str, "MemoryType"]) -> "MemoryType":
        if isinstance(value, MemoryType):
            return value
        val = str(value).strip().lower().replace("-", "_").replace(" ", "_")
        for member in cls:
            if member.value == val or member.name.lower() == val:
                return member
        raise ValueError(f"Unsupported memory type: {value}")


class MemoryStatus(str, Enum):
    """Lifecycle state of a memory entry."""
    ACTIVE = "active"
    ARCHIVED = "archived"
    SUPERSEDED = "superseded"

    @classmethod
    def from_str(cls, value: Union[str, "MemoryStatus"]) -> "MemoryStatus":
        if isinstance(value, MemoryStatus):
            return value
        val = str(value).strip().lower().replace("-", "_").replace(" ", "_")
        for member in cls:
            if member.value == val or member.name.lower() == val:
                return member
        raise ValueError(f"Unsupported memory status: {value}")


def _sanitize_metadata(val: Any) -> Any:
    """Recursively sanitize metadata into JSON-serializable structures."""
    if isinstance(val, dict):
        return {str(k): _sanitize_metadata(v) for k, v in val.items()}
    elif isinstance(val, (list, tuple, set)):
        return [_sanitize_metadata(x) for x in val]
    elif isinstance(val, uuid.UUID):
        return str(val)
    elif isinstance(val, datetime):
        return val.isoformat()
    elif isinstance(val, Enum):
        return val.value
    return val


@dataclass(slots=True)
class MemoryEntry:
    """
    Represents a single persistent memory unit in ARGUS.
    
    Covers attack patterns, user corrections, strategic decisions,
    session context, and free-form notes.
    """
    content: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    memory_type: Union[MemoryType, str] = MemoryType.NOTE
    mission_id: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    confidence: float = 1.0
    status: Union[MemoryStatus, str] = MemoryStatus.ACTIVE
    title: Optional[str] = None
    superseded_by: Optional[str] = None

    @property
    def project_id(self) -> Optional[str]:
        """Convenience property retrieving project_id from metadata if present."""
        if self.metadata and "project_id" in self.metadata:
            val = self.metadata["project_id"]
            if val is not None:
                s_val = str(val).strip()
                return s_val if s_val else None
        return None

    @project_id.setter
    def project_id(self, value: Optional[str]) -> None:
        """Set or remove project_id in metadata."""
        if self.metadata is None:
            self.metadata = {}
        if value is None:
            self.metadata.pop("project_id", None)
        else:
            s_val = str(value).strip()
            if s_val:
                self.metadata["project_id"] = s_val
            else:
                self.metadata.pop("project_id", None)

    @property
    def is_active(self) -> bool:
        """Check if memory entry is currently active."""
        st = self.status.value if isinstance(self.status, MemoryStatus) else str(self.status).strip().lower()
        return st == MemoryStatus.ACTIVE.value

    @property
    def is_archived(self) -> bool:
        """Check if memory entry has been archived."""
        st = self.status.value if isinstance(self.status, MemoryStatus) else str(self.status).strip().lower()
        return st == MemoryStatus.ARCHIVED.value

    @property
    def is_superseded(self) -> bool:
        """Check if memory entry has been superseded by a newer entry."""
        st = self.status.value if isinstance(self.status, MemoryStatus) else str(self.status).strip().lower()
        return st == MemoryStatus.SUPERSEDED.value

    def __post_init__(self) -> None:
        if not self.id:
            self.id = str(uuid.uuid4())

        # Normalize content to string
        if self.content is None:
            self.content = ""
        elif not isinstance(self.content, str):
            self.content = str(self.content)

        # Normalize memory_type
        if not self.memory_type:
            self.memory_type = MemoryType.NOTE
        elif isinstance(self.memory_type, str):
            try:
                self.memory_type = MemoryType.from_str(self.memory_type)
            except ValueError:
                pass

        # Normalize status
        if not self.status:
            self.status = MemoryStatus.ACTIVE
        elif isinstance(self.status, str):
            try:
                self.status = MemoryStatus.from_str(self.status)
            except ValueError:
                pass

        # Validate confidence in [0.0, 1.0]
        try:
            conf = float(self.confidence)
            if math.isnan(conf) or math.isinf(conf):
                self.confidence = 1.0
            else:
                self.confidence = max(0.0, min(1.0, conf))
        except (ValueError, TypeError):
            self.confidence = 1.0

        # Ensure collections are valid and tags does not split strings into char lists
        if self.tags is None:
            self.tags = []
        elif isinstance(self.tags, str):
            s_tag = self.tags.strip()
            self.tags = [s_tag] if s_tag else []
        elif isinstance(self.tags, (list, tuple, set)):
            self.tags = [str(t).strip() for t in self.tags if t is not None and str(t).strip()]
        else:
            self.tags = []

        if self.metadata is None:
            self.metadata = {}
        elif not isinstance(self.metadata, dict):
            try:
                self.metadata = dict(self.metadata)
            except Exception:
                self.metadata = {}

        # Sanitize metadata to guarantee JSON serializability
        self.metadata = _sanitize_metadata(self.metadata)

        # Normalize and sync mission_id in metadata with strict precedence
        if self.mission_id is not None:
            s_mid = str(self.mission_id).strip()
            self.mission_id = s_mid if s_mid else None

        if self.mission_id:
            self.metadata["mission_id"] = self.mission_id
        else:
            self.metadata.pop("mission_id", None)

        # Normalize project_id in metadata if present
        if "project_id" in self.metadata:
            pid_raw = self.metadata["project_id"]
            if pid_raw is None or (isinstance(pid_raw, str) and not pid_raw.strip()):
                self.metadata.pop("project_id", None)
            else:
                self.metadata["project_id"] = str(pid_raw).strip()

        # Validate timestamps
        if not self.created_at or not isinstance(self.created_at, str) or not str(self.created_at).strip():
            self.created_at = datetime.now(timezone.utc).isoformat()
        if not self.updated_at or not isinstance(self.updated_at, str) or not str(self.updated_at).strip():
            self.updated_at = datetime.now(timezone.utc).isoformat()

        # Auto-generate title if missing or whitespace only
        if self.title is not None:
            self.title = str(self.title).strip()
        if not self.title:
            type_label = (
                self.memory_type.value.replace("_", " ").title()
                if isinstance(self.memory_type, MemoryType)
                else str(self.memory_type).title()
            )
            clean_content = (self.content or "").strip().splitlines()
            first_line = clean_content[0].strip() if clean_content else ""
            if first_line:
                preview = first_line[:50] + ("..." if len(first_line) > 50 else "")
                self.title = f"[{type_label}] {preview}"
            else:
                self.title = f"[{type_label}] Memory {self.id[:8]}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to dictionary representation."""
        type_val = (
            self.memory_type.value
            if isinstance(self.memory_type, MemoryType)
            else str(self.memory_type)
        )
        status_val = (
            self.status.value
            if isinstance(self.status, MemoryStatus)
            else str(self.status)
        )
        return {
            "id": self.id,
            "content": self.content,
            "memory_type": type_val,
            "mission_id": self.mission_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "metadata": _sanitize_metadata(dict(self.metadata)),
            "tags": list(self.tags),
            "confidence": self.confidence,
            "status": status_val,
            "title": self.title,
            "superseded_by": self.superseded_by,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MemoryEntry":
        """Reconstitute MemoryEntry from dictionary representation."""
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict for MemoryEntry.from_dict, got {type(data).__name__}")
        raw_type = data.get("memory_type") or data.get("type") or MemoryType.NOTE
        raw_status = data.get("status")
        if raw_status is None:
            raw_status = MemoryStatus.ACTIVE

        raw_conf = data.get("confidence")
        try:
            confidence = float(raw_conf) if raw_conf is not None else 1.0
            if math.isnan(confidence) or math.isinf(confidence):
                confidence = 1.0
            else:
                confidence = max(0.0, min(1.0, confidence))
        except (ValueError, TypeError):
            confidence = 1.0

        raw_meta = data.get("metadata")
        meta = dict(raw_meta) if isinstance(raw_meta, dict) else {}

        # Preserve mission_id from either top-level or metadata
        mission_id = data.get("mission_id")
        if mission_id is None and "mission_id" in meta:
            mission_id = meta.get("mission_id")

        # Preserve project_id from top-level if not already in metadata
        if "project_id" in data and "project_id" not in meta:
            p_val = data.get("project_id")
            if p_val is not None and str(p_val).strip():
                meta["project_id"] = str(p_val).strip()

        raw_tags = data.get("tags")
        tags = list(raw_tags) if isinstance(raw_tags, (list, tuple, set)) else []

        return cls(
            id=str(data.get("id") or uuid.uuid4()),
            content=str(data.get("content", "") if data.get("content") is not None else ""),
            memory_type=raw_type,
            mission_id=mission_id,
            created_at=data.get("created_at") or datetime.now(timezone.utc).isoformat(),
            updated_at=data.get("updated_at") or datetime.now(timezone.utc).isoformat(),
            metadata=meta,
            tags=tags,
            confidence=confidence,
            status=raw_status,
            title=data.get("title"),
            superseded_by=data.get("superseded_by"),
        )

    def to_vector_document(self) -> VectorDocument:
        """Convert MemoryEntry to a VectorDocument with source_type='memory'."""
        type_str = (
            self.memory_type.value
            if isinstance(self.memory_type, MemoryType)
            else str(self.memory_type)
        )
        status_str = (
            self.status.value
            if isinstance(self.status, MemoryStatus)
            else str(self.status)
        )

        doc_meta = dict(self.metadata)
        doc_meta.update({
            "memory_type": type_str,
            "status": status_str,
            "confidence": self.confidence,
            "tags": list(self.tags),
            "title": self.title,
            "superseded_by": self.superseded_by,
            "mission_id": self.mission_id,
        })

        sanitized_meta = _sanitize_metadata(doc_meta)

        return VectorDocument(
            id=self.id,
            content=self.content,
            source_type="memory",
            mission_id=self.mission_id,
            category=type_str,
            metadata=sanitized_meta,
            created_at=self.created_at,
            updated_at=self.updated_at,
        )

    @classmethod
    def from_vector_document(cls, doc: VectorDocument) -> "MemoryEntry":
        """Reconstruct a MemoryEntry from a stored VectorDocument."""
        meta = dict(doc.metadata or {})
        memory_type = meta.pop("memory_type", doc.category or MemoryType.NOTE)
        status = meta.pop("status", MemoryStatus.ACTIVE)
        raw_conf = meta.pop("confidence", 1.0)
        try:
            confidence = float(raw_conf)
            if math.isnan(confidence) or math.isinf(confidence):
                confidence = 1.0
            else:
                confidence = max(0.0, min(1.0, confidence))
        except (ValueError, TypeError):
            confidence = 1.0
        tags = meta.pop("tags", [])
        title = meta.pop("title", None)
        superseded_by = meta.pop("superseded_by", None)
        mission_id = doc.mission_id if doc.mission_id is not None else meta.pop("mission_id", None)
        meta.pop("mission_id", None)

        return cls(
            id=doc.id,
            content=doc.content,
            memory_type=memory_type,
            mission_id=mission_id,
            created_at=doc.created_at,
            updated_at=doc.updated_at,
            metadata=meta,
            tags=list(tags) if isinstance(tags, (list, tuple, set)) else [],
            confidence=confidence,
            status=status,
            title=title,
            superseded_by=superseded_by,
        )


@dataclass(slots=True)
class MemoryQuery:
    """Query parameters for semantic memory recall."""
    query: Optional[Union[str, List[float]]] = None
    top_k: int = 10
    min_score: Optional[float] = None
    mission_id: Optional[str] = None
    project_id: Optional[str] = None
    memory_type: Optional[Union[MemoryType, str, List[Union[MemoryType, str]]]] = None
    status: Optional[Union[MemoryStatus, str, List[Union[MemoryStatus, str]]]] = None
    tags: Optional[List[str]] = None
    filters: Optional[Dict[str, Any]] = None
    global_only: bool = False
    active_only: bool = False


@dataclass(slots=True)
class MemorySearchResult:
    """Represents a scored recall result from the memory store."""
    entry: MemoryEntry
    score: float
    distance: float = 0.0

    def __post_init__(self) -> None:
        # Enforce score bound invariant [0.0, 1.0]
        try:
            s = float(self.score)
            if math.isnan(s):
                self.score = 0.0
            elif math.isinf(s):
                self.score = 1.0 if s > 0 else 0.0
            else:
                self.score = max(0.0, min(1.0, s))
        except (ValueError, TypeError):
            self.score = 0.0

    @property
    def id(self) -> str:
        return self.entry.id

    @property
    def content(self) -> str:
        return self.entry.content

    @property
    def title(self) -> str:
        return self.entry.title or ""

    @property
    def memory_type(self) -> Union[MemoryType, str]:
        return self.entry.memory_type

    @property
    def mission_id(self) -> Optional[str]:
        return self.entry.mission_id

    @property
    def status(self) -> Union[MemoryStatus, str]:
        return self.entry.status

    @property
    def is_active(self) -> bool:
        return self.entry.is_active

    @property
    def is_archived(self) -> bool:
        return self.entry.is_archived

    @property
    def is_superseded(self) -> bool:
        return self.entry.is_superseded

    @property
    def metadata(self) -> Dict[str, Any]:
        return self.entry.metadata

    @property
    def tags(self) -> List[str]:
        return self.entry.tags

    @property
    def confidence(self) -> float:
        return self.entry.confidence

    @property
    def created_at(self) -> str:
        return self.entry.created_at

    @property
    def updated_at(self) -> str:
        return self.entry.updated_at

    @property
    def project_id(self) -> Optional[str]:
        return self.entry.project_id

    @property
    def superseded_by(self) -> Optional[str]:
        return self.entry.superseded_by

    def to_dict(self) -> Dict[str, Any]:
        """Convert search result to dictionary."""
        d = self.entry.to_dict()
        d["score"] = self.score
        d["distance"] = self.distance
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MemorySearchResult":
        """Reconstitute MemorySearchResult from dictionary representation."""
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict for MemorySearchResult.from_dict, got {type(data).__name__}")
        if "entry" in data and isinstance(data["entry"], dict):
            entry = MemoryEntry.from_dict(data["entry"])
        else:
            entry = MemoryEntry.from_dict(data)
        raw_score = data.get("score", 0.0)
        raw_dist = data.get("distance", 0.0)
        try:
            score = float(raw_score)
        except (ValueError, TypeError):
            score = 0.0
        try:
            dist = float(raw_dist)
        except (ValueError, TypeError):
            dist = 0.0
        return cls(entry=entry, score=score, distance=dist)
