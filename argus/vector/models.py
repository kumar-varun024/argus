"""Data models for vector store, embeddings, and semantic search operations."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union


class DistanceMetric(str, Enum):
    """Supported distance metrics for vector similarity calculations."""
    COSINE = "cosine"
    L2 = "l2"
    DOT = "dot"

    @classmethod
    def from_str(cls, value: Union[str, "DistanceMetric"]) -> "DistanceMetric":
        if isinstance(value, DistanceMetric):
            return value
        val = str(value).strip().lower()
        if val in ("cosine", "cos"):
            return cls.COSINE
        elif val in ("l2", "euclidean"):
            return cls.L2
        elif val in ("dot", "inner_product", "ip"):
            return cls.DOT
        raise ValueError(f"Unsupported distance metric: {value}")


@dataclass
class VectorStoreConfig:
    """Configuration options for VectorStore instance."""
    db_path: str = "~/.argus/vector_store.db"
    dimension: int = 384
    distance_metric: DistanceMetric = DistanceMetric.COSINE
    table_name: str = "documents"
    use_sqlite_vec: bool = True
    auto_create_tables: bool = True
    embedding_provider: str = "auto"

    def __post_init__(self):
        if isinstance(self.distance_metric, str):
            self.distance_metric = DistanceMetric.from_str(self.distance_metric)


@dataclass
class VectorDocument:
    """Represents a document stored in the vector store with embeddings and metadata."""
    id: str
    content: str
    embedding: Optional[List[float]] = None
    source_type: str = "general"
    mission_id: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert VectorDocument instance to a dictionary."""
        return {
            "id": self.id,
            "content": self.content,
            "embedding": self.embedding,
            "source_type": self.source_type,
            "mission_id": self.mission_id,
            "severity": self.severity,
            "category": self.category,
            "metadata": self.metadata,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VectorDocument":
        """Create VectorDocument from a dictionary."""
        return cls(
            id=str(data["id"]),
            content=str(data["content"]),
            embedding=data.get("embedding"),
            source_type=str(data.get("source_type", "general")),
            mission_id=data.get("mission_id"),
            severity=data.get("severity"),
            category=data.get("category"),
            metadata=dict(data.get("metadata") or {}),
            created_at=data.get("created_at") or datetime.now(timezone.utc).isoformat(),
            updated_at=data.get("updated_at") or datetime.now(timezone.utc).isoformat(),
        )


@dataclass
class SearchResult:
    """Represents a single search result with similarity score and metadata."""
    id: str
    content: str
    score: float
    distance: float
    source_type: str = "general"
    mission_id: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    document: Optional[VectorDocument] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert SearchResult to dictionary."""
        return {
            "id": self.id,
            "content": self.content,
            "score": self.score,
            "distance": self.distance,
            "source_type": self.source_type,
            "mission_id": self.mission_id,
            "severity": self.severity,
            "category": self.category,
            "metadata": self.metadata,
            "created_at": self.created_at,
        }


@dataclass
class VectorFilter:
    """Metadata filter criteria for vector search and deletion operations."""
    source_type: Optional[Union[str, List[str]]] = None
    mission_id: Optional[Union[str, List[str]]] = None
    severity: Optional[Union[str, List[str]]] = None
    category: Optional[Union[str, List[str]]] = None
    metadata_filters: Optional[Dict[str, Any]] = None
    min_score: Optional[float] = None

    @classmethod
    def from_dict(cls, data: Optional[Union[Dict[str, Any], "VectorFilter"]]) -> "VectorFilter":
        """Factory method to convert dictionary or existing VectorFilter."""
        if data is None:
            return cls()
        if isinstance(data, VectorFilter):
            return data
        
        known_keys = {"source_type", "mission_id", "severity", "category", "metadata_filters", "min_score"}
        kwargs: Dict[str, Any] = {}
        extra_meta: Dict[str, Any] = {}
        for k, v in data.items():
            if k in known_keys:
                kwargs[k] = v
            else:
                extra_meta[k] = v
        if extra_meta:
            existing_meta = kwargs.get("metadata_filters") or {}
            kwargs["metadata_filters"] = {**existing_meta, **extra_meta}
        return cls(**kwargs)

    def matches(self, doc_dict: Dict[str, Any]) -> bool:
        """Check if a document dictionary matches this filter in-memory."""
        if self.source_type is not None:
            val = doc_dict.get("source_type")
            if isinstance(self.source_type, list):
                if val not in self.source_type:
                    return False
            elif val != self.source_type:
                return False

        if self.mission_id is not None:
            val = doc_dict.get("mission_id")
            if isinstance(self.mission_id, list):
                if val not in self.mission_id:
                    return False
            elif val != self.mission_id:
                return False

        if self.severity is not None:
            val = doc_dict.get("severity")
            if isinstance(self.severity, list):
                if val not in self.severity:
                    return False
            elif val != self.severity:
                return False

        if self.category is not None:
            val = doc_dict.get("category")
            if isinstance(self.category, list):
                if val not in self.category:
                    return False
            elif val != self.category:
                return False

        if self.metadata_filters:
            doc_meta = doc_dict.get("metadata") or {}
            for mk, mv in self.metadata_filters.items():
                if doc_meta.get(mk) != mv:
                    return False

        return True

    def to_sql_conditions(self, table_prefix: str = "") -> Tuple[str, List[Any]]:
        """Generate SQL WHERE clauses and parameters for column-level filters."""
        clauses = []
        params = []
        prefix = f"{table_prefix}." if table_prefix else ""

        if self.source_type is not None:
            if isinstance(self.source_type, list):
                placeholders = ", ".join(["?"] * len(self.source_type))
                clauses.append(f"{prefix}source_type IN ({placeholders})")
                params.extend(self.source_type)
            else:
                clauses.append(f"{prefix}source_type = ?")
                params.append(self.source_type)

        if self.mission_id is not None:
            if isinstance(self.mission_id, list):
                placeholders = ", ".join(["?"] * len(self.mission_id))
                clauses.append(f"{prefix}mission_id IN ({placeholders})")
                params.extend(self.mission_id)
            else:
                clauses.append(f"{prefix}mission_id = ?")
                params.append(self.mission_id)

        if self.severity is not None:
            if isinstance(self.severity, list):
                placeholders = ", ".join(["?"] * len(self.severity))
                clauses.append(f"{prefix}severity IN ({placeholders})")
                params.extend(self.severity)
            else:
                clauses.append(f"{prefix}severity = ?")
                params.append(self.severity)

        if self.category is not None:
            if isinstance(self.category, list):
                placeholders = ", ".join(["?"] * len(self.category))
                clauses.append(f"{prefix}category IN ({placeholders})")
                params.extend(self.category)
            else:
                clauses.append(f"{prefix}category = ?")
                params.append(self.category)

        where_clause = " AND ".join(clauses) if clauses else ""
        return where_clause, params
