"""
ARGUS Vector Store & Semantic Search Module.

Provides local, air-gapped vector embeddings, persistent SQLite storage,
sqlite-vec virtual table acceleration with resilient NumPy fallback,
and multi-field metadata filtering.
"""

from argus.vector.exceptions import (
    DimensionMismatchError,
    DocumentNotFoundError,
    EmbeddingError,
    ExtensionLoadError,
    VectorStoreError,
)
from argus.vector.embeddings import (
    BaseEmbeddingProvider,
    DeterministicEmbeddingProvider,
    EmbeddingEngine,
    FastEmbedProvider,
    SentenceTransformerProvider,
    get_embedding_engine,
)
from argus.vector.models import (
    DistanceMetric,
    SearchResult,
    VectorDocument,
    VectorFilter,
    VectorStoreConfig,
)
from argus.vector.store import (
    VectorStore,
    get_vector_store,
)

__all__ = [
    # Core Classes
    "VectorStore",
    "VectorDocument",
    "SearchResult",
    "VectorFilter",
    "EmbeddingEngine",
    "DistanceMetric",
    "VectorStoreConfig",
    # Providers
    "BaseEmbeddingProvider",
    "DeterministicEmbeddingProvider",
    "FastEmbedProvider",
    "SentenceTransformerProvider",
    # Factory Helpers
    "get_embedding_engine",
    "get_vector_store",
    # Exceptions
    "VectorStoreError",
    "EmbeddingError",
    "ExtensionLoadError",
    "DocumentNotFoundError",
    "DimensionMismatchError",
]
