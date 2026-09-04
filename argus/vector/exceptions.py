"""Vector store and embedding exceptions for ARGUS."""


class VectorStoreError(Exception):
    """Base exception for all vector store and embedding errors."""
    pass


class EmbeddingError(VectorStoreError):
    """Exception raised when embedding generation fails."""
    pass


class ExtensionLoadError(VectorStoreError):
    """Exception raised when sqlite-vec extension cannot be loaded."""
    pass


class DocumentNotFoundError(VectorStoreError):
    """Exception raised when a requested document is not found."""
    pass


class DimensionMismatchError(EmbeddingError):
    """Exception raised when vector dimensions do not match the expected store dimension."""
    pass
