"""ARGUS Conversational Memory System.

Provides vector-backed persistent storage, lifecycle management, and semantic recall
for attack patterns, user corrections, strategic decisions, session contexts, and notes.
"""

from argus.memory.manager import MemoryManager, get_memory_manager
from argus.memory.models import (
    MemoryEntry,
    MemoryQuery,
    MemorySearchResult,
    MemoryStatus,
    MemoryType,
)
from argus.memory.store import MemoryStore

__all__ = [
    "MemoryType",
    "MemoryStatus",
    "MemoryEntry",
    "MemoryQuery",
    "MemorySearchResult",
    "MemoryStore",
    "MemoryManager",
    "get_memory_manager",
]
