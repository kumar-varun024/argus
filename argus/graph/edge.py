from dataclasses import dataclass, field
from typing import Any

@dataclass(slots=True)
class Edge:
    """
    Represents a directional relationship between two Nodes in the Knowledge Graph.
    
    Attributes:
        source (str): The ID of the origin Node.
        target (str): The ID of the destination Node.
        type (str): The type of relationship (e.g., 'HAS_ENDPOINT').
        metadata (dict[str, Any]): Additional context or properties for the edge.
    """
    source: str
    target: str
    type: str
    metadata: dict[str, Any] = field(default_factory=dict)
