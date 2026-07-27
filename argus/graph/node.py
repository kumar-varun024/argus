from dataclasses import dataclass, field
from typing import Any

@dataclass(slots=True)
class Node:
    """
    Represents a discrete entity within the Knowledge Graph.
    
    Attributes:
        id (str): Unique identifier for the node.
        type (str): The category or classification of the node (e.g., 'Business Object').
        value (str): The core value or name represented by the node.
        metadata (dict[str, Any]): Additional context or properties for the node.
    """
    id: str
    type: str
    value: str
    metadata: dict[str, Any] = field(default_factory=dict)
