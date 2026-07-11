from dataclasses import dataclass, field


@dataclass(slots=True)
class Node:

    id: str

    type: str

    value: str

    metadata: dict = field(default_factory=dict)

    relationships: set[str] = field(default_factory=set)
