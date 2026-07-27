from typing import Any, Optional
from .node import Node
from .edge import Edge


class KnowledgeGraph:
    """
    Central memory structure mapping discovered entities and relationships.
    """

    def __init__(self) -> None:
        """
        Initializes an empty Knowledge Graph.
        """
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []

    def add(self, node: Node) -> bool:
        """
        Adds a new node to the graph if it doesn't already exist.
        
        Args:
            node (Node): The node to add.
            
        Returns:
            bool: True if added successfully, False if the node already exists.
        """
        if node.id in self.nodes:
            return False
        self.nodes[node.id] = node
        return True

    def get(self, node_id: str) -> Optional[Node]:
        """
        Retrieves a node by its ID.
        
        Args:
            node_id (str): The node ID.
            
        Returns:
            Optional[Node]: The Node if found, else None.
        """
        return self.nodes.get(node_id)

    def connect(self, source: str, target: str, edge_type: str = "RELATED_TO", metadata: Optional[dict[str, Any]] = None) -> bool:
        """
        Connects two nodes with a directional edge.
        
        Args:
            source (str): The ID of the source node.
            target (str): The ID of the target node.
            edge_type (str): The type of relationship.
            metadata (Optional[dict[str, Any]]): Contextual metadata for the edge.
            
        Returns:
            bool: True if connected successfully, False if nodes are missing or edge exists.
        """
        if source not in self.nodes or target not in self.nodes:
            return False

        for edge in self.edges:
            if edge.source == source and edge.target == target and edge.type == edge_type:
                return False

        new_edge = Edge(source=source, target=target, type=edge_type, metadata=metadata or {})
        self.edges.append(new_edge)
        return True

    def all(self) -> list[Node]:
        """
        Returns all nodes in the graph.
        
        Returns:
            list[Node]: A list of all nodes.
        """
        return list(self.nodes.values())
        
    def node_count(self) -> int:
        """
        Returns the total number of nodes.
        
        Returns:
            int: Node count.
        """
        return len(self.nodes)
        
    def edge_count(self) -> int:
        """
        Returns the total number of edges.
        
        Returns:
            int: Edge count.
        """
        return len(self.edges)

    def nodes_by_type(self, node_type: str) -> list[Node]:
        """
        Finds all nodes matching a specific type.
        
        Args:
            node_type (str): The type to filter by.
            
        Returns:
            list[Node]: Matching nodes.
        """
        return [n for n in self.nodes.values() if n.type == node_type]

    def edges_from(self, node: Node) -> list[Edge]:
        """
        Gets all edges originating from the given node.
        
        Args:
            node (Node): Source node.
            
        Returns:
            list[Edge]: Outgoing edges.
        """
        return [e for e in self.edges if e.source == node.id]

    def edges_to(self, node: Node) -> list[Edge]:
        """
        Gets all edges pointing to the given node.
        
        Args:
            node (Node): Target node.
            
        Returns:
            list[Edge]: Incoming edges.
        """
        return [e for e in self.edges if e.target == node.id]

    def neighbors(self, node: Node) -> list[Node]:
        """
        Gets all nodes connected to the given node via any edge (incoming or outgoing).
        
        Args:
            node (Node): Node.
            
        Returns:
            list[Node]: A deduplicated list of connected nodes.
        """
        neighbor_ids = set()
        for e in self.edges_from(node):
            neighbor_ids.add(e.target)
        for e in self.edges_to(node):
            neighbor_ids.add(e.source)
            
        return [self.nodes[nid] for nid in neighbor_ids if nid in self.nodes]

    def summary(self) -> dict[str, int]:
        """
        Generates graph statistics including node and edge counts, and counts by node type.
        
        Returns:
            dict[str, int]: A dictionary of metric names and their counts.
        """
        stats: dict[str, int] = {
            "Node Count": self.node_count(),
            "Relationship Count": self.edge_count(),
        }
        for n in self.nodes.values():
            stats[f"{n.type} Nodes"] = stats.get(f"{n.type} Nodes", 0) + 1
            
        return stats
