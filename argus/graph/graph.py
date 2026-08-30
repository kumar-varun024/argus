from typing import Any, Optional, Union
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

    def get_hosts_without_endpoints(self) -> list[Node]:
        """
        Finds all live_host nodes that have no outgoing HAS_ENDPOINT edges.

        Returns:
            list[Node]: List of live host nodes without endpoints.
        """
        hosts_with_endpoints = {
            e.source for e in self.edges if e.type == "HAS_ENDPOINT"
        }
        return [
            n for n in self.nodes.values()
            if n.type == "live_host" and n.id not in hosts_with_endpoints
        ]

    def get_hosts_without_vulnerabilities(self) -> list[Node]:
        """
        Finds all live_host nodes that have no outgoing HAS_VULNERABILITY edges.

        Returns:
            list[Node]: List of live host nodes without vulnerabilities.
        """
        hosts_with_vulns = {
            e.source for e in self.edges if e.type == "HAS_VULNERABILITY"
        }
        return [
            n for n in self.nodes.values()
            if n.type == "live_host" and n.id not in hosts_with_vulns
        ]

    def get_asset_counts(self) -> dict[str, int]:
        """
        Returns asset counts grouped by asset node type.

        Returns:
            dict[str, int]: Counts for target, subdomain, live_host, endpoint,
                technology, vulnerability, and any other types.
        """
        counts: dict[str, int] = {
            "target": 0,
            "subdomain": 0,
            "live_host": 0,
            "endpoint": 0,
            "technology": 0,
            "vulnerability": 0,
        }
        for n in self.nodes.values():
            counts[n.type] = counts.get(n.type, 0) + 1
        return counts

    def get_host_for_node(self, node_or_id: Union[str, Node]) -> Optional[Node]:
        """
        Resolves a node or node ID to its parent or corresponding live_host Node.

        Args:
            node_or_id: The Node instance or string node ID.

        Returns:
            Optional[Node]: The associated live_host Node, or None if not resolvable.
        """
        if isinstance(node_or_id, Node):
            node = node_or_id
        else:
            node = self.get(node_or_id)
        if node is None:
            return None

        if node.type == "live_host":
            return node

        # Direct incoming edges (e.g. live_host -> endpoint / technology / vulnerability)
        for e in self.edges_to(node):
            src = self.get(e.source)
            if src and src.type == "live_host":
                return src

        # Direct outgoing edges (e.g. subdomain -> live_host)
        for e in self.edges_from(node):
            tgt = self.get(e.target)
            if tgt and tgt.type == "live_host":
                return tgt

        # BFS traversal (up to 3 hops) to find connected live_host
        visited = {node.id}
        queue = [(node, 0)]
        while queue:
            curr, depth = queue.pop(0)
            if depth >= 3:
                break
            for neighbor in self.neighbors(curr):
                if neighbor.id not in visited:
                    if neighbor.type == "live_host":
                        return neighbor
                    visited.add(neighbor.id)
                    queue.append((neighbor, depth + 1))

        return None

    def in_same_host_subgraph(self, node_id1: str, node_id2: str) -> bool:
        """
        Determines whether two nodes resolve to the same live_host or connected host subgraph.

        Args:
            node_id1: First node ID.
            node_id2: Second node ID.

        Returns:
            bool: True if in the same host subgraph, False otherwise.
        """
        if node_id1 == node_id2:
            return True

        host1 = self.get_host_for_node(node_id1)
        host2 = self.get_host_for_node(node_id2)
        if host1 is not None and host2 is not None and host1.id == host2.id:
            return True

        return self.are_connected(node_id1, node_id2, max_depth=2)

    def are_connected(self, node_id1: str, node_id2: str, max_depth: int = 2) -> bool:
        """
        Performs an undirected BFS traversal checking if two nodes are connected within max_depth hops.

        Args:
            node_id1: Starting node ID.
            node_id2: Target node ID.
            max_depth: Maximum number of hops (default 2).

        Returns:
            bool: True if a path exists within max_depth hops, False otherwise.
        """
        if node_id1 == node_id2:
            return True
        if node_id1 not in self.nodes or node_id2 not in self.nodes:
            return False

        visited = {node_id1}
        queue = [(node_id1, 0)]
        while queue:
            curr_id, depth = queue.pop(0)
            if curr_id == node_id2:
                return True
            if depth >= max_depth:
                continue
            curr_node = self.nodes[curr_id]
            for neighbor in self.neighbors(curr_node):
                if neighbor.id not in visited:
                    if neighbor.id == node_id2:
                        return True
                    visited.add(neighbor.id)
                    queue.append((neighbor.id, depth + 1))

        return False

    def get_node_degree(self, node_or_id: Union[str, Node]) -> int:
        """
        Returns the total degree (in-degree + out-degree) of a node.

        Args:
            node_or_id: The Node instance or string node ID.

        Returns:
            int: Number of incoming and outgoing edges attached to the node.
        """
        if isinstance(node_or_id, Node):
            node = node_or_id
        else:
            node = self.get(node_or_id)
        if node is None:
            return 0

        return len(self.edges_from(node)) + len(self.edges_to(node))

    def get_connected_endpoints(self, host_node_or_id: Union[str, Node]) -> list[Node]:
        """
        Returns all endpoint nodes connected to a live_host node via HAS_ENDPOINT edges.

        Args:
            host_node_or_id: The host Node or node ID.

        Returns:
            list[Node]: List of endpoint Node instances.
        """
        if isinstance(host_node_or_id, Node):
            node = host_node_or_id
        else:
            node = self.get(host_node_or_id)
        if node is None:
            return []

        if node.type != "live_host":
            host = self.get_host_for_node(node)
            if host:
                node = host

        endpoints = []
        for e in self.edges_from(node):
            if e.type == "HAS_ENDPOINT":
                tgt = self.get(e.target)
                if tgt and tgt.type == "endpoint":
                    endpoints.append(tgt)
        return endpoints

