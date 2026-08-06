from typing import Set, Dict, Any, List
import hashlib
import json

class IncrementalTracker:
    """Tracks dirty state and deltas for incremental processing."""
    def __init__(self):
        # Store hashes of node contents to detect changes
        self._node_hashes: Dict[str, str] = {}
        # Track IDs of nodes that have been modified since the last clear
        self._dirty_nodes: Set[str] = set()

    def compute_hash(self, data: Any) -> str:
        """Compute a deterministic hash for a given object or dict."""
        try:
            if hasattr(data, "model_dump_json"):
                # Pydantic v2
                json_str = data.model_dump_json()
            elif hasattr(data, "json"):
                # Pydantic v1
                json_str = data.json()
            else:
                # Dict or other JSON serializable
                json_str = json.dumps(data, sort_keys=True, default=str)
        except Exception:
            # Fallback to string representation
            json_str = str(data)
            
        return hashlib.sha256(json_str.encode('utf-8')).hexdigest()

    def mark_dirty(self, node_id: str) -> None:
        """Explicitly mark a node as dirty."""
        self._dirty_nodes.add(str(node_id))

    def update_node(self, node_id: str, data: Any) -> bool:
        """Update a node's hash and return True if it changed (dirty)."""
        nid = str(node_id)
        current_hash = self.compute_hash(data)
        
        if nid not in self._node_hashes or self._node_hashes[nid] != current_hash:
            self._node_hashes[nid] = current_hash
            self._dirty_nodes.add(nid)
            return True
        return False

    def is_dirty(self, node_id: str) -> bool:
        """Check if a node is currently dirty."""
        return str(node_id) in self._dirty_nodes

    def any_dirty(self, node_ids: List[str]) -> bool:
        """Check if any of the provided node IDs are dirty."""
        return any(str(nid) in self._dirty_nodes for nid in node_ids)

    def clear_dirty_state(self) -> None:
        """Clear the dirty flags after a processing cycle is complete."""
        self._dirty_nodes.clear()

    def reset(self) -> None:
        """Completely reset the incremental tracker."""
        self._node_hashes.clear()
        self._dirty_nodes.clear()

# Global tracker for simple usage
tracker = IncrementalTracker()
