from typing import Dict, List, Type
from collections import defaultdict, deque
from argus.plugins.interfaces import BasePlugin
from argus.plugins.manifest import PluginManifest

class PluginRegistry:
    def __init__(self):
        self._plugins: Dict[str, BasePlugin] = {}
        # Simple mock of allowed system permissions
        self._allowed_permissions = {"network", "filesystem", "db_read", "db_write"}

    def register(self, plugin: BasePlugin):
        """Register a loaded plugin instance."""
        manifest = plugin.manifest
        
        if manifest.name in self._plugins:
            raise ValueError(f"Plugin '{manifest.name}' is already registered.")

        # Validate permissions
        for perm in manifest.permissions:
            if perm not in self._allowed_permissions:
                raise ValueError(f"Plugin '{manifest.name}' requested invalid permission: {perm}")

        self._plugins[manifest.name] = plugin

    def get_plugin(self, name: str) -> BasePlugin:
        return self._plugins.get(name)

    def list_plugins(self) -> List[BasePlugin]:
        return list(self._plugins.values())

    def remove_plugin(self, name: str):
        if name in self._plugins:
            del self._plugins[name]

    def resolve_load_order(self) -> List[BasePlugin]:
        """Topological sort based on plugin dependencies."""
        in_degree = {name: 0 for name in self._plugins}
        graph = defaultdict(list)
        
        for name, plugin in self._plugins.items():
            for dep in plugin.manifest.dependencies:
                if dep in self._plugins:
                    graph[dep].append(name)
                    in_degree[name] += 1
                else:
                    # Optional: Throw error if missing hard dependency
                    raise ValueError(f"Missing dependency '{dep}' for plugin '{name}'")
                    
        queue = deque([name for name in self._plugins if in_degree[name] == 0])
        load_order = []
        
        while queue:
            current = queue.popleft()
            load_order.append(self._plugins[current])
            
            for neighbor in graph[current]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
                    
        if len(load_order) != len(self._plugins):
            raise ValueError("Circular dependency detected among plugins.")
            
        return load_order
