from typing import List
from argus.plugins.loader import PluginLoader
from argus.plugins.registry import PluginRegistry
from argus.plugins.interfaces import BasePlugin

class PluginManager:
    def __init__(self, plugin_dir: str):
        self.plugin_dir = plugin_dir
        self.loader = PluginLoader(self.plugin_dir)
        self.registry = PluginRegistry()

    def load_all(self):
        """Loads and registers all valid plugins from the plugin directory."""
        plugins = self.loader.discover_and_load()
        for plugin in plugins:
            try:
                self.registry.register(plugin)
            except Exception as e:
                print(f"Failed to register plugin {plugin.manifest.name}: {e}")
                
        # Resolve topological order based on dependencies
        try:
            self._ordered_plugins = self.registry.resolve_load_order()
        except Exception as e:
            print(f"Failed to resolve plugin load order: {e}")
            self._ordered_plugins = []

    def initialize_plugins(self):
        """Calls the initialize() hook on all registered plugins."""
        for plugin in getattr(self, '_ordered_plugins', []):
            try:
                plugin.initialize()
            except Exception as e:
                print(f"Failed to initialize plugin {plugin.manifest.name}: {e}")

    def register_hooks(self):
        """Calls the register() hook on all registered plugins."""
        for plugin in getattr(self, '_ordered_plugins', []):
            try:
                plugin.register()
            except Exception as e:
                print(f"Failed to run register hook for plugin {plugin.manifest.name}: {e}")

    def shutdown_plugins(self):
        """Calls the shutdown() hook on all registered plugins."""
        for plugin in reversed(getattr(self, '_ordered_plugins', [])):
            try:
                plugin.shutdown()
            except Exception as e:
                print(f"Failed to shutdown plugin {plugin.manifest.name}: {e}")
                
    def get_registered_plugins(self) -> List[BasePlugin]:
        return self.registry.list_plugins()
