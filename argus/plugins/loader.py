import os
import importlib.util
from typing import List, Type
from argus.plugins.interfaces import BasePlugin

class PluginLoader:
    def __init__(self, plugin_dir: str):
        self.plugin_dir = plugin_dir

    def discover_and_load(self) -> List[BasePlugin]:
        """Scans the plugin_dir and dynamically loads plugin classes."""
        loaded_plugins = []
        if not os.path.exists(self.plugin_dir):
            return loaded_plugins

        for item in os.listdir(self.plugin_dir):
            plugin_path = os.path.join(self.plugin_dir, item)
            
            # Simple assumption: each plugin is a python file or a folder with __init__.py
            if os.path.isfile(plugin_path) and plugin_path.endswith('.py') and item != '__init__.py':
                plugin_instance = self._load_from_file(plugin_path, item[:-3])
                if plugin_instance:
                    loaded_plugins.append(plugin_instance)
            elif os.path.isdir(plugin_path) and os.path.exists(os.path.join(plugin_path, '__init__.py')):
                plugin_instance = self._load_from_module(plugin_path, item)
                if plugin_instance:
                    loaded_plugins.append(plugin_instance)
                    
        return loaded_plugins

    def _load_from_file(self, path: str, module_name: str) -> BasePlugin:
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return self._extract_plugin(module)
        return None

    def _load_from_module(self, path: str, module_name: str) -> BasePlugin:
        init_path = os.path.join(path, '__init__.py')
        return self._load_from_file(init_path, module_name)

    def _extract_plugin(self, module) -> BasePlugin:
        """Finds a subclass of BasePlugin in the module and returns an instance."""
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and issubclass(attr, BasePlugin) and attr is not BasePlugin:
                try:
                    return attr()
                except Exception as e:
                    print(f"Failed to instantiate plugin class {attr_name}: {e}")
        return None
