import os
import logging
from typing import Any, Optional, Dict
from argus.plugins.manager import PluginManager
from argus.plugins.interfaces import ControlledMission

logger = logging.getLogger(__name__)


class PluginExecutorAdapter:
    """Adapts class-based internal plugins to the tool execution interface."""

    def __init__(self, plugin_dir: Optional[str] = None):
        self.plugin_dir = plugin_dir or os.environ.get("ARGUS_PLUGIN_DIR", "plugins")
        self._manager: Optional[PluginManager] = None

    @property
    def manager(self) -> PluginManager:
        """Lazily initialize and load the plugin manager."""
        if self._manager is None:
            self._manager = PluginManager(self.plugin_dir)
            try:
                self._manager.load_all()
                self._manager.initialize_plugins()
                self._manager.register_hooks()
            except Exception as e:
                logger.error(f"PluginExecutorAdapter: Failed loading plugins: {e}")
        return self._manager

    def execute_plugin(self, plugin_id: str, mission: Any) -> Dict[str, Any]:
        """
        Locates the plugin in the manager, wraps the mission in a ControlledMission,
        and invokes the execution hooks.
        """
        # Try to get registered plugin from the manager
        plugin = self.manager.registry.get_plugin(plugin_id)

        # Fallback to direct specialist instantiation if registry isn't fully populated
        if not plugin:
            plugin = self._instantiate_specialist_fallback(plugin_id)

        if not plugin:
            raise ValueError(f"Internal plugin or specialist '{plugin_id}' could not be loaded")

        logger.info(f"PluginExecutorAdapter: Executing internal plugin/specialist '{plugin_id}'")
        controlled_mission = ControlledMission(mission)

        # Execute hook based on plugin class methods
        if hasattr(plugin, "execute"):
            plugin.execute(controlled_mission)
        elif hasattr(plugin, "discover"):
            # If it's a Specialist agent class (which has discover/analyze hooks)
            plugin.discover(controlled_mission)
            if hasattr(plugin, "analyze"):
                plugin.analyze(controlled_mission)
            if hasattr(plugin, "generate_observations"):
                plugin.generate_observations(controlled_mission)
            if hasattr(plugin, "generate_investigations"):
                plugin.generate_investigations(controlled_mission)
        else:
            raise AttributeError(f"Plugin '{plugin_id}' does not have executable hooks (execute or discover)")

        return {"status": "success", "plugin_instance": plugin}

    def _instantiate_specialist_fallback(self, plugin_id: str) -> Optional[Any]:
        """Dynamically instantiates a specialist class by ID when not found in plugins folder."""
        try:
            if "graphql" in plugin_id:
                from argus.plugins.graphql.plugin import GraphQLPlugin
                return GraphQLPlugin()
            elif "javascript" in plugin_id:
                from argus.plugins.javascript.plugin import JavaScriptPlugin
                return JavaScriptPlugin()
            elif "authorization" in plugin_id or "authz" in plugin_id:
                from argus.agents.authorization.agent import AuthorizationSpecialist
                return AuthorizationSpecialist()
            elif "authentication" in plugin_id or "authn" in plugin_id:
                from argus.plugins.authentication.agent import AuthenticationIntelligenceSpecialist
                return AuthenticationIntelligenceSpecialist()
            elif "file_upload" in plugin_id:
                from argus.plugins.file_upload.agent import FileUploadSpecialist
                return FileUploadSpecialist()
            elif "api" in plugin_id:
                from argus.plugins.api.agent import APIIntelligenceSpecialist
                return APIIntelligenceSpecialist()
            elif "business" in plugin_id:
                from argus.agents.business_logic.agent import BusinessLogicSpecialist
                return BusinessLogicSpecialist()
        except Exception as e:
            logger.error(f"PluginExecutorAdapter: Failed instantiating fallback for {plugin_id}: {e}")
        return None
