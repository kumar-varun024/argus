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
            if (
                "graphql_security" in plugin_id
                or "graphql_vuln" in plugin_id
                or "graphql_vulnerability" in plugin_id
                or "graphql_introspection" in plugin_id
                or "graphql_collector" in plugin_id
            ):
                from argus.collectors.graphql import GraphQLSecurityCollector
                return GraphQLSecurityCollector()
            elif "graphql" in plugin_id:
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
            elif (
                "file_upload" in plugin_id
                or "upload" in plugin_id
                or "unrestricted_upload" in plugin_id
                or "arbitrary_upload" in plugin_id
            ):
                from argus.collectors.file_upload import FileUploadCollector
                return FileUploadCollector()
            elif (
                "api_security" in plugin_id
                or "api_security_collector" in plugin_id
                or "api_security_detector" in plugin_id
                or "api_security_specialist" in plugin_id
                or "rest_api_security" in plugin_id
                or "rest_security" in plugin_id
                or "grpc_security" in plugin_id
                or "bola" in plugin_id
                or "excessive_data" in plugin_id
                or "rate_limit_bypass" in plugin_id
                or "method_tampering" in plugin_id
                or plugin_id == "api_security"
            ):
                from argus.collectors.api_security import APISecurityCollector
                return APISecurityCollector()
            elif "api" in plugin_id:
                from argus.plugins.api.agent import APIIntelligenceSpecialist
                return APIIntelligenceSpecialist()
            elif (
                "business_logic_collector" in plugin_id
                or "business_logic_security" in plugin_id
                or "business_logic_detector" in plugin_id
                or "business_logic_flaws" in plugin_id
                or "state_machine" in plugin_id
                or "workflow_bypass" in plugin_id
                or "workflow_skip" in plugin_id
                or "price_tampering" in plugin_id
                or "quantity_tampering" in plugin_id
                or "parameter_tampering" in plugin_id
                or "mass_assignment" in plugin_id
                or "coupon_stacking" in plugin_id
                or "idempotency_abuse" in plugin_id
                or plugin_id == "business_logic"
            ):
                from argus.collectors.business_logic import BusinessLogicCollector
                return BusinessLogicCollector()
            elif "business" in plugin_id:
                from argus.agents.business_logic.agent import BusinessLogicSpecialist
                return BusinessLogicSpecialist()
            elif "info_disclosure" in plugin_id or "information_disclosure" in plugin_id:
                from argus.collectors.information_disclosure import InformationDisclosureCollector
                return InformationDisclosureCollector()
            elif "access_control" in plugin_id or "idor" in plugin_id:
                from argus.collectors.access_control import AccessControlCollector
                return AccessControlCollector()
            elif "path_traversal" in plugin_id or "traversal" in plugin_id or "lfi" in plugin_id:
                from argus.collectors.path_traversal import PathTraversalCollector
                return PathTraversalCollector()
            elif "sql_injection" in plugin_id or "sqli" in plugin_id or plugin_id == "sql":
                from argus.collectors.sql_injection import SQLInjectionCollector
                return SQLInjectionCollector()
            elif "xss" in plugin_id or "cross_site_scripting" in plugin_id:
                from argus.collectors.xss import XSSCollector
                return XSSCollector()
            elif "command_injection" in plugin_id or "cmdi" in plugin_id or "cmd_injection" in plugin_id or plugin_id == "command":
                from argus.collectors.command_injection import CommandInjectionCollector
                return CommandInjectionCollector()
            elif "ssrf" in plugin_id or "server_side_request_forgery" in plugin_id:
                from argus.collectors.ssrf import SSRFCollector
                return SSRFCollector()
            elif "oauth" in plugin_id or "oidc" in plugin_id:
                from argus.collectors.oauth import OAuthCollector
                return OAuthCollector()
            elif "xml" in plugin_id or "xxe" in plugin_id:
                from argus.collectors.xml_parser import XMLParserSecurityCollector
                return XMLParserSecurityCollector()
            elif (
                "deserialization" in plugin_id
                or "deser" in plugin_id
                or "pickle" in plugin_id
                or "unserialize" in plugin_id
                or "marshal" in plugin_id
                or "viewstate" in plugin_id
            ):
                from argus.collectors.deserialization import DeserializationCollector
                return DeserializationCollector()
            elif (
                "websocket" in plugin_id
                or "ws" in plugin_id
                or "cswsh" in plugin_id
            ):
                from argus.collectors.websocket import WebSocketSecurityCollector
                return WebSocketSecurityCollector()
            elif (
                "smuggl" in plugin_id
                or "cl_te" in plugin_id
                or "te_cl" in plugin_id
                or "te_te" in plugin_id
                or "h2_cl" in plugin_id
                or "h2_te" in plugin_id
                or "desync" in plugin_id
            ):
                from argus.collectors.request_smuggling import HTTPRequestSmugglingCollector
                return HTTPRequestSmugglingCollector()
            elif (
                "race" in plugin_id
                or "toctou" in plugin_id
                or "concurrency" in plugin_id
                or "limit_overrun" in plugin_id
                or "multi_redemption" in plugin_id
                or "single_packet" in plugin_id
            ):
                from argus.collectors.race_conditions import RaceConditionsCollector
                return RaceConditionsCollector()
            elif (
                "ssti" in plugin_id
                or "template_injection" in plugin_id
                or "jinja" in plugin_id
                or "twig" in plugin_id
                or "freemarker" in plugin_id
                or "velocity" in plugin_id
                or "mako" in plugin_id
                or "spel" in plugin_id
                or "thymeleaf" in plugin_id
                or "erb" in plugin_id
                or "smarty" in plugin_id
            ):
                from argus.collectors.ssti import SSTICollector
                return SSTICollector()
            elif (
                "cache_security" in plugin_id
                or "cache_poison" in plugin_id
                or "cache_deception" in plugin_id
                or "web_cache" in plugin_id
                or "unkeyed_header" in plugin_id
                or "unkeyed_param" in plugin_id
                or "wcd" in plugin_id
                or plugin_id == "cache"
            ):
                from argus.collectors.cache_security import CacheSecurityCollector
                return CacheSecurityCollector()
            elif (
                "cors" in plugin_id
                or "header_security" in plugin_id
                or "security_header" in plugin_id
                or "hsts" in plugin_id
                or "csp" in plugin_id
                or "x_frame" in plugin_id
                or "http_header" in plugin_id
                or "header_audit" in plugin_id
                or "xfo" in plugin_id
                or plugin_id == "cors_security"
            ):
                from argus.collectors.cors_security import CORSSecurityCollector
                return CORSSecurityCollector()
            elif (
                "auth_bypass" in plugin_id
                or "authentication" in plugin_id
                or "credential_attack" in plugin_id
                or "brute_force" in plugin_id
                or "password_reset" in plugin_id
                or "mfa_bypass" in plugin_id
                or "session_fixation" in plugin_id
                or "jwt_manipulation" in plugin_id
                or "default_credentials" in plugin_id
                or "credential_stuffing" in plugin_id
                or plugin_id == "auth"
            ):
                from argus.collectors.auth_bypass import AuthBypassCollector
                return AuthBypassCollector()
            elif (
                "prototype_pollution" in plugin_id
                or "proto" in plugin_id
                or "client_side" in plugin_id
                or "dom_clobbering" in plugin_id
                or "html_clobbering" in plugin_id
                or "open_redirect" in plugin_id
                or "clickjacking" in plugin_id
                or "ui_redressing" in plugin_id
                or plugin_id == "prototype_pollution"
            ):
                from argus.collectors.prototype_pollution import PrototypePollutionCollector
                return PrototypePollutionCollector()
        except Exception as e:

            logger.error(f"PluginExecutorAdapter: Failed instantiating fallback for {plugin_id}: {e}")
        return None


