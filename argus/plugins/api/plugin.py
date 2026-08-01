import logging
from argus.plugins.interfaces import BasePlugin, PluginType, ControlledMission
from argus.plugins.manifest import PluginManifest
from argus.plugins.api.agent import APIIntelligenceSpecialist

logger = logging.getLogger(__name__)

class APIIntelligencePlugin(BasePlugin):
    """API Intelligence Specialist Plugin."""
    
    def __init__(self, manifest: PluginManifest = None):
        if manifest is None:
            manifest = PluginManifest(
                name="api_intelligence",
                version="1.0.0",
                author="Argus Team",
                description="Understands API ecosystems and generates investigations.",
                entrypoint="argus.plugins.api.plugin"
            )
        super().__init__(manifest)
        self.specialist = APIIntelligenceSpecialist()
        
    def initialize(self):
        logger.info("Initializing API Intelligence Plugin...")
        
    def register(self):
        logger.info("Registering API Intelligence components...")
        
    def execute(self, mission: ControlledMission):
        logger.info("Executing API Intelligence Plugin...")
        self.specialist.analyze(mission)
        
    def shutdown(self):
        logger.info("Shutting down API Intelligence Plugin...")
