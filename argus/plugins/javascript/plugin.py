import logging
from argus.plugins.interfaces import BasePlugin, ControlledMission
from argus.plugins.manifest import PluginManifest
from argus.plugins.javascript.agent import JavaScriptSpecialist

logger = logging.getLogger(__name__)

class JavaScriptPlugin(BasePlugin):
    """JavaScript Specialist Plugin."""
    
    def __init__(self, manifest: PluginManifest = None):
        if manifest is None:
            manifest = PluginManifest(
                name="javascript_specialist",
                version="1.0.0",
                author="Argus Team",
                description="Models JavaScript logic, frameworks, and vulnerabilities.",
                entrypoint="argus.plugins.javascript.plugin"
            )
        super().__init__(manifest)
        self.specialist = JavaScriptSpecialist()
        
    def initialize(self):
        logger.info("Initializing JavaScript Specialist Plugin...")
        
    def register(self):
        logger.info("Registering JavaScript Specialist components...")
        
    def execute(self, mission: ControlledMission):
        logger.info("Executing JavaScript Specialist Plugin...")
        self.specialist.discover(mission)
        self.specialist.collect_context(mission)
        self.specialist.analyze(mission)
        self.specialist.generate_observations(mission)
        self.specialist.generate_investigations(mission)
        
    def shutdown(self):
        logger.info("Shutting down JavaScript Specialist Plugin...")
