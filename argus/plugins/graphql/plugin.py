import logging
from argus.plugins.interfaces import BasePlugin, ControlledMission
from argus.plugins.manifest import PluginManifest
from argus.plugins.graphql.agent import GraphQLSpecialist

logger = logging.getLogger(__name__)

class GraphQLPlugin(BasePlugin):
    """GraphQL Specialist Plugin."""
    
    def __init__(self, manifest: PluginManifest = None):
        if manifest is None:
            manifest = PluginManifest(
                name="graphql_specialist",
                version="1.0.0",
                author="Argus Team",
                description="Models GraphQL endpoints, schemas, and operations.",
                entrypoint="argus.plugins.graphql.plugin"
            )
        super().__init__(manifest)
        self.specialist = GraphQLSpecialist()
        
    def initialize(self):
        logger.info("Initializing GraphQL Specialist Plugin...")
        
    def register(self):
        logger.info("Registering GraphQL Specialist components...")
        
    def execute(self, mission: ControlledMission):
        logger.info("Executing GraphQL Specialist Plugin...")
        self.specialist.discover(mission)
        self.specialist.collect_context(mission)
        self.specialist.analyze(mission)
        self.specialist.generate_observations(mission)
        self.specialist.generate_investigations(mission)
        
    def shutdown(self):
        logger.info("Shutting down GraphQL Specialist Plugin...")
