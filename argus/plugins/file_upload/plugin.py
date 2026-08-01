import logging
from argus.plugins.interfaces import BasePlugin, PluginType, ControlledMission
from argus.plugins.manifest import PluginManifest
from argus.plugins.file_upload.agent import FileUploadSpecialist

logger = logging.getLogger(__name__)

class FileUploadPlugin(BasePlugin):
    """File Upload Specialist Plugin."""
    
    def __init__(self, manifest: PluginManifest = None):
        if manifest is None:
            manifest = PluginManifest(
                name="file_upload_intelligence",
                version="1.0.0",
                author="Argus Team",
                description="Models file uploads, storage, and processing.",
                entrypoint="argus.plugins.file_upload.plugin"
            )
        super().__init__(manifest)
        self.specialist = FileUploadSpecialist()
        
    def initialize(self):
        logger.info("Initializing File Upload Intelligence Plugin...")
        
    def register(self):
        logger.info("Registering File Upload Intelligence components...")
        
    def execute(self, mission: ControlledMission):
        logger.info("Executing File Upload Intelligence Plugin...")
        self.specialist.analyze(mission)
        
    def shutdown(self):
        logger.info("Shutting down File Upload Intelligence Plugin...")
