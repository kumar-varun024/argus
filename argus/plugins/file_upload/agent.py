import logging
import hashlib
from typing import Dict, Any
from argus.plugins.interfaces import ControlledMission
from argus.plugins.file_upload.uploads import UploadAnalyzer
from argus.plugins.file_upload.storage import StorageAnalyzer
from argus.plugins.file_upload.objects import ObjectAnalyzer
from argus.plugins.file_upload.workflow import FileUploadWorkflow
from argus.plugins.file_upload.heuristics import FILE_UPLOAD_HEURISTIC_REGISTRY
from argus.plugins.file_upload.confidence import FileUploadConfidenceScorer

logger = logging.getLogger(__name__)

class FileUploadSpecialist:
    """Specialist agent for identifying file upload and processing mechanisms."""
    
    def __init__(self):
        self.upload_analyzer = UploadAnalyzer()
        self.storage_analyzer = StorageAnalyzer()
        self.object_analyzer = ObjectAnalyzer()
        self.heuristics = FILE_UPLOAD_HEURISTIC_REGISTRY
        self.scorer = FileUploadConfidenceScorer()
        
    def analyze(self, mission: ControlledMission):
        logger.info(f"File Upload Intelligence starting for Mission {mission.target}")
        
        # Extract inputs
        endpoints = mission._mission.endpoints if hasattr(mission._mission, 'endpoints') else []
        
        # Run analyzers
        uploads, downloads = self.upload_analyzer.extract_endpoints(endpoints)
        
        # Build workflows naively
        workflows = []
        for up in uploads:
            # Try to classify the object based on the endpoint path
            obj = self.object_analyzer.classify(up.path)
            # Infer potential storage
            storage_list = self.storage_analyzer.infer_storage([up.path])
            st = storage_list[0] if storage_list else None
            
            # Create a workflow
            wf = FileUploadWorkflow(upload=up, file_object=obj, storage=st)
            workflows.append(wf)
            
        context = {
            "endpoints": endpoints,
            "workflows": workflows
        }
        
        investigations = []
        
        for heuristic in self.heuristics:
            logger.info(f"Running heuristic {heuristic.__class__.__name__}")
            results = heuristic.run(context)
            
            for inv in results:
                inv.confidence = self.scorer.score(inv, context)
                
                if inv.confidence > 80:
                    inv.priority = "High"
                elif inv.confidence > 50:
                    inv.priority = "Medium"
                else:
                    inv.priority = "Low"
                    
                investigations.append(inv)
                
        # Deduplicate
        seen_hashes = set()
        deduped = []
        for inv in investigations:
            hash_str = f"{inv.title}|{inv.category}|{','.join(sorted(inv.affected_objects))}"
            inv_hash = hashlib.sha256(hash_str.encode()).hexdigest()
            if inv_hash not in seen_hashes:
                seen_hashes.add(inv_hash)
                deduped.append(inv)
                
        # Publish to mission safely
        if not hasattr(mission._mission, 'upload_workflows'):
            mission._mission.upload_workflows = []
        if not hasattr(mission._mission, 'file_inventory'):
            mission._mission.file_inventory = []
            
        mission._mission.upload_workflows.extend(deduped)
        
        # Just store raw workflow models in inventory for reference
        mission._mission.file_inventory.extend(workflows)
        
        logger.info(f"File Upload Intelligence finished. Generated {len(deduped)} investigations.")
