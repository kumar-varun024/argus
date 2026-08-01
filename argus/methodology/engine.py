from typing import Optional
from argus.runtime.mission import Mission
from argus.methodology.registry import PlaybookRegistry
from argus.methodology.executor import PlaybookExecutor
import logging

logger = logging.getLogger(__name__)

class MethodologyEngine:
    """Orchestrates the selection and execution of Methodology Playbooks."""
    
    def __init__(self, registry: PlaybookRegistry = None):
        self.registry = registry or PlaybookRegistry()
        self.executor = PlaybookExecutor()

    def run(self, mission: Mission, playbook_id: Optional[str] = None):
        """
        Executes a specific playbook, or automatically selects playbooks 
        if none is specified.
        """
        logger.info(f"Starting Methodology Engine for Mission {mission.id}")
        
        target_playbooks = []
        if playbook_id:
            pb = self.registry.get(playbook_id)
            if not pb:
                raise ValueError(f"Playbook {playbook_id} not found in registry.")
            target_playbooks.append(pb)
        else:
            # Automatic selection based on intelligence and scope
            # For demonstration, we just select all available
            target_playbooks = self.registry.get_all()
            
        for pb in target_playbooks:
            if pb.id not in mission.playbooks:
                mission.playbooks.append(pb.id)
                
            if pb.id in mission.completed_playbooks:
                logger.info(f"Playbook {pb.id} already completed. Skipping.")
                continue
                
            if pb.id not in mission.active_playbooks:
                mission.active_playbooks.append(pb.id)
                
            try:
                result = self.executor.execute(pb, mission)
                
                mission.playbook_results[pb.id] = result
                
                if result.status == "completed":
                    if pb.id in mission.active_playbooks:
                        mission.active_playbooks.remove(pb.id)
                    mission.completed_playbooks.append(pb.id)
                    logger.info(f"Playbook {pb.id} completed successfully.")
                else:
                    logger.warning(f"Playbook {pb.id} finished with status: {result.status}")
                    
            except Exception as e:
                logger.error(f"Error executing playbook {pb.id}: {e}")
                
        logger.info("Methodology Engine execution finished.")
