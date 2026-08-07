from argus.runtime.mission import Mission
from argus.benchmark.models import Benchmark

class MissionLoader:
    """Constructs a Mission object for a Benchmark."""
    
    @staticmethod
    def load_mission(benchmark: Benchmark) -> Mission:
        """Translates a Benchmark definition into a Mission instance."""
        mission = Mission(target=benchmark.target)
        mission.name = f"Benchmark: {benchmark.name}"
        
        # Load configurations
        config = benchmark.mission_config
        
        if "scope" in config:
            mission.scope = config["scope"]
            
        if "policy" in config:
            mission.policy = config["policy"]
            
        if "configuration" in config:
            mission.configuration = config["configuration"]
            
        return mission
