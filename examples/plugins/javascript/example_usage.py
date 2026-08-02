from argus.runtime.manager import mission_manager
from argus.plugins.javascript.agent import JavaScriptSpecialist
from argus.runtime.mission import Mission
from argus.evidence.model import Evidence
from argus.graph.graph import KnowledgeGraph

def run_javascript_intelligence():
    # 1. Initialize a new mission
    mission = Mission(target="example.com")
    mission.graph = KnowledgeGraph()
    mission_manager.missions[mission.id] = mission
    
    # 2. Add some raw evidence (e.g. from web scraping)
    mission.evidence.add(Evidence(category="JavaScript", value="const API_KEY = 'secret'; import React from 'react'; function login() {}", source="main.js"))
    
    # 3. Initialize specialist and run discovery and analysis
    agent = JavaScriptSpecialist()
    print("Running Discovery...")
    agent.discover(mission)
    
    print("Running Analysis...")
    agent.analyze(mission)
    
    print("Generating Investigations...")
    agent.generate_investigations(mission)
    
    # 4. Review results
    js = mission.javascript
    print(f"\\n--- Analysis Complete ---")
    print(f"Symbols found: {len(js.symbols)}")
    print(f"Frameworks found: {len(js.frameworks)}")
    print(f"Investigations: {len(js.investigations)}")
    
    for s in js.symbols:
        print(f" - {s.symbol_type}: {s.name}")

if __name__ == "__main__":
    run_javascript_intelligence()
