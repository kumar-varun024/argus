from argus.core.mission import Mission
from argus.intelligence.business_models import BusinessObject

class BusinessObjectAnalyzer:

    def analyze(self, mission: Mission):
        objects = {}

        for endpoint in mission.api_intelligence:
            name = endpoint.business_object
            
            if not name:
                continue

            if name not in objects:
                objects[name] = BusinessObject(name=name)

            bo = objects[name]
            bo.endpoints.append(endpoint)

            if endpoint.operation:
                bo.operations.add(endpoint.operation)

            # Inherit highest priority
            priority_levels = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            current_level = priority_levels.get(bo.priority, 1)
            endpoint_level = priority_levels.get(endpoint.priority, 1)
            
            if endpoint_level > current_level:
                bo.priority = endpoint.priority

            # Inherit highest risk score
            if endpoint.risk_score > bo.risk_score:
                bo.risk_score = endpoint.risk_score
                
            # Accumulate reasoning if present and not duplicated
            if endpoint.reasoning:
                for reason in endpoint.reasoning:
                    if reason not in bo.reasoning:
                        bo.reasoning.append(reason)

        mission.business_objects = list(objects.values())
