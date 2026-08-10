class ContextBuilder:

    def build(self, mission) -> dict:
        workflows = getattr(mission, "workflows", [])
        
        workflow_summary = []
        auth_summary = []
        for wf in workflows:
            workflow_summary.append({
                "Name": wf.name,
                "Description": wf.description,
                "Steps": len(wf.steps),
                "Business Objects": list(wf.business_objects),
                "Risk Score": wf.risk_score
            })
            if wf.roles or any(s.required_role for s in wf.steps):
                # Fallback auth summary if graph doesn't exist
                auth_summary.append({
                    "Workflow": wf.name,
                    "Roles": list(wf.roles),
                    "Step Roles": {s.title: s.required_role for s in wf.steps if s.required_role}
                })
                
        # If we have an AuthorizationGraph, use its richer analysis
        auth_graph = getattr(mission, "authorization_graph", None)
        if auth_graph:
            from argus.authorization.analyzer import AuthorizationAnalyzer
            analyzer = AuthorizationAnalyzer(auth_graph)
            auth_summary = {
                "Role Hierarchy": analyzer.get_role_hierarchy(),
                "Ownership Chains": analyzer.get_ownership_chains(),
                "Authorization Boundaries": analyzer.get_authorization_boundaries()
            }

        context = {
            "Application Overview": {
                "Target": mission.target,
                "Technologies": getattr(mission, "technologies", []),
                "Authentication": f"Auth Type: {mission.authentication.authentication_type}, Token Type: {mission.authentication.token_type}" if getattr(mission, "authentication", None) and mission.authentication.authentication_type else "None detected.",
            },
            "Business Objects": [bo.name for bo in getattr(mission, "business_objects", [])] if hasattr(mission, 'business_objects') and getattr(mission, 'business_objects', []) and hasattr(mission.business_objects[0], 'name') else getattr(mission, "business_objects", []),
            "Workflow Summary": workflow_summary,
            "Authorization Summary": auth_summary,
            "Evidence": len(getattr(mission, "evidence", [])),
            "Knowledge Base Matches": getattr(mission, "knowledge_matches", []) # Placeholder for KB matches if any
        }

        return context
