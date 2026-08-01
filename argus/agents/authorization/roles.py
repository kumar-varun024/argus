from argus.agents.authorization.models import AuthzContext

class RoleAnalyzer:
    """Analyzes role hierarchies for vertical privilege escalation risks."""
    
    def get_admin_roles(self, context: AuthzContext) -> list[str]:
        """Identifies roles that are likely administrative."""
        admin_roles = []
        for role in context.roles:
            if any(k in role.lower() for k in ["admin", "root", "system", "owner", "manager"]):
                admin_roles.append(role)
        return admin_roles
        
    def get_overlapping_roles(self, context: AuthzContext) -> list[tuple[str, str]]:
        """Finds roles that might have overlapping permissions but are on different hierarchical levels."""
        overlapping = []
        if not context.hierarchy:
            return overlapping
            
        # Find all descendants for each role
        descendants = {}
        def get_desc(role):
            if role in descendants:
                return descendants[role]
            children = set(context.hierarchy.get(role, []))
            all_desc = set(children)
            for child in children:
                all_desc.update(get_desc(child))
            descendants[role] = all_desc
            return all_desc
            
        for role in context.roles:
            get_desc(role)
            
        # For this mock logic, if two roles share similar name prefixes but are hierarchical, flag them
        for parent, children in context.hierarchy.items():
            for child in children:
                # If they share resources in graph (mocked by same name prefix)
                if parent.split("_")[0] == child.split("_")[0]:
                    overlapping.append((parent, child))
                    
        return overlapping
