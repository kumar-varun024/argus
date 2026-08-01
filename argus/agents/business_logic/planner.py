from argus.agents.business_logic.models import BusinessLogicContext

class BusinessLogicPlanner:
    """Provides high-level guidance for investigating business logic."""
    
    def generate_plan(self, context: BusinessLogicContext) -> str:
        plan = "Business Logic Investigation Plan:\n"
        if not context.workflows:
            plan += "No workflows detected to plan against.\n"
            return plan
            
        plan += "1. Map all discovered workflows in the UI to match backend API calls.\n"
        plan += "2. Identify the core state machines and boundary conditions.\n"
        plan += "3. Verify step-by-step state transition enforcement.\n"
        plan += "4. Attempt cross-workflow interaction (e.g. using a Draft object from Workflow A in Workflow B).\n"
        return plan
