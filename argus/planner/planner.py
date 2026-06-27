from argus.planner.tasks import Task


class Planner:

    def build_plan(self, target: str):

        plan = [

            Task(
                "Passive Recon",
                "Collect public intelligence about the target."
            ),

            Task(
                "Subdomain Enumeration",
                "Discover subdomains."
            ),

            Task(
                "Live Host Discovery",
                "Identify live hosts."
            ),

            Task(
                "Technology Fingerprinting",
                "Identify technologies used."
            ),

            Task(
                "Endpoint Discovery",
                "Find hidden endpoints."
            ),

            Task(
                "Parameter Discovery",
                "Collect HTTP parameters."
            ),

            Task(
                "JavaScript Analysis",
                "Analyze JavaScript bundles."
            ),

            Task(
                "Authentication Mapping",
                "Locate authentication mechanisms."
            ),

            Task(
                "API Discovery",
                "Discover REST, GraphQL and WebSocket APIs."
            )

        ]

        return plan
