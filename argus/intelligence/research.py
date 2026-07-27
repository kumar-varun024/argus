class ResearchGenerator:

    def generate(self, endpoint):

        endpoint.reasoning = []

        endpoint.manual_checks = []

        if endpoint.operation == "CREATE":
            endpoint.reasoning.append("Creates persistent server-side state.")

        if endpoint.operation == "UPDATE":
            endpoint.reasoning.append("Modifies existing objects.")

        if endpoint.operation == "DELETE":
            endpoint.reasoning.append("Deletes persistent resources.")

        if endpoint.object_identifier:

            endpoint.reasoning.append("Uses object identifiers.")

            endpoint.manual_checks.extend(
                [
                    "Replay request as another user",
                    "Replace object identifier",
                    "Observe authorization response",
                ]
            )

        if endpoint.priority == "HIGH":

            endpoint.manual_checks.extend(
                [
                    "Test authorization",
                    "Test mass assignment",
                    "Inspect business rules",
                ]
            )

        return endpoint
