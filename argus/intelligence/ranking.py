class APIRanker:

    HIGH_VALUE = {
        "admin",
        "role",
        "permission",
        "organization",
        "billing",
        "payment",
        "wallet",
        "invoice",
        "subscription",
        "invite",
        "member",
        "team",
        "user",
        "account",
        "profile",
        "token",
        "apikey",
        "secret",
        "key",
    }

    def score(self, endpoint):

        score = 0

        # HTTP method
        if endpoint.operation == "DELETE":
            score += 5

        elif endpoint.operation == "UPDATE":
            score += 4

        elif endpoint.operation == "CREATE":
            score += 4

        elif endpoint.operation == "READ":
            score += 1

        # Object IDs
        if endpoint.object_identifier:
            score += 3

        # High-value business objects
        if endpoint.resource.lower() in self.HIGH_VALUE:
            score += 5

        endpoint.risk_score = score

        if score >= 8:
            endpoint.priority = "HIGH"

        elif score >= 5:
            endpoint.priority = "MEDIUM"

        else:
            endpoint.priority = "LOW"

        return endpoint
