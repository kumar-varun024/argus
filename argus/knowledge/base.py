from .models import KnowledgeRule


class KnowledgeBase:

    def __init__(self):

        self.rules = []

        self._load_rules()

    def _load_rules(self):

        self.rules.extend(

            [

                KnowledgeRule(

                    name="GraphQL Authorization",

                    requires=[
                        "GraphQL",
                        "JWT",
                    ],

                    hypothesis="Possible GraphQL authorization weaknesses.",

                    description=(
                        "GraphQL APIs using JWT often require "
                        "object-level authorization testing."
                    ),

                    severity="High",

                    investigation=[

                        "Locate GraphQL mutations",

                        "Create two test accounts",

                        "Replay mutations with another user's object ID",

                        "Compare responses",

                        "Verify authorization",

                    ],

                    tags=[
                        "graphql",
                        "jwt",
                        "bola",
                    ],

                ),

                KnowledgeRule(

                    name="OAuth Session Management",

                    requires=[
                        "OAuth",
                        "refresh_token",
                    ],

                    hypothesis="Possible refresh token issues.",

                    description=(
                        "Applications using OAuth refresh tokens "
                        "should be evaluated for token rotation, "
                        "logout invalidation, and replay behavior."
                    ),

                    severity="Medium",

                    investigation=[

                        "Identify refresh token flow",

                        "Log out",

                        "Reuse refresh token",

                        "Observe server response",

                    ],

                    tags=[
                        "oauth",
                        "tokens",
                    ],

                ),

                KnowledgeRule(

                    name="Source Maps",

                    requires=[
                        "Source Map",
                    ],

                    hypothesis="Source maps may expose application internals.",

                    description=(
                        "Review exposed source maps for API routes, "
                        "hidden functionality, secrets, and debugging code."
                    ),

                    severity="Medium",

                    investigation=[

                        "Download source map",

                        "Recover original source",

                        "Review routes",

                        "Review API calls",

                    ],

                    tags=[
                        "javascript",
                        "source-map",
                    ],

                ),

            ]

        )

    def rules_for(self):

        return self.rules
