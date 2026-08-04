from enum import Enum

class ObservationCategory(str, Enum):
    AUTHORIZATION = "Authorization"
    AUTHENTICATION = "Authentication"
    WORKFLOW = "Workflow"
    BUSINESS_LOGIC = "Business Logic"
    API = "API"
    GRAPHQL = "GraphQL"
    JAVASCRIPT = "JavaScript"
    INFRASTRUCTURE = "Infrastructure"
    TECHNOLOGY = "Technology"
    EVIDENCE = "Evidence"
    CONFIGURATION = "Configuration"

class ObservationPriority(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
