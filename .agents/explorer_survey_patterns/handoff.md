# Collector Pattern Survey & Architecture Specification for API Security Testing Module

**Author**: Explorer 1 (Collector Pattern Explorer)  
**Date**: 2026-09-02  
**Target Module**: `argus/collectors/api_security.py`  
**Working Directory**: `/home/varun/argus/.agents/explorer_survey_patterns`  

---

## 1. Observation

A detailed survey of the ARGUS codebase was conducted across existing collectors, HTTP infrastructure, state publishing mechanisms, graph construction, planning DAGs, and CVSS reporting.

### 1.1 Existing Collector Implementations Audited

1. **`argus/collectors/base.py` (Lines 1-10)**:
   ```python
   from abc import ABC, abstractmethod

   class BaseCollector(ABC):
       @abstractmethod
       def collect(self, mission):
           """Collect information and update the mission."""
           pass
   ```
   All collectors implement `BaseCollector` with the abstract `collect(self, mission)` method, typically providing `execute(self, mission)` as an alias for plugin executor compatibility.

2. **`argus/collectors/file_upload.py` (1,410 lines)**:
   - **Pattern**: Tripartite architecture consisting of:
     - `FileUploadPayloadGenerator` (Lines 193-650): Generates probes across 6 detection modes and 7 mutation strategies with safe canary tokens (`generate_canary()`, `build_payload_content()`, `apply_mutation()`).
     - `FileUploadProber` (Lines 655-876): Uses `AuthenticatedHttpClient` to execute multipart/form-data POST requests and follow-up verification GET requests (`execute_upload()`, `_extract_storage_information()`, `_check_web_shell_reachability()`).
     - `FileUploadAnalyzer` (Lines 881-1174): Analyzes path disclosure regexes, stack trace patterns, error message disclosures, and applies strict false positive rejection (`is_false_positive()`, `evaluate_probe()`).
     - `FileUploadCollector` (Lines 1180-1401): Discovers endpoints from `mission.inputs`, `mission.endpoints`, `mission.live_hosts`, `mission.target`, `mission.evidence`, coordinates probing, and implements Quadruple State Publishing (`_emit_evidence()`, `collect()`, `execute()`).
   - Backwards compatibility aliases: `UploadVulnerabilityCollector`, `FileUploadSecurityCollector`, `UnrestrictedFileUploadCollector`, `ArbitraryFileUploadCollector`.

3. **`argus/collectors/cache_security.py` (1,523 lines)**:
   - Implements `CacheSecurityPayloadGenerator`, `CacheSecurityProber`, `CacheSecurityAnalyzer`, and `CacheSecurityCollector`.
   - Uses 4-step differential confirmation sequences (`baseline B0` -> `perturbed B1` -> `replay B1` -> `isolation control B2`).
   - Rigorous PII pattern scanner (`SENSITIVE_PII_PATTERNS`) and CDN engine fingerprinting.

4. **`argus/collectors/cors_security.py` (706 lines)**:
   - Implements `CORSPayloadGenerator`, `CORSSecurityAnalyzer`, and `CORSSecurityCollector`.
   - Dispatches origin reflection, null origin, wildcard credentials, and preflight bypass probes.
   - Audits missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).

5. **`argus/collectors/access_control.py` (397 lines)**:
   - Implements `AccessControlCollector` testing for Horizontal IDOR (user ID manipulation in URL paths and query parameters) and Vertical Privilege Escalation (`/admin` routes) using `MultiIdentitySessionCoordinator` and `ResponseDiscrepancyAnalyzer`.

6. **`argus/collectors/business_logic.py` (1,556 lines)**:
   - Implements `BusinessLogicPayloadGenerator`, `BusinessLogicAnalyzer`, and `BusinessLogicCollector`.
   - Probes price/quantity tampering (negative amounts, zero values, extreme floats), mass assignment (privileged field injection), coupon stacking, and step-skipping workflow manipulation.

### 1.2 HTTP Infrastructure (`argus/http/client.py`)

- **`HttpResponse` dataclass (Lines 72-85)**:
  - Fields: `success: bool`, `status_code: Optional[int]`, `headers: Dict[str, str]`, `request_headers: Dict[str, str]`, `body: Optional[str]`, `raw_body: Optional[str]`, `url: str`, `method: str`, `elapsed: float`, `error: Optional[str]`, `scope_decision: Optional[ScopeDecision]`, `authorization_decision: Optional[AuthDecision]`.
- **`AuthenticatedHttpClient` (Lines 302-590)**:
  - Inherits from `AuthorizedHttpClient`.
  - Session-aware wrapper around `httpx.Client` with connection pooling, cookie jar synchronization (`self.cookies`), and retry backoff loop (`max_retries=3`, `backoff_factor=0.5`).
  - Supports identity injection: `request(mission, method, url, headers=None, params=None, json=None, data=None, files=None, timeout=None, action="http_request", identity=None, cookies=None)`.
  - Convenience methods: `get(mission, url, ...)`, `post(mission, url, ...)`, `put(mission, url, ...)`, `patch(mission, url, ...)`, `delete(mission, url, ...)`, `head(mission, url, ...)`, `options(mission, url, ...)`.
  - Automated authentication via `login(mission, identity, login_url, payload, login_type)`.
  - Sensitive header redaction (`sanitize_headers()`) and URL redaction (`sanitize_url()`) in log outputs.

### 1.3 State Publishing & Knowledge Graph Wiring

Quadruple State Publishing pattern requires four synchronized state mutations per confirmed finding:
1. **Evidence Store**:
   - Creates `Evidence(category="api_security", value="api_security:<template_id>:<target_url>:<parameter>", source="api_security", status="CONFIRMED", confidence=..., severity=..., title=..., description=..., provenance=ProvenanceData(observation_id=str(uuid.uuid4()), step_id=f"step_{technique}"), tags=[...], metadata={...})`.
   - Added to `raw_mission.evidence` via `.add()` or `.append()`.
2. **Vulnerabilities List**:
   - Appends dictionary to `raw_mission.vulnerabilities`:
     ```python
     {
         "name": title,
         "template_id": template_id,
         "severity": severity,
         "host": base_url,
         "url": target_url,
         "description": description,
         "technique": technique,
         "parameter": parameter,
         "strategy": mutation_strategy,
         "cwe_id": cwe_id,
         "cvss_score": cvss_score,
     }
     ```
3. **Attack Surface Knowledge Graph**:
   - Obtains `graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)`.
   - Creates Nodes: `live_host:{base_url}`, `endpoint:{target_url}`, `vulnerability:{template_id}:{target_url}:{parameter}`.
   - Creates Edges:
     - `graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")`
     - `graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")`
     - `graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")`
4. **ControlledMission Wrapper**:
   - If `mission` wraps raw mission and has `publish_finding(evidence_id, evidence)`, invokes it safely with exception guarding.

### 1.4 Pipeline Connectivity & Subsystems

1. **`argus/runtime/registry.py`**:
   - Global `ToolRegistry` with alias resolution and tool lookup.
   - Needs registration of `api_security` with aliases (`api_security_testing`, `api_security_collector`, `api_security_detector`, `api_vulnerability_detector`, `rest_security`, `bola_detector`, `idor_detector`, `mass_assignment_detector`, `rate_limit_detector`).
2. **`argus/runtime/plugins.py`**:
   - `PluginExecutorAdapter._instantiate_specialist_fallback`:
   - Needs conditional branch for `"api_security" in plugin_id` or `"rest_security" in plugin_id` or `"bola" in plugin_id` or `"api_vuln" in plugin_id` returning `APISecurityCollector()`.
3. **`argus/planning/task_generator.py`**:
   - `_RECON_TEMPLATES["api_security"]`: Entry with `title="Validate API Security"`, `dependencies=["Discover API Endpoints"]`, `category=TaskCategory.EVIDENCE_CORRELATION`, `metadata={"tool_id": "api_security"}`.
   - `_resolve_template_for_gap()`: Keyword matching for `"api security"`, `"rest security"`, `"bola"`, `"idor"`, `"mass assignment"`, `"rate limit bypass"`, `"excessive data exposure"`, `"method tampering"`.
4. **`argus/graph/attack_surface.py`**:
   - `AttackSurfaceGraphBuilder.build_from_evidence()`: Section 27 for `api_security` categories (`"api_security"`, `"api_vulnerability"`, `"bola_idor"`, `"mass_assignment"`, `"rate_limiting"`, `"excessive_data"`, `"method_tampering"`), creating `Node(type="vulnerability")` and `HAS_VULNERABILITY` edges.
5. **`argus/reporting/cvss.py`**:
   - `CWE_DATABASE` mappings for CWE-639 (BOLA/IDOR), CWE-915 (Mass Assignment), CWE-770 (Rate Limiting), CWE-602 (Parameter Tampering), CWE-200 (Excessive Data Exposure), CWE-650 (Method Tampering).

---

## 2. Logic Chain

### 2.1 The Tripartite Pattern Architecture for `api_security.py`

The module `argus/collectors/api_security.py` must follow the established Tripartite architecture:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        APISecurityCollector                            │
│  - Discovers candidate API endpoints & schemas from Mission state       │
│  - Iterates over endpoints and coordinates probe generation             │
│  - Dispatches probes via APISecurityProber                             │
│  - Evaluates outcomes via APISecurityAnalyzer                          │
│  - Executes Quadruple State Publishing (_emit_evidence)                │
└────────────────────────────────────────────────────────────────────────┘
          │                                              │
          ▼                                              ▼
┌───────────────────────────────────┐    ┌───────────────────────────────┐
│     APISecurityPayloadGenerator   │    │      APISecurityProber        │
│ - 6 Detection Mode Generators     │    │ - Wraps AuthenticatedClient   │
│ - 5 Mutation Strategy Mutators    │    │ - Burst Request Dispatcher    │
│ - Benign Baseline Generators      │    │ - Differential Identity Prober│
│ - Canary Token Injector           │    │ - HttpResponse Wrapper Parser │
└───────────────────────────────────┘    └───────────────────────────────┘
                                                         │
                                                         ▼
                                         ┌───────────────────────────────┐
                                         │      APISecurityAnalyzer      │
                                         │ - 6 Multi-Vector Evaluators   │
                                         │ - Sensitive Field Regex Engine│
                                         │ - Rate Limit Header Auditor   │
                                         │ - False Positive Rejection    │
                                         │ - Severity/CWE/CVSS Calibrator│
                                         └───────────────────────────────┘
```

### 2.2 Six Multi-Vector API Detection Modes Specification (R2)

| Detection Mode | Vector / Technique Enum | Probe Logic | Success / Confirmation Criteria | False Positive Rejection Criteria | Severity / CWE / CVSS |
|---|---|---|---|---|---|
| **1. Parameter Tampering** | `PARAMETER_TAMPERING` | Injects modified financial/business parameter values (`price: 0.01`, `price: -50.00`, `quantity: -1`, `quantity: 0`, `discount: 100`, `role: "admin"`) via JSON body or query string. | Server returns `200 OK` or `201 Created` with accepted price/quantity reflected in response body without validation rejection. | Rejects `400 Bad Request`, `422 Unprocessable Entity`, explicit validation error messages (`"invalid price"`, `"negative values disallowed"`). | **High**<br>CWE-602<br>CVSS 8.5 |
| **2. Mass Assignment** | `MASS_ASSIGNMENT` | Injects privileged and unauthorized attributes into request bodies (`isAdmin: true`, `is_admin: true`, `role: "admin"`, `role: "superuser"`, `balance: 999999`, `verified: true`, `permissions: ["*"]`, `tier: "enterprise"`, `account_type: "administrator"`). | Server accepts request (`200`/`201`) and response body or state confirmation reflects the injected privileged field persisted in the user object. | Rejects if server strips unexpected fields (response returns user object without the injected field), or returns `400`/`422` parameter validation errors. | **High**<br>CWE-915<br>CVSS 8.1 |
| **3. Rate Limiting Bypass** | `RATE_LIMITING_BYPASS` | Dispatches burst requests (10-20 requests in rapid succession). If rate limited (`429 Too Many Requests`), retries with rotated client headers (`X-Forwarded-For: <random_ip>`, `X-Real-IP`, `X-Originating-IP`, `Client-IP`, `True-Client-IP`, `X-Client-IP`). | (a) Server allows 15+ rapid requests without any rate limiting (`429` missing, no `X-RateLimit-*`), or (b) `429` rate limit is successfully bypassed by rotating IP headers (returns `200 OK`). | Rejects if server consistently enforces IP/token rate limits across rotated headers (returns `429` with `Retry-After`), or standard low-volume endpoints. | **Medium**<br>CWE-770<br>CVSS 5.3 |
| **4. BOLA / IDOR** | `BOLA_IDOR` | Probes REST resource paths containing entity identifiers (`/api/v1/users/{id}`, `/api/v1/orders/{id}`, `/api/v1/accounts/{id}/invoices`) by swapping ID values (e.g. `user_id=1` -> `user_id=2`, UUID swapping) across unauthenticated or secondary user contexts (`identity_b`). | Accessing resource belonging to User B returns `200 OK` with User B's private record/PII when requested with User A's token or unauthenticated. | Rejects `401 Unauthorized`, `403 Forbidden`, `404 Not Found`, or responses where object belongs to public/anonymous catalog data without PII. | **High**<br>CWE-639<br>CVSS 8.5 |
| **5. Excessive Data Exposure** | `EXCESSIVE_DATA_EXPOSURE` | Inspects standard API responses for over-exposed internal and sensitive properties beyond functional requirements. | API response body contains sensitive PII, password hashes (`$2a$`, `pbkdf2`), auth tokens, private API keys, SSNs, credit card numbers, internal database IDs, or internal network topology. | Rejects public marketing content, non-sensitive standard identifiers (`user_id`, `username`, `display_name`), or properly masked tokens (`***`). | **Medium**<br>CWE-200<br>CVSS 5.3 |
| **6. Method Tampering** | `METHOD_TAMPERING` | Probes read-only or restricted endpoints using unexpected HTTP methods (`PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS`, `TRACE`) and method override headers (`X-HTTP-Method-Override: PUT`). | Endpoint executes administrative actions or accepts modifications via unexpected methods, or returns `200 OK`/`204 No Content` performing unauthorized state changes, or leaks debug stack traces. | Rejects `405 Method Not Allowed`, `501 Not Implemented`, `401`/`403` standard method rejections with no side effects or leaks. | **High**<br>CWE-650<br>CVSS 7.5 |

### 2.3 Five Mutation & Evasion Strategies Specification (R4)

```
                       Original API Probe
                               │
       ┌───────────────────────┼───────────────────────┬───────────────────────┐
       ▼                       ▼                       ▼                       ▼
1. Content-Type         2. Parameter            3. Header-Based         4. Version             5. Encoding
   Switching               Pollution               Auth Bypass             Downgrade              Variations
- JSON -> Form-Url      - Duplicates:           - X-Forwarded-For       - /v2/ -> /v1/         - URL-Encoding:
- JSON -> XML             id=1&id=2               127.0.0.1             - /v3/ -> /v1/           %61%64%6d%69%6e
- JSON -> Multipart     - Array Wrapping:       - X-Original-URL: /admin- Header Versioning:   - Double URL:
- XML -> JSON             {"role": ["admin"]}   - X-Rewrite-URL: /admin   Accept: v=1.0          %2531
                        - HPP in query/body     - X-Custom-IP-Auth                             - JSON Unicode:
                                                                                                 \u0061\u0064...
```

1. **Content-Type Switching (`CONTENT_TYPE_SWITCHING`)**:
   - Converts JSON payload body `{"price": 0.01, "role": "admin"}` into:
     - `application/x-www-form-urlencoded`: `price=0.01&role=admin`
     - `application/xml`: `<request><price>0.01</price><role>admin</role></request>`
     - `multipart/form-data`: boundary form fields
     - `text/plain`: raw JSON or form format
   - Tests if backend WAF/filters only inspect JSON parsers while application deserializes alternate media types.
2. **Parameter Pollution (`PARAMETER_POLLUTION`)**:
   - Injects duplicate query or body keys: `?role=user&role=admin`, `?id=101&id=102`.
   - Injects array representations in JSON: `{"role": ["user", "admin"]}` or `{"isAdmin": [false, true]}`.
   - Exploits framework precedence differentials (e.g. Express/PHP/Django picking first vs last vs array).
3. **Header-Based Auth Bypass (`HEADER_AUTH_BYPASS`)**:
   - Injects spoofed reverse-proxy and gateway authorization bypass headers:
     - `X-Forwarded-For: 127.0.0.1`, `X-Forwarded-For: 10.0.0.1`, `X-Forwarded-For: localhost`
     - `X-Original-URL: <endpoint_path>`, `X-Rewrite-URL: <endpoint_path>`
     - `X-Custom-IP-Authorization: 127.0.0.1`, `X-Remote-IP: 127.0.0.1`, `X-Client-IP: 127.0.0.1`
     - `X-Forwarded-Host: localhost`, `X-Host: localhost`
4. **Version Downgrade (`VERSION_DOWNGRADE`)**:
   - Rewrites endpoint URL path version prefixes to older, unpatched API implementations:
     - `/api/v2/users/123` -> `/api/v1/users/123`
     - `/v3/checkout` -> `/v1/checkout` or `/v2/checkout`
     - `/api/latest/orders` -> `/api/v1/orders`
   - Injects downgrade version headers: `Accept: application/vnd.api+json;version=1.0` or `X-API-Version: 1.0`.
5. **Encoding Variations (`ENCODING_VARIATIONS`)**:
   - URL-encodes parameter names and string literals: `admin` -> `%61%64%6d%69%6e`, `role` -> `%72%6f%6c%65`.
   - Double URL-encoding: `%2561%2564%256d%2569%256e`.
   - JSON Unicode escape sequences: `\u0061\u0064\u006d\u0069\u006e`, `\u0069\u0073\u0041\u0064\u006d\u0069\u006e`.
   - Unicode fullwidth normalizations (e.g. `\uff41\uff44\uff4d\uff49\uff4e`).

### 2.4 Response Analysis & Sensitive Data Extraction Criteria (R3)

1. **Sensitive Field Detection Regexes**:
   - Passwords / Hashes: `r'"(?:password|passwd|pwd|password_hash|hash|secret_key)"\s*:\s*"[^"]+"'`
   - Tokens / Keys: `r'"(?:access_token|refresh_token|jwt|api_key|auth_token|secret)"\s*:\s*"[^"]{10,}"'`
   - PII / Financial: `r'"(?:ssn|social_security|credit_card|card_number|cvv|pin|dob|date_of_birth)"\s*:\s*"[^"]+"'`
   - Internal Architecture / Credentials: `r'"(?:internal_ip|db_connection|aws_secret|private_key)"\s*:\s*"[^"]+"'`
2. **Error Message & Information Disclosure Regexes**:
   - Stack Traces: `Traceback (most recent call last):`, `org.springframework.web`, `NullPointerException`, `System.Web.HttpException`
   - SQL Errors: `SQL syntax error`, `ORA-01756`, `pg_query()`, `SQLite3::SQLException`
   - File Paths: `/var/www/`, `/app/src/`, `C:\inetpub\wwwroot\`, `/node_modules/`
3. **Rate Limit Headers Auditing**:
   - Parses: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, `Retry-After`, `RateLimit-*`.
   - Flags when rate limits are absent or when headers indicate no decrements during high-frequency requests.
4. **Strict False Positive Rejection Algorithm**:
   - If probe was benign baseline -> reject.
   - If HTTP status code == 0 or connection timeout -> reject.
   - If response is `400`, `401`, `403`, `404`, `405`, `422`, and contains no leaked sensitive data / stack trace -> reject.
   - If mass assignment field was submitted but response does not contain the field in updated JSON -> reject.
   - If BOLA resource access returns public product catalog with identical responses across identities -> reject.

---

## 3. Detailed Proposed Architecture for `argus/collectors/api_security.py`

### 3.1 Enums & Data Structures

```python
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient, HttpResponse


class APISecuritySeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Compatibility alias
APISeverity = APISecuritySeverity


class APIVulnerabilityType(str, Enum):
    PARAMETER_TAMPERING = "parameter_tampering"
    MASS_ASSIGNMENT = "mass_assignment"
    RATE_LIMITING_BYPASS = "rate_limiting_bypass"
    BOLA_IDOR = "bola_idor"
    EXCESSIVE_DATA_EXPOSURE = "excessive_data_exposure"
    METHOD_TAMPERING = "method_tampering"
    ERROR_INFO_DISCLOSURE = "error_info_disclosure"


# Compatibility aliases
APISecurityTechnique = APIVulnerabilityType
APIVulnerabilityType.BOLA = APIVulnerabilityType.BOLA_IDOR  # type: ignore[attr-defined]
APIVulnerabilityType.IDOR = APIVulnerabilityType.BOLA_IDOR  # type: ignore[attr-defined]
APIVulnerabilityType.RATE_LIMIT = APIVulnerabilityType.RATE_LIMITING_BYPASS  # type: ignore[attr-defined]
APIVulnerabilityType.DATA_EXPOSURE = APIVulnerabilityType.EXCESSIVE_DATA_EXPOSURE  # type: ignore[attr-defined]


class APIMutationStrategy(str, Enum):
    CONTENT_TYPE_SWITCHING = "content_type_switching"
    PARAMETER_POLLUTION = "parameter_pollution"
    HEADER_AUTH_BYPASS = "header_auth_bypass"
    VERSION_DOWNGRADE = "version_downgrade"
    ENCODING_VARIATIONS = "encoding_variations"
    STANDARD = "standard"


# Compatibility alias
APISecurityMutationStrategy = APIMutationStrategy


@dataclass
class APIProbe:
    """Represents a targeted API security validation probe."""
    probe_id: str
    target_url: str
    method: str = "GET"
    vulnerability_type: Union[APIVulnerabilityType, str] = APIVulnerabilityType.PARAMETER_TAMPERING
    strategy: Union[APIMutationStrategy, str] = APIMutationStrategy.STANDARD
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, Any] = field(default_factory=dict)
    json_data: Optional[Any] = None
    data: Optional[Any] = None
    canary_token: str = ""
    tested_parameter: str = ""
    original_value: Any = None
    tampered_value: Any = None
    is_auth_required: bool = False
    secondary_identity: Optional[Any] = None
    burst_count: int = 1
    is_benign: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class APIProbeResponse:
    """Captures the response metadata from an API probe execution."""
    probe: APIProbe
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    json_body: Optional[Any] = None
    elapsed: float = 0.0
    error: Optional[str] = None
    raw_http_response: Optional[HttpResponse] = None
    burst_responses: List[Dict[str, Any]] = field(default_factory=list)
    rate_limit_headers: Dict[str, str] = field(default_factory=dict)
    sensitive_fields_detected: List[str] = field(default_factory=list)
    error_disclosure_detected: Optional[str] = None
    is_persisted: bool = False
    is_unauthorized_access: bool = False


@dataclass
class APISecurityResult:
    """Represents a confirmed and evaluated API security vulnerability."""
    template_id: str
    technique: str
    vulnerability_type: Union[APIVulnerabilityType, str]
    mutation_strategy: str
    endpoint_url: str
    severity: str
    cwe_id: str
    cvss_score: float
    description: str
    evidence_snippet: str
    parameter: Optional[str] = None
    status_code: int = 200
    confidence: float = 0.95
    is_valid_finding: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
```

### 3.2 Class Signatures & Implementation Map

```python
class APISecurityPayloadGenerator:
    """
    Generates multi-vector API security probes covering all 6 detection modes
    and applying all 5 mutation strategies.
    """
    def __init__(self): ...
    def generate_canary(self, prefix: str = "ARGUS_API") -> str: ...
    def generate_parameter_tampering_probes(self, endpoint_url: str) -> List[APIProbe]: ...
    def generate_mass_assignment_probes(self, endpoint_url: str) -> List[APIProbe]: ...
    def generate_rate_limiting_probes(self, endpoint_url: str) -> List[APIProbe]: ...
    def generate_bola_idor_probes(self, endpoint_url: str) -> List[APIProbe]: ...
    def generate_excessive_data_exposure_probes(self, endpoint_url: str) -> List[APIProbe]: ...
    def generate_method_tampering_probes(self, endpoint_url: str) -> List[APIProbe]: ...
    def generate_benign_baseline_probes(self, endpoint_url: str) -> List[APIProbe]: ...
    def apply_mutation(self, probe: APIProbe, strategy: Union[APIMutationStrategy, str]) -> APIProbe: ...
    def generate_all_probes(self, endpoint_url: str) -> List[APIProbe]: ...


class APISecurityProber:
    """
    Executes HTTP requests and burst sequences against API endpoints using AuthenticatedHttpClient.
    """
    def __init__(self, client: Optional[Any] = None, timeout: float = 10.0): ...
    def execute_probe(self, mission: Any, target_url: str, probe: APIProbe) -> APIProbeResponse: ...
    def execute_burst_sequence(self, mission: Any, target_url: str, probe: APIProbe, count: int = 15) -> APIProbeResponse: ...
    def execute_differential_identity_probe(self, mission: Any, target_url: str, probe: APIProbe) -> APIProbeResponse: ...


class APISecurityAnalyzer:
    """
    Evaluates API responses, analyzes sensitive data disclosures, parses rate limit headers,
    and applies strict false positive suppression.
    """
    SENSITIVE_PATTERNS = [...]
    ERROR_PATTERNS = [...]

    def detect_sensitive_fields(self, body: str) -> List[str]: ...
    def detect_error_disclosure(self, body: str) -> Optional[str]: ...
    def parse_rate_limit_headers(self, headers: Dict[str, str]) -> Dict[str, str]: ...
    def is_false_positive(self, probe: APIProbe, response: APIProbeResponse) -> bool: ...
    def evaluate_probe(self, probe: APIProbe, response: APIProbeResponse, target_url: str) -> Optional[APISecurityResult]: ...


class APISecurityCollector(BaseCollector):
    """
    Active security collector for API (REST/gRPC) vulnerabilities in ARGUS.
    Orchestrates probe generation, request dispatch, response analysis, and quadruple state publishing.
    """
    def __init__(
        self,
        http_client: Optional[Any] = None,
        prober: Optional[APISecurityProber] = None,
        generator: Optional[APISecurityPayloadGenerator] = None,
        analyzer: Optional[APISecurityAnalyzer] = None,
        timeout: float = 10.0,
        max_probes_per_endpoint: int = 50,
        client: Optional[Any] = None,
    ): ...
    def _discover_candidate_endpoints(self, mission: Any) -> List[str]: ...
    def _emit_evidence(self, mission: Any, result: APISecurityResult, target_url: str, base_url: str) -> Evidence: ...
    def collect(self, mission: Any) -> List[Evidence]: ...
    def execute(self, mission: Any) -> List[Evidence]: ...


# Backwards compatibility aliases
APISecurityTestingCollector = APISecurityCollector
RESTSecurityCollector = APISecurityCollector
APIVulnerabilityCollector = APISecurityCollector
BOLACollector = APISecurityCollector
IDORCollector = APISecurityCollector
```

---

## 4. Pipeline Connectivity Changes Required

### 4.1 Tool Registry (`argus/runtime/registry.py`)

1. Register `api_security` in `registry.py`:
   ```python
   registry.register(
       Tool(
           id="api_security",
           name="API Security Testing Collector",
           capability="api_security_detector",
           description="Actively discovers and validates REST/API vulnerabilities (parameter tampering, mass assignment, rate limiting bypass, BOLA/IDOR, excessive data exposure, and method tampering) using AuthenticatedHttpClient.",
           supported_tasks=[
               "API Security Testing",
               "API Vulnerability Detection",
               "Parameter Tampering",
               "Mass Assignment",
               "Rate Limiting Bypass",
               "BOLA Detection",
               "IDOR Detection",
               "Excessive Data Exposure",
               "Method Tampering",
               "Vulnerability Scanning",
               "Evidence Correlation",
               "API Discovery",
           ],
           required_inputs=["endpoints"],
           produced_outputs=["vulnerabilities", "observations", "evidence"],
           capabilities=[
               "api_security_detector",
               "api_security_collector",
               "api_security",
               "bola_detector",
               "idor_detector",
               "mass_assignment_detector",
               "rate_limit_detector",
               "api_vulnerability_detector",
           ],
           safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
           timeout=300.0,
           priority=95,
       )
   )
   ```
2. Add aliases in `ToolRegistry.get()`:
   - `"api_security": "api_security"`, `"api_security_testing": "api_security"`, `"api_security_collector": "api_security"`, `"api_security_detector": "api_security"`, `"api_vuln": "api_security"`, `"api_vulnerability": "api_security"`, `"bola": "api_security"`, `"idor": "api_security"`, `"rest_security": "api_security"`.

### 4.2 Plugin Fallbacks (`argus/runtime/plugins.py`)

In `PluginExecutorAdapter._instantiate_specialist_fallback()`:
```python
elif (
    "api_security" in plugin_id
    or "rest_security" in plugin_id
    or "api_vuln" in plugin_id
    or "api_vulnerability" in plugin_id
    or "bola" in plugin_id
    or "idor_detector" in plugin_id
    or "mass_assignment_detector" in plugin_id
    or "rate_limit_detector" in plugin_id
):
    from argus.collectors.api_security import APISecurityCollector
    return APISecurityCollector()
```

### 4.3 Task Generator DAG (`argus/planning/task_generator.py`)

1. Add `api_security` to `_RECON_TEMPLATES`:
   ```python
   "api_security": {
       "title": "Validate API Security",
       "goal": "Actively test discovered REST/API endpoints for parameter tampering, mass assignment, rate limiting bypass, BOLA/IDOR, excessive data exposure, and method tampering using AuthenticatedHttpClient.",
       "category": TaskCategory.EVIDENCE_CORRELATION,
       "required_inputs": ["endpoints"],
       "expected_outputs": ["vulnerabilities", "observations", "evidence"],
       "dependencies": ["Discover API Endpoints"],
       "required_specialists": [],
       "metadata": {"tool_id": "api_security"},
       "estimated_duration_minutes": 10,
       "priority": 0.82,
   },
   ```
2. Add keyword match in `_resolve_template_for_gap()`:
   ```python
   if area_lower in (
       "api security",
       "api_security",
       "rest security",
       "rest_security",
       "api vulnerability",
       "api vulnerabilities",
       "bola",
       "idor",
       "broken object level authorization",
       "mass assignment",
       "rate limit bypass",
       "rate limiting bypass",
       "excessive data exposure",
       "method tampering",
   ):
       return _RECON_TEMPLATES["api_security"]
   ```

### 4.4 Attack Surface Graph Builder (`argus/graph/attack_surface.py`)

Add Section 27 in `AttackSurfaceGraphBuilder.build_from_evidence()`:
```python
# 27. API Security (REST/gRPC) Vulnerabilities
for ev in get_items(
        "api_security",
        "api_vulnerability",
        "bola_idor",
        "bola",
        "idor",
        "mass_assignment",
        "rate_limiting_bypass",
        "rate_limiting",
        "excessive_data_exposure",
        "method_tampering",
    ):
    target_url = ev.metadata.get("url") or ev.value
    parsed_url = urllib.parse.urlparse(target_url) if target_url else None
    base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
    template_id = ev.metadata.get("template_id") or "api-security-finding"
    param_name = ev.metadata.get("parameter") or ev.metadata.get("tested_parameter") or ""
    vuln_type = ev.metadata.get("vulnerability_type") or ev.metadata.get("technique") or "api_security"
    vuln_id = f"vulnerability:{template_id}:{target_url}:{param_name}" if (target_url and param_name) else (f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}")
    vuln_name = ev.title or f"API Security Vulnerability ({vuln_type})"
    vuln_meta = dict(ev.metadata) if ev.metadata else {}
    if "name" not in vuln_meta:
        vuln_meta["name"] = vuln_name
    if "severity" not in vuln_meta:
        vuln_meta["severity"] = getattr(ev, "severity", "high") or "high"

    ep_id = f"endpoint:{target_url}" if target_url else None
    if ep_id and ep_id not in graph.nodes:
        graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": ev.metadata.get("status_code", 200)}))

    graph.add(Node(id=vuln_id, type="vulnerability", value=vuln_name, metadata=vuln_meta))

    # Link live host to endpoint & vulnerability
    lh_node = resolve_lh(target_url_val=target_url, host_val=base_url)
    if not lh_node and base_url:
        lh_id = f"live_host:{base_url}"
        if lh_id not in graph.nodes:
            parsed_b = urllib.parse.urlparse(base_url)
            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url, "host": parsed_b.hostname or base_url}))
        lh_node = graph.get(lh_id)

    if lh_node:
        if ep_id:
            graph.connect(lh_node.id, ep_id, edge_type="HAS_ENDPOINT")
        graph.connect(lh_node.id, vuln_id, edge_type="HAS_VULNERABILITY")
    if ep_id:
        graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")
```

### 4.5 CVSS & CWE Mappings (`argus/reporting/cvss.py`)

Verify and ensure entries in `CWE_DATABASE` and `_get_preset_vector`:
- `api_security`: `CWEInfo("CWE-699", "Software Development Security Issue")`
- `bola`: `CWEInfo("CWE-639", "Authorization Bypass Through User-Controlled Key")`
- `idor`: `CWEInfo("CWE-639", "Authorization Bypass Through User-Controlled Key")`
- `bola_idor`: `CWEInfo("CWE-639", "Authorization Bypass Through User-Controlled Key")`
- `mass_assignment`: `CWEInfo("CWE-915", "Improperly Controlled Modification of Dynamically-Determined Object Attributes")`
- `rate_limiting_bypass`: `CWEInfo("CWE-770", "Allocation of Resources Without Limits or Throttling")`
- `rate_limit`: `CWEInfo("CWE-770", "Allocation of Resources Without Limits or Throttling")`
- `parameter_tampering`: `CWEInfo("CWE-602", "Client-Side Enforcement of Server-Side Security")`
- `excessive_data_exposure`: `CWEInfo("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor")`
- `method_tampering`: `CWEInfo("CWE-650", "Trusting HTTP Permission Methods on the Server Side")`

---

## 5. Caveats

1. **Multi-Identity Testing Context**:
   - In production environments, BOLA/IDOR detection is most effective when multiple configured `TestIdentity` instances (e.g. `UserA` and `UserB`) are present on the mission.
   - When only a single identity or no identity is configured, the collector will perform simulated parameter swapping (`id=1` -> `id=2`) and unauthenticated differential checks, comparing response length and schema variation.
2. **Rate Limiting Burst Thresholds**:
   - To avoid overwhelming test targets or triggering unwanted network freezes, the default burst count for rate limit testing is calibrated to 15 requests with a concurrency throttle.
3. **Strict Validation Persistence Verification**:
   - Mass Assignment detection must strictly verify that the injected parameter was actually reflected in the server response or persisted state, avoiding false positives on APIs that simply ignore and discard unrecognized JSON keys.

---

## 6. Conclusion

The ARGUS Collector framework follows a strict, well-defined Tripartite architecture (Collector + Payload Generator + Response Analyzer) paired with Quadruple State Publishing (Evidence store, Vulnerabilities list, Attack Surface KnowledgeGraph, ControlledMission notification).

The design for `argus/collectors/api_security.py` fully addresses requirements R1, R2, R3, R4, R5, and R6:
- 6 Detection Modes: Parameter Tampering, Mass Assignment, Rate Limiting Bypass, BOLA/IDOR, Excessive Data Exposure, Method Tampering.
- 5 Mutation Strategies: Content-Type Switching, Parameter Pollution, Header-Based Auth Bypass, Version Downgrade, Encoding Variations.
- Seamless wiring into `registry.py`, `plugins.py`, `task_generator.py`, `attack_surface.py`, and `cvss.py`.
- Full backwards compatibility and zero regression across the existing 1,827+ test suite.

---

## 7. Verification Method

1. **Unit Test Suite**:
   - Run: `python -m pytest tests/collectors/test_api_security.py -v` (at least 15 tests covering all 6 detection modes, 5 mutation strategies, model enums, and prober/analyzer logic).
2. **Adversarial & False Positive Test Suite**:
   - Run: `python -m pytest tests/collectors/test_api_security_adversarial.py -v` (at least 10 tests verifying false positive suppression, rate limit resets, mass assignment field stripping, and network timeout handling).
3. **Full System Regression Suite**:
   - Run: `python -m pytest tests/ --ignore=tests/workspace -q`
   - Expected result: 1,852+ tests passing with 0 regressions.
4. **Graph & DAG Verification**:
   - Verify `AttackSurfaceGraphBuilder.build_from_evidence()` creates `endpoint` and `vulnerability` nodes with `HAS_VULNERABILITY` edges.
   - Verify `TaskGenerator._resolve_template_for_gap()` resolves `api_security` for API security coverage gaps.
