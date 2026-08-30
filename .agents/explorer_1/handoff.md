# Exploration & Architecture Survey: SSRF Validation Collector (Sprint 12)

## 1. Observation

Direct empirical inspection of the ARGUS repository reveals the following architecture, code conventions, and file locations:

### 1.1 Existing Validation Collectors
- **`argus/collectors/base.py` (lines 1-10)**:
  - Abstract base class `BaseCollector(ABC)` defining the single abstract method `collect(self, mission)`.
- **`argus/collectors/command_injection.py` (lines 1-1339)**:
  - Most recently implemented validation collector (Sprint 11).
  - Tri-class modular design:
    - `CommandInjectionPayloadGenerator`: Generates base commands and mutation variants across 8 strategies (semicolons, pipes, ampersands, command substitutions, newlines, URL encoding, whitespace substitution, inline quotes).
    - `CommandInjectionAnalyzer`: Analyzes `HttpResponse` objects using POSIX/Windows regex patterns (`OS_RESULT_SIGNATURES`), shell error regexes (`SHELL_ERROR_SIGNATURES`), arithmetic canary evaluation, differential latency checks ($\Delta T \ge 4.0\text{s}$), and baseline/reflection false-positive suppression.
    - `CommandInjectionCollector(BaseCollector)`: Inherits from `BaseCollector`, implements `collect(self, mission) -> List[Evidence]` and `execute(self, mission) -> List[Evidence]` (for plugin adapter compatibility).
    - Extracts candidate endpoints via `_extract_candidate_endpoints(raw_mission)` from `raw_mission.endpoints`, `raw_mission.live_hosts`, and `raw_mission.target`.
    - Fuzzes 4 vectors:
      1. GET query parameters (existing URL query parameters, raw candidate params, and default probe fallbacks).
      2. POST body fields (both JSON body dictionaries and form-urlencoded parameter pairs).
      3. RESTful path segments (numeric/resource path tokens).
      4. HTTP request headers (`User-Agent`, `Referer`, `Cookie`, `X-Forwarded-For`, `X-Client-IP`).
- **`argus/collectors/sql_injection.py` (lines 1-1184)**:
  - Tri-class architecture: `SQLInjectionPayloadGenerator`, `SQLInjectionAnalyzer`, `SQLInjectionCollector(BaseCollector)`.
  - Multi-DBMS error signatures for MySQL, PostgreSQL, MSSQL, Oracle, SQLite (`DBMS_ERROR_SIGNATURES`), boolean differential length checks ($\Delta L \ge 25\text{B}$), and time-delay analysis ($\Delta T \ge 4.0\text{s}$).
  - Fuzzes query parameters, POST JSON/form bodies, path segments, and HTTP headers.
- **`argus/collectors/xss.py` (lines 1-1079)**:
  - Tri-class architecture: `XSSPayloadGenerator`, `XSSAnalyzer`, `XSSCollector(BaseCollector)`.
  - Context enumeration `XSSContext` (HTML body, attributes, script blocks, URL attributes).
  - Validates reflected and stored XSS with HTML entity-encoding false-positive suppression.
- **`argus/collectors/path_traversal.py` (lines 1-591)**:
  - Tri-class architecture: `PathTraversalPayloadGenerator`, `PathTraversalAnalyzer`, `PathTraversalCollector(BaseCollector)`.
  - Signatures for `/etc/passwd`, `/etc/shadow`, `/etc/hosts`, `/proc/self/environ`, `win.ini`, `boot.ini`.
- **`argus/collectors/__init__.py` (lines 1-48)**:
  - Exports all collectors, analyzers, payload generators, enums, and data models in `__all__`.

### 1.2 HTTP Client Utility
- **`argus/http/client.py` (lines 1-587)**:
  - `HttpResponse` dataclass (lines 72-85): contains `success: bool`, `status_code: Optional[int]`, `headers: Dict[str, str]`, `request_headers: Dict[str, str]`, `body: Optional[str]`, `raw_body: Optional[str]`, `url: str`, `method: str`, `elapsed: float`, `error: Optional[str]`, `scope_decision`, `authorization_decision`.
  - `AuthorizedHttpClient` (lines 86-298): Wraps `httpx` with `ScopeResolver` boundary checks and `authorization_gate`.
  - `AuthenticatedHttpClient(AuthorizedHttpClient)` (lines 300-400+): Session-aware client with context manager support (`__enter__` / `__exit__`), cookie preservation, authentication identity injection (`TestIdentity`), and timeout handling.
  - Collector pattern for client execution:
    ```python
    def _execute_request(self, mission, method, url, params=None, data=None, json_data=None, headers=None, cookies=None):
        if self.http_client is not None:
            # Polymorphic handling for mock clients in unit/integration tests
            if method == "GET" and hasattr(self.http_client, "get"):
                return self.http_client.get(mission, url, params=params, headers=headers, cookies=cookies, timeout=self.timeout)
            ...
        with AuthenticatedHttpClient(timeout=self.timeout, max_retries=1) as client:
            if method == "GET":
                return client.get(mission, url, params=params, headers=headers, cookies=cookies, timeout=self.timeout)
            elif method == "POST":
                return client.post(mission, url, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout)
            else:
                return client.request(mission, method, url, params=params, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout)
    ```

### 1.3 Pipeline & Task DAG Generation
- **`argus/planning/task_generator.py` (lines 1-508)**:
  - `_RECON_TEMPLATES` dictionary (lines 13-134): Defines recon task templates for `subfinder`, `httpx`, `katana_crawler`, `nuclei`, `info_disclosure`, `access_control`, `path_traversal`, `sql_injection`, `xss`, `command_injection`.
  - Validation tasks declare `category: TaskCategory.EVIDENCE_CORRELATION` (or `TaskCategory.AUTHORIZATION_ANALYSIS`), `dependencies: ["Discover API Endpoints"]`, `required_inputs: ["endpoints"]`, and `metadata: {"tool_id": "<tool_id>"}`.
  - `_resolve_template_for_gap(gap: CoverageGap)` (lines 350-450): Maps coverage gap area strings and synonym keywords to template entries in `_RECON_TEMPLATES`.
  - `from_gaps(self, gaps: List[CoverageGap]) -> List[ResearchTask]` (lines 452-508): Binds endpoint inputs from `mission.endpoints` or `mission.live_hosts` to the generated task.

### 1.4 Tool Registry & Plugin Adapter
- **`argus/runtime/registry.py` (lines 1-354)**:
  - `ToolRegistry.get(self, key: str)` (lines 15-34): Resolves tool by exact ID or alias dict (`aliases = {"cross_site_scripting": "xss", "sqli": "sql_injection", "cmdi": "command_injection", ...}`).
  - Global `registry.register(Tool(...))` entries (lines 55-347): Registers each tool with `id`, `name`, `capability`, `description`, `supported_tasks`, `required_inputs`, `produced_outputs`, `capabilities`, `safety_requirements`, `timeout`, and `priority=95`.
- **`argus/runtime/plugins.py` (lines 1-112)**:
  - `PluginExecutorAdapter._instantiate_specialist_fallback(self, plugin_id: str)` (lines 65-109): Fallback instantiator mapping `plugin_id` strings (e.g. `if "command_injection" in plugin_id ...`) to the instantiated collector object.

### 1.5 Attack Surface Graph & Evidence Data Models
- **`argus/evidence/model.py`**:
  - `Evidence` dataclass with fields `mission_id`, `source_type="LOG"`, `created_by="SYSTEM_GENERATED"`, `title`, `description`, `category`, `value`, `source`, `status="CONFIRMED"`, `confidence`, `severity`, `provenance=ProvenanceData(step_id=...)`, `tags`, `metadata`.
- **`argus/graph/attack_surface.py` (lines 1-761)**:
  - `AttackSurfaceGraphBuilder.build_from_evidence(evidence, target, graph)`: Iterates over evidence items and creates `Node(id=lh_id, type="live_host")`, `Node(id=ep_id, type="endpoint")`, `Node(id=vuln_id, type="vulnerability")`, and connects `lh_id -> ep_id` (`HAS_ENDPOINT`), `lh_id -> vuln_id` (`HAS_VULNERABILITY`), `ep_id -> vuln_id` (`HAS_VULNERABILITY`).
  - Section 13 (lines 523-577) handles `command_injection`.
- **Collector Graph Expansion**:
  - In `_create_evidence_and_update_state`, each collector directly updates `raw_mission.evidence`, `raw_mission.vulnerabilities` list, and `raw_mission.attack_surface_graph` (or `raw_mission.graph`), connecting `live_host`, `endpoint`, and `vulnerability` nodes with `HAS_VULNERABILITY` edges.

### 1.6 Existing Tests & Test Runner Harness
- **Test files**:
  - `tests/collectors/test_command_injection.py` (613 lines, 26 unit tests)
  - `tests/collectors/test_command_injection_adversarial.py` (608 lines, 26 adversarial tests)
  - `tests/collectors/test_sql_injection.py` (535 lines)
  - `tests/collectors/test_sql_injection_adversarial.py` (680 lines)
  - `tests/collectors/test_xss.py` (539 lines)
  - `tests/collectors/test_xss_adversarial.py` (582 lines)
  - `tests/collectors/test_path_traversal.py` (520 lines)
  - `tests/collectors/test_path_traversal_adversarial.py` (586 lines)
- **Baseline Test Suite Execution**:
  - Running `python -m pytest tests/ --ignore=tests/workspace -x -q` passed all **1071 tests** in 41.41s with exit code 0.

---

## 2. Logic Chain

The requirements R1-R5 for Sprint 12 directly map to the proven 3-tier collector pattern established across Sprints 6, 9, 10, and 11.

```
Step 1 (Observation 1.1, 1.2):
Existing collectors (SQLi, XSS, Path Traversal, CMDi) follow a 3-class architecture:
  <Module>PayloadGenerator -> <Module>Analyzer -> <Module>Collector(BaseCollector)
Therefore, SSRF should implement SSRFPayloadGenerator, SSRFAnalyzer, and SSRFCollector(BaseCollector) in argus/collectors/ssrf.py.

Step 2 (Observation 1.1, Requirement R1):
Endpoint parameter extraction inspects:
  - GET query parameters (candidate URL, raw_params, and common SSRF param names like 'url', 'target', 'dest', 'webhook', 'feed', 'uri', 'redirect', 'src', 'fetch').
  - POST body parameters (JSON objects and form-urlencoded keys).
  - RESTful path segments (encoded URLs or resource targets).
  - HTTP headers (Referer, X-Forwarded-For, X-Forwarded-Host, X-Original-URL, X-Rewrite-URL).
Therefore, SSRFCollector must fuzz all 4 vectors using AuthenticatedHttpClient.

Step 3 (Observation 1.1, Requirement R2):
Detection requires 3 distinct techniques:
  1. Cloud Metadata Response Detection: AWS IMDSv1/v2 (IAM security credentials, token responses, dynamic identity document), GCP computeMetadata (project ID, instance ID, service accounts with Metadata-Flavor header), Azure IMDS (VM metadata JSON with Metadata: true header), DigitalOcean/Oracle/Alibaba metadata.
  2. Internal Service Response Detection: Redis (PONG, +OK, -ERR, redis_version), Database Handshake Banners (MySQL, PostgreSQL, Elasticsearch 'You Know, for Search', MongoDB 'isWritablePrimary', Memcached 'STAT pid', RabbitMQ, Consul/etcd), Internal Admin HTML titles (<title>Admin Dashboard</title>, pfSense, Kibana, Grafana, Jenkins, phpMyAdmin, Actuator).
  3. Differential Timing Detection: Delta T = (injected_elapsed - baseline_elapsed) >= 4.0s against unroutable / dropping addresses (e.g. 10.255.255.1:81, 192.0.2.1:81) compared to baseline.
  4. False-Positive & Reflection Suppression: Check that the payload isn't merely reflected as static echo on a search page, and verify the pattern wasn't already present in baseline_resp.

Step 4 (Observation 1.1, Requirement R3):
Input Validation Bypass Mutations require at least 6 distinct strategies:
  1. Decimal IP notation: 127.0.0.1 -> 2130706433, 169.254.169.254 -> 2852039166.
  2. Hexadecimal IP notation: 127.0.0.1 -> 0x7f000001 or 0x7f.0x0.0x0.0x1, 169.254.169.254 -> 0xa9fea9fe or 0xa9.0xfe.0xa9.0xfe.
  3. Octal IP notation: 127.0.0.1 -> 0177.0.0.1 or 017700000001, 169.254.169.254 -> 0251.0376.0251.0376.
  4. Shortened IP notation: 127.0.0.1 -> 127.1, 127.0.1, 0, 0.0.0.0.
  5. URL Encoding & Double URL Encoding: http%3A%2F%2F169.254.169.254%2F, %31%32%37%2E%30%2E%30%2E%31.
  6. Alternative URI schemes: dict://127.0.0.1:11211/, gopher://127.0.0.1:6379/_INFO, file:///etc/passwd, ldap://127.0.0.1:389/.
  7. IPv6 representations: http://[::1]/, http://[::]/, http://[::ffff:127.0.0.1]/, http://[::ffff:a9fe:a9fe]/.
  8. DNS rebinding & alternative localhost domains: http://localhost/, http://127.0.0.1.nip.io/, http://localtest.me/, http://customer.localhost/.
  9. URL parser ambiguity & credential tricks: http://127.0.0.1:80@target.com/, http://target.com#@127.0.0.1/, http://127.0.0.1?.target.com/.

Step 5 (Observation 1.3, 1.4, 1.5, Requirement R4):
Pipeline, registry, adapter, and graph integration requires:
  - Adding 'ssrf' recon template to _RECON_TEMPLATES in argus/planning/task_generator.py with dependency ['Discover API Endpoints'].
  - Updating _resolve_template_for_gap and from_gaps in argus/planning/task_generator.py.
  - Registering Tool(id='ssrf', ...) and aliases in argus/runtime/registry.py.
  - Adding fallback instantiation for 'ssrf' in argus/runtime/plugins.py.
  - Ingesting category='ssrf' evidence into KnowledgeGraph with HAS_VULNERABILITY edges in argus/graph/attack_surface.py.
  - Exporting SSRF classes in argus/collectors/__init__.py.

Step 6 (Observation 1.6, Requirement R5):
Unit and adversarial test suites in tests/collectors/test_ssrf.py and tests/collectors/test_ssrf_adversarial.py will test all modules using MockSSRFHttpClient without live network dependencies, ensuring zero regressions across all 1071 existing tests.
```

---

## 3. Caveats

1. **Network Independence**: Real network connections to `169.254.169.254` or `127.0.0.1` must never be attempted during automated pytest runs; tests must strictly inject a `MockSSRFHttpClient` or utilize mock response handlers.
2. **Scope Resolver Compatibility**: When running inside ARGUS missions, `AuthenticatedHttpClient` enforces `ScopeResolver.check_scope`. Payloads targeting internal IPs/metadata endpoints are sent as query/body parameters to the target server (which is in scope), not as direct HTTP destinations for the client itself.
3. **No other caveats**: The codebase architecture is completely consistent, uniform, and fully understood.

---

## 4. Conclusion & Technical Blueprint

### 4.1 Comparison of Existing Collectors

| Feature | `SQLInjectionCollector` | `XSSCollector` | `PathTraversalCollector` | `CommandInjectionCollector` | **`SSRFCollector` (Sprint 12 Target)** |
|---|---|---|---|---|---|
| **Module File** | `argus/collectors/sql_injection.py` | `argus/collectors/xss.py` | `argus/collectors/path_traversal.py` | `argus/collectors/command_injection.py` | `argus/collectors/ssrf.py` |
| **Generator** | `SQLInjectionPayloadGenerator` | `XSSPayloadGenerator` | `PathTraversalPayloadGenerator` | `CommandInjectionPayloadGenerator` | `SSRFPayloadGenerator` |
| **Analyzer** | `SQLInjectionAnalyzer` | `XSSAnalyzer` | `PathTraversalAnalyzer` | `CommandInjectionAnalyzer` | `SSRFAnalyzer` |
| **Techniques** | Error, Boolean diff, Time delay | Context reflection, Stored POST-GET | File signatures, Null byte bypasses | Result signatures, Time delay, Shell errors | Cloud metadata, Internal services, Differential timing |
| **Latency Threshold** | $\Delta T \ge 4.0\text{s}$ | N/A | N/A | $\Delta T \ge 4.0\text{s}$ | $\Delta T \ge 4.0\text{s}$ |
| **Bypass Engine** | 5 WAF bypasses (comments, hex, case, concat, spaces) | Context breakouts (quotes, script tags, event handlers) | Nested traversal, URL/Double enc, null bytes, overlong UTF-8 | 8 Separator/substitution mutations ($IFS, quotes, %, ;, |, &) | 9 Strategies (Decimal, Hex, Octal, Short, URL enc, Schemes, IPv6, Rebinding, Parser ambiguity) |
| **Injection Vectors** | GET query, POST json/form, path, headers | GET query, POST json/form, headers | GET query, POST json/form, URL path | GET query, POST json/form, path, headers | GET query, POST json/form, path, headers (Referer, X-Forwarded-For, etc.) |
| **Evidence Category** | `"sql_injection"` | `"xss"` | `"path_traversal"` | `"command_injection"` | `"ssrf"` |
| **Severity** | `CRITICAL` / `HIGH` | `HIGH` / `MEDIUM` | `CRITICAL` / `HIGH` | `CRITICAL` | `CRITICAL` (Metadata/Admin) / `HIGH` (Internal/Timing) |
| **Graph Edges** | `HAS_ENDPOINT`, `HAS_VULNERABILITY` | `HAS_ENDPOINT`, `HAS_VULNERABILITY` | `HAS_VULNERABILITY` | `HAS_ENDPOINT`, `HAS_VULNERABILITY` | `HAS_ENDPOINT`, `HAS_VULNERABILITY` |
| **DAG Dependency** | `["Discover API Endpoints"]` | `["Discover API Endpoints"]` | `["Discover API Endpoints"]` | `["Discover API Endpoints"]` | `["Discover API Endpoints"]` |
| **Tool ID** | `"sql_injection"` | `"xss"` | `"path_traversal"` | `"command_injection"` | `"ssrf"` |

---

### 4.2 Detailed Specifications for SSRF Validation Collector

#### A. Data Models & Enums (`argus/collectors/ssrf.py`)
```python
class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class SSRFTechnique(str, Enum):
    CLOUD_METADATA = "cloud_metadata"
    INTERNAL_SERVICE = "internal_service"
    DIFFERENTIAL_TIMING = "differential_timing"

class SSRFCloudProvider(str, Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    DIGITALOCEAN = "digitalocean"
    ORACLE = "oracle"
    ALIBABA = "alibaba"
    GENERIC = "generic"

@dataclass
class SSRFResult:
    technique: str  # "cloud_metadata", "internal_service", "differential_timing"
    payload: str
    parameter: str
    parameter_type: str  # "query", "body", "json", "path", "header"
    status_code: int = 200
    target_service: str = "generic"  # "aws_imds", "gcp_metadata", "redis", "mysql", etc.
    matched_pattern: str = ""
    snippet: str = ""
    severity: str = Severity.CRITICAL
    confidence: float = 0.95
    template_id: str = "ssrf"
    delay_delta: float = 0.0
    baseline_elapsed: float = 0.0
    injected_elapsed: float = 0.0
    bypass_strategy: str = "none"
    extra: Dict[str, Any] = field(default_factory=dict)
```

#### B. Signature Catalogs (`argus/collectors/ssrf.py`)
1. **Cloud Metadata Signatures (`CLOUD_METADATA_SIGNATURES`)**:
   - `aws_iam_role`: `re.compile(r"security-credentials/[a-zA-Z0-9_\-\.]+", re.IGNORECASE)`
   - `aws_security_credentials`: `re.compile(r"\{\s*\"Code\"\s*:\s*\"Success\"[^\}]*\"AccessKeyId\"\s*:\s*\"(?:AKIA|ASIA)[A-Z0-9]{16}\"", re.IGNORECASE)`
   - `aws_instance_identity`: `re.compile(r"\"instanceId\"\s*:\s*\"i-[0-9a-f]{8,17}\"", re.IGNORECASE)`
   - `aws_ami_id`: `re.compile(r"\bami-[0-9a-f]{8,17}\b", re.IGNORECASE)`
   - `gcp_instance_id`: `re.compile(r"\bcomputeMetadata/v1\b|\"project\":\s*\{\s*\"projectId\"", re.IGNORECASE)`
   - `gcp_service_accounts`: `re.compile(r"instance/service-accounts/[a-zA-Z0-9_\-\.]+@developer\.gserviceaccount\.com", re.IGNORECASE)`
   - `azure_vm_metadata`: `re.compile(r"\{\s*\"compute\"\s*:\s*\{[^\}]*\"vmId\"\s*:\s*\"[0-9a-f\-]{36}\"", re.IGNORECASE)`
   - `digitalocean_droplet`: `re.compile(r"\"droplet_id\"\s*:\s*\d+|\"vendor_data\"", re.IGNORECASE)`
   - `oracle_cloud`: `re.compile(r"\"id\"\s*:\s*\"ocid1\.instance\.", re.IGNORECASE)`
   - `alibaba_cloud`: `re.compile(r"\binstance-id\b.*\bimage-id\b", re.IGNORECASE)`

2. **Internal Service Signatures (`INTERNAL_SERVICE_SIGNATURES`)**:
   - `redis_pong`: `re.compile(r"(?:\+PONG|PONG|\+OK|-ERR unknown command|redis_version:\d+\.\d+)", re.IGNORECASE)`
   - `mysql_handshake`: `re.compile(r"(?:\x00\x00\x00\n\d+\.\d+\.\d+|mysql_native_password|caching_sha2_password|mariadb\.org binary)", re.IGNORECASE)`
   - `postgres_handshake`: `re.compile(r"(?:FATAL:\s+password authentication failed|org\.postgresql\.util\.PSQLException)", re.IGNORECASE)`
   - `elasticsearch_banner`: `re.compile(r"(?:You Know, for Search|\"cluster_name\"\s*:|\"lucene_version\"\s*:)", re.IGNORECASE)`
   - `mongodb_banner`: `re.compile(r"(?:\"isWritablePrimary\"\s*:|\"ismaster\"\s*:|\"wireVersionMin\"\s*:)", re.IGNORECASE)`
   - `memcached_banner`: `re.compile(r"(?:STAT pid \d+|STAT uptime \d+|VERSION \d+\.\d+)", re.IGNORECASE)`
   - `rabbitmq_banner`: `re.compile(r"(?:RabbitMQ|\"rabbitmq_version\"\s*:|AMQP:\d+-\d+)", re.IGNORECASE)`
   - `consul_etcd`: `re.compile(r"(?:\{\s*\"action\"\s*:\s*\"get\"|\"kvs\"\s*:\s*\[|\"Consul\")", re.IGNORECASE)`
   - `admin_titles`: `re.compile(r"<title>[^<]*(?:Admin Dashboard|Internal Router|phpMyAdmin|Kibana|Grafana|Jenkins|RabbitMQ Management|HAProxy Statistics|Spring Boot Actuator|Traefik|Kubernetes Dashboard)[^<]*</title>", re.IGNORECASE)`

#### C. Bypass Mutation Engine (`SSRFPayloadGenerator`)
Methods on `SSRFPayloadGenerator`:
- `mutate_decimal_ip(host: str, path: str = "/") -> List[str]`: converts IPv4 to decimal (e.g. `127.0.0.1` -> `2130706433`).
- `mutate_hex_ip(host: str, path: str = "/") -> List[str]`: converts IPv4 to 32-bit hex (`0x7f000001`) and dotted hex (`0x7f.0x0.0x0.0x1`).
- `mutate_octal_ip(host: str, path: str = "/") -> List[str]`: converts IPv4 to octal notation (`0177.0.0.1`, `017700000001`, `0251.0376.0251.0376`).
- `mutate_shortened_ip(host: str, path: str = "/") -> List[str]`: converts to `127.1`, `127.0.1`, `0`, `0.0.0.0`.
- `mutate_url_encoding(url: str) -> List[str]`: generates single and double URL-encoded strings, plus character-encoded variants (`%31%32%37...`).
- `mutate_alternative_schemes(host: str, port: int, path: str = "") -> List[str]`: generates `dict://`, `gopher://`, `file:///`, `ldap://`, `tftp://`.
- `mutate_ipv6(host: str, path: str = "/") -> List[str]`: generates `[::1]`, `[::]`, `[::ffff:127.0.0.1]`, `[::ffff:a9fe:a9fe]`.
- `mutate_dns_rebinding(host: str, path: str = "/") -> List[str]`: generates `localhost`, `127.0.0.1.nip.io`, `localtest.me`, `spoofed.burpcollaborator.net`.
- `mutate_parser_ambiguity(host: str, path: str = "/") -> List[str]`: generates `http://127.0.0.1:80@target.com/`, `http://target.com#@127.0.0.1/`, `http://127.0.0.1?.target.com/`.
- `generate_mutated_payloads(target_url: str) -> List[str]`: Combines and deduplicates variants across all 9 strategies.

#### D. SSRF Analyzer (`SSRFAnalyzer`)
Methods on `SSRFAnalyzer`:
- `analyze_cloud_metadata(response, baseline, target_info) -> Optional[Dict[str, Any]]`:
  - Scans body against `CLOUD_METADATA_SIGNATURES`.
  - Rejects if pattern was present in baseline response.
  - Rejects if pattern is merely an echo of the target parameter.
  - Returns structured finding dict with `technique="cloud_metadata"`, `template_id=f"ssrf_cloud_{provider}"`, `severity=Severity.CRITICAL`.
- `analyze_internal_service(response, baseline, target_info) -> Optional[Dict[str, Any]]`:
  - Scans body against `INTERNAL_SERVICE_SIGNATURES`.
  - Rejects baseline echoes.
  - Returns structured finding dict with `technique="internal_service"`, `template_id=f"ssrf_internal_{service}"`, `severity=Severity.CRITICAL` (for admin/DB) or `Severity.HIGH` (for Redis/memcached).
- `analyze_differential_timing(injected_resp, baseline_resp, threshold=4.0) -> Optional[Dict[str, Any]]`:
  - Checks latency delta $\Delta T = \text{injected\_elapsed} - \text{baseline\_elapsed} \ge 4.0\text{s}$.
  - Returns structured finding dict with `technique="differential_timing"`, `template_id="ssrf_timing_blind"`, `severity=Severity.HIGH`.

#### E. SSRF Collector (`SSRFCollector(BaseCollector)`)
- Inherits `BaseCollector`.
- `_extract_candidate_endpoints(raw_mission)`: Extracts candidate endpoints and seeds common fetch/webhook/proxy routes (`/webhook`, `/fetch`, `/proxy`, `/download`, `/preview`, `/api/fetch`, `/api/proxy`, `/api/webhook`, `/import`, `/url`, `/load`, `/feed`) with default SSRF parameters (`url`, `target`, `dest`, `uri`, `webhook`, `feed`, `link`, `src`, `source`, `redirect`, `load`, `fetch`, `domain`, `host`, `path`, `data`, `proxy`, `endpoint`, `callback`).
- `collect(mission) -> List[Evidence]`:
  - Fuzzes GET query parameters.
  - Fuzzes POST body fields (JSON & form-urlencoded).
  - Fuzzes RESTful path segments.
  - Fuzzes HTTP request headers (`Referer`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL`).
  - Calls `_create_evidence_and_update_state` to add to `mission.evidence`, `mission.vulnerabilities`, and expand `mission.attack_surface_graph` with `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges.
- `execute(mission) -> List[Evidence]`: Delegates to `self.collect(mission)`.

---

## 5. Verification Method

To independently verify the implementation and findings:

### 5.1 Verification Commands
1. **Run Full Test Suite (Zero Regression Check)**:
   ```bash
   python -m pytest tests/ --ignore=tests/workspace -x -q
   ```
   *Success condition*: All 1071+ tests pass with exit code 0.

2. **Run New SSRF Unit & Adversarial Tests**:
   ```bash
   python -m pytest tests/collectors/test_ssrf.py tests/collectors/test_ssrf_adversarial.py -v
   ```
   *Success condition*: >= 50 tests across unit and adversarial suites pass with exit code 0.

3. **Verify Tool Registry & DAG Integration**:
   ```bash
   python -c "from argus.runtime.registry import registry; assert registry.get('ssrf') is not None; assert registry.get('ssrf_validator') is not None; print('ToolRegistry OK')"
   python -c "from argus.planning.task_generator import _RECON_TEMPLATES; assert 'ssrf' in _RECON_TEMPLATES; print('TaskGenerator OK')"
   python -c "from argus.collectors import SSRFCollector, SSRFAnalyzer, SSRFPayloadGenerator; print('Exports OK')"
   python -c "from argus.runtime.plugins import PluginExecutorAdapter; adapter = PluginExecutorAdapter(); assert adapter._instantiate_specialist_fallback('ssrf') is not None; print('Plugin adapter OK')"
   ```

### 5.2 Exact Files to Create & Modify

| Action | File Path | Scope & Responsibilities |
|---|---|---|
| **Create** | `argus/collectors/ssrf.py` | `SSRFCollector(BaseCollector)`, `SSRFPayloadGenerator`, `SSRFAnalyzer`, `SSRFResult`, `SSRFTechnique`, `SSRFCloudProvider`, `CLOUD_METADATA_SIGNATURES`, `INTERNAL_SERVICE_SIGNATURES`, `DEFAULT_SSRF_TARGETS`, `DEFAULT_SSRF_PROBE_ROUTES`, `COMMON_SSRF_PARAMS`. |
| **Create** | `tests/collectors/test_ssrf.py` | Comprehensive unit tests (>= 25 tests) covering payload generator (all 9 bypass mutations), analyzer (cloud metadata, internal services, differential timing, false positive rejection), collector fuzzing (GET query, POST json/form, headers, path, WAF bypass, ControlledMission, empty mission). |
| **Create** | `tests/collectors/test_ssrf_adversarial.py` | Adversarial and boundary tests (>= 25 tests) covering latency boundaries (3.99s vs 4.00s, high baseline traps), static documentation rejection, search echo reflection rejection, 404/500 page rejection, nested JSON fuzzing, complex header vectors, and multi-mutation filter bypasses. |
| **Modify** | `argus/collectors/__init__.py` | Export `SSRFCollector`, `SSRFPayloadGenerator`, `SSRFAnalyzer`, `SSRFResult`, `SSRFTechnique`, `SSRFCloudProvider` in `__all__`. |
| **Modify** | `argus/planning/task_generator.py` | Add `_RECON_TEMPLATES["ssrf"]` (`dependencies=["Discover API Endpoints"]`, `category=TaskCategory.EVIDENCE_CORRELATION`, `metadata={"tool_id": "ssrf"}`), wire keyword matching in `_resolve_template_for_gap`, bind endpoints in `from_gaps`. |
| **Modify** | `argus/runtime/registry.py` | Add alias mappings (`"ssrf_validator": "ssrf"`, `"ssrf_collector": "ssrf"`, `"server_side_request_forgery": "ssrf"`) and register `Tool(id="ssrf", name="SSRF Validation Collector", capability="ssrf_detector", ...)` with `priority=95`. |
| **Modify** | `argus/runtime/plugins.py` | Add `"ssrf"` handler to `_instantiate_specialist_fallback` returning `SSRFCollector()`. |
| **Modify** | `argus/graph/attack_surface.py` | Add section 14 in `AttackSurfaceGraphBuilder.build_from_evidence` for `category in ("ssrf", "server_side_request_forgery", "ssrf_validation")`, creating `live_host`, `endpoint`, `vulnerability` nodes and `HAS_VULNERABILITY` edges. |
