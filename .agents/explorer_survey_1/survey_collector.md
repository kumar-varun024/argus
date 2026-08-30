# Sprint 5 Architecture Survey: Collector System, Registry & HTTP Probing

## Executive Summary
This survey provides a comprehensive architectural analysis of ARGUS's collector framework, runtime registry, HTTP client capabilities, and graph connectivity models to prepare for the design and implementation of Sprint 5: **Information Disclosure Engine** (`InformationDisclosureCollector`).

---

## 1. Collector Architecture (`argus/collectors/`)

### 1.1 Base Collector Definition
All collectors inherit from the abstract base class `BaseCollector` defined in `argus/collectors/base.py`:

```python
# argus/collectors/base.py
from abc import ABC, abstractmethod

class BaseCollector(ABC):

    @abstractmethod
    def collect(self, mission):
        """Collect information and update the mission."""
        pass
```

### 1.2 Execution Model & Method Signatures
- **Method Signature**: `collect(self, mission: Any) -> Optional[List[Evidence]]`
- **Execution Paradigm**: Synchronous (`def collect`), invoked sequentially during reconnaissance (e.g. by `ReconAgent.execute(mission)` in `argus/agents/recon.py` or via runtime task dispatchers).
- **Constructor Injection**: Recent advanced collectors like `SubdomainTakeoverCollector` (`argus/collectors/takeover.py`) accept optional injected tools and clients:
  ```python
  def __init__(
      self,
      dns_tool: Optional[DNSXTool] = None,
      signatures: Optional[List[TakeoverSignature]] = None,
      runtime: Optional[LocalRuntime] = None,
      http_client: Optional[Any] = None,
  ):
  ```
  This pattern enables seamless unit and integration testing via mock injection without spawning live network operations.

### 1.3 Survey of Existing Collectors
| Collector Class | Source File | Inputs Read from Mission | Outputs Produced & Mission Mutated |
|---|---|---|---|
| `SubfinderCollector` | `argus/collectors/subfinder.py` | `mission.target` | `mission.subdomains` |
| `HttpxCollector` | `argus/collectors/httpx.py` | `mission.subdomains` | `mission.live_hosts` |
| `KatanaCollector` | `argus/collectors/katana.py` | `mission.live_hosts` | `mission.endpoints` |
| `JavaScriptCollector` | `argus/collectors/javascript.py` | `mission.live_hosts` | `mission.javascript`, `mission.apis`, `mission.evidence`, `mission.findings` |
| `NucleiCollector` | `argus/collectors/nuclei.py` | `mission.live_hosts` | `mission.notes` / `mission.vulnerabilities` |
| `TechnologyCollector` | `argus/collectors/technology.py` | `mission.live_hosts` | `mission.evidence` (`category="technology"`) |
| `SubdomainTakeoverCollector` | `argus/collectors/takeover.py` | `mission.subdomains`, `mission.target` | `mission.evidence` (`category="subdomain_takeover"`), `mission.vulnerabilities`, `mission.attack_surface_graph` / `mission.graph` (`Node`, `Edge`) |

---

## 2. Runtime Registry & Tool Management (`argus/runtime/registry.py`)

### 2.1 Registry Pattern
`argus/runtime/registry.py` defines `ToolRegistry` and exposes a singleton instance `registry = ToolRegistry()`.
- **Tool Storage**: `self.tools: Dict[str, Tool] = {}`
- **Registration**: `registry.register(tool: Tool)`
- **Lookup**: `registry.get(key: str) -> Optional[Tool]` (supports both tool ID and capability names).
- **Capability Discovery**: `registry.find_compatible_tools(task_category: str) -> List[Tool]` sorts matches deterministically by `(-t.priority, t.id)`.

### 2.2 Tool Schema (`argus/runtime/models.py:Tool`)
```python
class Tool(BaseModel):
    id: str = ""
    name: str
    version: str = "1.0.0"
    description: str = ""
    supported_tasks: List[str] = Field(default_factory=list)
    required_inputs: List[str] = Field(default_factory=list)
    produced_outputs: List[str] = Field(default_factory=list)
    capabilities: List[str] = Field(default_factory=list)
    safety_requirements: Dict[str, Any] = Field(default_factory=dict)
    timeout: float = 300.0
    priority: int = 100
    command: Optional[str] = None
    capability: Optional[str] = None
```

### 2.3 Dispatch & Execution Pipeline
- `ToolDispatcher` (`argus/runtime/dispatcher.py`) maps `task.metadata["tool_id"]` or `task.category` to registered `Tool` instances.
- If `tool.safety_requirements["type"] == ToolType.INTERNAL` (or tool ID ends with `"specialist"` / internal), `InternalPluginExecutor` (`argus/runtime/executor.py`) invokes the component.
- External tools run through `ExternalToolExecutor` inside a sandboxed subprocess.
- For `InformationDisclosureCollector`:
  - Register as `Tool` in `argus/runtime/registry.py` with:
    - `id="information_disclosure"` (or `"information_disclosure_collector"` / `"information_disclosure_specialist"`)
    - `capability="information_disclosure_detector"`
    - `supported_tasks=["Information Disclosure Detection", "Vulnerability Scanning", "Evidence Correlation"]`
    - `required_inputs=["live_hosts", "endpoints", "subdomains"]`
    - `produced_outputs=["vulnerabilities", "evidence", "subdomains"]`
    - `safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]}`

---

## 3. HTTP Probing with `AuthenticatedHttpClient` (`argus/http/client.py`)

### 3.1 Class Hierarchy and Initialization
`AuthenticatedHttpClient` extends `AuthorizedHttpClient` and wraps a persistent `httpx.Client`:

```python
class AuthenticatedHttpClient(AuthorizedHttpClient):
    def __init__(
        self,
        identity: Optional[TestIdentity] = None,
        proxy: Optional[str] = None,
        verify_ssl: bool = False,
        timeout: float = 10.0,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        follow_redirects: bool = True,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ):
```

### 3.2 Features & Capabilities
1. **Synchronous Execution**: Uses `httpx.Client` for synchronous HTTP/1.1 and HTTP/2 network operations (it does not use `aiohttp` or `httpx.AsyncClient`).
2. **Context Management**: Supports `with AuthenticatedHttpClient(...) as client:` ensuring connection teardown on exit.
3. **Mission Scope Enforcement**: Before every request, `ScopeResolver.check_scope(url, mission.id)` is evaluated. If out of scope (`ScopeState.OUT_OF_SCOPE`), the request is blocked and returns `HttpResponse(success=False, error="Blocked by scope: ...")`.
4. **Authorization Gating**: Checks `authorization_gate.can_execute_action(user_id, action, url, mission.id)`.
5. **Credential & Identity Injection**: Automatically retrieves auth headers and cookies from `self.identity` or `mission.get_active_identity()`.
6. **Retry & Backoff**: Automatically handles `httpx.TimeoutException` and `httpx.RequestError` with configurable `max_retries` and exponential backoff (`backoff_factor * (2 ** attempt)`).
7. **Redaction & Sanitization**: Strips sensitive headers (Authorization, Cookies, API Keys) in logs and metadata while preserving network payloads.
8. **Response Model (`HttpResponse`)**:
   - `success: bool`
   - `status_code: Optional[int]`
   - `headers: Dict[str, str]`
   - `body: Optional[str]`
   - `raw_body: Optional[str]`
   - `url: str`
   - `elapsed: float`
   - `error: Optional[str]`
   - `scope_decision`, `authorization_decision`
9. **Convenience Methods**: `get(mission, url, **kwargs)`, `post(mission, url, **kwargs)`, `put(...)`, `head(...)`, etc.

---

## 4. Input/Output Models & Graph Connectivity

### 4.1 Collector Inputs
Collectors consume structured assets from the `Mission` instance:
- `mission.target` (`str`): Base target domain/IP.
- `mission.subdomains` (`list[str]` or `list[dict]`): Discovered subdomains.
- `mission.live_hosts` (`list[dict]`): Live HTTP hosts with `url`, `host`, `technologies`, `status_code`.
- `mission.endpoints` (`list[dict]`): Endpoints with `url`, `path`, `host`, `method`.
- `mission.scope` (`list[str]`): Allowed scope rules.

### 4.2 Collector Outputs
1. **Evidence Emission (`argus.evidence.model.Evidence`)**:
   ```python
   ev = Evidence(
       mission_id=getattr(mission, "id", ""),
       source_type="LOG",
       created_by="SYSTEM_GENERATED",
       title=f"Information Disclosure: {path} on {base_url}",
       description=f"Exposed {path} discovered containing sensitive data",
       category="information_disclosure",
       value=target_url,
       source=target_url,
       status="CONFIRMED",
       confidence=0.95,
       severity="high",
       metadata={
           "url": target_url,
           "path": path,
           "status_code": 200,
           "extracted_secrets": secrets,
           "extracted_domains": internal_domains,
           "category": "information_disclosure",
       }
   )
   mission.evidence.add(ev)
   ```
2. **Vulnerabilities (`mission.vulnerabilities`)**:
   Appends structured dictionaries:
   ```python
   mission.vulnerabilities.append({
       "name": f"Information Disclosure ({path})",
       "template_id": f"info-disclosure-{slug}",
       "severity": "high",
       "host": base_url,
       "url": target_url,
       "description": f"Exposed sensitive file {path}",
       "extracted_secrets": secrets,
   })
   ```
3. **Attack Surface Graph Expansion (`argus.graph.graph.KnowledgeGraph`)**:
   - `graph = getattr(mission, "attack_surface_graph", None) or getattr(mission, "graph", None)`
   - Create node for host/endpoint/vulnerability:
     - `Node(id=f"vulnerability:info-disclosure:{slug}:{base_url}", type="vulnerability", value=..., metadata=...)`
     - Connect: `graph.connect(host_id, vuln_id, edge_type="HAS_VULNERABILITY")`
   - **Graph Loop Feedback**: Discovered internal domains/hostnames from `.env`, `.git/config`, `phpinfo.php`, etc. are added back to:
     - `mission.subdomains` (if not already present)
     - `KnowledgeGraph` via `Node(id=f"subdomain:{new_domain}", type="subdomain", value=new_domain)`
     - Connected via `graph.connect(f"target:{target}", f"subdomain:{new_domain}", edge_type="RESOLVES_TO")` or `graph.connect(host_id, f"subdomain:{new_domain}", edge_type="REFERENCES_DOMAIN")`

---

## 5. DAG Integration (`argus/planning/task_generator.py`)

### 5.1 Recon Task Chain & Planning
In `argus/planning/task_generator.py`:
1. `TaskCategory`: Has categories including `TECHNOLOGY_DISCOVERY`, `API_DISCOVERY`, `EVIDENCE_CORRELATION`, etc.
2. `TaskGenerator.generate_recon_tasks()` currently defines:
   - `subfinder` -> `httpx` (depends on subfinder) -> `katana_crawler` (depends on httpx) -> `nuclei` (depends on httpx)
3. Adding Information Disclosure task:
   - Task Title: `"Probe Information Disclosure"`
   - Depends on: `"Fingerprint Live Hosts"` (or `"Discover API Endpoints"`)
   - Category: `TaskCategory.EVIDENCE_CORRELATION` (or dedicated task category)
   - `required_inputs=["live_hosts", "endpoints"]`
   - `expected_outputs=["vulnerabilities", "evidence", "subdomains"]`
   - `metadata={"tool_id": "information_disclosure"}`

---

## 6. Recommendations for Sprint 5 Implementation

1. **New Collector Module**: Create `argus/collectors/information_disclosure.py` implementing `InformationDisclosureCollector(BaseCollector)` with `__init__(self, http_client=None, wordlist=None, patterns=None)`.
2. **Export Collector**: Export `InformationDisclosureCollector` in `argus/collectors/__init__.py`.
3. **Register in Tool Registry**: Register `Tool(id="information_disclosure", ...)` in `argus/runtime/registry.py`.
4. **Define Wordlist & Regex Matchers**:
   - Wordlist: `.git/config`, `.env`, `phpinfo.php`, `.js.map`, `/actuator/env`, `/actuator/heapdump`.
   - Secret Extractors: AWS keys (`AKIA...`), JWT/Bearer tokens, Stripe keys (`sk_live_...`), Google API keys (`AIza...`), passwords (`DB_PASSWORD=...`), private keys (`-----BEGIN ... PRIVATE KEY-----`).
   - Hostname/Domain Extractors: Regex matching valid FQDNs / internal hostnames (e.g. `*.internal`, `*.corp`, `*.local`, `*.<target>`).
5. **Graph Feedback**: Add discovered subdomains to `mission.subdomains` and connect in `mission.attack_surface_graph` / `mission.graph`.
6. **TaskGenerator Integration**: Add template and chain step in `argus/planning/task_generator.py`.
7. **Comprehensive Testing**: Write unit tests, mock probing tests, secret parser tests, graph integration tests, and an end-to-end integration test mocking `.env` discovery.
