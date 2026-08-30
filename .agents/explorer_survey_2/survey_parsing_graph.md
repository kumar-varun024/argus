# Sprint 5 Architecture Survey: Parsing, Data Models & KnowledgeGraph Integration

**Date**: 2026-08-28  
**Author**: Explorer Survey Agent 2  
**Scope**: ARGUS Sprint 5 (Information Disclosure Engine - Phase 6 of Roadmap)

---

## 1. Executive Summary

This survey provides a comprehensive architectural analysis of the ARGUS platform to support the implementation of **Sprint 5: Information Disclosure Engine**. The investigation specifically covers:
1. The **`Evidence`** data model, its fields, lifecycle status, severity ratings, and canonical construction patterns.
2. Existing and required **secret extraction / regex patterns / wordlists** (API keys, JWTs, AWS credentials, database URLs, passwords, internal domains/IPs).
3. The **`KnowledgeGraph`** and **`Mission`** models, including node/edge ontology, entity storage, and graph builders.
4. The **attack surface feedback loop**, detailing how discoveries from collectors dynamically expand `mission.subdomains`, mutate `KnowledgeGraph`, and trigger downstream DAG recon tasks.

---

## 2. Focus Area 1: ARGUS Evidence & Core Data Models

### 2.1 Evidence Data Model Definition
`Evidence` is defined in `argus/evidence/model.py` (lines 25–57) as a Python dataclass using slots for performance:

```python
@dataclass(slots=True)
class Evidence:
    """Represents confirmed or reviewed research evidence."""
    evidence_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    project_id: str = ""
    mission_id: str = ""
    investigation_id: str = ""
    
    source_type: str = "SYSTEM" # e.g., SCREENSHOT, LOG, OBSERVATION
    source_id: str = ""
    created_by: str = "SYSTEM_GENERATED" # USER_PROVIDED, AI_DERIVED, SYSTEM_GENERATED
    
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    title: str = ""
    description: str = ""
    content_reference: str = ""
    
    category: str = "Other"
    value: str = "" # Primary value (URL, hostname, token, finding name)
    source: str = "" # Originating tool/source reference
    
    status: str = "UNVERIFIED" # UNVERIFIED, USER_REVIEWED, CORROBORATED, CONFIRMED, REJECTED, SUPERSEDED
    confidence: float = 1.0 # 0.0 to 1.0
    severity: str = "info"  # "info", "low", "medium", "high", "critical"
    
    provenance: ProvenanceData = field(default_factory=ProvenanceData)
    relationships: List[EvidenceRelationship] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
```

### 2.2 Supporting Models in `argus/evidence/model.py`
- **`ProvenanceData`**:
  ```python
  @dataclass
  class ProvenanceData:
      conversation_id: str = ""
      message_id: str = ""
      image_id: str = ""
      observation_id: str = ""
      original_ai_description: str = ""
      corrected_by_user: bool = False
      workflow_id: str = ""
      step_id: str = ""
  ```
- **`EvidenceRelationship`**:
  ```python
  @dataclass
  class EvidenceRelationship:
      relationship_type: str  # DERIVED_FROM, SUPPORTS, CONTRADICTS, SUPERSEDED_BY, SUPERSEDES
      target_id: str
      target_type: str        # 'hypothesis', 'evidence', 'observation'
  ```

### 2.3 `EvidenceStore` (`argus/evidence/store.py`)
`mission.evidence` is an instance of `EvidenceStore`:
- `add(evidence: Evidence)`: Appends evidence to internal list.
- `all()`: Returns list of all `Evidence` objects.
- `filter(category: str)`: Returns evidence matching the given category.
- `count()` / `__len__()`: Returns total evidence count.
- `clear()`: Clears items.
- Supports iteration (`for ev in mission.evidence:`).

### 2.4 Canonical Construction for Information Disclosure
When `InformationDisclosureCollector` identifies an exposed file (e.g. HTTP 200 on `.env` with extracted secrets and internal hostnames), the evidence object is constructed as follows:

```python
from argus.evidence.model import Evidence, ProvenanceData

evidence = Evidence(
    mission_id=getattr(mission, "id", ""),
    source_type="LOG",
    created_by="SYSTEM_GENERATED",
    title=f"Information Disclosure: {path} exposed on {host}",
    description=(
        f"Exposed file found at {target_url} (HTTP 200). "
        f"Extracted {len(extracted_secrets)} secret(s) and "
        f"{len(extracted_domains)} internal host(s)."
    ),
    category="information_disclosure",
    value=target_url,
    source=target_url,
    status="CONFIRMED",
    confidence=0.95,
    severity="high",
    provenance=ProvenanceData(
        step_id="information_disclosure_probe",
    ),
    tags=["information_disclosure", "sensitive_data", path.strip("/").replace("/", "_")],
    metadata={
        "url": target_url,
        "host": host,
        "path": path,
        "status_code": 200,
        "category": "information_disclosure",
        "severity": "high",
        "template_id": f"info-disclosure-{path.strip('/').replace('/', '-').replace('.', '')}",
        "secrets": [s.to_dict() if hasattr(s, "to_dict") else s for s in extracted_secrets],
        "internal_domains": list(extracted_domains),
        "secret_count": len(extracted_secrets),
        "domain_count": len(extracted_domains),
    },
)

# Ingestion into Mission
if hasattr(mission, "evidence") and mission.evidence is not None:
    if hasattr(mission.evidence, "add"):
        mission.evidence.add(evidence)
    elif isinstance(mission.evidence, list):
        mission.evidence.append(evidence)

if hasattr(mission, "vulnerabilities") and isinstance(mission.vulnerabilities, list):
    mission.vulnerabilities.append({
        "name": f"Information Disclosure ({path})",
        "template_id": evidence.metadata["template_id"],
        "severity": "high",
        "host": host,
        "url": target_url,
        "description": evidence.description,
        "secrets": evidence.metadata["secrets"],
        "internal_domains": evidence.metadata["internal_domains"],
    })
```

---

## 3. Focus Area 2: Secret Extraction & Artifact Parsing Architecture

### 3.1 Existing Patterns Across ARGUS
1. **`argus/analyzers/javascript.py` (lines 17–56)**:
   - Google API Key: `r"AIza[0-9A-Za-z\-_]{35}"`
   - Stripe Live Key: `r"sk_live_[0-9A-Za-z]+"`
   - AWS Access Key ID: `r"AKIA[0-9A-Z]{16}"`
   - GitHub PAT: `r"ghp_[A-Za-z0-9]{36}"`
   - JWT Keywords: `Bearer`, `access_token`, `refresh_token`, `Authorization`
   - Source Maps: `r"//# sourceMappingURL=(.+)"`
   - WebSockets: `r'wss?://[^"\']+'`
   - Route Regex: `r'["\'](/[a-zA-Z0-9_\-/]{2,})["\']'`
2. **`argus/runtime/observability.py` (lines 8–16)**:
   - JWT Pattern: `re.compile(r'bearer\s+[\w\-]+\.[\w\-]+\.[\w\-]+', re.IGNORECASE)`
   - API Key Pattern: `re.compile(r'api_?key[\s=:]+[\w\-]+', re.IGNORECASE)`
   - Password Pattern: `re.compile(r'password[\s=:]+[\w\-\.\!@#\$%\^&\*]+', re.IGNORECASE)`
   - Authorization: `re.compile(r'authorization[\s=:]+[\w\-]+', re.IGNORECASE)`
3. **`argus/http/client.py` (lines 17–35)**:
   - Sensitive Header Blacklist: `authorization`, `cookie`, `set-cookie`, `x-api-key`, `api-key`, `apikey`, `token`, `access-token`, `session`, `session-id`
   - Sensitive Param Regex: `re.compile(r'(api[_-]?key|token|bearer|access[_-]?token|refresh[_-]?token|pass|password|pwd|session[_-]?(id|token|key)?)=[^\&]+', re.IGNORECASE)`

### 3.2 High-Value Wordlists for Sprint 5 (Requirement R2)
The information disclosure engine requires probing high-impact files across all target hosts/subdomains:
1. `.git/config` — Git repository configuration containing remote origin URLs, credentials, and internal hostnames.
2. `.env` — Environment configuration containing API secrets, DB connection strings, and passwords.
3. `phpinfo.php` — PHP runtime environment disclosing server environment variables, OS details, internal IPs, and modules.
4. `.js.map` (or `<script>.map`) — JavaScript source maps revealing full frontend source code and comments.
5. `/actuator/env` — Spring Boot Actuator environment endpoint exposing system properties and sensitive configs.
6. `/actuator/heapdump` — Spring Boot Actuator heapdump endpoint providing binary memory dump.

### 3.3 Enhanced Secret Extraction Pattern Library
For Sprint 5, an extensible analyzer (`SecretExtractor` or `ArtifactParser`) should support the following comprehensive regex patterns:

| Secret Category | Regular Expression Pattern | Description |
|---|---|---|
| **AWS Access Key ID** | `\b((?:AKIA\|ABIA\|ACCA\|ASIA)[0-9A-Z]{16})\b` | AWS IAM / STS access key |
| **AWS Secret Access Key** | `(?i)(?:aws_secret_access_key\|aws_secret_key\|secret_key)\s*[:=]\s*['"]?([A-Za-z0-9\/+=]{40})['"]?` | AWS 40-character secret key |
| **JWT Token** | `\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b` | Compact serialized JSON Web Token |
| **Generic API Key** | `(?i)(?:api_key\|apikey\|client_secret\|app_secret\|api_secret\|access_token\|auth_token\|private_key)\s*[:=]\s*['"]?([a-zA-Z0-9_\-\.]{12,64})['"]?` | Key-value secret assignments |
| **Generic Password** | `(?i)(?:password\|passwd\|pwd\|db_pass\|database_password\|db_password\|secret)\s*[:=]\s*['"]?([^\s'"#]{4,64})['"]?` | Cleartext passwords |
| **Database Connection URI** | `\b(?:postgres\|postgresql\|mysql\|mongodb\|redis\|amqp\|mssql):\/\/(?:[a-zA-Z0-9_\-\.]+):(?:[^\s@]+)@(?:[a-zA-Z0-9_\-\.]+)(?::\d+)?(?:\/[a-zA-Z0-9_\-\.]*)?\b` | Full database connection strings |
| **Google API Key** | `\b(AIza[0-9A-Za-z\-_]{35})\b` | Google Cloud / Maps API Key |
| **Stripe Secret Key** | `\b(sk_live_[0-9a-zA-Z]{24,})\b` | Stripe production secret |
| **GitHub Token** | `\b((?:ghp_\|gho_\|ghu_\|ghs_\|ghr_)[A-Za-z0-9]{36})\b` | GitHub personal & OAuth tokens |
| **Slack Webhook / Token** | `https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}` | Slack incoming webhook |
| **Private IP (RFC 1918)** | `\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}\|172\.(?:1[6-9]\|2\d\|3[01])\.\d{1,3}\.\d{1,3}\|192\.168\.\d{1,3}\.\d{1,3})\b` | Internal network IP address |
| **Internal Domain Suffix** | `\b([a-zA-Z0-9_\-]+(?:\.[a-zA-Z0-9_\-]+)*\.(?:local\|internal\|corp\|lan\|intranet\|priv\|private\|cluster\.local))\b` | Internal intranet hostnames |

### 3.4 Parsing Workflow on HTTP 200
When an exposed file is fetched with `status_code == 200`:
1. Use `resp.raw_body` (unredacted HTTP response text) to ensure full secret visibility (avoiding client-side redaction).
2. For structured formats (`.env`, key-value configs), parse line-by-line using key-value splitting and regex matching.
3. For JSON formats (`/actuator/env`), recursively traverse keys and values for secrets and network addresses.
4. For `.git/config`, extract `url = https://...` or `git@...` to discover internal repository hosts and subdomains.
5. For all bodies, run domain & IP extraction matching internal patterns and subdomains of the target domain.

---

## 4. Focus Area 3: KnowledgeGraph & Attack Surface Models

### 4.1 KnowledgeGraph Architecture (`argus/graph/`)
The ARGUS graph ontology consists of:
- **`KnowledgeGraph`** (`argus/graph/graph.py`):
  - `nodes: dict[str, Node]`
  - `edges: list[Edge]`
  - Query methods: `get(id)`, `nodes_by_type(type)`, `edges_from(node)`, `edges_to(node)`, `neighbors(node)`, `get_host_for_node(node)`, `are_connected(id1, id2)`, `get_connected_endpoints(host_node)`.
- **`Node`** (`argus/graph/node.py`):
  - `id: str` (e.g. `subdomain:api.target.com`, `endpoint:https://target.com/.env`, `vulnerability:info-disclosure-env:https://target.com/.env`)
  - `type: str` (e.g. `"target"`, `"subdomain"`, `"live_host"`, `"endpoint"`, `"technology"`, `"vulnerability"`, `"cname"`, `"secret"`)
  - `value: str`
  - `metadata: dict[str, Any]`
- **`Edge`** (`argus/graph/edge.py`):
  - `source: str` (Node ID)
  - `target: str` (Node ID)
  - `type: str` (Edge relationship)
  - `metadata: dict[str, Any]`

### 4.2 Standard Node and Edge Types

| Node Type | ID Format | Value | Metadata Fields |
|---|---|---|---|
| `target` | `target:{target}` | `{target}` | `{"target": target}` |
| `subdomain` | `subdomain:{hostname}` | `{hostname}` | `{"hostname": hostname, "source": source}` |
| `live_host` | `live_host:{url_or_host}` | `{url_or_host}` | `{"url": url, "host": host, "technologies": [...]}` |
| `endpoint` | `endpoint:{url}` | `{url}` | `{"url": url, "host": host, "status_code": 200}` |
| `vulnerability` | `vulnerability:{template_id}:{url}` | `{vuln_title}` | `{"template_id": ..., "severity": ..., "url": ...}` |
| `secret` | `secret:{type}:{hash_or_preview}` | `{masked_secret}` | `{"secret_type": ..., "key": ..., "source_url": ...}` |
| `cname` | `cname:{cname}` | `{cname}` | `{"cname": cname, "service": service}` |
| `technology` | `technology:{name}` | `{name}` | `{"name": name}` |

| Edge Type | Source Node Type | Target Node Type | Meaning |
|---|---|---|---|
| `RESOLVES_TO` | `target` | `subdomain` | Target encompasses subdomain |
| `HOSTS` | `subdomain` | `live_host` | Subdomain resolves to live host URL |
| `HAS_ENDPOINT` | `live_host` | `endpoint` | Live host contains exposed endpoint |
| `HAS_VULNERABILITY` | `live_host` / `endpoint` / `subdomain` | `vulnerability` | Asset possesses vulnerability |
| `POINTS_TO_CNAME` | `subdomain` | `cname` | Subdomain points to external CNAME |
| `EXPOSES_SECRET` | `vulnerability` / `endpoint` | `secret` | Vulnerability leaks sensitive secret |
| `DISCLOSED_SUBDOMAIN` | `vulnerability` / `endpoint` | `subdomain` | Leaked file reveals new subdomain |
| `RUNS_TECHNOLOGY` | `live_host` | `technology` | Live host runs software technology |

### 4.3 Graph Builder Pipeline (`AttackSurfaceGraphBuilder`)
In `argus/graph/attack_surface.py`:
- `build(mission)`: Reads `mission.evidence` via `build_from_evidence()` and ingests `mission.subdomains`, `mission.live_hosts`, `mission.endpoints`, `mission.vulnerabilities`.
- It dynamically links:
  - `target` $\rightarrow$ `subdomain` via `RESOLVES_TO`
  - `subdomain` $\rightarrow$ `live_host` via `HOSTS`
  - `live_host` $\rightarrow$ `endpoint` via `HAS_ENDPOINT`
  - `live_host` / `subdomain` $\rightarrow$ `vulnerability` via `HAS_VULNERABILITY`
  - `subdomain` $\rightarrow$ `cname` via `POINTS_TO_CNAME`

---

## 5. Focus Area 4: Attack Surface Expansion Feedback Loop

### 5.1 The Expansion Mechanism
When `InformationDisclosureCollector` extracts internal domains or subdomains from response bodies (e.g. from `.env` or `/actuator/env`), it performs a **dual-path synchronization**:

```
                                  [ Exposed File: HTTP 200 ]
                                              │
                                              ▼
                                   [ Secret / Domain Parser ]
                                              │
                    ┌─────────────────────────┴────────────────────────┐
                    ▼                                                  ▼
      [ Discovered Internal Subdomains ]                     [ Discovered Secrets ]
                    │                                                  │
       ┌────────────┴────────────┐                                     │
       ▼                         ▼                                     │
[ mission.subdomains ]   [ KnowledgeGraph ]                            ▼
(append new strings)     (add Node & Edges)                 [ Evidence Model ]
       │                         │                     (category="information_disclosure")
       │                         │                                     │
       └────────────┬────────────┘                                     │
                    ▼                                                  ▼
          [ EvidenceStore ] ─────────────────────────────────► [ mission.vulnerabilities ]
   (category="subdomain", value=domain)                                │
                    │                                                  │
                    ▼                                                  ▼
       [ Attack Surface Expanded ]                           [ Correlation & Hypotheses ]
```

### 5.2 Concrete Collector Implementation Pattern
Inside `InformationDisclosureCollector.collect(mission)`:
```python
# 1. Probe candidate URLs using AuthenticatedHttpClient
client = self.http_client or AuthenticatedHttpClient()
for base_url in candidate_targets:
    for word in WORDLIST:
        target_url = urllib.parse.urljoin(base_url.rstrip("/") + "/", word.lstrip("/"))
        resp = client.get(mission, target_url, timeout=5.0)
        
        if resp.success and resp.status_code == 200:
            raw_text = resp.raw_body or resp.body or ""
            
            # 2. Extract Secrets and Hostnames
            secrets, internal_domains = self.parser.parse(raw_text, target_url, target_domain=mission.target)
            
            # 3. Emit Information Disclosure Evidence
            info_ev = Evidence(
                mission_id=getattr(mission, "id", ""),
                category="information_disclosure",
                severity="high",
                title=f"Information Disclosure: {word} on {base_url}",
                description=f"Exposed file {target_url} revealed {len(secrets)} secrets and {len(internal_domains)} internal domains.",
                value=target_url,
                source=target_url,
                status="CONFIRMED",
                confidence=0.95,
                metadata={
                    "url": target_url,
                    "path": word,
                    "status_code": 200,
                    "secrets": secrets,
                    "internal_domains": internal_domains,
                }
            )
            mission.evidence.add(info_ev)
            mission.vulnerabilities.append({
                "name": f"Information Disclosure ({word})",
                "template_id": f"info-disclosure-{word.strip('/').replace('/', '-')}",
                "severity": "high",
                "url": target_url,
                "host": base_url,
                "secrets": secrets,
                "internal_domains": internal_domains,
            })
            
            # 4. Feed newly discovered subdomains into mission.subdomains
            current_subs = set(
                s.get("hostname") if isinstance(s, dict) else str(s)
                for s in (mission.subdomains or [])
            )
            
            for domain in internal_domains:
                if domain not in current_subs:
                    mission.subdomains.append(domain)
                    current_subs.add(domain)
                    
                    # Emit subdomain Evidence for downstream consumers
                    sub_ev = Evidence(
                        mission_id=getattr(mission, "id", ""),
                        category="subdomain",
                        value=domain,
                        source=target_url,
                        description=f"Discovered subdomain {domain} disclosed in {target_url}",
                        metadata={"source": target_url, "hostname": domain, "discovered_by": "information_disclosure"},
                    )
                    mission.evidence.add(sub_ev)
            
            # 5. Direct KnowledgeGraph Updates
            graph = getattr(mission, "attack_surface_graph", None) or getattr(mission, "graph", None)
            if graph is not None:
                ep_id = f"endpoint:{target_url}"
                vuln_id = f"vulnerability:info-disclosure-{word.strip('/').replace('/', '-')}:{target_url}"
                
                graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": 200}))
                graph.add(Node(id=vuln_id, type="vulnerability", value=f"Information Disclosure ({word})", metadata=info_ev.metadata))
                graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")
                
                for domain in internal_domains:
                    sub_id = f"subdomain:{domain}"
                    graph.add(Node(id=sub_id, type="subdomain", value=domain, metadata={"hostname": domain, "source": target_url}))
                    graph.connect(vuln_id, sub_id, edge_type="DISCLOSED_SUBDOMAIN")
                    if getattr(mission, "target", None):
                        graph.connect(f"target:{mission.target}", sub_id, edge_type="RESOLVES_TO")
```

### 5.3 DAG Integration in `TaskGenerator` & `ResearchPlanner`
To wire Information Disclosure into the autonomous research loop:
1. In `argus/runtime/registry.py`:
   - Register `information_disclosure_collector` (or `info_disclosure` tool):
     ```python
     registry.register(
         Tool(
             id="info_disclosure",
             name="Information Disclosure Prober",
             capability="information_disclosure_detector",
             description="Actively probes live hosts and endpoints for exposed configuration files, .env, .git, and actuator endpoints.",
             supported_tasks=["Information Disclosure", "Vulnerability Scanning", "Evidence Correlation"],
             required_inputs=["live_hosts", "endpoints"],
             produced_outputs=["vulnerabilities", "observations", "subdomains"],
             capabilities=["information_disclosure_detector"],
             safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
             timeout=300.0,
             priority=95,
         )
     )
     ```
2. In `argus/planning/task_generator.py`:
   - Add `TaskCategory.INFORMATION_DISCLOSURE` (or map to `VULNERABILITY_ASSESSMENT` / `EVIDENCE_CORRELATION`).
   - Add `info_disclosure` task template to `_RECON_TEMPLATES` with dependencies on `Fingerprint Live Hosts`:
     ```python
     "info_disclosure": {
         "title": "Probe Information Disclosure",
         "goal": "Probe endpoints and live hosts for high-value exposed files (.env, .git, phpinfo, actuators) and extract leaked secrets/hostnames.",
         "category": TaskCategory.EVIDENCE_CORRELATION, # or INFORMATION_DISCLOSURE
         "required_inputs": ["live_hosts"],
         "expected_outputs": ["vulnerabilities", "observations", "subdomains"],
         "dependencies": ["Fingerprint Live Hosts"],
         "required_specialists": [],
         "metadata": {"tool_id": "info_disclosure"},
         "estimated_duration_minutes": 5,
         "priority": 0.88,
     }
     ```
   - In `generate_recon_tasks()`, append the `info_disclosure` task after live host fingerprinting and endpoint crawling.

---

## 6. Synthesis & Architecture Recommendations for Sprint 5

### Component Map

| Component | Target Location | Purpose & Responsibility |
|---|---|---|
| `InformationDisclosureCollector` | `argus/collectors/information_disclosure.py` | Inherits `BaseCollector`, iterates subdomains/hosts, requests wordlist paths via `AuthenticatedHttpClient`, parses responses, creates `Evidence(category="information_disclosure", severity="high")`, updates `mission.vulnerabilities` and `mission.subdomains`, connects `KnowledgeGraph` nodes. |
| `SecretExtractor` / `ArtifactParser` | `argus/analyzers/secret_extractor.py` (or `recon/`) | Parses raw response bodies for API keys, AWS keys, JWTs, DB URLs, passwords, private IPs, and internal domains. |
| `ToolRegistry` Entry | `argus/runtime/registry.py` | Registers `info_disclosure` with capability `information_disclosure_detector` and supported tasks. |
| `TaskGenerator` Integration | `argus/planning/task_generator.py` | Generates `Probe Information Disclosure` task dependent on `Fingerprint Live Hosts`. |
| `AttackSurfaceGraphBuilder` | `argus/graph/attack_surface.py` | Ingests `Evidence(category="information_disclosure")` to create `vulnerability` nodes and link `DISCLOSED_SUBDOMAIN` / `EXPOSES_SECRET` edges. |
| Unit & Integration Tests | `tests/test_information_disclosure.py` | $\ge 10$ comprehensive test cases validating secret parsing, HTTP mocking, Evidence generation, graph feedback loops, and E2E `.env` scenario. |

---

## 7. Conclusion

The ARGUS architecture is structured with modular interfaces (`BaseCollector`, `EvidenceStore`, `KnowledgeGraph`, `AuthenticatedHttpClient`, and `TaskGenerator`) that cleanly accommodate the Information Disclosure Engine. By following the existing patterns established in `SubdomainTakeoverCollector` and `AttackSurfaceGraphBuilder`, the implementation can achieve full feature parity, robust graph expansion, and zero regression across the existing test suite.
