# Handoff Report: Graph & Evidence Subsystems Architecture for Sprint 2

## 1. Observation

### 1.1 Knowledge Graph Architecture (`argus/graph/`)
Direct observation of the graph subsystem files reveals the following structure:

- **`argus/graph/node.py` (lines 4–19)**:
  ```python
  @dataclass(slots=True)
  class Node:
      id: str
      type: str
      value: str
      metadata: dict[str, Any] = field(default_factory=dict)
  ```
  - Slotted dataclass.
  - Node identity is determined by `id: str`.
  - Classification is determined by `type: str`.
  - Value holds the string representation (`value: str`).
  - Contextual attributes are stored in `metadata: dict[str, Any]`.

- **`argus/graph/edge.py` (lines 4–19)**:
  ```python
  @dataclass(slots=True)
  class Edge:
      source: str
      target: str
      type: str
      metadata: dict[str, Any] = field(default_factory=dict)
  ```
  - Slotted dataclass representing a directed relationship from `source` node ID to `target` node ID.
  - `type: str` holds the edge label (e.g. `RESOLVES_TO`, `HOSTS`, `HAS_ENDPOINT`, `RUNS_TECHNOLOGY`, `HAS_VULNERABILITY`).

- **`argus/graph/graph.py` (lines 6–165)**:
  - `KnowledgeGraph` manages nodes in `self.nodes: dict[str, Node]` and edges in `self.edges: list[Edge]`.
  - **Node Deduplication (lines 28–31)**:
    ```python
    if node.id in self.nodes:
        return False
    self.nodes[node.id] = node
    return True
    ```
    `add(node)` rejects duplicate node IDs, preserving first-inserted node integrity.
  - **Edge Deduplication (lines 58–67)**:
    ```python
    if source not in self.nodes or target not in self.nodes:
        return False
    for edge in self.edges:
        if edge.source == source and edge.target == target and edge.type == edge_type:
            return False
    new_edge = Edge(source=source, target=target, type=edge_type, metadata=metadata or {})
    self.edges.append(new_edge)
    return True
    ```
    `connect(source, target, edge_type, metadata)` requires both endpoints to exist and enforces uniqueness of the `(source, target, type)` triplet.
  - **Query & Traversal API**:
    - `get(node_id: str) -> Optional[Node]`
    - `all() -> list[Node]`
    - `node_count() -> int` / `edge_count() -> int`
    - `nodes_by_type(node_type: str) -> list[Node]`
    - `edges_from(node: Node) -> list[Edge]` (outgoing edges)
    - `edges_to(node: Node) -> list[Edge]` (incoming edges)
    - `neighbors(node: Node) -> list[Node]` (all connected adjacent nodes)
    - `summary() -> dict[str, int]` (counts by node type and total relationships)

- **Legacy Builder `argus/graph/builder.py` (lines 1–129)**:
  - Currently contains `KnowledgeGraphBuilder`, which maps legacy business objects, endpoints, and authentication entities.
  - It does NOT map the full typed recon hierarchy required for Sprint 2 (`target` -> `subdomain` -> `live_host` -> `endpoint` / `technology` / `vulnerability` with typed relationships `RESOLVES_TO`, `HOSTS`, `HAS_ENDPOINT`, `RUNS_TECHNOLOGY`, `HAS_VULNERABILITY`).

---

### 1.2 Evidence Subsystem Architecture (`argus/evidence/`)
- **`argus/evidence/model.py` (lines 25–56)**:
  ```python
  @dataclass(slots=True)
  class Evidence:
      evidence_id: str = field(default_factory=lambda: str(uuid.uuid4()))
      project_id: str = ""
      mission_id: str = ""
      investigation_id: str = ""
      source_type: str = "SYSTEM"
      source_id: str = ""
      created_by: str = "SYSTEM_GENERATED"
      created_at: str = ...
      updated_at: str = ...
      title: str = ""
      description: str = ""
      content_reference: str = ""
      category: str = "Other"
      value: str = ""
      source: str = ""
      status: str = "UNVERIFIED"
      confidence: float = 1.0
      severity: str = "info"
      provenance: ProvenanceData = field(default_factory=ProvenanceData)
      relationships: List[EvidenceRelationship] = field(default_factory=list)
      tags: List[str] = field(default_factory=list)
      metadata: Dict[str, Any] = field(default_factory=dict)
  ```
- **`argus/evidence/store.py` (lines 4–37)**:
  - `EvidenceStore` holds an in-memory collection `self._items: list[Evidence]`.
  - Methods: `add(evidence)`, `all() -> list[Evidence]`, `filter(category: str) -> list[Evidence]`, `count() -> int`, `clear()`, `__iter__()`, `__len__()`.

---

### 1.3 How Tools Populate Evidence (`argus/runtime/executor.py`)
Investigation of `ExternalToolExecutor.execute()` (lines 234–353) demonstrates how the 4 normalized recon tools populate `EvidenceStore` and `Mission`:

1. **Subfinder (`tool.id == "subfinder"`)**:
   - Emits `Evidence`:
     - `category="subdomain"`
     - `value=hostname` (e.g. `"api.example.com"`)
     - `source="subfinder"`
     - `description=f"Discovered subdomain {hostname} for target {target}"`
     - `metadata={"source": "subfinder", "hostname": hostname}`
   - Updates `mission.subdomains: list[str]`.

2. **HTTPX (`tool.id == "httpx"`)**:
   - Emits `Evidence` (Live Host):
     - `category="live_host"`
     - `value=host_val` (e.g. `"http://api.example.com"` or `h.get("url")`)
     - `source="httpx"`
     - `description=f"Discovered live host {h.get('url') or host_val}"`
     - `metadata=h` (schema: `url`, `scheme`, `host`, `port`, `status`, `title`, `server`, `technologies`)
   - Emits `Evidence` (Technology - per detected tech in `h.get("technologies", [])`):
     - `category="technology"`
     - `value=tech` (e.g. `"nginx"`, `"React"`)
     - `source="httpx"`
     - `description=f"Detected technology {tech} on {h.get('url') or target}"`
     - `metadata={"name": tech, "host": h.get("host"), "url": h.get("url"), "source": "httpx"}`
   - Updates `mission.live_hosts: list[dict]` and `mission.technologies: list[str]`.

3. **Katana (`tool.id == "katana_crawler"` or `"katana" in tool.id`)**:
   - Emits `Evidence`:
     - `category="endpoint"`
     - `value=url_val` (e.g. `"http://api.example.com/v1/users"`)
     - `source="katana"`
     - `description=f"Discovered endpoint {url_val}"`
     - `metadata=ep` (schema: `url`, `path`, `host`, `method`, `params`)
   - Extends `mission.endpoints: list[dict]`.

4. **Nuclei (`tool.id == "nuclei"`)**:
   - Emits `Evidence`:
     - `category="vulnerability"`
     - `value=name_val` (e.g. `"Example CVE"` or `vuln.get("name") or vuln.get("template_id")`)
     - `source="nuclei"`
     - `severity=sev_val.lower()` (`info`, `low`, `medium`, `high`, `critical`)
     - `description=vuln.get("description", "") or name_val`
     - `metadata=vuln` (schema: `template_id`, `name`, `severity`, `host`, `matched_at`, `description`, `tags`, `extracted_results`)
   - Extends `mission.vulnerabilities: list[dict]`.

---

## 2. Logic Chain

1. **Premise 1: Attack-Surface Hierarchy & Relational Semantics**
   - The attack surface follows a 5-level directed acyclic graph hierarchy:
     $$\text{Target} \xrightarrow{\text{RESOLVES\_TO}} \text{Subdomain} \xrightarrow{\text{HOSTS}} \text{LiveHost} \begin{cases} \xrightarrow{\text{HAS\_ENDPOINT}} \text{Endpoint} \\ \xrightarrow{\text{RUNS\_TECHNOLOGY}} \text{Technology} \\ \xrightarrow{\text{HAS\_VULNERABILITY}} \text{Vulnerability} \end{cases}$$
   - Every node must be strongly typed with lowercase types (`target`, `subdomain`, `live_host`, `endpoint`, `technology`, `vulnerability`) to satisfy Sprint 2 criteria (`graph.nodes_by_type("subdomain")`, etc.).

2. **Premise 2: Deterministic Node ID Conventions & Properties**
   - Because `KnowledgeGraph.add()` and `KnowledgeGraph.connect()` are inherently idempotent based on unique node IDs and unique `(source, target, edge_type)` tuples, node IDs must be deterministic canonical keys:
     - **Target**: `id = f"target:{target}"`, `type = "target"`, `value = target`, `metadata = {"target": target}`
     - **Subdomain**: `id = f"subdomain:{hostname.lower()}"`, `type = "subdomain"`, `value = hostname`, `metadata = {"hostname": hostname, "source": source, ...}`
     - **Live Host**: `id = f"live_host:{url.rstrip('/')}"`, `type = "live_host"`, `value = url`, `metadata = {"url": url, "scheme": scheme, "host": host, "port": port, "status": status, "title": title, "server": server, "technologies": [...]}`
     - **Endpoint**: `id = f"endpoint:{url}"` (or `f"endpoint:{method.upper()}:{url}"` when method is differentiated), `type = "endpoint"`, `value = url`, `metadata = {"url": url, "path": path, "host": host, "method": method, "params": params}`
     - **Technology**: `id = f"technology:{name.lower()}"`, `type = "technology"`, `value = name`, `metadata = {"name": name}`
     - **Vulnerability**: `id = f"vulnerability:{template_id}:{matched_at}"` (or `f"vulnerability:{template_id}"` / `f"vulnerability:{name}"` if template_id is unique per host), `type = "vulnerability"`, `value = name or template_id`, `metadata = {"template_id": template_id, "name": name, "severity": severity, "host": host, "matched_at": matched_at, ...}`

3. **Premise 3: Edge Connection Logic**
   - **`RESOLVES_TO` (`target` → `subdomain`)**:
     - Connects `target:{target}` to `subdomain:{hostname}` for every discovered subdomain.
     - Fallback: If no subdomains discovered, connects `target:{target}` to `subdomain:{target}`.
   - **`HOSTS` (`subdomain` → `live_host`)**:
     - Live host hostname is parsed via `urllib.parse.urlparse(host_url).hostname` or `host_dict.get("host")`.
     - Subdomain node `subdomain:{hostname}` is resolved or created on-the-fly and linked to `target:{target}`.
     - Connects `subdomain:{hostname}` to `live_host:{host_url}`.
   - **`HAS_ENDPOINT` (`live_host` → `endpoint`)**:
     - Endpoint host is extracted from `ep_dict.get("host")` or `urllib.parse.urlparse(ep_url).hostname`.
     - Endpoint matched to candidate live host node whose `host` attribute or base URL matches the endpoint host/port.
     - Connects `live_host:{host_url}` to `endpoint:{ep_url}`.
   - **`RUNS_TECHNOLOGY` (`live_host` → `technology`)**:
     - For each technology associated with a live host (from `Evidence(category="technology")` metadata `url`/`host` or `live_host.metadata["technologies"]`), connects `live_host:{host_url}` to `technology:{tech_name.lower()}`.
   - **`HAS_VULNERABILITY` (`live_host` → `vulnerability`)**:
     - Vulnerability host/matched_at is resolved to the corresponding `live_host:{host_url}` node.
     - Connects `live_host:{host_url}` to `vulnerability:{vuln_id}`.

4. **Premise 4: Complete Idempotency**
   - `AttackSurfaceGraphBuilder.build(mission)` or `build_from_evidence(evidence_store, target)` can be called repeatedly.
   - Because all IDs and edge triplets are uniquely defined:
     - First pass: adds $N$ nodes, $E$ edges.
     - Second pass: `graph.add()` returns `False` for all existing nodes; `graph.connect()` returns `False` for all existing edges.
     - Resulting graph maintains identical `node_count()` and `edge_count()`.

5. **Premise 5: Graph Queries for Downstream Consumers (R2)**
   - **Uncovered Endpoints**:
     ```python
     def get_hosts_without_endpoints(graph: KnowledgeGraph) -> list[Node]:
         live_hosts = graph.nodes_by_type("live_host")
         return [
             h for h in live_hosts
             if not any(e.type == "HAS_ENDPOINT" for e in graph.edges_from(h))
         ]
     ```
   - **Uncovered Vulnerabilities**:
     ```python
     def get_hosts_without_vulnerabilities(graph: KnowledgeGraph) -> list[Node]:
         live_hosts = graph.nodes_by_type("live_host")
         return [
             h for h in live_hosts
             if not any(e.type == "HAS_VULNERABILITY" for e in graph.edges_from(h))
         ]
     ```
   - **Asset Counts by Type**:
     ```python
     def get_asset_counts(graph: KnowledgeGraph) -> dict[str, int]:
         types = ["target", "subdomain", "live_host", "endpoint", "technology", "vulnerability"]
         return {t: len(graph.nodes_by_type(t)) for t in types}
     ```

---

## 3. Caveats

1. **Case Normalization**:
   - Technology names (e.g. `"Nginx"`, `"nginx"`) and hostnames (e.g. `"API.EXAMPLE.COM"`, `"api.example.com"`) must be lowercased for node IDs to avoid duplicate nodes representing the same physical asset, while preserving human-readable display values in `node.value`.
2. **Missing Host Context**:
   - If an endpoint or vulnerability lacks an explicit scheme/port in its `host` field (e.g. `host: "api.example.com"` instead of `"https://api.example.com"`), the builder must match against all live host nodes sharing that hostname, or fallback to the primary matching live host.
3. **Backward Compatibility**:
   - Existing `KnowledgeGraphBuilder` in `argus/graph/builder.py` is referenced by `tests/test_graph_root.py` and `argus/workspace/api.py`.
   - The new `AttackSurfaceGraphBuilder` can either be placed in `argus/graph/attack_surface.py` or integrated into `argus/graph/builder.py` without breaking existing `KnowledgeGraphBuilder.build()` tests.
4. **Mission Graph Attachment**:
   - The graph should be attached to `mission.attack_surface_graph` (and optionally synced to `mission.graph` for backward compatibility).

---

## 4. Conclusion & Recommended Design

### 4.1 Proposed Class Architecture: `AttackSurfaceGraphBuilder`
Location: `argus/graph/attack_surface.py` (or `argus/graph/builder.py`)

```python
from typing import Optional, List, Dict, Any
import urllib.parse
from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.graph.edge import Edge
from argus.evidence.store import EvidenceStore

class AttackSurfaceGraphBuilder:
    """Transforms structured recon evidence into a typed KnowledgeGraph."""

    def build_from_evidence(self, evidence: EvidenceStore, target: str, graph: Optional[KnowledgeGraph] = None) -> KnowledgeGraph:
        if graph is None:
            graph = KnowledgeGraph()

        def get_or_create(node_id: str, node_type: str, value: str, metadata: Optional[dict] = None) -> Node:
            existing = graph.get(node_id)
            if existing:
                if metadata:
                    existing.metadata.update(metadata)
                return existing
            node = Node(id=node_id, type=node_type, value=value, metadata=metadata or {})
            graph.add(node)
            return node

        # 1. Target Node
        target_clean = str(target or "unknown").strip()
        target_id = f"target:{target_clean}"
        get_or_create(target_id, "target", target_clean, {"target": target_clean})

        # 2. Subdomains
        subdomain_nodes = {}
        for ev in evidence.filter("subdomain"):
            hostname = ev.metadata.get("hostname") or ev.value
            if hostname:
                sub_id = f"subdomain:{hostname.lower()}"
                s_node = get_or_create(sub_id, "subdomain", hostname, ev.metadata)
                subdomain_nodes[hostname.lower()] = s_node
                graph.connect(target_id, s_node.id, "RESOLVES_TO")

        # 3. Live Hosts
        host_nodes = {}
        for ev in evidence.filter("live_host"):
            meta = ev.metadata or {}
            url = meta.get("url") or ev.value
            if not url:
                continue
            parsed = urllib.parse.urlparse(url)
            hostname = meta.get("host") or parsed.hostname or url
            
            # Ensure parent subdomain node exists
            sub_id = f"subdomain:{hostname.lower()}"
            if sub_id not in graph.nodes:
                s_node = get_or_create(sub_id, "subdomain", hostname, {"hostname": hostname, "source": "httpx"})
                graph.connect(target_id, s_node.id, "RESOLVES_TO")
            
            host_id = f"live_host:{url.rstrip('/')}"
            h_node = get_or_create(host_id, "live_host", url, meta)
            host_nodes[host_id] = h_node
            host_nodes[hostname.lower()] = h_node
            
            graph.connect(sub_id, h_node.id, "HOSTS")

        # 4. Technologies
        for ev in evidence.filter("technology"):
            meta = ev.metadata or {}
            tech_name = meta.get("name") or ev.value
            if not tech_name:
                continue
            tech_id = f"technology:{tech_name.lower()}"
            t_node = get_or_create(tech_id, "technology", tech_name, meta)

            # Connect to corresponding live host
            matched_host = None
            if meta.get("url"):
                matched_host = graph.get(f"live_host:{meta['url'].rstrip('/')}")
            if not matched_host and meta.get("host"):
                matched_host = host_nodes.get(meta["host"].lower())
            
            if matched_host:
                graph.connect(matched_host.id, t_node.id, "RUNS_TECHNOLOGY")

        # 5. Endpoints
        for ev in evidence.filter("endpoint"):
            meta = ev.metadata or {}
            ep_url = meta.get("url") or ev.value
            if not ep_url:
                continue
            ep_id = f"endpoint:{ep_url}"
            ep_node = get_or_create(ep_id, "endpoint", ep_url, meta)

            # Match to live host
            parsed = urllib.parse.urlparse(ep_url)
            ep_host = meta.get("host") or parsed.hostname
            matched_host = None
            if ep_host:
                matched_host = host_nodes.get(ep_host.lower())
            
            if matched_host:
                graph.connect(matched_host.id, ep_node.id, "HAS_ENDPOINT")

        # 6. Vulnerabilities
        for ev in evidence.filter("vulnerability"):
            meta = ev.metadata or {}
            template_id = meta.get("template_id") or "vuln"
            matched_at = meta.get("matched_at") or meta.get("host") or ""
            vuln_id = f"vulnerability:{template_id}:{matched_at}" if matched_at else f"vulnerability:{template_id}"
            vuln_name = meta.get("name") or ev.value or template_id
            v_node = get_or_create(vuln_id, "vulnerability", vuln_name, meta)

            # Match to live host
            target_host_str = meta.get("host") or matched_at
            matched_host = None
            if target_host_str:
                matched_host = graph.get(f"live_host:{target_host_str.rstrip('/')}")
                if not matched_host:
                    parsed = urllib.parse.urlparse(target_host_str)
                    if parsed.hostname:
                        matched_host = host_nodes.get(parsed.hostname.lower())
            
            if matched_host:
                graph.connect(matched_host.id, v_node.id, "HAS_VULNERABILITY")

        return graph

    def build(self, mission: Any) -> KnowledgeGraph:
        target = getattr(mission, "target", "")
        evidence = getattr(mission, "evidence", None)
        if evidence is None:
            evidence = EvidenceStore()
        graph = self.build_from_evidence(evidence, target, getattr(mission, "attack_surface_graph", None))
        mission.attack_surface_graph = graph
        return graph
```

---

## 5. Verification Method

### 5.1 Concrete Verification Commands
1. **Existing Baseline Tests**:
   ```bash
   python3 -m pytest tests/ --ignore=tests/workspace -q
   ```
   *Expectation*: 493+ tests pass (0 failures).

2. **Graph Unit Tests**:
   ```bash
   python3 -m pytest tests/test_graph_root.py -q
   ```
   *Expectation*: All existing KnowledgeGraph unit tests pass.

3. **Verification of Graph Builder Properties**:
   ```python
   # Verify node count = 10 for (1 target + 2 subdomains + 2 live hosts + 3 endpoints + 1 technology + 1 vulnerability)
   # Verify idempotency by calling build() twice and asserting node_count() and edge_count() are invariant.
   ```

4. **Conditions that Invalidate Conclusions**:
   - Inability to link endpoints or vulnerabilities to live hosts due to URL mismatch.
   - Non-deterministic node ID generation causing duplicate nodes on rebuild.
   - Regression in any of the 493 existing tests.
