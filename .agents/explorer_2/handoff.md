# Handoff Report: Explorer 2 — Scan Evidence, Findings & CVE Knowledge Base Specialist (Requirements R2 & R3)

**Author:** Explorer 2 (Scan Evidence, Findings & CVE Knowledge Base Specialist)  
**Date:** 2026-09-03  
**Working Directory:** `/home/varun/argus/.agents/explorer_2/`  
**Target Milestone:** Sprint 31 Vector RAG & Semantic Search (R2 & R3 Architecture)  

---

## 1. Observations

### 1.1 Scan Lifecycle, Evidence Collection, and Finding Models
- **Evidence Model (`argus/evidence/model.py:25-56`)**:
  - `Evidence` is a `@dataclass(slots=True)` containing:
    - `evidence_id: str = field(default_factory=lambda: str(uuid.uuid4()))`
    - `project_id: str`, `mission_id: str`, `investigation_id: str`
    - `source_type: str = "SYSTEM"` (`SCREENSHOT`, `LOG`, `OBSERVATION`, etc.)
    - `source_id: str`, `created_by: str = "SYSTEM_GENERATED"` (`USER_PROVIDED`, `AI_DERIVED`, `SYSTEM_GENERATED`)
    - `created_at: str`, `updated_at: str`
    - `title: str`, `description: str`, `content_reference: str`
    - `category: str = "Other"`, `value: str`, `source: str`
    - `status: str = "UNVERIFIED"` (`UNVERIFIED`, `USER_REVIEWED`, `CORROBORATED`, `CONFIRMED`, `REJECTED`, `SUPERSEDED`)
    - `confidence: float = 1.0`, `severity: str = "info"`
    - `provenance: ProvenanceData`, `relationships: List[EvidenceRelationship]`, `tags: List[str]`, `metadata: Dict[str, Any]`
- **Evidence Storage & Manager**:
  - In-memory aggregation: `EvidenceStore` (`argus/evidence/store.py:4-37`) acts as an in-memory collection implementing `add()`, `all()`, `filter()`, `count()`, `clear()`, `__iter__()`, and `__len__()`.
  - Disk persistence: `EvidenceManager` (`argus/evidence/manager.py:8-86`) persists individual evidence items as JSON files at `~/.argus/workspace/evidence/{evidence_id}.json`.
- **Finding Model (`argus/reporting/models.py:80-136`)**:
  - `Finding` is a `@dataclass` containing:
    - `id: str`, `title: str`, `category: str`, `severity: str` (`critical`, `high`, `medium`, `low`, `info`)
    - `cvss: CVSSData` (`score: float`, `vector: str`, `severity_rating: str`, `metrics: dict[str, str]`)
    - `cwe: Optional[CWEInfo]` (`id: str`, `name: str`)
    - `host: str`, `endpoint: str`, `parameter: Optional[str]`, `parameter_type: Optional[str]`, `payload: Optional[str]`
    - `description: str`, `steps_to_reproduce: list[str]`, `impact: str`, `remediation: str`
    - `confidence: float = 1.0`, `status: str = "CONFIRMED"`
    - `evidence_ids: list[str]`, `duplicate_count: int = 1`, `tags: list[str]`, `references: list[str]`, `metadata: dict[str, Any]`
- **Report Summary & Vulnerability Report (`argus/reporting/models.py:139-205`)**:
  - `ReportSummary`: aggregate metrics (`total_findings`, `total_evidence_items`, `deduplicated_count`, `severity_counts`, `category_counts`, `host_counts`).
  - `VulnerabilityReport`: `report_id`, `mission_id`, `target`, `generated_at`, `generator_version`, `summary`, `findings`, `grouped_by_category`, `grouped_by_host`.
- **Finding Generation & Normalization (`argus/reporting/processor.py:20-232`)**:
  - `EvidenceProcessor.process(evidence_source, target, mission_id)` normalizes `Evidence` items into `Finding` candidates.
  - Deduplication key: `(category.lower(), host.lower(), endpoint.lower(), parameter.lower())`.
  - Deduplication merge: `_merge_findings()` merges `evidence_ids`, retains the highest severity rank and CVSS score, preserves highest confidence, unions tags/references, and enriches payloads/parameters.
  - Generates default descriptions, CVSS scores, CWE mappings, impact statements, and remediation guidance if missing in raw evidence.
- **Report Generation & Persistence (`argus/reporting/generator.py:16-114`)**:
  - `ReportGenerator` creates Markdown (`HackerOneMarkdownRenderer`) and JSON (`JSONReportRenderer`).
  - `save_report(report, output_dir)` writes files named `report_{safe_target}_{timestamp}_{short_id}.json` and `.md` into `.argus/reports/` by default.
  - `generate_and_save(mission)` saves files and registers output file paths into `mission.reports`.
- **Scan Lifecycle Execution Engines**:
  - `ScanEngine.run(mission)` (`argus/scanning/engine.py:182-509`):
    - Progresses through `MissionStateMachine`: `CREATED` -> `READY` -> `RUNNING` -> `COLLECTING_EVIDENCE`.
    - Resolves DAG (`ScanDAG`) and executes 30+ collectors (`argus/collectors/*.py`).
    - Aggregates evidence into `mission.evidence` (`EvidenceStore`).
    - Transitions to `MissionState.CORRELATING` and invokes `AttackSurfaceGraphBuilder().build(mission)`.
    - Invokes `self.report_generator.generate_and_save(mission)` at line 431.
    - Computes vulnerability severity breakdown and transitions to `MissionState.COMPLETED` at line 477.
    - Returns `ScanResult`.
  - `AutonomousMissionRuntime.step()` (`argus/runtime/mission_runtime.py:60-248`):
    - Runs multi-phase autonomous loop: `PLANNING` -> `RESEARCHING` -> `COLLECTING_EVIDENCE` -> `CORRELATING` -> `BUILDING_INVESTIGATIONS` -> `GENERATING_HYPOTHESES` -> `COMPLETED`.
    - Generates and saves reports at completion (lines 231-237).
    - Publishes `RuntimeEventType.MISSION_COMPLETED` on `EventBus` (line 240).
  - `MissionLifecycle.complete(mission)` (`argus/runtime/lifecycle.py:40-58`):
    - Transitions mission status to `COMPLETED`, generates and saves report, and populates `mission.reports`.
- **Event Bus Infrastructures**:
  - `argus.runtime.events.EventBus` (`argus/runtime/events.py:53-102`): Event bus with `subscribe()` and `publish(event_type: RuntimeEventType, mission_id: str, details: dict)`. Events include `MISSION_COMPLETED`, `EVIDENCE_CREATED`, `EVIDENCE_BUNDLE_CREATED`, `OBSERVATION_ADDED`, `CORRELATION_CREATED`, `PLAN_CREATED`.
  - `argus.core.event_bus.EventBus` (`argus/core/event_bus.py:5-20`): Lightweight string-based pub/sub (`subscribe(event_name, callback)`, `publish(event_name, data)`).

### 1.2 Knowledge Base Structure & Importers
- **Knowledge Entry Model (`argus/knowledge/models.py:21-46`)**:
  - `KnowledgeEntry` dataclass contains `id`, `title`, `category` (`KnowledgeCategory`), `description`, `tags`, `source`, `references`, `confidence`, `created_at`, `updated_at`, `version`, `related_business_objects`, `related_technologies`, `related_authentication`, `related_cwes`, `related_capecs`, `related_owasp`, `related_entries`, `examples`, `notes`.
- **Knowledge Manager (`argus/knowledge/manager.py:11-172`)**:
  - Stores JSON files in `~/.argus/knowledge/{entry_id}.json`.
  - Implements `add()`, `update()`, `delete()`, `get()`, `filter_by_category()`, `filter_by_tag()`, `search()`, `related()`, `export()`, and `import_file()`.
  - `search()` currently performs simple substring keyword matching on `title` and `description` (lines 78-84) and exact string matching on metadata lists.
- **Knowledge Importers (`argus/knowledge/importers.py:9-52`)**:
  - `import_json(file_path)`: parses single dict or list of dicts.
  - `import_yaml(file_path)`: parses YAML list or dict.
  - `import_markdown(file_path)`: extracts YAML frontmatter.

---

## 2. Logic Chain

### 2.1 Post-Scan Evidence & Finding Semantic Indexing (R2)
1. **Trigger Points**:
   - `ScanEngine.run()` completes report generation and transitions to `MissionState.COMPLETED`.
   - `AutonomousMissionRuntime` emits `RuntimeEventType.MISSION_COMPLETED`.
   - `MissionLifecycle.complete()` completes mission.
   - An indexer can attach as an `EventBus` listener on `RuntimeEventType.MISSION_COMPLETED` AND be explicitly invoked inside `ScanEngine.run()` and `MissionLifecycle.complete()`.
2. **Indexing Target Entities**:
   - **Confirmed & Corroborated Findings**: Each `Finding` generated by `EvidenceProcessor` from scan evidence.
   - **Raw Evidence Items**: Each `Evidence` item stored in `mission.evidence` (and persisted in `EvidenceManager`).
   - **Historical Scan Reports**: Scan reports in `.argus/reports/*.json` containing past scan findings and summaries.
3. **Embedding Representation for Findings**:
   - A finding has multiple semantic dimensions: title, vulnerability category, severity, endpoint, parameter, description, technical impact, remediation, steps to reproduce, and payload.
   - Creating a rich composite embedding text ensures high cosine similarity for conceptual queries:
     - Example: A query `"auth bypass via parameter tampering"` will semantically match:
       - IDOR findings: `"Broken Object Level Authorization in /api/v1/users?id=123"`
       - Parameter tampering findings: `"Price Tampering via unit_price POST parameter"`
       - JWT parameter manipulation findings: `"JWT algorithm confusion in Authorization header"`
       - SQL injection authentication bypass: `"SQL Injection in username login parameter"`
4. **Metadata Filtering**:
   - Filtering allows combining semantic similarity with strict filters:
     - Filter by `mission_id` (scope to single scan or all scans).
     - Filter by `severity` (`critical`, `high`, etc.).
     - Filter by `category` (`sql_injection`, `auth_bypass`, `idor`, `ssrf`, etc.).
     - Filter by `host` / `target`.
     - Filter by `source_type` (`"finding"`, `"evidence"`, `"report"`).

### 2.2 CVE & Vulnerability Knowledge Base (R3)
1. **Absence of Dedicated CVE Subsystem**:
   - Currently, `argus/knowledge/` handles conceptual knowledge (`KnowledgeEntry`) and rules, but there is no dedicated CVE ingestion or semantic CVE lookup model.
2. **CVE Record Structure & Feed Support**:
   - CVE feeds (NVD 2.0 JSON, CVE 5.0 JSON schema, GitHub Advisory JSON, custom JSON/YAML feeds) provide:
     - `cve_id` (e.g., `CVE-2023-38606`, `CVE-2021-44228`)
     - `title` / `summary`
     - `description`
     - `cvss_score`, `cvss_vector`, `severity`
     - `cwes` (e.g. `["CWE-89", "CWE-502"]`)
     - `affected_products` / `cpe` / `technologies` (e.g. `["Apache Log4j", "Spring Framework"]`)
     - `references` (URLs)
     - `published_date`, `last_modified_date`
3. **CVE Ingestion & Semantic Vector Indexing**:
   - Embedding representation: `f"{cve_id}: {title or ''}\nDescription: {description}\nAffected: {', '.join(affected_products)}\nCWE: {', '.join(cwes)}"`
   - Indexed into the SQLite-vec vector store under `source_type="cve"`.
4. **Finding-to-CVE Correlation Algorithm**:
   - For a given `Finding` or `Evidence`:
     - Construct a contextual search query: `f"{finding.title} {finding.category} {finding.description} {finding.cwe.name if finding.cwe else ''}"`.
     - Query the CVE vector store for top-$K$ candidates (e.g., $K=10$).
     - Calculate a blended correlation score:
       $$\text{Score} = w_{\text{vector}} \cdot S_{\text{vector}} + w_{\text{cwe}} \cdot S_{\text{cwe}} + w_{\text{tech}} \cdot S_{\text{tech}} + w_{\text{cat}} \cdot S_{\text{cat}}$$
       - $S_{\text{vector}} \in [0, 1]$ (cosine similarity).
       - $S_{\text{cwe}} = 1.0$ if finding's CWE matches any of CVE's CWEs, else $0.0$.
       - $S_{\text{tech}} = 1.0$ if finding's host/endpoint/metadata technologies overlap with CVE's affected products, else $0.0$.
       - $S_{\text{cat}} = 1.0$ if category keywords match.
     - Threshold filter (e.g., Score $\ge 0.65$) generates `CVECorrelationSuggestion`.

---

## 3. Caveats
- **Offline & Local-Only Constraint**: All embeddings and vector operations must run strictly locally without external network dependencies (file-based SQLite-vec, lightweight local embedding generator).
- **Graceful Fallback**: If vector extension / embedding model is initializing or in testing fallback mode, indexing and search operations must degrade gracefully to keyword/lexical indexing without crashing the test suite or scan engine.
- **Deduplication vs Versioning**: When scans re-run on the same target, findings should either be updated or versioned with unique document IDs (`f"{mission_id}:{finding_id}"`) so past historical scans remain searchable.

---

## 4. Conclusion & Architecture Proposals for R2 & R3

### 4.1 Data Models (`argus/knowledge/cve_models.py` & `argus/reporting/vector_models.py`)

#### `CVEEntry` & `CVECorrelationSuggestion`
```python
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

@dataclass
class CVEEntry:
    """Structured CVE / vulnerability intelligence record."""
    cve_id: str                              # e.g. "CVE-2021-44228"
    description: str                         # Full text description
    title: str = ""                          # Summary or short advisory title
    severity: str = "info"                   # critical, high, medium, low, info
    cvss_score: float = 0.0                  # e.g. 10.0
    cvss_vector: Optional[str] = None        # e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    cwes: list[str] = field(default_factory=list)               # e.g. ["CWE-502", "CWE-20"]
    affected_products: list[str] = field(default_factory=list)  # e.g. ["Apache Log4j", "log4j-core"]
    references: list[str] = field(default_factory=list)         # Advisory URLs
    published_date: Optional[str] = None
    last_modified_date: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cwes": list(self.cwes),
            "affected_products": list(self.affected_products),
            "references": list(self.references),
            "published_date": self.published_date,
            "last_modified_date": self.last_modified_date,
            "metadata": dict(self.metadata),
        }

    def to_embedding_text(self) -> str:
        parts = [f"CVE ID: {self.cve_id}"]
        if self.title:
            parts.append(f"Title: {self.title}")
        parts.append(f"Description: {self.description}")
        if self.affected_products:
            parts.append(f"Affected Products: {', '.join(self.affected_products)}")
        if self.cwes:
            parts.append(f"CWEs: {', '.join(self.cwes)}")
        if self.severity:
            parts.append(f"Severity: {self.severity}")
        return "\n".join(parts)


@dataclass
class CVECorrelationSuggestion:
    """Correlation link between a Finding and a CVEEntry."""
    finding_id: str
    cve_id: str
    similarity_score: float                  # Vector cosine similarity [0.0, 1.0]
    confidence_score: float                  # Blended score [0.0, 1.0]
    rationale: str                           # Explanation of why this CVE matched
    cve: CVEEntry
    matched_cwes: list[str] = field(default_factory=list)
    matched_technologies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "cve_id": self.cve_id,
            "similarity_score": round(self.similarity_score, 4),
            "confidence_score": round(self.confidence_score, 4),
            "rationale": self.rationale,
            "cve": self.cve.to_dict(),
            "matched_cwes": list(self.matched_cwes),
            "matched_technologies": list(self.matched_technologies),
        }
```

#### `FindingVectorDocument` & `EvidenceVectorDocument`
```python
@dataclass
class FindingVectorDocument:
    """Vector document representation of a Finding."""
    document_id: str                         # f"finding:{mission_id}:{finding_id}"
    finding_id: str
    mission_id: str
    target: str
    title: str
    category: str
    severity: str
    cvss_score: float
    cwe_id: Optional[str]
    host: str
    endpoint: str
    parameter: Optional[str]
    description: str
    impact: str
    remediation: str
    status: str
    confidence: float
    text_content: str                        # Composite text for embedding
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_finding(cls, finding: Finding, mission_id: str, target: str) -> "FindingVectorDocument":
        cwe_id = finding.cwe.id if finding.cwe else None
        text_parts = [
            f"Vulnerability Finding: {finding.title}",
            f"Category: {finding.category}",
            f"Severity: {finding.severity} (CVSS: {finding.cvss.score if finding.cvss else 'N/A'})",
            f"Target: {target} (Host: {finding.host}, Endpoint: {finding.endpoint})",
        ]
        if finding.parameter:
            text_parts.append(f"Vulnerable Parameter: {finding.parameter} (Type: {finding.parameter_type or 'unknown'})")
        if finding.payload:
            text_parts.append(f"Proof of Concept Payload: {finding.payload}")
        if finding.description:
            text_parts.append(f"Description: {finding.description}")
        if finding.impact:
            text_parts.append(f"Impact: {finding.impact}")
        if finding.remediation:
            text_parts.append(f"Remediation: {finding.remediation}")
        if finding.steps_to_reproduce:
            text_parts.append(f"Steps to Reproduce: {' '.join(finding.steps_to_reproduce)}")
        if finding.tags:
            text_parts.append(f"Tags: {', '.join(finding.tags)}")

        text_content = "\n".join(text_parts)
        doc_id = f"finding:{mission_id}:{finding.id}"

        return cls(
            document_id=doc_id,
            finding_id=finding.id,
            mission_id=mission_id,
            target=target,
            title=finding.title,
            category=finding.category,
            severity=finding.severity,
            cvss_score=finding.cvss.score if finding.cvss else 0.0,
            cwe_id=cwe_id,
            host=finding.host,
            endpoint=finding.endpoint,
            parameter=finding.parameter,
            description=finding.description,
            impact=finding.impact,
            remediation=finding.remediation,
            status=finding.status,
            confidence=finding.confidence,
            text_content=text_content,
            metadata={
                "source_type": "finding",
                "mission_id": mission_id,
                "target": target,
                "severity": finding.severity,
                "category": finding.category,
                "cwe_id": cwe_id,
                "host": finding.host,
                "endpoint": finding.endpoint,
                "status": finding.status,
                "confidence": finding.confidence,
                "raw_finding": finding.to_dict(),
            }
        )
```

---

### 4.2 Proposed API Interfaces for R2: Semantic Search Over Evidence & Findings

#### `ScanEvidenceIndexer` (`argus/reporting/indexer.py` or `argus/evidence/indexer.py`)
```python
class ScanEvidenceIndexer:
    """Indexes scan findings, evidence items, and historical reports into the Vector Store."""

    def __init__(self, vector_store: Optional[Any] = None):
        self.vector_store = vector_store or get_default_vector_store()

    def index_finding(self, finding: Finding, mission_id: str, target: str) -> str:
        """Indexes a single Finding into the vector store."""
        doc = FindingVectorDocument.from_finding(finding, mission_id=mission_id, target=target)
        self.vector_store.insert_document(
            doc_id=doc.document_id,
            text=doc.text_content,
            metadata=doc.metadata,
        )
        return doc.document_id

    def index_report(self, report: VulnerabilityReport) -> int:
        """Indexes all findings within a VulnerabilityReport."""
        count = 0
        for finding in report.findings:
            self.index_finding(finding, mission_id=report.mission_id, target=report.target)
            count += 1
        return count

    def index_evidence_item(self, evidence: Evidence) -> str:
        """Indexes an individual Evidence item."""
        doc_id = f"evidence:{evidence.mission_id}:{evidence.evidence_id}"
        text = (
            f"Evidence Title: {evidence.title}\n"
            f"Category: {evidence.category}\n"
            f"Severity: {evidence.severity}\n"
            f"Description: {evidence.description}\n"
            f"Value: {evidence.value}\n"
            f"Reference: {evidence.content_reference}\n"
            f"Tags: {', '.join(evidence.tags)}"
        )
        metadata = {
            "source_type": "evidence",
            "evidence_id": evidence.evidence_id,
            "mission_id": evidence.mission_id,
            "category": evidence.category,
            "severity": evidence.severity,
            "status": evidence.status,
            "confidence": evidence.confidence,
            "created_at": evidence.created_at,
        }
        self.vector_store.insert_document(doc_id=doc_id, text=text, metadata=metadata)
        return doc_id

    def index_historical_reports(self, reports_dir: str = ".argus/reports") -> int:
        """Discovers and indexes all historical report JSON files from disk."""
        total_indexed = 0
        path = Path(reports_dir)
        if not path.exists():
            return 0
        for json_file in path.glob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if "findings" in data and "report_id" in data:
                    report = VulnerabilityReport(**{
                        k: v for k, v in data.items() if k in VulnerabilityReport.__annotations__
                    })
                    total_indexed += self.index_report(report)
            except Exception as e:
                logger.warning(f"Failed to index historical report {json_file}: {e}")
        return total_indexed
```

#### `FindingSemanticSearchEngine` (`argus/reporting/search.py`)
```python
@dataclass
class FindingSearchResult:
    document_id: str
    similarity_score: float
    finding: Finding
    mission_id: str
    target: str

class FindingSemanticSearchEngine:
    """High-level semantic search engine for security findings and evidence."""

    def __init__(self, vector_store: Optional[Any] = None):
        self.vector_store = vector_store or get_default_vector_store()

    def search_findings(
        self,
        query: str,
        top_k: int = 10,
        min_score: float = 0.0,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        mission_id: Optional[str] = None,
        host: Optional[str] = None,
    ) -> list[FindingSearchResult]:
        """Performs semantic similarity search over indexed security findings."""
        filters: dict[str, Any] = {"source_type": "finding"}
        if severity:
            filters["severity"] = severity.lower()
        if category:
            filters["category"] = category.lower()
        if mission_id:
            filters["mission_id"] = mission_id
        if host:
            filters["host"] = host

        raw_results = self.vector_store.query(query=query, top_k=top_k, filters=filters)
        
        results = []
        for r in raw_results:
            if r.score < min_score:
                continue
            meta = r.metadata or {}
            raw_f = meta.get("raw_finding", {})
            finding = Finding(**{
                k: v for k, v in raw_f.items() if k in Finding.__annotations__
            }) if raw_f else Finding(id=r.doc_id, title=r.text[:50], description=r.text)
            
            results.append(
                FindingSearchResult(
                    document_id=r.doc_id,
                    similarity_score=r.score,
                    finding=finding,
                    mission_id=meta.get("mission_id", ""),
                    target=meta.get("target", ""),
                )
            )
        return results
```

---

### 4.3 Proposed API Interfaces for R3: CVE Knowledge Base & Correlation

#### `CVEKnowledgeBase` (`argus/knowledge/cve_kb.py`)
```python
class CVEKnowledgeBase:
    """Knowledge base engine for ingesting, embedding, and semantically querying CVE records."""

    def __init__(self, vector_store: Optional[Any] = None, storage_dir: str = "~/.argus/cve_kb"):
        self.vector_store = vector_store or get_default_vector_store()
        self.storage_dir = Path(os.path.expanduser(storage_dir))
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._cve_records: dict[str, CVEEntry] = {}

    def ingest_cve_entries(self, entries: list[CVEEntry]) -> int:
        """Ingests a batch of CVE entries, stores them, and inserts them into vector index."""
        indexed_count = 0
        for entry in entries:
            self._cve_records[entry.cve_id] = entry
            doc_id = f"cve:{entry.cve_id}"
            self.vector_store.insert_document(
                doc_id=doc_id,
                text=entry.to_embedding_text(),
                metadata={
                    "source_type": "cve",
                    "cve_id": entry.cve_id,
                    "severity": entry.severity.lower(),
                    "cvss_score": entry.cvss_score,
                    "cwes": entry.cwes,
                    "affected_products": entry.affected_products,
                    "raw_cve": entry.to_dict(),
                }
            )
            indexed_count += 1
        return indexed_count

    def ingest_json_file(self, file_path: str) -> int:
        """Ingests CVEs from a JSON file (supports CVE 5.0, NVD 2.0, or simplified list format)."""
        path = Path(file_path)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        entries = self._parse_json_payload(data)
        return self.ingest_cve_entries(entries)

    def search_cves(
        self,
        query: str,
        top_k: int = 5,
        min_score: float = 0.5,
        cwe: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> list[tuple[CVEEntry, float]]:
        """Searches CVEs by semantic description similarity."""
        filters: dict[str, Any] = {"source_type": "cve"}
        if severity:
            filters["severity"] = severity.lower()
        if cwe:
            filters["cwe"] = cwe

        raw_results = self.vector_store.query(query=query, top_k=top_k, filters=filters)
        
        results = []
        for r in raw_results:
            if r.score < min_score:
                continue
            meta = r.metadata or {}
            raw_cve = meta.get("raw_cve", {})
            entry = CVEEntry(**{
                k: v for k, v in raw_cve.items() if k in CVEEntry.__annotations__
            }) if raw_cve else CVEEntry(cve_id=r.doc_id.replace("cve:", ""), description=r.text)
            results.append((entry, r.score))
        return results

    def _parse_json_payload(self, data: Any) -> list[CVEEntry]:
        """Normalizes various CVE feed formats into list of CVEEntry objects."""
        entries = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and "cve_id" in item:
                    entries.append(CVEEntry(**{k: v for k, v in item.items() if k in CVEEntry.__annotations__}))
        elif isinstance(data, dict):
            if "cve_id" in data:
                entries.append(CVEEntry(**{k: v for k, v in data.items() if k in CVEEntry.__annotations__}))
            elif "vulnerabilities" in data:  # NVD 2.0 format
                for vuln in data["vulnerabilities"]:
                    cve_obj = vuln.get("cve", {})
                    cve_id = cve_obj.get("id")
                    descriptions = cve_obj.get("descriptions", [])
                    desc_text = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
                    if cve_id and desc_text:
                        entries.append(CVEEntry(cve_id=cve_id, description=desc_text))
        return entries
```

#### `CVECorrelator` (`argus/knowledge/cve_correlator.py`)
```python
class CVECorrelator:
    """Correlates ARGUS findings with CVE records using hybrid semantic and heuristic scoring."""

    def __init__(self, cve_kb: CVEKnowledgeBase):
        self.cve_kb = cve_kb

    def suggest_cves_for_finding(
        self,
        finding: Finding,
        top_k: int = 3,
        min_confidence: float = 0.65,
    ) -> list[CVECorrelationSuggestion]:
        """Suggests matching CVEs for a given security Finding."""
        # 1. Build composite search query
        query_terms = [finding.title, finding.category.replace("_", " ")]
        if finding.description:
            query_terms.append(finding.description)
        if finding.cwe:
            query_terms.append(f"CWE-{finding.cwe.id} {finding.cwe.name}")
        search_query = " ".join(query_terms)

        # 2. Vector search over CVE KB
        candidate_matches = self.cve_kb.search_cves(query=search_query, top_k=top_k * 3, min_score=0.4)

        # 3. Hybrid scoring & re-ranking
        suggestions = []
        finding_cwe_id = finding.cwe.id.upper() if finding.cwe else ""
        finding_tags_lower = {t.lower() for t in finding.tags}

        for cve_entry, sim_score in candidate_matches:
            confidence = sim_score * 0.60  # Base similarity contribution (60%)
            matched_cwes = []
            matched_techs = []
            reasons = [f"Semantic similarity score: {sim_score:.2f}"]

            # CWE matching bonus (+20%)
            if finding_cwe_id:
                for cwe in cve_entry.cwes:
                    if finding_cwe_id in cwe.upper() or cwe.upper() in finding_cwe_id:
                        confidence += 0.20
                        matched_cwes.append(cwe)
                        reasons.append(f"Matching CWE ({cwe})")
                        break

            # Product / Technology overlap bonus (+20%)
            for prod in cve_entry.affected_products:
                prod_lower = prod.lower()
                if (
                    prod_lower in finding.host.lower()
                    or prod_lower in finding.endpoint.lower()
                    or any(prod_lower in tag for tag in finding_tags_lower)
                    or (finding.category.lower() in prod_lower)
                ):
                    confidence += 0.20
                    matched_technologies.append(prod)
                    reasons.append(f"Matched technology: {prod}")
                    break

            confidence = min(1.0, confidence)
            if confidence >= min_confidence:
                suggestions.append(
                    CVECorrelationSuggestion(
                        finding_id=finding.id,
                        cve_id=cve_entry.cve_id,
                        similarity_score=sim_score,
                        confidence_score=confidence,
                        rationale="; ".join(reasons),
                        cve=cve_entry,
                        matched_cwes=matched_cwes,
                        matched_technologies=matched_technologies,
                    )
                )

        suggestions.sort(key=lambda s: s.confidence_score, reverse=True)
        return suggestions[:top_k]

    def correlate_report(self, report: VulnerabilityReport) -> dict[str, list[CVECorrelationSuggestion]]:
        """Runs CVE correlation across all findings in a scan report."""
        report_correlations = {}
        for finding in report.findings:
            suggestions = self.suggest_cves_for_finding(finding)
            if suggestions:
                report_correlations[finding.id] = suggestions
        return report_correlations
```

---

### 4.4 Hook Points in Scan Lifecycle
1. **`argus/scanning/engine.py` (Line 434, inside `ScanEngine.run`)**:
   ```python
   # 5.1 Automatic Semantic Indexing of Scan Report & Findings
   try:
       from argus.reporting.indexer import ScanEvidenceIndexer
       indexer = ScanEvidenceIndexer()
       indexer.index_report(report)  # Index all findings into SQLite-vec
   except Exception as e:
       logger.warning(f"Semantic indexing of scan findings skipped: {e}")
   ```
2. **`argus/runtime/lifecycle.py` (Line 54, inside `MissionLifecycle.complete`)**:
   ```python
   # Trigger vector RAG indexing upon mission completion
   try:
       from argus.reporting.indexer import ScanEvidenceIndexer
       ScanEvidenceIndexer().index_report(report)
   except Exception as e:
       logging.getLogger(__name__).debug(f"Vector indexing skipped: {e}")
   ```
3. **`argus/workspace/context/engine.py` (Inside `ResearchContextEngine._retrieve_sources`)**:
   - Ingest semantically relevant findings and CVE entries using `FindingSemanticSearchEngine` and `CVEKnowledgeBase` to fulfill Requirement R4.

---

## 5. Verification Method

### 5.1 Test Commands
1. Run existing reporting and knowledge tests to verify baseline compatibility:
   ```bash
   python -m pytest tests/reporting/ tests/test_knowledge.py -q
   ```
2. Run full regression test suite (excluding workspace mock fixtures):
   ```bash
   python -m pytest tests/ --ignore=tests/workspace -x -q
   ```
3. Target test suite for newly added R2 & R3 components:
   ```bash
   python -m pytest tests/test_vector_rag_r2.py tests/test_vector_rag_r3.py -v
   ```

### 5.2 Verification Invalidation Conditions
- A change causes existing tests in `tests/reporting/` or `tests/test_knowledge.py` to fail.
- Adding finding vector indexing slows scan execution by > 200ms per finding when operating locally.
- Substring search queries like `"auth bypass via parameter tampering"` fail to rank BOLA/IDOR or SQLi auth bypass findings higher than unrelated low-severity info findings.
- The CVE correlation suggester suggests unrelated CVEs when CWE and descriptions are completely disjoint.

