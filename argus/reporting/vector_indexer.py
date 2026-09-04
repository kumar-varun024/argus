"""
Vector RAG Indexing and Semantic Search Engine for Scan Findings and Evidence.

Provides automatic post-scan indexing of confirmed findings, raw evidence, and historical
scan reports into VectorStore, plus high-level semantic search APIs with multi-field filtering.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.reporting.models import Finding, VulnerabilityReport
from argus.reporting.processor import EvidenceProcessor
from argus.vector.models import SearchResult, VectorDocument, VectorFilter
from argus.vector.store import VectorStore, get_vector_store

logger = logging.getLogger(__name__)


class ScanEvidenceIndexer:
    """
    Indexes scan findings, evidence items, and historical reports into the Vector Store.
    
    Supports:
    - Finding indexing under source_type='finding'
    - Evidence indexing under source_type='evidence'
    - Report summary indexing under source_type='report'
    - Historical scan report ingestion from .argus/reports/
    """

    def __init__(self, vector_store: Optional[VectorStore] = None):
        self.vector_store = vector_store or get_vector_store()
        self.processor = EvidenceProcessor()

    def _build_finding_text(self, finding: Finding, target: str) -> str:
        """Construct a comprehensive composite text representation for a Finding."""
        parts = [
            f"Finding Title: {finding.title}",
            f"Vulnerability Category: {finding.category}",
            f"Severity: {finding.severity}",
        ]
        if finding.cvss and finding.cvss.score > 0:
            parts.append(f"CVSS Score: {finding.cvss.score} ({finding.cvss.severity_rating})")
        if finding.cwe:
            parts.append(f"CWE: CWE-{finding.cwe.id} {finding.cwe.name}")
        if target:
            parts.append(f"Target: {target}")
        if finding.host:
            parts.append(f"Host: {finding.host}")
        if finding.endpoint:
            parts.append(f"Endpoint: {finding.endpoint}")
        if finding.parameter:
            param_type = finding.parameter_type or "unknown"
            parts.append(f"Parameter: {finding.parameter} (type: {param_type})")
        if finding.payload:
            parts.append(f"Payload: {finding.payload}")
        if finding.description:
            parts.append(f"Description: {finding.description}")
        if finding.impact:
            parts.append(f"Impact: {finding.impact}")
        if finding.remediation:
            parts.append(f"Remediation: {finding.remediation}")
        if finding.steps_to_reproduce:
            parts.append(f"Steps: {' '.join(finding.steps_to_reproduce)}")
        if finding.tags:
            parts.append(f"Tags: {', '.join(finding.tags)}")
        return "\n".join(parts)

    def _build_evidence_text(self, evidence: Evidence) -> str:
        """Construct composite text representation for an Evidence item."""
        parts = [
            f"Evidence Title: {evidence.title}",
            f"Category: {evidence.category}",
            f"Severity: {evidence.severity}",
            f"Status: {evidence.status}",
        ]
        if evidence.source_type:
            parts.append(f"Source Type: {evidence.source_type}")
        if evidence.description:
            parts.append(f"Description: {evidence.description}")
        if evidence.value:
            # Include snippet of value if text
            val_str = str(evidence.value)
            if len(val_str) > 300:
                val_str = val_str[:300] + "..."
            parts.append(f"Value: {val_str}")
        if evidence.content_reference:
            parts.append(f"Reference: {evidence.content_reference}")
        if evidence.tags:
            parts.append(f"Tags: {', '.join(evidence.tags)}")
        return "\n".join(parts)

    def index_finding(
        self,
        finding: Finding,
        mission_id: Optional[str] = None,
        target: Optional[str] = None,
    ) -> str:
        """
        Indexes a single Finding into the VectorStore.
        Returns the generated document ID.
        """
        mid = mission_id or "adhoc"
        tgt = target or finding.host or "unknown"
        doc_id = f"finding:{mid}:{finding.id}"

        content = self._build_finding_text(finding, target=tgt)
        doc = VectorDocument(
            id=doc_id,
            content=content,
            source_type="finding",
            mission_id=mid,
            severity=finding.severity.lower() if finding.severity else "info",
            category=finding.category.lower() if finding.category else "general",
            metadata={
                "finding_id": finding.id,
                "title": finding.title,
                "target": tgt,
                "host": finding.host,
                "endpoint": finding.endpoint,
                "parameter": finding.parameter,
                "parameter_type": finding.parameter_type,
                "cvss_score": finding.cvss.score if finding.cvss else 0.0,
                "cwe_id": finding.cwe.id if finding.cwe else None,
                "cwe_name": finding.cwe.name if finding.cwe else None,
                "confidence": finding.confidence,
                "status": finding.status,
                "tags": list(finding.tags),
                "raw_finding": finding.to_dict(),
            },
        )

        self.vector_store.add_document(doc)
        return doc_id

    def index_findings(
        self,
        findings: List[Finding],
        mission_id: Optional[str] = None,
        target: Optional[str] = None,
    ) -> List[str]:
        """
        Batch indexes a list of Finding instances.
        Returns a list of indexed document IDs.
        """
        if not findings:
            return []

        mid = mission_id or "adhoc"
        tgt = target or "unknown"
        docs: List[VectorDocument] = []
        ids: List[str] = []

        for finding in findings:
            doc_id = f"finding:{mid}:{finding.id}"
            ids.append(doc_id)
            content = self._build_finding_text(finding, target=tgt)
            doc = VectorDocument(
                id=doc_id,
                content=content,
                source_type="finding",
                mission_id=mid,
                severity=finding.severity.lower() if finding.severity else "info",
                category=finding.category.lower() if finding.category else "general",
                metadata={
                    "finding_id": finding.id,
                    "title": finding.title,
                    "target": tgt,
                    "host": finding.host,
                    "endpoint": finding.endpoint,
                    "parameter": finding.parameter,
                    "parameter_type": finding.parameter_type,
                    "cvss_score": finding.cvss.score if finding.cvss else 0.0,
                    "cwe_id": finding.cwe.id if finding.cwe else None,
                    "cwe_name": finding.cwe.name if finding.cwe else None,
                    "confidence": finding.confidence,
                    "status": finding.status,
                    "tags": list(finding.tags),
                    "raw_finding": finding.to_dict(),
                },
            )
            docs.append(doc)

        self.vector_store.add_documents(docs)
        return ids

    def index_mission_findings(
        self,
        mission_id: str,
        findings: List[Finding],
        target: Optional[str] = None,
    ) -> int:
        """
        Helper to index findings for a specific mission ID.
        Returns the count of findings indexed.
        """
        ids = self.index_findings(findings, mission_id=mission_id, target=target)
        return len(ids)

    def index_evidence(self, evidence: Evidence) -> str:
        """
        Indexes a single Evidence item into the VectorStore.
        Returns the generated document ID.
        """
        mid = evidence.mission_id or "adhoc"
        doc_id = f"evidence:{mid}:{evidence.evidence_id}"

        content = self._build_evidence_text(evidence)
        doc = VectorDocument(
            id=doc_id,
            content=content,
            source_type="evidence",
            mission_id=mid,
            severity=evidence.severity.lower() if evidence.severity else "info",
            category=evidence.category.lower() if evidence.category else "other",
            metadata={
                "evidence_id": evidence.evidence_id,
                "project_id": evidence.project_id,
                "investigation_id": evidence.investigation_id,
                "title": evidence.title,
                "status": evidence.status,
                "confidence": evidence.confidence,
                "source_type": evidence.source_type,
                "created_by": evidence.created_by,
                "tags": list(evidence.tags),
                "created_at": evidence.created_at,
            },
        )

        self.vector_store.add_document(doc)
        return doc_id

    def index_evidence_items(
        self,
        evidence_items: Union[EvidenceStore, List[Evidence], Any],
    ) -> List[str]:
        """
        Batch indexes multiple Evidence items from an EvidenceStore or list.
        Returns a list of indexed document IDs.
        """
        items: List[Evidence] = []
        if isinstance(evidence_items, EvidenceStore):
            items = list(evidence_items.all())
        elif isinstance(evidence_items, list):
            items = [e for e in evidence_items if isinstance(e, Evidence)]
        elif hasattr(evidence_items, "all"):
            items = list(evidence_items.all())
        elif hasattr(evidence_items, "__iter__"):
            items = [e for e in evidence_items if isinstance(e, Evidence)]

        if not items:
            return []

        docs: List[VectorDocument] = []
        ids: List[str] = []
        for evidence in items:
            mid = evidence.mission_id or "adhoc"
            doc_id = f"evidence:{mid}:{evidence.evidence_id}"
            ids.append(doc_id)
            content = self._build_evidence_text(evidence)
            doc = VectorDocument(
                id=doc_id,
                content=content,
                source_type="evidence",
                mission_id=mid,
                severity=evidence.severity.lower() if evidence.severity else "info",
                category=evidence.category.lower() if evidence.category else "other",
                metadata={
                    "evidence_id": evidence.evidence_id,
                    "project_id": evidence.project_id,
                    "investigation_id": evidence.investigation_id,
                    "title": evidence.title,
                    "status": evidence.status,
                    "confidence": evidence.confidence,
                    "source_type": evidence.source_type,
                    "created_by": evidence.created_by,
                    "tags": list(evidence.tags),
                    "created_at": evidence.created_at,
                },
            )
            docs.append(doc)

        self.vector_store.add_documents(docs)
        return ids

    def index_report(self, report: VulnerabilityReport) -> int:
        """
        Indexes all findings within a VulnerabilityReport and the report summary itself.
        Returns the number of findings indexed.
        """
        if not report or not hasattr(report, "findings"):
            return 0

        # Index all findings
        f_ids = self.index_findings(
            findings=report.findings,
            mission_id=report.mission_id,
            target=report.target,
        )

        # Index report overview document
        rep_id = report.report_id or f"rep_{report.mission_id}"
        summary_text = (
            f"Vulnerability Report for Target: {report.target}\n"
            f"Mission ID: {report.mission_id}\n"
            f"Total Findings: {len(report.findings)}\n"
            f"Categories: {', '.join(report.grouped_by_category.keys())}\n"
            f"Hosts: {', '.join(report.grouped_by_host.keys())}"
        )
        report_doc = VectorDocument(
            id=f"report:{report.mission_id}:{rep_id}",
            content=summary_text,
            source_type="report",
            mission_id=report.mission_id,
            severity="info",
            category="report_summary",
            metadata={
                "report_id": rep_id,
                "target": report.target,
                "mission_id": report.mission_id,
                "total_findings": len(report.findings),
                "generated_at": report.generated_at,
            },
        )
        self.vector_store.add_document(report_doc)

        return len(f_ids)

    def index_mission(self, mission: Any) -> Dict[str, int]:
        """
        Indexes findings and evidence directly from an active Mission instance.
        Returns a dict with counts: {'findings': f_count, 'evidence': e_count}.
        """
        target = getattr(mission, "target", "Unknown Target")
        mission_id = getattr(mission, "id", "adhoc")
        evidence_source = getattr(mission, "evidence", None)

        evidence_count = 0
        if evidence_source is not None:
            ev_ids = self.index_evidence_items(evidence_source)
            evidence_count = len(ev_ids)

        # Process and index findings
        try:
            report = self.processor.process(
                evidence_source=evidence_source or [],
                target=target,
                mission_id=mission_id,
            )
            findings_count = self.index_report(report)
        except Exception as e:
            logger.warning(f"Failed to process findings for mission {mission_id}: {e}")
            findings_count = 0

        return {"findings": findings_count, "evidence": evidence_count}

    def index_historical_reports(self, reports_dir: Union[str, Path] = ".argus/reports") -> int:
        """
        Scans reports_dir for existing JSON report files and indexes all findings.
        Returns the total number of findings indexed across historical reports.
        """
        path = Path(reports_dir).resolve()
        if not path.exists():
            return 0

        total_findings_indexed = 0
        for json_file in path.glob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                if isinstance(data, dict) and "findings" in data:
                    # Construct report
                    mission_id = data.get("mission_id", "historical")
                    target = data.get("target", "historical_target")
                    report_id = data.get("report_id", json_file.stem)

                    findings_list: List[Finding] = []
                    for f_dict in data.get("findings", []):
                        if isinstance(f_dict, dict):
                            findings_list.append(Finding(
                                id=str(f_dict.get("id", "")),
                                title=str(f_dict.get("title", "")),
                                category=str(f_dict.get("category", "general")),
                                severity=str(f_dict.get("severity", "info")),
                                host=str(f_dict.get("host", "")),
                                endpoint=str(f_dict.get("endpoint", "")),
                                parameter=f_dict.get("parameter"),
                                parameter_type=f_dict.get("parameter_type"),
                                payload=f_dict.get("payload"),
                                description=str(f_dict.get("description", "")),
                                steps_to_reproduce=list(f_dict.get("steps_to_reproduce") or []),
                                impact=str(f_dict.get("impact", "")),
                                remediation=str(f_dict.get("remediation", "")),
                                confidence=float(f_dict.get("confidence", 1.0)),
                                status=str(f_dict.get("status", "CONFIRMED")),
                                tags=list(f_dict.get("tags") or []),
                                references=list(f_dict.get("references") or []),
                                metadata=dict(f_dict.get("metadata") or {}),
                            ))

                    report = VulnerabilityReport(
                        report_id=report_id,
                        mission_id=mission_id,
                        target=target,
                        findings=findings_list,
                    )
                    count = self.index_report(report)
                    total_findings_indexed += count
            except Exception as e:
                logger.warning(f"Failed to index historical report {json_file}: {e}")

        return total_findings_indexed


class FindingSemanticSearchEngine:
    """
    High-level semantic search API for scan findings, evidence, and historical reports.
    
    Provides rich vector search queries combined with metadata filtering across
    missions, severity tiers, vulnerability categories, and targets.
    """

    def __init__(self, vector_store: Optional[VectorStore] = None):
        self.vector_store = vector_store or get_vector_store()
        self.indexer = ScanEvidenceIndexer(vector_store=self.vector_store)

    def search_findings(
        self,
        query: str,
        top_k: int = 10,
        min_score: float = 0.0,
        severity: Optional[Union[str, List[str]]] = None,
        category: Optional[Union[str, List[str]]] = None,
        mission_id: Optional[Union[str, List[str]]] = None,
        target: Optional[str] = None,
        host: Optional[str] = None,
    ) -> List[SearchResult]:
        """
        Performs semantic similarity search over indexed Findings.
        
        Args:
            query: Natural language query (e.g. 'authentication bypass via parameter tampering')
            top_k: Max results to return
            min_score: Minimum similarity score threshold [0.0, 1.0]
            severity: Filter by severity ('critical', 'high', etc.) or list of severities
            category: Filter by category ('sql_injection', 'idor', etc.) or list
            mission_id: Filter by mission ID or list of IDs
            target: Filter by target name/URL in metadata
            host: Filter by host in metadata
        """
        filters: Dict[str, Any] = {"source_type": "finding"}
        if severity:
            if isinstance(severity, list):
                filters["severity"] = [s.lower() for s in severity]
            else:
                filters["severity"] = severity.lower()

        if category:
            if isinstance(category, list):
                filters["category"] = [c.lower() for c in category]
            else:
                filters["category"] = category.lower()

        if mission_id:
            filters["mission_id"] = mission_id

        meta_filters: Dict[str, Any] = {}
        if target:
            meta_filters["target"] = target
        if host:
            meta_filters["host"] = host
        if meta_filters:
            filters["metadata_filters"] = meta_filters

        return self.vector_store.search(
            query=query,
            top_k=top_k,
            filters=filters,
            min_score=min_score,
        )

    def search_evidence(
        self,
        query: str,
        top_k: int = 10,
        min_score: float = 0.0,
        mission_id: Optional[Union[str, List[str]]] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
    ) -> List[SearchResult]:
        """
        Performs semantic search over raw Evidence items.
        """
        filters: Dict[str, Any] = {"source_type": "evidence"}
        if mission_id:
            filters["mission_id"] = mission_id
        if severity:
            filters["severity"] = severity.lower()
        if category:
            filters["category"] = category.lower()

        return self.vector_store.search(
            query=query,
            top_k=top_k,
            filters=filters,
            min_score=min_score,
        )

    def search_all(
        self,
        query: str,
        top_k: int = 10,
        min_score: float = 0.0,
        mission_id: Optional[Union[str, List[str]]] = None,
    ) -> List[SearchResult]:
        """
        Performs semantic search across findings, evidence, and report summaries.
        """
        filters: Dict[str, Any] = {}
        if mission_id:
            filters["mission_id"] = mission_id

        return self.vector_store.search(
            query=query,
            top_k=top_k,
            filters=filters if filters else None,
            min_score=min_score,
        )

    def get_finding(self, finding_id: str, mission_id: Optional[str] = None) -> Optional[SearchResult]:
        """
        Retrieves an indexed finding SearchResult by ID.
        """
        if mission_id:
            doc = self.vector_store.get(f"finding:{mission_id}:{finding_id}")
            if doc:
                return SearchResult(
                    id=doc.id,
                    content=doc.content,
                    score=1.0,
                    distance=0.0,
                    source_type=doc.source_type,
                    mission_id=doc.mission_id,
                    severity=doc.severity,
                    category=doc.category,
                    metadata=doc.metadata,
                    created_at=doc.created_at,
                    document=doc,
                )

        # Fallback search across findings
        results = self.vector_store.search(
            query=finding_id,
            top_k=10,
            filters={"source_type": "finding"},
        )
        for r in results:
            if r.metadata.get("finding_id") == finding_id or r.id.endswith(f":{finding_id}"):
                return r

        return None

    def count_findings(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """Count findings matching optional filters."""
        f_dict = {"source_type": "finding"}
        if filters:
            f_dict.update(filters)
        return self.vector_store.count(VectorFilter.from_dict(f_dict))

    def clear_mission(self, mission_id: str) -> int:
        """Delete all indexed documents for a specific mission ID."""
        return self.vector_store.delete_where(VectorFilter(mission_id=mission_id))
