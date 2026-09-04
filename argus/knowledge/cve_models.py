"""
Data models for CVE intelligence and Finding-to-CVE correlation.

Provides structured records for vulnerability intelligence feeds (NVD, CVE 5.0),
semantic embedding representation, and hybrid correlation suggestion scoring.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union


@dataclass
class CVEEntry:
    """
    Structured CVE / vulnerability intelligence record.
    
    Contains CVE identifiers, descriptions, CVSS scoring, CWE taxonomy,
    affected vendor/product lists, and reference links.
    """
    cve_id: str
    description: str
    title: str = ""
    severity: str = "info"  # critical, high, medium, low, info
    cvss_score: float = 0.0
    cvss_vector: Optional[str] = None
    cwes: List[str] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    published_date: Optional[str] = None
    last_modified_date: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert CVEEntry into a serializable dictionary."""
        return {
            "cve_id": self.cve_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.lower() if self.severity else "info",
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cwes": list(self.cwes),
            "affected_products": list(self.affected_products),
            "references": list(self.references),
            "published_date": self.published_date,
            "last_modified_date": self.last_modified_date,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CVEEntry":
        """Construct CVEEntry from a dictionary payload."""
        cve_id = str(data.get("cve_id") or data.get("id") or "").strip()
        description = str(data.get("description") or data.get("summary") or "").strip()
        title = str(data.get("title") or "")
        severity = str(data.get("severity") or "info").lower().strip()
        
        cvss_raw = data.get("cvss_score") or data.get("cvss") or data.get("score") or 0.0
        try:
            cvss_score = float(cvss_raw)
        except (ValueError, TypeError):
            cvss_score = 0.0

        cvss_vector = data.get("cvss_vector") or data.get("vector")
        
        cwes_raw = data.get("cwes") or data.get("cwe") or []
        if isinstance(cwes_raw, str):
            cwes = [c.strip() for c in cwes_raw.split(",") if c.strip()]
        elif isinstance(cwes_raw, list):
            cwes = [str(c).strip() for c in cwes_raw if str(c).strip()]
        else:
            cwes = []

        prods_raw = data.get("affected_products") or data.get("products") or data.get("affected") or []
        if isinstance(prods_raw, str):
            affected_products = [p.strip() for p in prods_raw.split(",") if p.strip()]
        elif isinstance(prods_raw, list):
            affected_products = [str(p).strip() for p in prods_raw if str(p).strip()]
        else:
            affected_products = []

        refs_raw = data.get("references") or data.get("refs") or []
        if isinstance(refs_raw, str):
            references = [r.strip() for r in refs_raw.split(",") if r.strip()]
        elif isinstance(refs_raw, list):
            references = [str(r).strip() for r in refs_raw if str(r).strip()]
        else:
            references = []

        metadata = dict(data.get("metadata") or {})

        return cls(
            cve_id=cve_id,
            description=description,
            title=title,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cwes=cwes,
            affected_products=affected_products,
            references=references,
            published_date=data.get("published_date"),
            last_modified_date=data.get("last_modified_date"),
            metadata=metadata,
        )

    def to_embedding_text(self) -> str:
        """
        Generate rich composite text representation for vector embedding.
        Includes CVE ID, Title, Severity, CVSS, CWEs, Affected Products, and Description.
        """
        parts = [f"CVE ID: {self.cve_id}"]
        if self.title:
            parts.append(f"Title: {self.title}")
        if self.severity:
            parts.append(f"Severity: {self.severity}")
        if self.cvss_score > 0:
            parts.append(f"CVSS Score: {self.cvss_score}")
        if self.cwes:
            parts.append(f"CWEs: {', '.join(self.cwes)}")
        if self.affected_products:
            parts.append(f"Affected Products: {', '.join(self.affected_products)}")
        if self.description:
            parts.append(f"Description: {self.description}")
        return "\n".join(parts)


@dataclass
class CVECorrelationSuggestion:
    """
    Correlation link between an ARGUS Finding and a CVEEntry.
    
    Contains hybrid scoring metrics:
    - vector_similarity: cosine similarity from semantic embedding search
    - cwe_match: whether CWE taxonomy aligns
    - tech_match: whether target technology / host overlaps with affected products
    - category_match: whether vulnerability category keywords align
    - correlation_score: blended confidence score [0.0, 1.0]
    - rationale: human-readable explanation of why the correlation was made
    """
    cve_id: str
    cve_title: str = ""
    cve_description: str = ""
    finding_id: str = ""
    finding_title: str = ""
    correlation_score: float = 0.0
    vector_similarity: float = 0.0
    cwe_match: bool = False
    tech_match: bool = False
    category_match: bool = False
    rationale: str = ""
    matched_cwes: List[str] = field(default_factory=list)
    matched_products: List[str] = field(default_factory=list)
    cve_entry: Optional[CVEEntry] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert suggestion to dictionary."""
        return {
            "cve_id": self.cve_id,
            "cve_title": self.cve_title,
            "cve_description": self.cve_description,
            "finding_id": self.finding_id,
            "finding_title": self.finding_title,
            "correlation_score": round(self.correlation_score, 4),
            "vector_similarity": round(self.vector_similarity, 4),
            "cwe_match": self.cwe_match,
            "tech_match": self.tech_match,
            "category_match": self.category_match,
            "rationale": self.rationale,
            "matched_cwes": list(self.matched_cwes),
            "matched_products": list(self.matched_products),
            "cve_entry": self.cve_entry.to_dict() if self.cve_entry else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CVECorrelationSuggestion":
        """Recreate suggestion from dictionary."""
        cve_entry_data = data.get("cve_entry")
        cve_entry = CVEEntry.from_dict(cve_entry_data) if cve_entry_data else None

        return cls(
            cve_id=str(data.get("cve_id", "")),
            cve_title=str(data.get("cve_title", "")),
            cve_description=str(data.get("cve_description", "")),
            finding_id=str(data.get("finding_id", "")),
            finding_title=str(data.get("finding_title", "")),
            correlation_score=float(data.get("correlation_score", 0.0)),
            vector_similarity=float(data.get("vector_similarity", 0.0)),
            cwe_match=bool(data.get("cwe_match", False)),
            tech_match=bool(data.get("tech_match", False)),
            category_match=bool(data.get("category_match", False)),
            rationale=str(data.get("rationale", "")),
            matched_cwes=list(data.get("matched_cwes") or []),
            matched_products=list(data.get("matched_products") or []),
            cve_entry=cve_entry,
        )
