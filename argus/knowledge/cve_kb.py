"""
CVE Knowledge Base Engine for ARGUS.

Provides ingestion of vulnerability records from JSON feeds, files, and dictionaries
into VectorStore under source_type='cve', with semantic search and metadata filtering.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from argus.knowledge.cve_models import CVEEntry
from argus.vector.models import SearchResult, VectorDocument, VectorFilter
from argus.vector.store import VectorStore, get_vector_store

logger = logging.getLogger(__name__)


class CVEKnowledgeBase:
    """
    Knowledge base engine for ingesting, embedding, and semantically querying CVE records.
    
    Integrates with VectorStore (source_type='cve') for persistent similarity search,
    offline deterministic embeddings, and multi-field filtering (severity, CWE, affected products).
    """

    def __init__(
        self,
        vector_store: Optional[VectorStore] = None,
        storage_dir: Optional[str] = None,
    ):
        self.vector_store = vector_store or get_vector_store()
        self.storage_dir = Path(os.path.expanduser(storage_dir or "~/.argus/cve_kb"))
        self._cve_cache: Dict[str, CVEEntry] = {}

    def _cve_to_vector_doc(self, entry: CVEEntry) -> VectorDocument:
        """Convert CVEEntry into a VectorDocument for storage and semantic indexing."""
        primary_cwe = entry.cwes[0] if entry.cwes else "cve"
        return VectorDocument(
            id=f"cve:{entry.cve_id}",
            content=entry.to_embedding_text(),
            source_type="cve",
            severity=entry.severity.lower() if entry.severity else "info",
            category=primary_cwe,
            metadata={
                "cve_id": entry.cve_id,
                "title": entry.title,
                "cvss_score": entry.cvss_score,
                "cvss_vector": entry.cvss_vector,
                "cwes": list(entry.cwes),
                "affected_products": list(entry.affected_products),
                "references": list(entry.references),
                "published_date": entry.published_date,
                "last_modified_date": entry.last_modified_date,
                "metadata": entry.metadata,
                "raw_cve": entry.to_dict(),
            },
        )

    def _doc_to_cve_entry(self, doc: Union[VectorDocument, SearchResult, Dict[str, Any]]) -> CVEEntry:
        """Reconstruct a CVEEntry from VectorDocument, SearchResult, or raw dict."""
        if isinstance(doc, (VectorDocument, SearchResult)):
            meta = doc.metadata or {}
            raw_cve = meta.get("raw_cve")
            if raw_cve and isinstance(raw_cve, dict):
                return CVEEntry.from_dict(raw_cve)
            
            cve_id = meta.get("cve_id") or doc.id.replace("cve:", "")
            return CVEEntry(
                cve_id=cve_id,
                description=doc.content,
                title=str(meta.get("title", "")),
                severity=str(doc.severity or meta.get("severity", "info")),
                cvss_score=float(meta.get("cvss_score", 0.0)),
                cvss_vector=meta.get("cvss_vector"),
                cwes=list(meta.get("cwes") or []),
                affected_products=list(meta.get("affected_products") or []),
                references=list(meta.get("references") or []),
                published_date=meta.get("published_date"),
                last_modified_date=meta.get("last_modified_date"),
                metadata=dict(meta.get("metadata") or {}),
            )
        elif isinstance(doc, dict):
            return CVEEntry.from_dict(doc)
        raise ValueError(f"Cannot convert {type(doc)} to CVEEntry")

    def ingest_entries(self, entries: List[CVEEntry]) -> int:
        """
        Ingests a list of structured CVEEntry objects into the VectorStore.
        
        Returns the number of entries successfully ingested.
        """
        if not entries:
            return 0

        docs: List[VectorDocument] = []
        for entry in entries:
            self._cve_cache[entry.cve_id] = entry
            doc = self._cve_to_vector_doc(entry)
            docs.append(doc)

        self.vector_store.add_documents(docs)
        return len(docs)

    def ingest_records(self, records: List[Dict[str, Any]]) -> int:
        """
        Ingests a list of raw dictionary records by converting them into CVEEntry objects.
        """
        if not records:
            return 0
        entries = [CVEEntry.from_dict(r) for r in records if r]
        return self.ingest_entries(entries)

    def ingest_cve_records(self, records: Union[List[Dict[str, Any]], List[CVEEntry]]) -> int:
        """
        Alias for cross-compatibility with Context Engine and other interfaces.
        """
        if not records:
            return 0
        if isinstance(records[0], CVEEntry):
            return self.ingest_entries(records)  # type: ignore[arg-type]
        return self.ingest_records(records)  # type: ignore[arg-type]

    def ingest_file(self, file_path: Union[str, Path]) -> int:
        """
        Ingests CVEs from a JSON file.
        
        Supports:
        - List of CVE dictionaries
        - Dict with 'cves' or 'vulnerabilities' key (NVD 2.0 or CVE 5.0)
        - Single CVE dictionary
        """
        path = Path(file_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"CVE file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        entries = self._parse_json_payload(data)
        return self.ingest_entries(entries)

    def ingest_directory(self, dir_path: Union[str, Path]) -> int:
        """
        Recursively scans a directory for JSON CVE files and ingests all records.
        """
        path = Path(dir_path).resolve()
        if not path.exists():
            return 0

        total_ingested = 0
        for json_file in path.glob("**/*.json"):
            try:
                count = self.ingest_file(json_file)
                total_ingested += count
            except Exception as e:
                logger.warning(f"Failed to ingest CVE file {json_file}: {e}")
        return total_ingested

    def _parse_json_payload(self, data: Any) -> List[CVEEntry]:
        """
        Normalizes various CVE feed formats (NVD 2.0, CVE 5.0, GitHub Advisories, generic lists)
        into a uniform list of CVEEntry instances.
        """
        entries: List[CVEEntry] = []

        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    entries.append(self._parse_single_cve_dict(item))
        elif isinstance(data, dict):
            if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
                # NVD 2.0 JSON API format
                for item in data["vulnerabilities"]:
                    cve_obj = item.get("cve", {}) if isinstance(item, dict) else {}
                    if cve_obj:
                        entry = self._parse_nvd20_cve(cve_obj)
                        if entry:
                            entries.append(entry)
            elif "cveMetadata" in data and "containers" in data:
                # CVE 5.0 JSON Schema format
                entry = self._parse_cve50(data)
                if entry:
                    entries.append(entry)
            elif "cves" in data and isinstance(data["cves"], list):
                for item in data["cves"]:
                    if isinstance(item, dict):
                        entries.append(self._parse_single_cve_dict(item))
            elif "cve_id" in data or "id" in data:
                entries.append(self._parse_single_cve_dict(data))

        return entries

    def _parse_single_cve_dict(self, d: Dict[str, Any]) -> CVEEntry:
        """Parse standard or semi-standard CVE dictionary."""
        return CVEEntry.from_dict(d)

    def _parse_nvd20_cve(self, cve: Dict[str, Any]) -> Optional[CVEEntry]:
        """Parse NVD 2.0 vulnerability object."""
        cve_id = cve.get("id")
        if not cve_id:
            return None

        descriptions = cve.get("descriptions", [])
        desc_text = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc_text = d.get("value", "")
                break
        if not desc_text and descriptions:
            desc_text = descriptions[0].get("value", "")

        # Extract CVSS
        cvss_score = 0.0
        cvss_vector = None
        severity = "info"
        metrics = cve.get("metrics", {})
        
        cvss_data = None
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})

        if cvss_data:
            cvss_score = float(cvss_data.get("baseScore", 0.0))
            cvss_vector = cvss_data.get("vectorString")
            base_sev = cvss_data.get("baseSeverity")
            if base_sev:
                severity = str(base_sev).lower()

        # Extract CWEs
        cwes = []
        for w in cve.get("weaknesses", []):
            for wd in w.get("description", []):
                val = wd.get("value")
                if val and val.upper() != "NVD-CWE-OTHER" and val.upper() != "NVD-CWE-NOPINFO":
                    cwes.append(val)

        # Extract Affected Products
        affected_products = []
        for conf in cve.get("configurations", []):
            for node in conf.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "")
                    if criteria.startswith("cpe:2.3:"):
                        parts = criteria.split(":")
                        if len(parts) >= 5:
                            vendor, product = parts[3], parts[4]
                            prod_name = f"{vendor} {product}".replace("_", " ").strip()
                            if prod_name and prod_name not in affected_products:
                                affected_products.append(prod_name)

        # References
        references = [r.get("url") for r in cve.get("references", []) if r.get("url")]

        return CVEEntry(
            cve_id=cve_id,
            description=desc_text,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cwes=cwes,
            affected_products=affected_products,
            references=references,
            published_date=cve.get("published"),
            last_modified_date=cve.get("lastModified"),
        )

    def _parse_cve50(self, data: Dict[str, Any]) -> Optional[CVEEntry]:
        """Parse CVE 5.0 JSON schema object."""
        cve_meta = data.get("cveMetadata", {})
        cve_id = cve_meta.get("cveId")
        if not cve_id:
            return None

        containers = data.get("containers", {})
        cna = containers.get("cna", {})

        title = cna.get("title", "")
        descriptions = cna.get("descriptions", [])
        desc_text = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc_text = d.get("value", "")
                break
        if not desc_text and descriptions:
            desc_text = descriptions[0].get("value", "")

        # Metrics
        cvss_score = 0.0
        cvss_vector = None
        severity = "info"
        metrics = cna.get("metrics", [])
        for m in metrics:
            if "cvssV3_1" in m:
                v31 = m["cvssV3_1"]
                cvss_score = float(v31.get("baseScore", 0.0))
                cvss_vector = v31.get("vectorString")
                severity = str(v31.get("baseSeverity", "info")).lower()
                break

        # Affected
        affected_products = []
        for aff in cna.get("affected", []):
            vendor = aff.get("vendor", "")
            product = aff.get("product", "")
            prod_str = f"{vendor} {product}".strip()
            if prod_str and prod_str not in affected_products:
                affected_products.append(prod_str)

        # Problem types (CWEs)
        cwes = []
        for pt in cna.get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                cwe_id = desc.get("cweId") or desc.get("description")
                if cwe_id and "CWE" in cwe_id.upper():
                    cwes.append(cwe_id.strip())

        references = [r.get("url") for r in cna.get("references", []) if r.get("url")]

        return CVEEntry(
            cve_id=cve_id,
            description=desc_text,
            title=title,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cwes=cwes,
            affected_products=affected_products,
            references=references,
            published_date=cve_meta.get("datePublished"),
            last_modified_date=cve_meta.get("dateUpdated"),
        )

    def get_cve(self, cve_id: str) -> Optional[CVEEntry]:
        """
        Retrieve a CVEEntry by CVE ID.
        Checks memory cache first, then queries VectorStore.
        """
        clean_id = cve_id.strip().upper()
        if clean_id in self._cve_cache:
            return self._cve_cache[clean_id]

        # Check standard key variants in vector store
        doc = self.vector_store.get(f"cve:{clean_id}") or self.vector_store.get(clean_id)
        if doc:
            entry = self._doc_to_cve_entry(doc)
            self._cve_cache[clean_id] = entry
            return entry

        return None

    def search_cves(
        self,
        query: str,
        top_k: int = 5,
        min_score: float = 0.0,
        severity: Optional[str] = None,
        cwe: Optional[str] = None,
        affected_product: Optional[str] = None,
    ) -> List[Tuple[CVEEntry, float]]:
        """
        Perform semantic similarity search over CVE records.
        
        Supports post-filtering by severity, CWE taxonomy, and affected product keywords.
        Returns a list of (CVEEntry, similarity_score) pairs ordered by relevance.
        """
        filters: Dict[str, Any] = {"source_type": "cve"}
        if severity:
            filters["severity"] = severity.lower().strip()

        # Query vector store with expanded candidate pool if post-filters are applied
        needs_post_filter = bool(cwe or affected_product)
        query_top_k = max(top_k * 4, 20) if needs_post_filter else top_k

        raw_results = self.vector_store.search(
            query=query,
            top_k=query_top_k,
            filters=filters,
            min_score=min_score,
        )

        matched_results: List[Tuple[CVEEntry, float]] = []
        cwe_clean = cwe.upper().replace("-", "").strip() if cwe else None
        prod_clean = affected_product.lower().strip() if affected_product else None

        for res in raw_results:
            entry = self._doc_to_cve_entry(res)
            
            # Post-filter: CWE match
            if cwe_clean:
                entry_cwes_clean = [c.upper().replace("-", "").strip() for c in entry.cwes]
                if not any(cwe_clean in ec or ec in cwe_clean for ec in entry_cwes_clean):
                    # Also check if description contains CWE
                    if cwe.upper() not in entry.description.upper():
                        continue

            # Post-filter: Affected Product match
            if prod_clean:
                prod_matches = any(prod_clean in p.lower() for p in entry.affected_products)
                if not prod_matches and prod_clean not in entry.description.lower():
                    continue

            matched_results.append((entry, res.score))
            if len(matched_results) >= top_k:
                break

        return matched_results

    def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """Count CVE records stored in the vector database."""
        filter_dict = {"source_type": "cve"}
        if filters:
            filter_dict.update(filters)
        return self.vector_store.count(VectorFilter.from_dict(filter_dict))

    def clear(self) -> int:
        """Clear all CVE entries from vector store and in-memory cache."""
        deleted = self.vector_store.delete_where(VectorFilter(source_type="cve"))
        self._cve_cache.clear()
        return deleted
