"""
Hybrid Finding-to-CVE Correlation Engine for ARGUS.

Combines semantic vector similarity, CWE taxonomy alignment, technology/vendor matching,
and vulnerability category heuristic alignment into a unified correlation confidence score.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from argus.evidence.model import Evidence
from argus.knowledge.cve_kb import CVEKnowledgeBase
from argus.knowledge.cve_models import CVECorrelationSuggestion, CVEEntry
from argus.reporting.models import Finding, VulnerabilityReport

logger = logging.getLogger(__name__)


class CVECorrelator:
    """
    Correlates ARGUS security findings and evidence with known CVE records.
    
    Implements a multi-factor hybrid scoring ranker:
    - Vector Semantic Similarity (Default weight: 0.50)
    - CWE Taxonomy Matching (Default weight: 0.20)
    - Technology / Product Matching (Default weight: 0.15)
    - Vulnerability Category Matching (Default weight: 0.15)
    """

    DEFAULT_WEIGHTS: Dict[str, float] = {
        "vector": 0.50,
        "cwe": 0.20,
        "tech": 0.15,
        "category": 0.15,
    }

    # Common category keyword aliases for matching
    CATEGORY_ALIASES: Dict[str, List[str]] = {
        "sql_injection": ["sql", "sqli", "injection", "database", "rdbms", "cwe-89", "cwe89"],
        "sqli": ["sql", "sqli", "injection", "database", "rdbms", "cwe-89", "cwe89"],
        "xss": ["cross-site scripting", "xss", "script injection", "cwe-79", "cwe79", "javascript"],
        "rce": ["remote code execution", "rce", "command execution", "command injection", "shell", "arbitrary code", "cwe-78", "cwe78", "cwe-94"],
        "auth_bypass": ["authentication bypass", "auth bypass", "unauthorized", "login", "credential", "cwe-287", "cwe287"],
        "authorization_bypass": ["authorization bypass", "access control", "privilege escalation", "cwe-862", "cwe862"],
        "idor": ["insecure direct object reference", "idor", "bola", "broken object level authorization", "cwe-639", "cwe639"],
        "bola": ["insecure direct object reference", "idor", "bola", "broken object level authorization", "cwe-639", "cwe639"],
        "ssrf": ["server-side request forgery", "ssrf", "cloud metadata", "cwe-918", "cwe918"],
        "csrf": ["cross-site request forgery", "csrf", "xsrf", "cwe-352", "cwe352"],
        "deserialization": ["deserialization", "insecure deserialization", "object injection", "cwe-502", "cwe502", "untrusted data"],
        "path_traversal": ["path traversal", "directory traversal", "lfi", "file inclusion", "arbitrary file", "cwe-22", "cwe22"],
        "information_disclosure": ["information disclosure", "leak", "sensitive data", "source map", "exposure", "cwe-200", "cwe200"],
        "crypto": ["cryptographic", "encryption", "weak cipher", "weak key", "cwe-327", "cwe327"],
    }

    def __init__(
        self,
        cve_kb: CVEKnowledgeBase,
        weights: Optional[Dict[str, float]] = None,
    ):
        self.cve_kb = cve_kb
        self.weights = dict(self.DEFAULT_WEIGHTS)
        if weights:
            self.weights.update(weights)

        # Normalize weights so they sum to 1.0
        total_w = sum(self.weights.values()) or 1.0
        self.weights = {k: v / total_w for k, v in self.weights.items()}

    def _extract_tech_tokens(self, finding: Finding) -> Set[str]:
        """Extract technology, product, and framework tokens from finding attributes."""
        tokens: Set[str] = set()

        # From host
        if finding.host:
            host_parts = re.split(r"[.\-_:/]+", finding.host.lower())
            tokens.update(p for p in host_parts if len(p) > 2)

        # From endpoint
        if finding.endpoint:
            ep_parts = re.split(r"[/\-_?=&.]+", finding.endpoint.lower())
            tokens.update(p for p in ep_parts if len(p) > 2)

        # From tags
        for tag in finding.tags:
            tokens.add(tag.lower())
            tokens.update(p for p in re.split(r"[:\-_/]+", tag.lower()) if len(p) > 2)

        # From metadata
        meta = finding.metadata or {}
        for k in ("technology", "technologies", "tech", "server", "framework", "component", "product", "vendor"):
            v = meta.get(k)
            if isinstance(v, str):
                tokens.add(v.lower())
            elif isinstance(v, list):
                for item in v:
                    tokens.add(str(item).lower())

        # From title & description
        combined_text = f"{finding.title} {finding.description}".lower()
        common_techs = [
            "log4j", "apache", "spring", "struts", "nginx", "tomcat", "wordpress",
            "drupal", "joomla", "openssl", "openssh", "mysql", "postgresql",
            "redis", "mongodb", "elasticsearch", "django", "flask", "express",
            "node", "laravel", "rails", "jenkins", "gitlab", "grafana", "kibana",
            "docker", "kubernetes", "solr", "confluence", "jira", "keycloak",
        ]
        for tech in common_techs:
            if tech in combined_text:
                tokens.add(tech)

        return tokens

    def _check_cwe_match(self, finding: Finding, cve: CVEEntry) -> Tuple[bool, List[str]]:
        """Check if finding CWE aligns with CVE CWE records."""
        matched: List[str] = []
        if not finding.cwe:
            return False, matched

        # Format variations: "CWE-89", "89", "cwe89"
        raw_cwe_id = str(finding.cwe.id).upper().strip()
        cwe_digits = re.sub(r"[^\d]", "", raw_cwe_id)
        cwe_name = str(finding.cwe.name or "").lower()

        for cve_cwe in cve.cwes:
            cve_cwe_upper = cve_cwe.upper().strip()
            cve_digits = re.sub(r"[^\d]", "", cve_cwe_upper)

            if raw_cwe_id in cve_cwe_upper or cve_cwe_upper in raw_cwe_id:
                matched.append(cve_cwe)
            elif cwe_digits and cve_digits and cwe_digits == cve_digits:
                matched.append(cve_cwe)

        # Also check description if no explicit CWE list match
        if not matched and cwe_digits:
            if f"CWE-{cwe_digits}" in cve.description.upper() or f"CWE {cwe_digits}" in cve.description.upper():
                matched.append(f"CWE-{cwe_digits}")

        return len(matched) > 0, matched

    def _check_tech_match(self, tech_tokens: Set[str], cve: CVEEntry) -> Tuple[bool, List[str]]:
        """Check if extracted target technologies overlap with CVE affected products."""
        matched: List[str] = []
        if not tech_tokens:
            return False, matched

        for prod in cve.affected_products:
            prod_lower = prod.lower()
            prod_words = [w for w in re.split(r"[\s\-_:/]+", prod_lower) if len(w) > 2]
            
            # Exact or substring match on product name
            if prod_lower in tech_tokens or any(t in prod_lower for t in tech_tokens):
                matched.append(prod)
            elif any(w in tech_tokens for w in prod_words):
                matched.append(prod)

        # Also check if any tech token is explicitly mentioned in CVE title or description
        if not matched:
            cve_full_text = f"{cve.title} {cve.description}".lower()
            for token in tech_tokens:
                if len(token) >= 4 and f" {token} " in f" {cve_full_text} ":
                    matched.append(token)

        return len(matched) > 0, matched

    def _check_category_match(self, category: str, cve: CVEEntry) -> bool:
        """Check if vulnerability category aligns with CVE descriptions and title."""
        if not category:
            return False

        cat_clean = category.lower().replace(" ", "_").strip()
        aliases = self.CATEGORY_ALIASES.get(cat_clean, [cat_clean.replace("_", " ")])

        cve_text = f"{cve.title} {cve.description} {' '.join(cve.cwes)}".lower()

        for alias in aliases:
            if alias in cve_text:
                return True

        return False

    def correlate_finding(
        self,
        finding: Finding,
        top_k: int = 5,
        min_score: float = 0.35,
    ) -> List[CVECorrelationSuggestion]:
        """
        Suggests relevant CVEs for an individual security Finding using hybrid scoring.
        
        Returns a sorted list of CVECorrelationSuggestion instances.
        """
        # 1. Build composite search query
        query_parts = [finding.title]
        if finding.category:
            query_parts.append(finding.category.replace("_", " "))
        if finding.cwe and finding.cwe.name:
            query_parts.append(finding.cwe.name)
        if finding.description:
            # Take first 200 chars of description to keep query focused
            query_parts.append(finding.description[:200])
        if finding.host:
            query_parts.append(finding.host)
        if finding.tags:
            query_parts.append(" ".join(finding.tags))

        search_query = " ".join(query_parts)

        # 2. Vector search over CVE Knowledge Base
        candidate_matches = self.cve_kb.search_cves(
            query=search_query,
            top_k=max(top_k * 4, 15),
            min_score=0.0,
        )

        if not candidate_matches:
            return []

        # 3. Hybrid scoring evaluation
        suggestions: List[CVECorrelationSuggestion] = []
        tech_tokens = self._extract_tech_tokens(finding)

        w_vec = self.weights["vector"]
        w_cwe = self.weights["cwe"]
        w_tech = self.weights["tech"]
        w_cat = self.weights["category"]

        for cve_entry, sim_score in candidate_matches:
            cwe_match, matched_cwes = self._check_cwe_match(finding, cve_entry)
            tech_match, matched_products = self._check_tech_match(tech_tokens, cve_entry)
            cat_match = self._check_category_match(finding.category, cve_entry)

            # Compute blended score
            s_vec = max(0.0, min(1.0, float(sim_score)))
            s_cwe = 1.0 if cwe_match else 0.0
            s_tech = 1.0 if tech_match else 0.0
            s_cat = 1.0 if cat_match else 0.0

            correlation_score = (w_vec * s_vec) + (w_cwe * s_cwe) + (w_tech * s_tech) + (w_cat * s_cat)
            correlation_score = max(0.0, min(1.0, correlation_score))

            if correlation_score < min_score:
                continue

            # Build rationale
            rationale_items = [f"Semantic similarity: {s_vec:.2f}"]
            if cwe_match:
                rationale_items.append(f"CWE matched: {', '.join(matched_cwes)}")
            if tech_match:
                rationale_items.append(f"Technology matched: {', '.join(matched_products)}")
            if cat_match:
                rationale_items.append(f"Category aligned: {finding.category}")

            suggestion = CVECorrelationSuggestion(
                cve_id=cve_entry.cve_id,
                cve_title=cve_entry.title,
                cve_description=cve_entry.description,
                finding_id=finding.id,
                finding_title=finding.title,
                correlation_score=round(correlation_score, 4),
                vector_similarity=round(s_vec, 4),
                cwe_match=cwe_match,
                tech_match=tech_match,
                category_match=cat_match,
                rationale="; ".join(rationale_items),
                matched_cwes=matched_cwes,
                matched_products=matched_products,
                cve_entry=cve_entry,
            )
            suggestions.append(suggestion)

        # 4. Sort by correlation score descending, then vector similarity descending
        suggestions.sort(
            key=lambda s: (s.correlation_score, s.vector_similarity),
            reverse=True,
        )

        return suggestions[:top_k]

    def correlate_evidence(
        self,
        evidence: Evidence,
        top_k: int = 5,
        min_score: float = 0.35,
    ) -> List[CVECorrelationSuggestion]:
        """
        Correlates a raw Evidence instance with CVE records by converting it into a Finding representation.
        """
        temp_finding = Finding(
            id=evidence.evidence_id,
            title=evidence.title or f"Evidence {evidence.evidence_id[:8]}",
            category=evidence.category,
            severity=evidence.severity,
            description=evidence.description,
            tags=list(evidence.tags),
            metadata=dict(evidence.metadata),
        )
        return self.correlate_finding(temp_finding, top_k=top_k, min_score=min_score)

    def correlate_report(
        self,
        report: VulnerabilityReport,
        top_k: int = 3,
        min_score: float = 0.35,
    ) -> Dict[str, List[CVECorrelationSuggestion]]:
        """
        Runs CVE correlation across all findings in a VulnerabilityReport.
        Returns a dictionary mapping finding_id -> list of CVECorrelationSuggestion.
        """
        results: Dict[str, List[CVECorrelationSuggestion]] = {}
        for finding in report.findings:
            matches = self.correlate_finding(finding, top_k=top_k, min_score=min_score)
            if matches:
                results[finding.id] = matches
        return results
