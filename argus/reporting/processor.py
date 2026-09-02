from __future__ import annotations

from typing import Any, Iterable, List, Optional, Union
from urllib.parse import urlparse
from uuid import uuid4

from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.reporting.cvss import CVSSCalculator
from argus.reporting.models import (
    CVSSData,
    CWEInfo,
    Finding,
    ReportSeverity,
    ReportSummary,
    VulnerabilityReport,
)


class EvidenceProcessor:
    """Processes, normalizes, deduplicates, and groups raw security evidence into structured findings."""

    def __init__(self, default_target: str = "Unknown Target"):
        self.default_target = default_target

    def process(
        self,
        evidence_source: Union[EvidenceStore, Iterable[Evidence], List[Any]],
        target: Optional[str] = None,
        mission_id: str = "ad-hoc",
    ) -> VulnerabilityReport:
        """Transforms raw evidence collection into a fully deduplicated, sorted, and grouped VulnerabilityReport."""
        effective_target = target or self.default_target
        raw_items = self._extract_raw_items(evidence_source)
        total_evidence_items = len(raw_items)

        # Map for deduplication: key -> Finding
        dedup_map: dict[tuple[str, str, str, str], Finding] = {}

        for item in raw_items:
            finding_candidate = self._normalize_evidence_to_finding(item, effective_target)
            dedup_key = (
                finding_candidate.category.lower().strip(),
                finding_candidate.host.lower().strip(),
                finding_candidate.endpoint.lower().strip(),
                (finding_candidate.parameter or "").lower().strip(),
            )

            if dedup_key in dedup_map:
                existing = dedup_map[dedup_key]
                self._merge_findings(existing, finding_candidate)
            else:
                dedup_map[dedup_key] = finding_candidate

        # Extract findings and sort deterministically
        findings = list(dedup_map.values())
        findings.sort(key=self._finding_sort_key)

        # Build groupings
        grouped_by_category: dict[str, list[Finding]] = {}
        grouped_by_host: dict[str, list[Finding]] = {}

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        category_counts: dict[str, int] = {}
        host_counts: dict[str, int] = {}

        for f in findings:
            # Severity counts
            sev_key = f.severity.lower()
            if sev_key in severity_counts:
                severity_counts[sev_key] += 1
            else:
                severity_counts["info"] += 1

            # Category grouping & counts
            cat_key = f.category
            if cat_key not in grouped_by_category:
                grouped_by_category[cat_key] = []
            grouped_by_category[cat_key].append(f)
            category_counts[cat_key] = category_counts.get(cat_key, 0) + 1

            # Host grouping & counts
            h_key = f.host or "Unknown Host"
            if h_key not in grouped_by_host:
                grouped_by_host[h_key] = []
            grouped_by_host[h_key].append(f)
            host_counts[h_key] = host_counts.get(h_key, 0) + 1

        deduplicated_count = total_evidence_items - len(findings)
        summary = ReportSummary(
            total_findings=len(findings),
            total_evidence_items=total_evidence_items,
            deduplicated_count=max(0, deduplicated_count),
            severity_counts=severity_counts,
            category_counts=category_counts,
            host_counts=host_counts,
        )

        return VulnerabilityReport(
            report_id=str(uuid4()),
            mission_id=mission_id,
            target=effective_target,
            summary=summary,
            findings=findings,
            grouped_by_category=grouped_by_category,
            grouped_by_host=grouped_by_host,
        )

    def _extract_raw_items(
        self, evidence_source: Union[EvidenceStore, Iterable[Evidence], List[Any]]
    ) -> list[Any]:
        if evidence_source is None:
            return []
        if isinstance(evidence_source, EvidenceStore) or hasattr(evidence_source, "all"):
            return list(evidence_source.all())
        if isinstance(evidence_source, (list, tuple, set)):
            return list(evidence_source)
        try:
            return list(evidence_source)
        except TypeError:
            return [evidence_source]

    def _normalize_evidence_to_finding(self, ev: Any, target_fallback: str) -> Finding:
        """Extracts and normalizes attributes from an Evidence or dict-like object."""
        meta = getattr(ev, "metadata", {}) or {}
        if not isinstance(meta, dict):
            meta = {}

        # 1. Category
        category = str(getattr(ev, "category", "") or meta.get("category") or "general").strip().lower()
        if category in ("other", ""):
            category = "general"

        # 2. Host & Endpoint extraction
        host, endpoint = self._extract_host_and_endpoint(ev, meta, target_fallback)

        # 3. Parameter & Payload
        parameter = (
            meta.get("parameter")
            or meta.get("param")
            or meta.get("vulnerable_parameter")
            or meta.get("query_param")
            or None
        )
        if parameter is not None:
            parameter = str(parameter).strip()

        param_type = (
            meta.get("parameter_type")
            or meta.get("param_type")
            or ("query" if parameter and "?" in endpoint else None)
        )

        payload = (
            meta.get("payload")
            or meta.get("poc")
            or meta.get("exploit")
            or meta.get("payload_sample")
            or None
        )
        if payload is not None:
            payload = str(payload)

        # 4. Severity & CVSS
        raw_sev = getattr(ev, "severity", None) or meta.get("severity") or "info"
        sev_enum = ReportSeverity.from_string(str(raw_sev))
        severity_str = sev_enum.value

        cvss_data = CVSSCalculator.get_approximate_cvss(category, severity_str, meta)
        cwe_data = CVSSCalculator.get_cwe_for_category(category, meta)

        # 5. Title
        title = getattr(ev, "title", "") or meta.get("title") or ""
        if not title:
            human_cat = category.replace("_", " ").title()
            if endpoint and endpoint != "/":
                title = f"{human_cat} in {endpoint}"
            elif host:
                title = f"{human_cat} on {host}"
            else:
                title = f"{human_cat} Vulnerability"

        # 6. Description
        description = getattr(ev, "description", "") or meta.get("description") or ""
        if not description:
            description = self._generate_default_description(category, host, endpoint, parameter, payload)

        # 7. Steps to reproduce
        steps = self._extract_or_generate_steps(meta, host, endpoint, parameter, payload, category)

        # 8. Impact & Remediation
        impact = meta.get("impact") or self._generate_default_impact(category, severity_str)
        remediation = meta.get("remediation") or self._generate_default_remediation(category, cwe_data)

        # 9. Confidence, Status, IDs, Tags
        confidence = float(getattr(ev, "confidence", 1.0) or 1.0)
        status = str(getattr(ev, "status", "CONFIRMED") or "CONFIRMED")
        ev_id = str(getattr(ev, "evidence_id", "") or meta.get("id") or str(uuid4()))
        tags = list(getattr(ev, "tags", []) or meta.get("tags", []))
        references = list(meta.get("references", []))

        # Store extra context in metadata
        combined_meta = dict(meta)
        if hasattr(ev, "value") and ev.value:
            combined_meta["evidence_value"] = str(ev.value)
        if hasattr(ev, "source") and ev.source:
            combined_meta["source"] = str(ev.source)

        return Finding(
            id=str(uuid4()),
            title=title,
            category=category,
            severity=severity_str,
            cvss=cvss_data,
            cwe=cwe_data,
            host=host,
            endpoint=endpoint,
            parameter=parameter,
            parameter_type=param_type,
            payload=payload,
            description=description,
            steps_to_reproduce=steps,
            impact=impact,
            remediation=remediation,
            confidence=confidence,
            status=status,
            evidence_ids=[ev_id] if ev_id else [],
            duplicate_count=1,
            tags=tags,
            references=references,
            metadata=combined_meta,
        )

    def _extract_host_and_endpoint(
        self, ev: Any, meta: dict[str, Any], target_fallback: str
    ) -> tuple[str, str]:
        """Resolves target host and endpoint from URL, metadata, or evidence value."""
        url_candidate = (
            meta.get("url")
            or meta.get("endpoint_url")
            or meta.get("target_url")
            or getattr(ev, "content_reference", "")
            or getattr(ev, "value", "")
        )

        host = meta.get("host") or meta.get("domain") or meta.get("target") or ""
        endpoint = meta.get("endpoint") or meta.get("path") or ""

        if url_candidate and ("http://" in str(url_candidate) or "https://" in str(url_candidate)):
            parsed = urlparse(str(url_candidate))
            if not host and parsed.netloc:
                host = parsed.netloc
            if not endpoint and parsed.path:
                endpoint = parsed.path
                if parsed.query:
                    endpoint += f"?{parsed.query}"

        if not host:
            # If target_fallback is URL
            if target_fallback.startswith("http://") or target_fallback.startswith("https://"):
                parsed_target = urlparse(target_fallback)
                host = parsed_target.netloc or target_fallback
            else:
                host = target_fallback or "Unknown Host"

        if not endpoint:
            if hasattr(ev, "value") and str(ev.value).startswith("/"):
                endpoint = str(ev.value)
            else:
                endpoint = "/"

        return host, endpoint

    def _merge_findings(self, existing: Finding, incoming: Finding) -> None:
        """Merges duplicate finding into existing finding, retaining highest severity and confidence."""
        existing.duplicate_count += 1

        # Combine evidence IDs
        for ev_id in incoming.evidence_ids:
            if ev_id not in existing.evidence_ids:
                existing.evidence_ids.append(ev_id)

        # Severity comparison (retain highest rank)
        existing_sev = ReportSeverity.from_string(existing.severity)
        incoming_sev = ReportSeverity.from_string(incoming.severity)
        if incoming_sev.rank > existing_sev.rank or incoming.cvss.score > existing.cvss.score:
            existing.severity = incoming.severity
            existing.cvss = incoming.cvss
            if incoming.cwe and not existing.cwe:
                existing.cwe = incoming.cwe

        # Confidence (retain highest)
        if incoming.confidence > existing.confidence:
            existing.confidence = incoming.confidence

        # Combine Tags
        for tag in incoming.tags:
            if tag not in existing.tags:
                existing.tags.append(tag)

        # Combine References
        for ref in incoming.references:
            if ref not in existing.references:
                existing.references.append(ref)

        # Enrich payload / parameters if existing was empty
        if not existing.payload and incoming.payload:
            existing.payload = incoming.payload
        if not existing.parameter and incoming.parameter:
            existing.parameter = incoming.parameter
            existing.parameter_type = incoming.parameter_type

        # Merge metadata
        for k, v in incoming.metadata.items():
            if k not in existing.metadata:
                existing.metadata[k] = v

    @staticmethod
    def _finding_sort_key(f: Finding) -> tuple[int, float, str]:
        """Sorting key: Severity Rank (descending) -> CVSS Score (descending) -> Title (ascending)."""
        sev_rank = ReportSeverity.from_string(f.severity).rank
        # Return negative values for descending sorts
        return (-sev_rank, -f.cvss.score, f.title.lower())

    def _extract_or_generate_steps(
        self,
        meta: dict[str, Any],
        host: str,
        endpoint: str,
        parameter: Optional[str],
        payload: Optional[str],
        category: str,
    ) -> list[str]:
        if "steps_to_reproduce" in meta and isinstance(meta["steps_to_reproduce"], list):
            return [str(s) for s in meta["steps_to_reproduce"]]
        if "steps" in meta and isinstance(meta["steps"], list):
            return [str(s) for s in meta["steps"]]

        steps = [
            f"Navigate to the target endpoint `{endpoint}` on host `{host}`.",
        ]
        if parameter and payload:
            steps.append(
                f"Inject the security verification payload into the parameter `{parameter}`: `{payload}`."
            )
            steps.append(
                f"Submit the request and inspect the server response for indications of {category.replace('_', ' ')}."
            )
        elif payload:
            steps.append(f"Send the payload `{payload}` in the HTTP request body or headers.")
            steps.append("Verify that the application processes the input without adequate validation.")
        else:
            steps.append(f"Send a crafted HTTP request to `{endpoint}`.")
            steps.append(f"Observe the anomalous response behavior confirming {category.replace('_', ' ')}.")

        return steps

    @staticmethod
    def _generate_default_description(
        category: str,
        host: str,
        endpoint: str,
        parameter: Optional[str],
        payload: Optional[str],
    ) -> str:
        cat_title = category.replace("_", " ").title()
        desc = f"During security analysis of `{host}`, a {cat_title} vulnerability was identified at endpoint `{endpoint}`."
        if parameter:
            desc += f" The vulnerable input vector is the `{parameter}` parameter."
        if payload:
            desc += f" The vulnerability was triggered using payload: `{payload}`."
        return desc

    @staticmethod
    def _generate_default_impact(category: str, severity: str) -> str:
        cat = category.lower()
        if "sql" in cat:
            return "An attacker could manipulate database queries, leading to unauthorized read, modification, or deletion of sensitive database records, or potential administrative takeover."
        elif any(k in cat for k in ("rce", "command", "code", "deserialization")):
            return "An attacker could execute arbitrary operating system commands on the host server, achieving full system compromise and unauthorized remote control."
        elif any(k in cat for k in ("ssrf", "server_side_request")):
            return "An attacker could coerce the application server to make unauthorized requests to internal network services, cloud metadata endpoints, or adjacent private infrastructure."
        elif any(k in cat for k in ("idor", "bola", "broken_access", "bac")):
            return "An unauthorized user could access, modify, or delete resources belonging to other tenants or users, completely bypassing object-level access controls."
        elif any(k in cat for k in ("auth", "authentication")):
            return "An attacker could bypass authentication mechanisms and impersonate arbitrary user accounts or administrative identities."
        elif any(k in cat for k in ("xss", "cross_site_scripting")):
            return "An attacker could execute malicious scripts in the context of a victim user's browser session, leading to session hijacking, credential theft, or sensitive action execution."
        elif "csrf" in cat:
            return "An attacker could induce authenticated users to perform unintended actions without their consent."
        elif any(k in cat for k in ("info", "leak", "sensitive_data")):
            return "Exposure of sensitive system details, internal endpoints, or credentials that may assist attackers in staging further targeted attacks."
        elif any(k in cat for k in ("business_logic", "price_tampering", "workflow_step_skip", "mass_assignment", "coupon_stacking", "state_machine")):
            return "An attacker could manipulate application workflows, bypass critical payment or verification steps, tamper with pricing calculations, or escalate privileges via unauthorized parameter assignment."
        elif any(k in cat for k in ("ssti", "template_injection", "jinja", "twig", "freemarker", "velocity", "mako", "spel", "thymeleaf", "erb", "smarty")):
            return "An attacker could inject arbitrary template directives into server-side template engines, leading to remote code execution (RCE), arbitrary file read/write, sensitive data disclosure, or full host takeover."
        elif any(k in cat for k in ("cache_deception", "web_cache_deception", "wcd")):
            return "An attacker could induce caching reverse proxies or CDNs to store sensitive authenticated user data under static extension routes, allowing unauthenticated attackers to steal victim credentials and PII."
        elif any(k in cat for k in ("cache", "cache_security", "web_cache_poisoning", "cache_poisoning", "unkeyed_header", "unkeyed_param")):
            return "An attacker could poison shared web caching layers (CDNs/reverse proxies) by injecting unkeyed headers, parameters, or FAT GET payloads, serving malicious scripts, redirects, or altered content to all subsequent users."
        elif "redirect" in cat:
            return "An attacker could redirect users to external phishing sites while leveraging the trusted domain of the host."
        else:
            return f"Successful exploitation could compromise the confidentiality, integrity, or availability of the application with {severity} impact."

    @staticmethod
    def _generate_default_remediation(category: str, cwe: Optional[CWEInfo]) -> str:
        cat = category.lower()
        if "sql" in cat:
            return "Use parameterized queries or Object-Relational Mapping (ORM) frameworks with prepared statements. Never concatenate untrusted user input directly into SQL queries."
        elif any(k in cat for k in ("rce", "command", "code")):
            return "Avoid passing user input directly to system command execution functions. Use safe native APIs or enforce strict allowlist validation."
        elif "ssrf" in cat:
            return "Implement strict allowlisting of permissible destination hosts and protocols. Block requests to private IP ranges (RFC 1918) and cloud metadata services (e.g., 169.254.169.254)."
        elif any(k in cat for k in ("idor", "bola", "broken_access", "bac")):
            return "Enforce robust server-side authorization checks for every requested object, validating that the requesting identity has explicit permission to access the resource."
        elif any(k in cat for k in ("auth", "authentication")):
            return "Enforce strong authentication mechanisms, secure session management, and server-side token validation on all protected endpoints."
        elif any(k in cat for k in ("xss", "cross_site_scripting")):
            return "Contextually encode all user-supplied output before rendering it in web pages, and implement a robust Content Security Policy (CSP)."
        elif "csrf" in cat:
            return "Implement anti-CSRF tokens using the synchronizer token pattern or SameSite cookie attributes (SameSite=Strict or SameSite=Lax)."
        elif any(k in cat for k in ("business_logic", "price_tampering", "workflow_step_skip", "mass_assignment", "coupon_stacking", "state_machine")):
            return "Enforce strict server-side state machine validation and authoritative price calculation. Implement robust field allowlisting (mass assignment protection), cryptographically verify intermediate workflow step completion before fulfillment, and enforce idempotency on discount/coupon redemptions."
        elif any(k in cat for k in ("ssti", "template_injection", "jinja", "twig", "freemarker", "velocity", "mako", "spel", "thymeleaf", "erb", "smarty")):
            return "Never concatenate untrusted user input directly into template strings. Pass dynamic data strictly as template context variables. Utilize hardened sandboxes, disable arbitrary reflection/classloader access, and enforce strict input validation allowlists."
        elif any(k in cat for k in ("cache_deception", "web_cache_deception", "wcd")):
            return "Configure reverse proxies and CDNs to only cache static assets based on strict Content-Type headers rather than URL file extensions. Enforce Cache-Control: no-store, private on all authenticated dynamic endpoints."
        elif any(k in cat for k in ("cache", "cache_security", "web_cache_poisoning", "cache_poisoning", "unkeyed_header", "unkeyed_param")):
            return "Include all unkeyed input headers in the cache key or strip untrusted reverse proxy headers at the perimeter. Enforce strict Cache-Control directives, normalize request keys, and disable FAT GET body evaluation."


        elif any(k in cat for k in ("info", "leak", "sensitive_data")):
            return "Disable verbose error messages and debug outputs in production environments. Restrict access to sensitive configuration files and endpoints."
        elif "redirect" in cat:
            return "Avoid user-controllable destination URLs in redirection logic. Validate redirect targets against a strict allowlist of authorized relative paths or domains."
        else:
            cwe_ref = f" ({cwe.id})" if cwe else ""
            return f"Apply input validation, output encoding, and principle of least privilege to remediate the underlying flaw{cwe_ref}."
