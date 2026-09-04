"""Burp Suite Scan Results Importer for ARGUS Evidence Store."""

import base64
import json
import logging
from typing import Any, Dict, List, Optional, Union

try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

from argus.evidence.model import Evidence, ProvenanceData

logger = logging.getLogger(__name__)

SEVERITY_MAP: Dict[str, str] = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "information": "info",
    "info": "info",
    "critical": "critical",
    "false positive": "info",
}

CONFIDENCE_MAP: Dict[str, float] = {
    "certain": 1.0,
    "firm": 0.8,
    "tentative": 0.5,
    "high": 0.9,
    "medium": 0.7,
    "low": 0.4,
}


def _decode_b64(content: Optional[str]) -> Optional[str]:
    """Safely decode a base64-encoded string to UTF-8 text."""
    if not content:
        return content
    try:
        decoded_bytes = base64.b64decode(content.strip())
        return decoded_bytes.decode("utf-8", errors="replace")
    except Exception:
        return content


def _normalize_severity(raw_severity: Optional[str]) -> str:
    """Normalize severity string to standard lowercase format."""
    if not raw_severity:
        return "info"
    return SEVERITY_MAP.get(str(raw_severity).strip().lower(), "info")


def _normalize_confidence(raw_confidence: Any) -> float:
    """Normalize confidence string or numeric value to float between 0.0 and 1.0."""
    if raw_confidence is None:
        return 0.8
    if isinstance(raw_confidence, (int, float)):
        return max(0.0, min(1.0, float(raw_confidence)))
    conf_str = str(raw_confidence).strip().lower()
    return CONFIDENCE_MAP.get(conf_str, 0.8)


class BurpScanImporter:
    """Parser and importer for Burp Suite XML and JSON scan export files."""

    def __init__(self, mission: Optional[Any] = None) -> None:
        self.mission = mission

    def parse_xml(self, xml_content: str) -> List[Dict[str, Any]]:
        """Parse Burp XML scan report content into structured issue dictionaries.

        Handles <issues><issue> elements, extracting metadata, descriptions,
        remediations, and base64-decoded HTTP request/response sequences.
        """
        if not xml_content or not xml_content.strip():
            return []

        try:
            root = ET.fromstring(xml_content)
        except Exception as e:
            logger.error("Failed to parse Burp XML: %s", e)
            raise ValueError(f"Invalid XML format: {e}") from e

        issues: List[Dict[str, Any]] = []

        # Find all issue elements (can be root if single <issue> or children if <issues>)
        issue_nodes = root.findall(".//issue")
        if not issue_nodes and root.tag == "issue":
            issue_nodes = [root]

        for node in issue_nodes:
            issue: Dict[str, Any] = {}

            # Parse scalar fields
            for child in node:
                tag = child.tag
                if tag == "serialNumber":
                    issue["serial_number"] = child.text.strip() if child.text else ""
                elif tag == "type":
                    issue["issue_type"] = child.text.strip() if child.text else ""
                elif tag == "name":
                    issue["name"] = child.text.strip() if child.text else ""
                elif tag == "host":
                    issue["host"] = child.text.strip() if child.text else ""
                    if "ip" in child.attrib:
                        issue["host_ip"] = child.attrib["ip"]
                elif tag == "path":
                    issue["path"] = child.text.strip() if child.text else ""
                elif tag == "location":
                    issue["location"] = child.text.strip() if child.text else ""
                elif tag == "severity":
                    issue["severity"] = child.text.strip() if child.text else "info"
                elif tag == "confidence":
                    issue["confidence"] = child.text.strip() if child.text else "Certain"
                elif tag == "issueBackground":
                    issue["issue_background"] = child.text.strip() if child.text else ""
                elif tag == "remediationBackground":
                    issue["remediation_background"] = child.text.strip() if child.text else ""
                elif tag == "issueDetail":
                    issue["issue_detail"] = child.text.strip() if child.text else ""
                elif tag == "remediationDetail":
                    issue["remediation_detail"] = child.text.strip() if child.text else ""
                elif tag == "vulnerabilityClassifications":
                    issue["vulnerability_classifications"] = child.text.strip() if child.text else ""

            # Parse requestresponse pairs
            http_interactions: List[Dict[str, Any]] = []
            for rr_node in node.findall(".//requestresponse"):
                interaction: Dict[str, Any] = {}
                req_node = rr_node.find("request")
                if req_node is not None:
                    raw_req = req_node.text or ""
                    is_b64 = req_node.attrib.get("base64", "false").lower() == "true"
                    interaction["request"] = _decode_b64(raw_req) if is_b64 else raw_req
                    interaction["request_raw"] = raw_req
                    interaction["request_base64"] = is_b64

                resp_node = rr_node.find("response")
                if resp_node is not None:
                    raw_resp = resp_node.text or ""
                    is_b64 = resp_node.attrib.get("base64", "false").lower() == "true"
                    interaction["response"] = _decode_b64(raw_resp) if is_b64 else raw_resp
                    interaction["response_raw"] = raw_resp
                    interaction["response_base64"] = is_b64

                http_interactions.append(interaction)

            issue["http_interactions"] = http_interactions
            issues.append(issue)

        return issues

    def parse_json(self, json_content: str) -> List[Dict[str, Any]]:
        """Parse Burp JSON scan export content into structured issue dictionaries."""
        if not json_content or not json_content.strip():
            return []

        try:
            data = json.loads(json_content)
        except Exception as e:
            logger.error("Failed to parse Burp JSON: %s", e)
            raise ValueError(f"Invalid JSON format: {e}") from e

        raw_issues: List[Dict[str, Any]] = []
        if isinstance(data, list):
            raw_issues = data
        elif isinstance(data, dict):
            if "issues" in data and isinstance(data["issues"], list):
                raw_issues = data["issues"]
            elif "issue_events" in data and isinstance(data["issue_events"], list):
                for event in data["issue_events"]:
                    if isinstance(event, dict) and "issue" in event:
                        raw_issues.append(event["issue"])
                    elif isinstance(event, dict):
                        raw_issues.append(event)
            else:
                # Single issue object
                raw_issues = [data]

        issues: List[Dict[str, Any]] = []
        for raw in raw_issues:
            if not isinstance(raw, dict):
                continue
            issue: Dict[str, Any] = {
                "name": raw.get("name") or raw.get("issue_name") or "Burp Issue",
                "serial_number": str(raw.get("serial_number") or raw.get("serialNumber") or ""),
                "issue_type": str(raw.get("type") or raw.get("issue_type") or raw.get("type_index") or ""),
                "host": raw.get("host") or raw.get("origin") or "",
                "host_ip": raw.get("host_ip") or raw.get("ip") or "",
                "path": raw.get("path") or "",
                "location": raw.get("location") or raw.get("url") or "",
                "severity": raw.get("severity") or "info",
                "confidence": raw.get("confidence") or "Certain",
                "issue_background": raw.get("issue_background") or raw.get("issueBackground") or raw.get("description") or "",
                "remediation_background": raw.get("remediation_background") or raw.get("remediationBackground") or raw.get("remediation") or "",
                "issue_detail": raw.get("issue_detail") or raw.get("issueDetail") or raw.get("detail") or "",
                "remediation_detail": raw.get("remediation_detail") or raw.get("remediationDetail") or "",
            }

            # Handle requests/responses
            interactions: List[Dict[str, Any]] = []
            if "http_interactions" in raw and isinstance(raw["http_interactions"], list):
                interactions = raw["http_interactions"]
            elif "http_messages" in raw and isinstance(raw["http_messages"], list):
                for msg in raw["http_messages"]:
                    if isinstance(msg, dict):
                        req = msg.get("request", "")
                        resp = msg.get("response", "")
                        if msg.get("request_base64"):
                            req = _decode_b64(req)
                        if msg.get("response_base64"):
                            resp = _decode_b64(resp)
                        interactions.append({"request": req, "response": resp})
            elif "request" in raw or "response" in raw:
                req = raw.get("request", "")
                resp = raw.get("response", "")
                if raw.get("request_base64"):
                    req = _decode_b64(req)
                if raw.get("response_base64"):
                    resp = _decode_b64(resp)
                interactions.append({"request": req, "response": resp})

            issue["http_interactions"] = interactions
            issues.append(issue)

        return issues

    def import_scan(
        self,
        content: Optional[str] = None,
        file_path: Optional[str] = None,
        format: str = "auto",
        mission: Optional[Any] = None,
        mission_id: str = "",
    ) -> Dict[str, Any]:
        """Import Burp scan results from raw content string or file path.

        Converts all parsed issues into ARGUS Evidence instances, attaches them
        to the mission evidence store, and returns an import summary.

        Args:
            content: Raw XML or JSON text.
            file_path: Path to Burp XML/JSON export file.
            format: 'auto', 'xml', or 'json'.
            mission: Optional Mission object to attach findings and evidence to.
            mission_id: Optional mission ID string if mission object not provided.

        Returns:
            Dict containing status, import count, evidence IDs, and parsed issues.
        """
        target_mission = mission or self.mission

        if not content and not file_path:
            return {
                "status": "error",
                "message": "Either 'content' or 'file_path' must be provided.",
                "imported_count": 0,
                "issues": [],
                "evidence_ids": [],
            }

        raw_text = content or ""
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    raw_text = f.read()
            except Exception as e:
                logger.error("Failed to read scan file %s: %s", file_path, e)
                return {
                    "status": "error",
                    "message": f"Failed to read file: {e}",
                    "imported_count": 0,
                    "issues": [],
                    "evidence_ids": [],
                }

        # Auto-detect format
        fmt = format.lower()
        if fmt == "auto":
            trimmed = raw_text.strip()
            if trimmed.startswith("<") or "<?xml" in trimmed or "<issues" in trimmed:
                fmt = "xml"
            elif trimmed.startswith("{") or trimmed.startswith("["):
                fmt = "json"
            else:
                fmt = "xml"

        # Parse issues
        try:
            if fmt == "xml":
                issues = self.parse_xml(raw_text)
            elif fmt == "json":
                issues = self.parse_json(raw_text)
            else:
                return {
                    "status": "error",
                    "message": f"Unsupported format: {format}",
                    "imported_count": 0,
                    "issues": [],
                    "evidence_ids": [],
                }
        except Exception as e:
            return {
                "status": "error",
                "message": f"Parse error: {e}",
                "imported_count": 0,
                "issues": [],
                "evidence_ids": [],
            }

        effective_mission_id = (
            target_mission.id if target_mission and hasattr(target_mission, "id") else mission_id
        )

        created_evidences: List[Evidence] = []
        evidence_ids: List[str] = []

        for issue in issues:
            mapped_sev = _normalize_severity(issue.get("severity"))
            mapped_conf = _normalize_confidence(issue.get("confidence"))

            title = issue.get("name") or "Burp Suite Issue"
            location = issue.get("location") or (
                (issue.get("host", "") + issue.get("path", "")) if issue.get("host") else "burp_scan"
            )
            description = (
                issue.get("issue_detail")
                or issue.get("issue_background")
                or f"Burp Suite finding: {title} at {location}"
            )

            provenance = ProvenanceData(
                workflow_id=getattr(target_mission, "active_workflow_id", "") if target_mission else "",
                step_id="burp_import_scan",
            )

            evidence = Evidence(
                mission_id=effective_mission_id,
                source_type="TOOL",
                created_by="SYSTEM_GENERATED",
                title=title,
                description=description,
                category="burp_scan",
                value=json.dumps(issue, default=str),
                source=location,
                status="UNVERIFIED",
                confidence=mapped_conf,
                severity=mapped_sev,
                provenance=provenance,
                metadata={
                    **issue,
                    "mapped_severity": mapped_sev,
                    "mapped_confidence": mapped_conf,
                },
                tags=["burp", "burp_scan", mapped_sev],
            )

            created_evidences.append(evidence)
            evidence_ids.append(evidence.evidence_id)

            # Attach to mission
            if target_mission is not None:
                if hasattr(target_mission, "evidence") and target_mission.evidence is not None:
                    if hasattr(target_mission.evidence, "add"):
                        target_mission.evidence.add(evidence)
                    elif isinstance(target_mission.evidence, list):
                        target_mission.evidence.append(evidence)

                if hasattr(target_mission, "findings") and isinstance(target_mission.findings, list):
                    target_mission.findings.append(issue)

                if hasattr(target_mission, "vulnerabilities") and isinstance(
                    target_mission.vulnerabilities, list
                ):
                    target_mission.vulnerabilities.append({
                        "name": title,
                        "severity": mapped_sev,
                        "confidence": mapped_conf,
                        "host": issue.get("host"),
                        "path": issue.get("path"),
                        "location": location,
                        "source": "burp_scan",
                        "evidence_id": evidence.evidence_id,
                    })

        logger.info("Imported %d issues from Burp scan (%s)", len(created_evidences), fmt)

        return {
            "status": "success",
            "imported_count": len(created_evidences),
            "evidence_ids": evidence_ids,
            "issues": issues,
            "format": fmt,
        }
