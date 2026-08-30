"""
Response Discrepancy Analyzer.

Differential response analysis engine for detecting Broken Access Control (BAC),
Insecure Direct Object References (IDOR), Vertical Privilege Escalation, and
Reverse Proxy Header Bypasses while eliminating false positives.
"""
from __future__ import annotations

import difflib
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, List, Set

from argus.http.client import HttpResponse
from argus.models.test_identity import TestIdentity

logger = logging.getLogger(__name__)

# Signatures for soft errors and login pages
LOGIN_FORM_PATTERNS = [
    re.compile(r"<form[^>]*action=[\"'][^\"']*(?:login|signin|auth)[^\"']*[\"']", re.IGNORECASE),
    re.compile(r"<input[^>]*type=[\"']password[\"']", re.IGNORECASE),
]

ERROR_TEXT_PATTERNS = [
    re.compile(
        r"\b(access[_\-\s]*denied|unauthorized|forbidden|authentication[_\-\s]*required|"
        r"please\s+log\s+in|sign\s+in\s+to\s+continue|session[_\-\s]*expired|invalid[_\-\s]*session|"
        r"invalid[_\-\s]*credentials|permission[_\-\s]*denied|you\s+do\s+not\s+have\s+(?:the\s+)?(?:permission|access|authorization)|"
        r"you\s+don'?t\s+have\s+(?:the\s+)?(?:permission|access|authorization)|insufficient[_\-\s]*(?:privileges?|permissions?|scope)|"
        r"not\s+authorized|not\s+permitted|access\s+restricted|user\s+not\s+found|resource\s+not\s+found|unauthenticated)\b",
        re.IGNORECASE,
    ),
]

GENERIC_DISCARD_VALUES: Set[str] = {
    "true", "false", "null", "none", "undefined", "user", "admin", "test",
    "default", "system", "anonymous", "guest", "", "{}", "[]"
}


@dataclass
class DiscrepancyVerdict:
    """Outcome of differential response discrepancy analysis."""
    is_vulnerable: bool
    confidence: float
    discrepancy_type: str  # "horizontal_idor", "vertical_privilege_escalation", "header_bypass", "none"
    reason: str
    leaked_data: Dict[str, Any] = field(default_factory=dict)
    similarity_score: float = 0.0
    primary_status: Optional[int] = None
    secondary_status: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class ResponseDiscrepancyAnalyzer:
    """
    Analyzes and compares HTTP responses across different authenticated identities
    and unauthenticated probes to accurately classify access control vulnerabilities.
    """

    def is_error_or_login_response(self, response: Optional[HttpResponse]) -> bool:
        """
        Determines whether a response represents an error, access restriction,
        or login prompt, regardless of the HTTP status code.
        """
        if response is None:
            return True

        if not response.success:
            return True

        status = response.status_code
        if status is not None and status in (400, 401, 403, 404, 405, 422, 500, 502, 503, 504):
            return True

        raw_body = response.raw_body if response.raw_body is not None else (response.body or "")
        body_clean = raw_body.strip()

        # Near-empty responses on unauthorized requests
        if len(body_clean) < 5:
            return True

        # Check JSON soft errors
        try:
            parsed = json.loads(body_clean)
            if isinstance(parsed, dict):
                # Check for explicit boolean failure
                if parsed.get("success") is False:
                    return True
                if str(parsed.get("status", "")).lower() in ("error", "fail", "failed", "unauthorized", "forbidden"):
                    return True

                # Check error fields
                for err_key in ("error", "errors", "message", "msg", "detail", "reason", "description"):
                    if err_key in parsed:
                        val_str = str(parsed[err_key]).lower()
                        for pat in ERROR_TEXT_PATTERNS:
                            if pat.search(val_str):
                                return True
        except Exception:
            pass

        # Check HTML login forms
        for form_pat in LOGIN_FORM_PATTERNS:
            if form_pat.search(raw_body):
                return True

        # Check text error keywords
        for text_pat in ERROR_TEXT_PATTERNS:
            if text_pat.search(raw_body):
                return True

        return False

    def extract_identity_leakage(
        self,
        target_identity: TestIdentity,
        response_body: str,
        unauthorized_identity: Optional[TestIdentity] = None,
    ) -> Dict[str, Any]:
        """
        Scans response_body for distinctive private data belonging to target_identity
        that must not be exposed to unauthorized_identity.
        """
        if not response_body or not target_identity:
            return {"has_leakage": False, "leaked_fields": [], "matches": {}}

        # Unescape response_body if it is JSON to support \uXXXX escape sequences
        normalized_body = response_body
        try:
            parsed_json = json.loads(response_body)
            # Re-serialize with ensure_ascii=False or check against parsed dict/values
            normalized_body = json.dumps(parsed_json, ensure_ascii=False)
        except Exception:
            pass

        matches: Dict[str, Any] = {}
        leaked_fields: List[str] = []

        unauth_values: Set[str] = set()
        if unauthorized_identity:
            if unauthorized_identity.id:
                unauth_values.add(str(unauthorized_identity.id).lower())
            if unauthorized_identity.name:
                unauth_values.add(str(unauthorized_identity.name).lower())
            for val in unauthorized_identity.credentials.values():
                if val:
                    unauth_values.add(str(val).lower())
            for val in unauthorized_identity.metadata.values():
                if val:
                    unauth_values.add(str(val).lower())

        def evaluate_candidate(field_name: str, value: Any):
            if value is None:
                return
            v_str = str(value).strip()
            v_lower = v_str.lower()
            if len(v_str) < 3 or v_lower in GENERIC_DISCARD_VALUES or v_lower in unauth_values:
                return
            if v_str in normalized_body or v_lower in normalized_body.lower():
                if field_name not in matches:
                    matches[field_name] = v_str
                    leaked_fields.append(field_name)

        # 1. Target ID and Name
        evaluate_candidate("id", target_identity.id)
        evaluate_candidate("name", target_identity.name)

        # 2. Target Credentials
        for k, v in target_identity.credentials.items():
            evaluate_candidate(f"credential.{k}", v)

        # 3. Target Metadata
        for k, v in target_identity.metadata.items():
            evaluate_candidate(f"metadata.{k}", v)

        # 4. JSON body deep match for target's identifiers
        try:
            parsed = json.loads(response_body)
            if isinstance(parsed, dict):
                # Check for direct ID / username / email field match
                for id_field in ("id", "user_id", "userId", "account_id", "accountId", "email", "username"):
                    if id_field in parsed:
                        val = str(parsed[id_field])
                        if target_identity.id and val == str(target_identity.id):
                            evaluate_candidate("json.id", val)
                        elif target_identity.name and val == str(target_identity.name):
                            evaluate_candidate("json.name", val)
                        for cred_k, cred_v in target_identity.credentials.items():
                            if str(cred_v) == val:
                                evaluate_candidate(f"json.{cred_k}", val)
        except Exception:
            pass

        has_leakage = len(leaked_fields) > 0
        return {
            "has_leakage": has_leakage,
            "leaked_fields": leaked_fields,
            "matches": matches,
        }

    def analyze_horizontal(
        self,
        auth_response: HttpResponse,
        unauth_response: HttpResponse,
        auth_identity: TestIdentity,
        unauth_identity: TestIdentity,
    ) -> DiscrepancyVerdict:
        """
        Evaluates horizontal privilege escalation (IDOR) by comparing the response
        received by the authorized owner vs. the unauthorized requesting identity.
        """
        # Status code verification
        unauth_status = unauth_response.status_code
        auth_status = auth_response.status_code

        if unauth_status not in (200, 201, 202, 203, 204) or not unauth_response.success:
            return DiscrepancyVerdict(
                is_vulnerable=False,
                confidence=0.0,
                discrepancy_type="horizontal_idor",
                reason=f"Unauthorized request was properly rejected (HTTP {unauth_status})",
                primary_status=auth_status,
                secondary_status=unauth_status,
            )

        # Soft error / login prompt rejection
        if self.is_error_or_login_response(unauth_response):
            return DiscrepancyVerdict(
                is_vulnerable=False,
                confidence=0.0,
                discrepancy_type="horizontal_idor",
                reason="Unauthorized response contains an error message, login form, or access denied",
                primary_status=auth_status,
                secondary_status=unauth_status,
            )

        raw_unauth = unauth_response.raw_body if unauth_response.raw_body is not None else (unauth_response.body or "")
        raw_auth = auth_response.raw_body if auth_response.raw_body is not None else (auth_response.body or "")

        # Check for explicit identity data leakage
        leak_info = self.extract_identity_leakage(auth_identity, raw_unauth, unauth_identity)
        if leak_info["has_leakage"]:
            return DiscrepancyVerdict(
                is_vulnerable=True,
                confidence=0.95,
                discrepancy_type="horizontal_idor",
                reason=f"Confirmed Horizontal IDOR: Unauthorized identity '{unauth_identity.id}' accessed resource belonging to '{auth_identity.id}' and received private data ({', '.join(leak_info['leaked_fields'])})",
                leaked_data=leak_info["matches"],
                similarity_score=1.0,
                primary_status=auth_status,
                secondary_status=unauth_status,
                metadata={
                    "auth_identity": auth_identity.id,
                    "unauth_identity": unauth_identity.id,
                    "leaked_fields": leak_info["leaked_fields"],
                },
            )

        # Content similarity evaluation
        if auth_status in (200, 201, 204) and len(raw_unauth) >= 20:
            sample_auth = raw_auth[:5000]
            sample_unauth = raw_unauth[:5000]
            similarity = difflib.SequenceMatcher(None, sample_auth, sample_unauth).ratio()

            if similarity >= 0.85:
                return DiscrepancyVerdict(
                    is_vulnerable=True,
                    confidence=0.85,
                    discrepancy_type="horizontal_idor",
                    reason=f"Horizontal IDOR detected: Unauthorized response matched authorized owner response with high similarity ({similarity:.2f})",
                    similarity_score=similarity,
                    primary_status=auth_status,
                    secondary_status=unauth_status,
                    metadata={
                        "auth_identity": auth_identity.id,
                        "unauth_identity": unauth_identity.id,
                        "similarity": similarity,
                    },
                )

        return DiscrepancyVerdict(
            is_vulnerable=False,
            confidence=0.0,
            discrepancy_type="horizontal_idor",
            reason="Unauthorized response did not disclose target identity data or match owner response",
            primary_status=auth_status,
            secondary_status=unauth_status,
        )

    def analyze_vertical(
        self,
        admin_response: Optional[HttpResponse],
        user_response: HttpResponse,
        admin_identity: Optional[TestIdentity],
        user_identity: TestIdentity,
        endpoint_path: str = "",
    ) -> DiscrepancyVerdict:
        """
        Evaluates vertical privilege escalation when an unprivileged or guest identity
        attempts to access an administrative or privileged endpoint.
        """
        user_status = user_response.status_code
        admin_status = admin_response.status_code if admin_response else None

        if user_status not in (200, 201, 202, 203, 204) or not user_response.success:
            return DiscrepancyVerdict(
                is_vulnerable=False,
                confidence=0.0,
                discrepancy_type="vertical_privilege_escalation",
                reason=f"Unprivileged request was properly blocked (HTTP {user_status})",
                primary_status=admin_status,
                secondary_status=user_status,
            )

        if self.is_error_or_login_response(user_response):
            return DiscrepancyVerdict(
                is_vulnerable=False,
                confidence=0.0,
                discrepancy_type="vertical_privilege_escalation",
                reason="Unprivileged response is an error message, login page, or access restriction",
                primary_status=admin_status,
                secondary_status=user_status,
            )

        raw_user = user_response.raw_body if user_response.raw_body is not None else (user_response.body or "")
        user_role = getattr(user_identity, "role", "user") or "user"

        if admin_response and admin_response.status_code in (200, 201, 204):
            raw_admin = admin_response.raw_body if admin_response.raw_body is not None else (admin_response.body or "")
            similarity = difflib.SequenceMatcher(None, raw_admin[:5000], raw_user[:5000]).ratio()
            if similarity >= 0.70:
                return DiscrepancyVerdict(
                    is_vulnerable=True,
                    confidence=0.90,
                    discrepancy_type="vertical_privilege_escalation",
                    reason=f"Vertical privilege escalation confirmed: Unprivileged role '{user_role}' accessed administrative endpoint '{endpoint_path}' with valid response (similarity {similarity:.2f})",
                    similarity_score=similarity,
                    primary_status=admin_status,
                    secondary_status=user_status,
                    metadata={
                        "user_role": user_role,
                        "endpoint": endpoint_path,
                        "similarity": similarity,
                    },
                )

        # Standalone access to administrative endpoint with 200 OK and valid non-error content
        if len(raw_user) >= 20:
            return DiscrepancyVerdict(
                is_vulnerable=True,
                confidence=0.85,
                discrepancy_type="vertical_privilege_escalation",
                reason=f"Vertical privilege escalation: Unprivileged role '{user_role}' received HTTP {user_status} on administrative endpoint '{endpoint_path}'",
                similarity_score=1.0,
                primary_status=admin_status,
                secondary_status=user_status,
                metadata={
                    "user_role": user_role,
                    "endpoint": endpoint_path,
                },
            )

        return DiscrepancyVerdict(
            is_vulnerable=False,
            confidence=0.0,
            discrepancy_type="vertical_privilege_escalation",
            reason="Unprivileged response did not yield administrative functionality",
            primary_status=admin_status,
            secondary_status=user_status,
        )

    def analyze_header_bypass(
        self,
        baseline_response: HttpResponse,
        bypass_response: HttpResponse,
        header_name: str,
        header_value: str,
    ) -> DiscrepancyVerdict:
        """
        Evaluates reverse proxy / WAF header injection bypasses (e.g. X-Original-URL, X-Rewrite-URL).
        """
        base_status = baseline_response.status_code
        bypass_status = bypass_response.status_code

        # Baseline must have been blocked
        if base_status not in (401, 403, 404, 405, 500) and baseline_response.success:
            return DiscrepancyVerdict(
                is_vulnerable=False,
                confidence=0.0,
                discrepancy_type="header_bypass",
                reason=f"Baseline request was not restricted (HTTP {base_status})",
                primary_status=base_status,
                secondary_status=bypass_status,
            )

        # Bypass response must be successful 2xx
        if bypass_status not in (200, 201, 202, 204) or not bypass_response.success:
            return DiscrepancyVerdict(
                is_vulnerable=False,
                confidence=0.0,
                discrepancy_type="header_bypass",
                reason=f"Header injection was not successful (HTTP {bypass_status})",
                primary_status=base_status,
                secondary_status=bypass_status,
            )

        # Bypass response must not be soft error / login
        if self.is_error_or_login_response(bypass_response):
            return DiscrepancyVerdict(
                is_vulnerable=False,
                confidence=0.0,
                discrepancy_type="header_bypass",
                reason="Bypass response yielded an error or login page",
                primary_status=base_status,
                secondary_status=bypass_status,
            )

        return DiscrepancyVerdict(
            is_vulnerable=True,
            confidence=0.90,
            discrepancy_type="header_bypass",
            reason=f"Access control header bypass confirmed: '{header_name}: {header_value}' converted HTTP {base_status} into HTTP {bypass_status}",
            primary_status=base_status,
            secondary_status=bypass_status,
            metadata={
                "header_name": header_name,
                "header_value": header_value,
                "baseline_status": base_status,
                "bypass_status": bypass_status,
            },
        )
