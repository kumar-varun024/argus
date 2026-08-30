"""
Information Disclosure Collector & Secret Extractor Engine.

Actively probes live hosts, endpoints, and subdomains for exposed sensitive files
(.git/config, .env, phpinfo.php, .js.map, /actuator/env, etc.), extracts credentials,
API keys, database strings, private IPs, and internal domains, emits high-severity Evidence,
and expands the attack surface graph.
"""
from __future__ import annotations

import re
import json
import logging
import urllib.parse
from typing import Optional, List, Dict, Any, Set, Tuple

import httpx

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.graph.edge import Edge
from argus.http.client import AuthenticatedHttpClient

logger = logging.getLogger(__name__)

# Default high-value wordlist for active probing
DEFAULT_WORDLIST: List[str] = [
    ".git/config",
    ".git/HEAD",
    ".env",
    ".env.local",
    ".env.production",
    ".env.bak",
    "phpinfo.php",
    "info.php",
    ".js.map",
    "/actuator/env",
    "/actuator/heapdump",
    "/actuator/configprops",
]


class SecretExtractor:
    """
    Extracts secrets, API keys, tokens, credentials, private IPs,
    and internal hostnames/domains from arbitrary text payloads.
    """

    # Secret and token patterns
    GOOGLE_API_KEY_REGEX = re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b", re.ASCII)
    STRIPE_KEY_REGEX = re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})\b", re.ASCII)
    GITHUB_TOKEN_REGEX = re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36})\b", re.ASCII)
    SLACK_WEBHOOK_REGEX = re.compile(
        r"(https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8,12}\/B[a-zA-Z0-9_]{8,12}\/[a-zA-Z0-9_]{24})"
    )
    SLACK_TOKEN_REGEX = re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b", re.ASCII)
    AWS_ACCESS_KEY_REGEX = re.compile(r"\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b", re.ASCII)
    AWS_SECRET_KEY_REGEX = re.compile(
        r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9\/+=]{40})['\"]?"
    )
    JWT_REGEX = re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b", re.ASCII)
    PASSWORD_REGEX = re.compile(
        r"(?i)(?:db_password|database_password|password|passwd|pwd|db_pass|secret)\s*[:=]\s*['\"]?([^\s'\"#]{3,128})['\"]?"
    )
    GENERIC_API_KEY_REGEX = re.compile(
        r"(?i)(?:api_key|apikey|client_secret|app_secret|api_secret|access_token|auth_token|private_key)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{12,64})['\"]?"
    )
    DB_URI_REGEX = re.compile(
        r"\b((?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|amqp|mssql):\/\/(?:[a-zA-Z0-9_\-\.\%]*):(?:[^\s@]+)@(?:[a-zA-Z0-9_\-\.]+)(?::\d+)?(?:\/[a-zA-Z0-9_\-\.\?]*)?)\b"
    )

    # Network and hostname patterns
    PRIVATE_IP_REGEX = re.compile(
        r"\b((?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}))\b"
    )
    INTERNAL_DOMAIN_REGEX = re.compile(
        r"\b([a-zA-Z0-9_\-]+(?:\.[a-zA-Z0-9_\-]+)*\.(?:local|internal|corp|lan|intranet|priv|private|cluster\.local))\b",
        re.IGNORECASE,
    )
    GIT_REMOTE_REGEX = re.compile(
        r"(?:url\s*=\s*['\"]?)(https?:\/\/[a-zA-Z0-9_\-\.]+|git@[a-zA-Z0-9_\-\.]+:|ssh:\/\/[a-zA-Z0-9_\-\.]+)"
    )

    def extract(self, text: str, target_domain: Optional[str] = None) -> Dict[str, Any]:
        """
        Extracts secrets, private IPs, and internal domains/subdomains from text.

        Returns:
            Dict with 'secrets' (List[Dict]), 'internal_domains' (List[str]), 'private_ips' (List[str]).
        """
        if not text:
            return {"secrets": [], "internal_domains": [], "private_ips": []}

        secrets: List[Dict[str, str]] = []
        internal_domains: Set[str] = set()
        private_ips: Set[str] = set()
        seen_secret_values: Set[str] = set()

        def add_secret(secret_type: str, value: str, key_name: Optional[str] = None):
            val_clean = str(value).strip().strip("'\"")
            if not val_clean or val_clean in seen_secret_values:
                return
            seen_secret_values.add(val_clean)
            entry = {"type": secret_type, "value": val_clean}
            if key_name:
                entry["key"] = key_name
            secrets.append(entry)

        # 1. AWS Access Keys
        for match in self.AWS_ACCESS_KEY_REGEX.finditer(text):
            add_secret("aws_access_key_id", match.group(1))

        # 2. AWS Secret Keys
        for match in self.AWS_SECRET_KEY_REGEX.finditer(text):
            add_secret("aws_secret_access_key", match.group(1))

        # 3. Google API Keys
        for match in self.GOOGLE_API_KEY_REGEX.finditer(text):
            add_secret("google_api_key", match.group(1))

        # 4. Stripe Keys
        for match in self.STRIPE_KEY_REGEX.finditer(text):
            add_secret("stripe_secret_key", match.group(1))

        # 5. GitHub Tokens
        for match in self.GITHUB_TOKEN_REGEX.finditer(text):
            add_secret("github_token", match.group(1))

        # 6. Slack Tokens / Webhooks
        for match in self.SLACK_WEBHOOK_REGEX.finditer(text):
            add_secret("slack_webhook", match.group(1))
        for match in self.SLACK_TOKEN_REGEX.finditer(text):
            add_secret("slack_token", match.group(1))

        # 7. JWT Tokens
        for match in self.JWT_REGEX.finditer(text):
            add_secret("jwt_token", match.group(1))

        # 8. Database Connection Strings
        for match in self.DB_URI_REGEX.finditer(text):
            db_uri = match.group(1)
            add_secret("database_connection_string", db_uri)
            # Extract hostname from DB URI if present
            try:
                parsed = urllib.parse.urlparse(db_uri)
                if parsed.hostname:
                    h = parsed.hostname.lower()
                    if self._is_internal_domain(h, target_domain):
                        internal_domains.add(h)
            except Exception:
                pass

        # 9. Cleartext Passwords / Credentials
        for match in self.PASSWORD_REGEX.finditer(text):
            raw_val = match.group(1).strip()
            # Exclude obvious placeholders or comments
            if (
                raw_val
                and not raw_val.startswith("#")
                and not raw_val.startswith("*")
                and raw_val.lower() not in ("null", "none", "true", "false", "undefined", "redacted", "")
            ):
                add_secret("password", raw_val)

        # 10. Generic API Keys
        for match in self.GENERIC_API_KEY_REGEX.finditer(text):
            raw_val = match.group(1).strip()
            if (
                raw_val
                and not raw_val.startswith("#")
                and not raw_val.startswith("*")
                and raw_val.lower() not in ("null", "none", "true", "false", "undefined", "redacted", "")
            ):
                add_secret("api_key", raw_val)

        # 11. JSON Actuator parser fallback
        try:
            parsed_json = json.loads(text)
            self._extract_from_json(parsed_json, add_secret, internal_domains, target_domain)
        except Exception:
            pass

        # 12. Private RFC 1918 IPs
        for match in self.PRIVATE_IP_REGEX.finditer(text):
            ip = match.group(1)
            octets = [int(o) for o in ip.split(".")]
            if all(0 <= o <= 255 for o in octets):
                private_ips.add(ip)

        # 13. Internal Domain Suffixes (*.internal, *.corp, *.local, etc.)
        for match in self.INTERNAL_DOMAIN_REGEX.finditer(text):
            dom = match.group(1).lower()
            internal_domains.add(dom)

        # 14. Git Remote Hostnames
        for match in self.GIT_REMOTE_REGEX.finditer(text):
            remote_val = match.group(1)
            if "@" in remote_val:
                host_part = remote_val.split("@")[-1].split(":")[0]
                if self._is_internal_domain(host_part, target_domain):
                    internal_domains.add(host_part.lower())
            else:
                try:
                    parsed = urllib.parse.urlparse(remote_val)
                    if parsed.hostname and self._is_internal_domain(parsed.hostname, target_domain):
                        internal_domains.add(parsed.hostname.lower())
                except Exception:
                    pass

        # 15. Subdomains of mission target
        if target_domain:
            target_clean = target_domain.lower().strip(".")
            # Match word chars and dots followed by target domain
            target_pattern = re.compile(
                r"\b([a-zA-Z0-9_\-]+(?:\.[a-zA-Z0-9_\-]+)*\." + re.escape(target_clean) + r")\b",
                re.IGNORECASE,
            )
            for match in target_pattern.finditer(text):
                sub = match.group(1).lower()
                internal_domains.add(sub)

        return {
            "secrets": secrets,
            "internal_domains": sorted(list(internal_domains)),
            "private_ips": sorted(list(private_ips)),
        }

    def _is_internal_domain(self, hostname: str, target_domain: Optional[str] = None) -> bool:
        if not hostname or hostname in ("localhost", "127.0.0.1"):
            return False
        h = hostname.lower().strip(".")
        internal_suffixes = (".internal", ".corp", ".local", ".lan", ".intranet", ".priv", ".private", ".cluster.local")
        if any(h.endswith(suffix) for suffix in internal_suffixes):
            return True
        if target_domain and (h == target_domain.lower() or h.endswith("." + target_domain.lower())):
            return True
        return False

    def _extract_from_json(
        self,
        data: Any,
        add_secret_fn,
        internal_domains: Set[str],
        target_domain: Optional[str] = None,
        parent_key: Optional[str] = None,
    ):
        """Recursively walks JSON structures looking for properties, secrets, and URLs."""
        if isinstance(data, dict):
            if "value" in data and parent_key and isinstance(data["value"], (str, int, float, bool)):
                v_str = str(data["value"]).strip()
                parent_lower = str(parent_key).lower()
                if any(term in parent_lower for term in ["key", "secret", "password", "token", "pwd", "credential"]):
                    if (
                        v_str
                        and not v_str.startswith("*")
                        and v_str.lower() not in ("null", "none", "true", "false", "undefined", "redacted", "")
                    ):
                        add_secret_fn(parent_lower, v_str, key_name=str(parent_key))
                if "url" in parent_lower or "host" in parent_lower or "server" in parent_lower:
                    try:
                        parsed = urllib.parse.urlparse(v_str)
                        host = parsed.hostname or v_str.split(":")[0]
                        if host and self._is_internal_domain(host, target_domain):
                            internal_domains.add(host.lower())
                    except Exception:
                        pass

            for k, v in data.items():
                k_lower = str(k).lower()
                if isinstance(v, (str, int, float, bool)):
                    v_str = str(v).strip()
                    if any(term in k_lower for term in ["key", "secret", "password", "token", "pwd", "credential"]):
                        if (
                            v_str
                            and not v_str.startswith("*")
                            and v_str.lower() not in ("null", "none", "true", "false", "undefined", "redacted", "")
                        ):
                            add_secret_fn(k_lower, v_str, key_name=str(k))
                    if "url" in k_lower or "host" in k_lower or "server" in k_lower:
                        try:
                            parsed = urllib.parse.urlparse(v_str)
                            host = parsed.hostname or v_str.split(":")[0]
                            if host and self._is_internal_domain(host, target_domain):
                                internal_domains.add(host.lower())
                        except Exception:
                            pass
                elif isinstance(v, (dict, list)):
                    self._extract_from_json(v, add_secret_fn, internal_domains, target_domain, parent_key=str(k))
        elif isinstance(data, list):
            for item in data:
                self._extract_from_json(item, add_secret_fn, internal_domains, target_domain, parent_key=parent_key)


class InformationDisclosureCollector(BaseCollector):
    """
    Collector that actively probes live hosts, endpoints, and subdomains
    for exposed sensitive configuration files, environment definitions,
    actuator endpoints, source maps, and secrets.
    """

    def __init__(
        self,
        http_client: Optional[Any] = None,
        wordlist: Optional[List[str]] = None,
        secret_extractor: Optional[Any] = None,
    ):
        self.http_client = http_client
        self.wordlist = list(wordlist) if wordlist is not None else list(DEFAULT_WORDLIST)
        self.secret_extractor = secret_extractor or SecretExtractor()

    def _extract_candidate_base_urls(self, mission: Any) -> List[str]:
        """Gathers and normalizes candidate base URLs from mission assets."""
        candidate_urls: Set[str] = set()

        # 1. Live hosts
        for h in getattr(mission, "live_hosts", []) or []:
            if isinstance(h, dict):
                url = h.get("url") or h.get("host")
                if url:
                    candidate_urls.add(self._normalize_base_url(url))
            elif isinstance(h, str) and h:
                candidate_urls.add(self._normalize_base_url(h))

        # 2. Endpoints
        for ep in getattr(mission, "endpoints", []) or []:
            if isinstance(ep, dict):
                ep_url = ep.get("url") or ep.get("path")
                if ep_url:
                    candidate_urls.add(self._normalize_base_url(ep_url))
            elif isinstance(ep, str) and ep:
                candidate_urls.add(self._normalize_base_url(ep))

        # 3. Subdomains
        for s in getattr(mission, "subdomains", []) or []:
            if isinstance(s, dict):
                hostname = s.get("hostname") or s.get("host")
                if hostname:
                    candidate_urls.add(self._normalize_base_url(hostname))
            elif isinstance(s, str) and s:
                candidate_urls.add(self._normalize_base_url(s))

        # 4. Target domain
        target = getattr(mission, "target", None)
        if target and not candidate_urls:
            candidate_urls.add(self._normalize_base_url(str(target)))

        return sorted(list(candidate_urls))

    def _normalize_base_url(self, raw_url: str) -> str:
        raw_clean = str(raw_url).strip()
        if not raw_clean.startswith("http://") and not raw_clean.startswith("https://"):
            raw_clean = f"https://{raw_clean}"
        parsed = urllib.parse.urlparse(raw_clean)
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc or parsed.path.split("/")[0]
        return f"{scheme}://{netloc}"

    def _probe_path(self, mission: Any, base_url: str, path: str) -> Optional[Tuple[int, str, str]]:
        """
        Sends HTTP request for base_url + path.
        Returns tuple of (status_code, raw_body, final_url) if accessible, else None.
        """
        target_url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            if self.http_client is not None:
                # Support AuthenticatedHttpClient with (mission, url) or generic Client with (url)
                if hasattr(self.http_client, "get"):
                    try:
                        resp = self.http_client.get(mission, target_url, timeout=5.0)
                    except TypeError:
                        resp = self.http_client.get(target_url, timeout=5.0)
                elif callable(self.http_client):
                    resp = self.http_client(target_url)
                else:
                    return None
            else:
                with AuthenticatedHttpClient(timeout=5.0, max_retries=1) as client:
                    resp = client.get(mission, target_url, timeout=5.0)

            status_code = getattr(resp, "status_code", None)
            success = getattr(resp, "success", True)
            if status_code is None and hasattr(resp, "status"):
                status_code = getattr(resp, "status")

            if status_code == 200:
                raw_body = (
                    getattr(resp, "raw_body", None)
                    or getattr(resp, "body", None)
                    or getattr(resp, "text", "")
                    or ""
                )
                final_url = getattr(resp, "url", target_url) or target_url
                return status_code, str(raw_body), str(final_url)
        except Exception as e:
            logger.debug(f"Information disclosure probe failed for {target_url}: {e}")
            return None

        return None

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes active information disclosure probing across all candidate hosts and wordlist items.
        """
        candidate_base_urls = self._extract_candidate_base_urls(mission)
        if not candidate_base_urls:
            logger.info("No candidate targets available for information disclosure probing.")
            return []

        logger.info(
            f"Running Information Disclosure Probing across {len(candidate_base_urls)} target(s) with {len(self.wordlist)} paths..."
        )

        detected_evidence: List[Evidence] = []
        target_domain = getattr(mission, "target", None)
        if target_domain:
            target_domain = str(target_domain)

        # Track existing subdomains for expansion
        existing_subdomains: Set[str] = set()
        for s in getattr(mission, "subdomains", []) or []:
            if isinstance(s, dict):
                h = s.get("hostname") or s.get("host")
                if h:
                    existing_subdomains.add(str(h).lower())
            elif isinstance(s, str) and s:
                existing_subdomains.add(s.lower())

        for base_url in candidate_base_urls:
            for path in self.wordlist:
                result = self._probe_path(mission, base_url, path)
                if not result:
                    continue

                status_code, raw_body, target_url = result
                # Parse body for secrets and internal domains
                extraction = self.secret_extractor.extract(raw_body, target_domain=target_domain)
                secrets = extraction["secrets"]
                internal_domains = extraction["internal_domains"]
                private_ips = extraction["private_ips"]

                # Generate clean template slug
                clean_path_slug = (
                    re.sub(r"-+", "-", path.strip("/.").replace("/", "-").replace(".", "-").replace("_", "-")).strip("-")
                )
                template_id = f"info-disclosure-{clean_path_slug}"

                title = f"Information Disclosure: {path} on {base_url}"
                description = (
                    f"Exposed file found at {target_url} (HTTP 200). "
                    f"Disclosed {len(secrets)} secret(s), {len(internal_domains)} internal host(s), "
                    f"and {len(private_ips)} private IP(s)."
                )

                # 1. Construct and emit Evidence
                ev = Evidence(
                    mission_id=getattr(mission, "id", ""),
                    source_type="LOG",
                    created_by="SYSTEM_GENERATED",
                    title=title,
                    description=description,
                    category="information_disclosure",
                    value=target_url,
                    source=target_url,
                    status="CONFIRMED",
                    confidence=0.95,
                    severity="high",
                    provenance=ProvenanceData(
                        step_id="information_disclosure_probe",
                    ),
                    tags=["information_disclosure", "sensitive_data", clean_path_slug],
                    metadata={
                        "url": target_url,
                        "host": base_url,
                        "path": path,
                        "status_code": status_code,
                        "category": "information_disclosure",
                        "severity": "high",
                        "template_id": template_id,
                        "secrets": secrets,
                        "internal_domains": internal_domains,
                        "private_ips": private_ips,
                        "secret_count": len(secrets),
                        "domain_count": len(internal_domains),
                    },
                )

                # Add to mission.evidence
                if hasattr(mission, "evidence") and mission.evidence is not None:
                    if hasattr(mission.evidence, "add"):
                        mission.evidence.add(ev)
                    elif isinstance(mission.evidence, list):
                        mission.evidence.append(ev)

                # 2. Add to mission.vulnerabilities
                if hasattr(mission, "vulnerabilities") and isinstance(mission.vulnerabilities, list):
                    mission.vulnerabilities.append({
                        "name": f"Information Disclosure ({path})",
                        "template_id": template_id,
                        "severity": "high",
                        "host": base_url,
                        "url": target_url,
                        "description": description,
                        "secrets": secrets,
                        "internal_domains": internal_domains,
                        "private_ips": private_ips,
                    })

                # 3. Dynamic Subdomain Feedback Loop
                for domain in internal_domains:
                    if domain and domain.lower() not in existing_subdomains:
                        existing_subdomains.add(domain.lower())
                        if hasattr(mission, "subdomains") and isinstance(mission.subdomains, list):
                            mission.subdomains.append(domain)

                        sub_ev = Evidence(
                            mission_id=getattr(mission, "id", ""),
                            source_type="LOG",
                            created_by="SYSTEM_GENERATED",
                            title=f"Discovered Subdomain: {domain}",
                            description=f"Subdomain {domain} disclosed via exposed file at {target_url}",
                            category="subdomain",
                            value=domain,
                            source=target_url,
                            status="CONFIRMED",
                            confidence=0.9,
                            severity="info",
                            metadata={
                                "hostname": domain,
                                "source": target_url,
                                "discovered_by": "information_disclosure",
                            },
                        )
                        if hasattr(mission, "evidence") and mission.evidence is not None:
                            if hasattr(mission.evidence, "add"):
                                mission.evidence.add(sub_ev)
                            elif isinstance(mission.evidence, list):
                                mission.evidence.append(sub_ev)

                # 4. KnowledgeGraph Node & Edge Expansion
                graph = getattr(mission, "attack_surface_graph", None) or getattr(mission, "graph", None)
                if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
                    parsed_target = urllib.parse.urlparse(target_url)
                    host_part = parsed_target.hostname or base_url

                    lh_id = f"live_host:{base_url}"
                    ep_id = f"endpoint:{target_url}"
                    vuln_id = f"vulnerability:{template_id}:{target_url}"

                    graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url, "host": host_part}))
                    graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": status_code}))
                    graph.add(Node(id=vuln_id, type="vulnerability", value=f"Information Disclosure ({path})", metadata=ev.metadata))

                    graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
                    graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")
                    graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")

                    # Add secret nodes
                    for idx, sec in enumerate(secrets):
                        sec_type = sec.get("type", "secret")
                        sec_val = sec.get("value", "")
                        sec_id = f"secret:{sec_type}:{idx}:{target_url}"
                        graph.add(Node(id=sec_id, type="secret", value=sec_val, metadata=sec))
                        graph.connect(vuln_id, sec_id, edge_type="EXPOSES_SECRET")

                    # Add subdomain nodes and connections
                    if target_domain:
                        target_id = f"target:{target_domain}"
                        if target_id not in graph.nodes:
                            graph.add(Node(id=target_id, type="target", value=target_domain, metadata={"target": target_domain}))

                    for domain in internal_domains:
                        sub_id = f"subdomain:{domain}"
                        graph.add(Node(id=sub_id, type="subdomain", value=domain, metadata={"hostname": domain, "source": target_url}))
                        graph.connect(vuln_id, sub_id, edge_type="DISCLOSED_SUBDOMAIN")
                        if target_domain:
                            graph.connect(f"target:{target_domain}", sub_id, edge_type="RESOLVES_TO")


                detected_evidence.append(ev)

        logger.info(f"Information Disclosure Probing complete: {len(detected_evidence)} exposed file(s) identified.")
        return detected_evidence

    def execute(self, mission: Any) -> List[Evidence]:
        """Plugin/Specialist adapter interface."""
        return self.collect(mission)
