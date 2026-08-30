import json
import logging
import urllib.parse

logger = logging.getLogger(__name__)


class ReconParser:

    @staticmethod
    def parse_subfinder(output: str) -> list[dict]:
        """Parses Subfinder output (plain text or JSON lines) into structured subdomain dicts.
        
        Returns:
            list[dict]: List of {"hostname": str, "source": "subfinder"} dicts.
        """
        if not output:
            return []

        subdomains = []
        seen = set()

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            hostname = None
            source = "subfinder"

            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    if isinstance(data, dict):
                        hostname = data.get("host") or data.get("hostname") or data.get("subdomain")
                        if data.get("source"):
                            source = data.get("source")
                except json.JSONDecodeError:
                    pass

            if not hostname:
                if "://" in line:
                    parsed = urllib.parse.urlparse(line)
                    hostname = parsed.hostname or line
                else:
                    hostname = line

            hostname = hostname.strip()
            if hostname and hostname not in seen:
                seen.add(hostname)
                subdomains.append({
                    "hostname": hostname,
                    "source": source,
                })

        return subdomains

    @staticmethod
    def parse_httpx(output: str) -> list[dict]:
        """Parses HTTPX JSONL (or plain URLs fallback) into structured live-host dicts.
        
        Returns:
            list[dict]: List of dicts with keys: url, scheme, host, port, status, title, server, technologies.
        """
        if not output:
            return []

        hosts = []

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                item = json.loads(line)
                if not isinstance(item, dict):
                    logger.warning(f"ReconParser: HTTPX line is not a JSON object: {line}")
                    continue
            except json.JSONDecodeError as e:
                if line.startswith("http://") or line.startswith("https://"):
                    parsed = urllib.parse.urlparse(line)
                    hosts.append({
                        "url": line,
                        "scheme": parsed.scheme or None,
                        "host": parsed.hostname or None,
                        "port": parsed.port or (443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else None),
                        "status": None,
                        "title": None,
                        "server": None,
                        "technologies": [],
                    })
                    continue
                logger.warning(f"ReconParser: Malformed httpx output line skipped: {e}")
                continue

            raw_url = item.get("url")
            parsed = urllib.parse.urlparse(raw_url) if raw_url else None

            scheme = item.get("scheme") or (parsed.scheme if parsed else None)
            host = item.get("host") or (parsed.hostname if parsed else None)
            port = item.get("port")
            if port is None and parsed:
                port = parsed.port
            if port is None and scheme:
                port = 443 if scheme == "https" else 80 if scheme == "http" else None

            status = item.get("status")
            if status is None:
                status = item.get("status_code")
            if status is None:
                status = item.get("status-code")

            server = item.get("server") or item.get("webserver")
            title = item.get("title")

            raw_tech = item.get("technologies") if item.get("technologies") is not None else item.get("tech")
            if isinstance(raw_tech, list):
                technologies = [str(t).strip() for t in raw_tech if t and str(t).strip()]
            elif isinstance(raw_tech, str):
                technologies = [t.strip() for t in raw_tech.split(",") if t.strip()]
            else:
                technologies = []

            hosts.append({
                "url": raw_url,
                "scheme": scheme,
                "host": host,
                "port": port,
                "status": status,
                "title": title,
                "server": server,
                "technologies": technologies,
            })

        return hosts

    @staticmethod
    def parse_katana(output: str) -> list[dict]:
        """Parses Katana crawler output (plain text URLs or JSON lines) into structured endpoint dicts.
        
        Returns:
            list[dict]: List of dicts with keys: url, path, host, method, params.
        """
        if not output:
            return []

        endpoints = []
        seen = set()

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            raw_url = None
            path = None
            host = None
            method = "GET"
            params = {}

            if line.startswith("{"):
                try:
                    item = json.loads(line)
                    if isinstance(item, dict):
                        request_obj = item.get("request") if isinstance(item.get("request"), dict) else {}
                        raw_url = item.get("url") or item.get("endpoint") or request_obj.get("endpoint") or request_obj.get("url")
                        path = item.get("path")
                        host = item.get("host")
                        method = item.get("method") or request_obj.get("method") or "GET"
                        if item.get("params") is not None:
                            params = item.get("params")
                except json.JSONDecodeError:
                    pass

            if not raw_url:
                raw_url = line

            parsed = urllib.parse.urlparse(raw_url)
            if not path:
                path = parsed.path if parsed.path else "/"
            if not host:
                host = parsed.hostname or parsed.netloc or None
            if not params and parsed.query:
                params = urllib.parse.parse_qs(parsed.query)

            if raw_url not in seen:
                seen.add(raw_url)
                endpoints.append({
                    "url": raw_url,
                    "path": path,
                    "host": host,
                    "method": method,
                    "params": params,
                })

        return endpoints

    @staticmethod
    def parse_nuclei(output: str) -> list[dict]:
        """Parses Nuclei vulnerability scan JSONL output into structured finding dicts.
        
        Returns:
            list[dict]: List of dicts with keys: template_id, name, severity, host, matched_at, description, tags, extracted_results.
        """
        if not output:
            return []

        findings = []

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                item = json.loads(line)
                if not isinstance(item, dict):
                    logger.warning(f"ReconParser: Nuclei line is not a JSON object: {line}")
                    continue
            except json.JSONDecodeError as e:
                logger.warning(f"ReconParser: Malformed nuclei output line skipped: {e}")
                continue

            info = item.get("info") if isinstance(item.get("info"), dict) else {}

            template_id = item.get("template-id") or item.get("template_id") or item.get("id")
            name = info.get("name") or item.get("name") or template_id
            severity = info.get("severity") or item.get("severity") or "info"
            host = item.get("host")
            matched_at = item.get("matched-at") or item.get("matched_at") or item.get("matched") or host
            description = info.get("description") or item.get("description") or ""

            raw_tags = info.get("tags") if info.get("tags") is not None else item.get("tags")
            if isinstance(raw_tags, list):
                tags = [str(t).strip() for t in raw_tags if t and str(t).strip()]
            elif isinstance(raw_tags, str):
                tags = [t.strip() for t in raw_tags.split(",") if t.strip()]
            else:
                tags = []

            extracted = item.get("extracted-results") or item.get("extracted_results") or item.get("extractedResults") or []
            if not isinstance(extracted, list):
                extracted = [extracted] if extracted else []

            findings.append({
                "template_id": template_id,
                "name": name,
                "severity": severity,
                "host": host,
                "matched_at": matched_at,
                "description": description,
                "tags": tags,
                "extracted_results": extracted,
            })

        return findings

    @staticmethod
    def parse_dnsx(output: str) -> list[dict]:
        """Parses dnsx output (JSON lines or plain text) into structured DNS record dicts.
        
        Returns:
            list[dict]: List of dicts with keys: host, cname, a, aaaa, status_code, resolver, raw.
        """
        if not output:
            return []

        results = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            host = ""
            cname = []
            a = []
            aaaa = []
            status_code = ""
            resolver = []
            raw_dict = {}

            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    if isinstance(data, dict):
                        raw_dict = data
                        host = data.get("host") or data.get("domain") or data.get("hostname") or ""
                        
                        raw_cname = data.get("cname")
                        if isinstance(raw_cname, list):
                            cname = [str(c).strip().rstrip(".") for c in raw_cname if c]
                        elif isinstance(raw_cname, str) and raw_cname:
                            cname = [raw_cname.strip().rstrip(".")]

                        raw_a = data.get("a")
                        if isinstance(raw_a, list):
                            a = [str(ip).strip() for ip in raw_a if ip]
                        elif isinstance(raw_a, str) and raw_a:
                            a = [raw_a.strip()]

                        raw_aaaa = data.get("aaaa")
                        if isinstance(raw_aaaa, list):
                            aaaa = [str(ip).strip() for ip in raw_aaaa if ip]
                        elif isinstance(raw_aaaa, str) and raw_aaaa:
                            aaaa = [raw_aaaa.strip()]

                        status_code = (
                            data.get("status_code")
                            or data.get("status-code")
                            or data.get("rcode")
                            or data.get("status_code_name")
                            or ""
                        )
                        
                        raw_resolver = data.get("resolver")
                        if isinstance(raw_resolver, list):
                            resolver = [str(r).strip() for r in raw_resolver if r]
                        elif isinstance(raw_resolver, str) and raw_resolver:
                            resolver = [raw_resolver.strip()]
                except json.JSONDecodeError:
                    pass

            if not host:
                parts = line.split()
                if parts:
                    host = parts[0]
                    if "[CNAME]" in line:
                        idx = parts.index("[CNAME]") if "[CNAME]" in parts else -1
                        if idx != -1 and idx + 1 < len(parts):
                            cname.append(parts[idx + 1].strip().rstrip("."))
                    elif "[A]" in line:
                        idx = parts.index("[A]") if "[A]" in parts else -1
                        if idx != -1 and idx + 1 < len(parts):
                            a.append(parts[idx + 1].strip())
                    elif len(parts) > 1 and not parts[1].startswith("["):
                        cname.append(parts[1].strip().rstrip("."))

            if host:
                results.append({
                    "host": host,
                    "cname": cname,
                    "a": a,
                    "aaaa": aaaa,
                    "status_code": status_code,
                    "resolver": resolver,
                    "raw": raw_dict,
                })

        return results

