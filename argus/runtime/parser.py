import json


class ReconParser:

    @staticmethod
    def parse_subfinder(output: str):

        return [line.strip() for line in output.splitlines() if line.strip()]

    @staticmethod
    def parse_httpx(output: str):

        hosts = []

        for line in output.splitlines():

            line = line.strip()

            if not line:
                continue

            try:
                item = json.loads(line)
            except json.JSONDecodeError as e:
                import logging
                logging.getLogger(__name__).warning(f"ReconParser: Malformed httpx output line skipped: {e}")
                continue

            hosts.append(
                {
                    "url": item.get("url"),
                    "host": item.get("host"),
                    "scheme": item.get("scheme"),
                    "port": item.get("port"),
                    "status": item.get("status_code"),
                    "title": item.get("title"),
                    "server": item.get("webserver"),
                    "technologies": item.get("tech", []),
                }
            )

        return hosts

    @staticmethod
    def parse_katana(output: str):
        return [line.strip() for line in output.splitlines() if line.strip()]

    @staticmethod
    def parse_nuclei(output: str):
        findings = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as e:
                import logging
                logging.getLogger(__name__).warning(f"ReconParser: Malformed nuclei output line skipped: {e}")
                continue
            findings.append({
                "template_id": item.get("template-id"),
                "name": item.get("info", {}).get("name"),
                "severity": item.get("info", {}).get("severity"),
                "host": item.get("host"),
                "matched_at": item.get("matched-at"),
                "description": item.get("info", {}).get("description"),
                "tags": item.get("info", {}).get("tags", []),
                "extracted_results": item.get("extracted-results", [])
            })
        return findings
