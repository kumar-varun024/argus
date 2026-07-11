import json


class ReconParser:

    @staticmethod
    def parse_subfinder(output: str):

        return [
            line.strip()
            for line in output.splitlines()
            if line.strip()
        ]

    @staticmethod
    def parse_httpx(output: str):

        hosts = []

        for line in output.splitlines():

            line = line.strip()

            if not line:
                continue

            try:
                item = json.loads(line)
            except json.JSONDecodeError:
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

        return [
            line.strip()
            for line in output.splitlines()
            if line.strip()
        ]
