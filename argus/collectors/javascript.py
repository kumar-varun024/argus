from urllib.parse import urljoin

from bs4 import BeautifulSoup

from argus.analyzers.javascript import JavaScriptAnalyzer
from argus.collectors.base import BaseCollector
from argus.evidence import Evidence
from argus.runtime.local import LocalRuntime


class JavaScriptCollector(BaseCollector):

    def __init__(self):
        self.runtime = LocalRuntime()
        self.analyzer = JavaScriptAnalyzer()

    def collect(self, mission):

        mission.javascript.clear()
        mission.apis.clear()
        mission.findings.clear()
        mission.evidence.clear()

        seen = set()

        print("Collecting JavaScript...")

        for host in mission.live_hosts:

            host_url = host["url"]

            result = self.runtime.run_command(
                executable="curl",
                args=[
                    "-L",
                    "-s",
                    host_url,
                ],
            )

            soup = BeautifulSoup(
                result["stdout"],
                "html.parser",
            )

            for script in soup.find_all("script"):

                src = script.get("src")

                if not src:
                    continue

                js_url = urljoin(host_url, src)

                if js_url in seen:
                    continue

                seen.add(js_url)

                mission.javascript.append(
                    {
                        "host": host_url,
                        "url": js_url,
                    }
                )

        print(f"✓ Found {len(mission.javascript)} JavaScript files")

        graphql_count = 0
        websocket_count = 0
        jwt_count = 0
        secret_count = 0
        source_map_count = 0

        print("Analyzing JavaScript...")

        for js in mission.javascript:

            result = self.runtime.run_command(
                executable="curl",
                args=[
                    "-L",
                    "-s",
                    js["url"],
                ],
            )

            analysis = self.analyzer.analyze(result["stdout"])

            for api in analysis.apis:
                if api not in mission.apis:
                    mission.apis.append(api)

            for route in analysis.routes:
                mission.evidence.add(
                    Evidence(
                        category="route",
                        value=route,
                        source=js["url"],
                    )
                )

            for source_map in analysis.source_maps:
                source_map_count += 1
                mission.evidence.add(
                    Evidence(
                        category="source_map",
                        value=source_map,
                        source=js["url"],
                    )
                )

            for websocket in analysis.websockets:
                websocket_count += 1
                mission.findings.append(
                    {
                        "type": "websocket",
                        "value": websocket,
                        "source": js["url"],
                    }
                )

            for indicator in analysis.graphql:
                graphql_count += 1
                mission.findings.append(
                    {
                        "type": "graphql_indicator",
                        "value": indicator,
                        "source": js["url"],
                    }
                )

            for indicator in analysis.jwt:
                jwt_count += 1
                mission.findings.append(
                    {
                        "type": "jwt_indicator",
                        "value": indicator,
                        "source": js["url"],
                    }
                )

            for secret in analysis.secrets:
                secret_count += 1
                mission.findings.append(
                    {
                        "type": "possible_secret",
                        "value": secret,
                        "source": js["url"],
                    }
                )

        print("\nJavaScript Intelligence")
        print("-------------------------")
        print(f"JavaScript Files : {len(mission.javascript)}")
        print(f"REST APIs        : {len(mission.apis)}")
        print(f"Evidence         : {mission.evidence.count()}")
        print(f"GraphQL          : {graphql_count}")
        print(f"WebSockets       : {websocket_count}")
        print(f"JWT Indicators   : {jwt_count}")
        print(f"Source Maps      : {source_map_count}")
        print(f"Possible Secrets : {secret_count}")
