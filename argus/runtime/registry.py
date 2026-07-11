from dataclasses import dataclass


@dataclass
class Tool:

    name: str

    capability: str

    command: str

    description: str


class ToolRegistry:

    def __init__(self):

        self.tools = {}

    def register(self, tool: Tool):

        self.tools[tool.capability] = tool

    def get(self, capability: str):

        return self.tools.get(capability)

    def list(self):

        return list(self.tools.values())


registry = ToolRegistry()

registry.register(
    Tool(
        name="Subfinder",
        capability="subdomain_enumerator",
        command="subfinder",
        description="Discover subdomains",
    )
)

registry.register(
    Tool(
        name="httpx",
        capability="live_host_detector",
        command="/usr/bin/httpx-toolkit",
        description="Find live hosts",
    )
)

registry.register(
    Tool(
        name="Katana",
        capability="crawler",
        command="katana",
        description="Discover endpoints",
    )
)

registry.register(
    Tool(
        name="Katana",
        capability="crawler",
        command="katana",
        description="Crawl endpoints",
    )
)
