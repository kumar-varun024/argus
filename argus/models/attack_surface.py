from dataclasses import dataclass, field


@dataclass
class AttackSurface:

    subdomains: list[str] = field(default_factory=list)

    live_hosts: list[dict] = field(default_factory=list)

    endpoints: list[dict] = field(default_factory=list)

    javascript: list[dict] = field(default_factory=list)

    technologies: list[str] = field(default_factory=list)

    apis: list[dict] = field(default_factory=list)

    graphql: list[dict] = field(default_factory=list)

    websockets: list[dict] = field(default_factory=list)

    source_maps: list[dict] = field(default_factory=list)

    routes: list[str] = field(default_factory=list)

    parameters: list[str] = field(default_factory=list)
