from argus.core.mission import Mission
from argus.graph import KnowledgeGraph, Node

class KnowledgeGraphBuilder:

    def build(self, mission: Mission):
        graph = getattr(mission, "graph", None)
        if graph is None:
            graph = KnowledgeGraph()
            mission.graph = graph

        def get_or_create(node_id: str, node_type: str, value: str) -> Node:
            node = graph.get(node_id)
            if not node:
                node = Node(id=node_id, type=node_type, value=value)
                graph.add(node)
            return node

        # 1. Subdomains
        for sub in getattr(mission, "subdomains", []):
            get_or_create(f"sub_{sub}", "Subdomain", sub)

        # 2. Hosts
        for host in getattr(mission, "live_hosts", []):
            if isinstance(host, dict):
                h_val = host.get("host", str(host))
                sub_val = host.get("subdomain", "")
            else:
                h_val = str(host)
                sub_val = ""
            h_node = get_or_create(f"host_{h_val}", "Host", h_val)
            if sub_val:
                s_node = get_or_create(f"sub_{sub_val}", "Subdomain", sub_val)
                graph.connect(h_node.id, s_node.id, "DISCOVERED_ON")

        # 3. Business Objects, Operations, and Endpoints
        for bo in getattr(mission, "business_objects", []):
            bo_id = f"bo_{bo.name}"
            get_or_create(bo_id, "BusinessObject", bo.name)
            
            # Operations
            for op in getattr(bo, "operations", []):
                op_id = f"op_{op}"
                get_or_create(op_id, "Operation", op)
                graph.connect(bo_id, op_id, "PERFORMS_OPERATION")
            
            # Endpoints
            for endpoint in getattr(bo, "endpoints", []):
                ep_val = f"{endpoint.method} {endpoint.path}"
                ep_id = f"ep_{ep_val}"
                get_or_create(ep_id, "Endpoint", ep_val)
                graph.connect(bo_id, ep_id, "HAS_ENDPOINT")
                graph.connect(ep_id, bo_id, "BELONGS_TO")

        # 4. API Intelligence (Endpoints)
        for endpoint in getattr(mission, "api_intelligence", []):
            ep_val = f"{endpoint.method} {endpoint.path}"
            ep_id = f"ep_{ep_val}"
            get_or_create(ep_id, "Endpoint", ep_val)
            
            # Evidence supported by endpoint
            for ev in getattr(endpoint, "evidence", []):
                ev_id = f"ev_{ev}"
                get_or_create(ev_id, "Evidence", ev)
                graph.connect(ep_id, ev_id, "SUPPORTED_BY")
                graph.connect(ep_id, ev_id, "HAS_EVIDENCE") 

        # 5. Authentication
        auth = getattr(mission, "authentication", None)
        auth_nodes = []
        if auth:
            if getattr(auth, "authentication_type", None) and auth.authentication_type != "UNKNOWN":
                a_id = f"auth_{auth.authentication_type}"
                auth_nodes.append(get_or_create(a_id, "Authentication", auth.authentication_type))
            if getattr(auth, "token_type", None) and auth.token_type != "UNKNOWN":
                t_id = f"auth_{auth.token_type}"
                auth_nodes.append(get_or_create(t_id, "Authentication", auth.token_type))
            
            # Connect Business Objects to Authentication
            for bo in getattr(mission, "business_objects", []):
                bo_id = f"bo_{bo.name}"
                for a_node in auth_nodes:
                    graph.connect(bo_id, a_node.id, "USES_AUTH")

        # 6. Technologies
        tech_nodes = []
        for tech in getattr(mission, "technologies", []):
            tech_id = f"tech_{tech}"
            tech_nodes.append(get_or_create(tech_id, "Technology", tech))
            
        for bo in getattr(mission, "business_objects", []):
            bo_id = f"bo_{bo.name}"
            for t_node in tech_nodes:
                graph.connect(bo_id, t_node.id, "USES_TECHNOLOGY")

        # 7. Global Evidence and JavaScript
        evidence_list = getattr(mission, "evidence", [])
        try:
            if hasattr(evidence_list, "__iter__"):
                for ev in evidence_list:
                    val = getattr(ev, "value", str(ev))
                    ev_id = f"ev_{val}"
                    get_or_create(ev_id, "Evidence", val)
        except Exception:
            pass
            
        for js in getattr(mission, "javascript", []):
            if isinstance(js, dict):
                val = js.get("url", js.get("file", str(js)))
            else:
                val = str(js)
            js_id = f"js_{val}"
            get_or_create(js_id, "JavaScript", val)
            
        # 8. Findings
        for finding in getattr(mission, "findings", []):
            if isinstance(finding, dict):
                f_val = finding.get("title", str(finding))
                ref = finding.get("reference", "")
            else:
                f_val = str(finding)
                ref = ""
            f_id = f"find_{f_val}"
            f_node = get_or_create(f_id, "Finding", f_val)
            if ref:
                # Add tentative reference links
                graph.connect(f_node.id, f"ep_{ref}", "REFERENCES")
                graph.connect(f_node.id, f"bo_{ref}", "REFERENCES")
