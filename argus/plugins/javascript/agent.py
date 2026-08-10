import logging
from typing import Dict, Any, List
from argus.plugins.interfaces import ControlledMission
from argus.plugins.javascript.models import JavaScriptObservation, JavaScriptInvestigation

logger = logging.getLogger(__name__)

class JavaScriptSpecialist:
    """Specialist agent for discovering and modeling JavaScript files and frameworks."""
    
    def __init__(self):
        from argus.plugins.javascript.discovery import JavaScriptDiscovery
        self.discovery = JavaScriptDiscovery()

    def discover(self, mission: ControlledMission):
        logger.info("JavaScriptSpecialist: Discovering JavaScript context...")
        # Ensure JavaScript state is initialized
        if not getattr(mission, "javascript", None):
            from argus.runtime.mission import JavaScriptState
            mission.javascript = JavaScriptState()
            
        self.discovery.discover(mission)

    def collect_context(self, mission: ControlledMission):
        logger.info("JavaScriptSpecialist: Collecting context...")

    def analyze(self, mission: ControlledMission):
        logger.info("JavaScriptSpecialist: Analyzing mission data for AST and symbols (PR3)...")
        if not getattr(mission, "javascript", None):
            return

        from argus.plugins.javascript.parser import JavaScriptParser
        parser = JavaScriptParser()
        
        new_observations = []

        if hasattr(mission, "evidence"):
            evidence_store = mission.evidence
            evidence_list = []
            if hasattr(evidence_store, "get_all"):
                evidence_list = evidence_store.get_all()
            elif hasattr(evidence_store, "all"):
                evidence_list = evidence_store.all()
            elif hasattr(evidence_store, "_evidence"):
                evidence_list = evidence_store._evidence
            elif isinstance(evidence_store, list):
                evidence_list = evidence_store
            elif hasattr(evidence_store, "__iter__"):
                evidence_list = list(evidence_store)

            import hashlib

            for ev in evidence_list:
                if str(ev.category).lower() in ["javascript", "html", "network traffic", "http response"]:
                    val = str(ev.value)
                    
                    # Incremental Analysis Caching
                    payload_hash = hashlib.sha256(val.encode('utf-8', errors='ignore')).hexdigest()
                    if hasattr(mission.javascript, "processed_hashes"):
                        if payload_hash in mission.javascript.processed_hashes:
                            continue
                        mission.javascript.processed_hashes.add(payload_hash)
                        
                    source = str(ev.source)
                    ast_nodes, modules, symbols, routes, frameworks, websockets = parser.parse(val, source)
                    
                    mission.javascript.ast.extend(ast_nodes)
                    mission.javascript.modules.extend(modules)
                    mission.javascript.symbols.extend(symbols)
                    mission.javascript.routes.extend(routes)
                    mission.javascript.frameworks.extend(frameworks)
                    mission.javascript.websocket.extend(websockets)
                    
                    for sym in symbols:
                        obs = JavaScriptObservation(
                            description=f"Extracted {sym.symbol_type}: {sym.name}",
                            confidence=0.8,
                            evidence=[ev]
                        )
                        new_observations.append(obs)
                        
                        # Integration with PR5 areas
                        if sym.symbol_type == "RESTEndpoint":
                            if not any(e.get("url") == sym.name for e in mission.endpoints if isinstance(e, dict)):
                                mission.endpoints.append({"url": sym.name, "source": sym.source})
                            if hasattr(mission, "graph") and mission.graph:
                                from argus.graph.node import Node
                                mission.graph.add(Node(id=f"rest_{hash(sym.name)}", type="RESTEndpoint", value=sym.name))
                        elif sym.symbol_type == "GraphQLEndpoint":
                            # Note: We just indicate presence here, GraphQL plugin does the rest
                            pass
                        elif sym.symbol_type == "gRPCReference":
                            if "gRPC" not in mission.technologies:
                                mission.technologies.append("gRPC")
                            if hasattr(mission, "graph") and mission.graph:
                                from argus.graph.node import Node
                                mission.graph.add(Node(id="tech_grpc", type="Technology", value="gRPC"))
                        elif sym.symbol_type == "ThirdPartyAPI":
                            if sym.name not in mission.api_inventory:
                                mission.api_inventory.append(sym.name)
                            if hasattr(mission, "graph") and mission.graph:
                                from argus.graph.node import Node
                                mission.graph.add(Node(id=f"api_{hash(sym.name)}", type="ThirdPartyAPI", value=sym.name))
                        elif sym.symbol_type in ["AuthProvider", "OAuthProvider"]:
                            if sym.name not in mission.technologies:
                                mission.technologies.append(sym.name)
                            if hasattr(mission, "graph") and mission.graph:
                                from argus.graph.node import Node
                                mission.graph.add(Node(id=f"auth_{hash(sym.name)}", type="Authentication", value=sym.name))
                        elif sym.symbol_type == "Object":
                            if not any(bo.get("name") == sym.name for bo in mission.business_objects if isinstance(bo, dict)):
                                mission.business_objects.append({"name": sym.name})
                            if hasattr(mission, "graph") and mission.graph:
                                from argus.graph.node import Node
                                mission.graph.add(Node(id=f"bo_{hash(sym.name)}", type="BusinessObject", value=sym.name))
                        elif sym.symbol_type == "BusinessWorkflow":
                            if sym.name not in mission.business_logic:
                                mission.business_logic.append(sym.name)
                            if hasattr(mission, "graph") and mission.graph:
                                from argus.graph.node import Node
                                mission.graph.add(Node(id=f"wf_{hash(sym.name)}", type="Workflow", value=sym.name))
                        
                    for fw in frameworks:
                        obs = JavaScriptObservation(
                            description=f"Detected Framework: {fw.name}",
                            confidence=0.9,
                            evidence=[ev]
                        )
                        new_observations.append(obs)
                        if hasattr(mission, "technologies") and fw.name not in mission.technologies:
                            mission.technologies.append(fw.name)
                            
                    for r in routes:
                        obs = JavaScriptObservation(
                            description=f"Inferred {r.route_type} Route: {r.path}",
                            confidence=0.7,
                            evidence=[ev]
                        )
                        new_observations.append(obs)
                        
                    for ws in websockets:
                        obs = JavaScriptObservation(
                            description=f"Detected WebSocket: {ws.url}",
                            confidence=0.9,
                            evidence=[ev]
                        )
                        new_observations.append(obs)

                    # Update Knowledge Graph for Frameworks/Routes/WebSockets
                    if hasattr(mission, "graph") and mission.graph:
                        from argus.graph.node import Node
                        for fw in frameworks:
                            mission.graph.add(Node(id=f"fw_{fw.name.lower()}", type="Technology", value=fw.name))
                        for r in routes:
                            route_id = f"route_{r.route_type.lower()}_{hash(r.path)}"
                            mission.graph.add(Node(id=route_id, type="ClientRoute", value=r.path))
                        for ws in websockets:
                            ws_id = f"ws_{hash(ws.url)}"
                            mission.graph.add(Node(id=ws_id, type="WebSocket", value=ws.url))
                        
            if not hasattr(mission, "findings"):
                mission.findings = []
            mission.findings.extend(new_observations)

    def generate_observations(self, mission: ControlledMission):
        logger.info("JavaScriptSpecialist: Generating observations...")

    def generate_investigations(self, mission: ControlledMission):
        logger.info("JavaScriptSpecialist: Generating investigations... (PR6)")
        if not getattr(mission, "javascript", None):
            return
            
        js_state = mission.javascript
        new_invs = []

        # 1. Hidden admin route review
        admin_routes = [r for r in js_state.routes if any(keyword in r.path.lower() for keyword in ["admin", "dashboard", "internal", "config", "debug"])]
        if admin_routes:
            inv = JavaScriptInvestigation(
                title="Hidden Admin Route Review",
                description="Review discovered client-side routes for potentially sensitive administrative or internal interfaces.",
                category="Routing",
                reasoning="Client-side routing tables reveal endpoints that may not be linked in the UI but could expose administrative functionality if server-side authorization is weak.",
                evidence=[r.path for r in admin_routes],
                confidence=0.7,
                priority="Medium",
                tags=["admin", "routes", "authorization"]
            )
            inv.reasoning += "\nManual validation guidance: Intercept traffic and attempt to access these routes with various privilege levels. Verify server-side enforcement."
            new_invs.append(inv)
            if hasattr(mission, "authorization_investigations"):
                mission.authorization_investigations.append(inv)

        # 2. Hidden API review
        hidden_apis = [e for e in mission.endpoints if isinstance(e, dict) and e.get("url") and "api" in e["url"].lower()]
        if hidden_apis:
            inv = JavaScriptInvestigation(
                title="Hidden API Review",
                description="Review extracted REST endpoints and Third-party APIs discovered in JavaScript bundles.",
                category="API Intelligence",
                reasoning="JavaScript bundles often contain hardcoded endpoints, including hidden or unauthenticated APIs.",
                evidence=[e["url"] for e in hidden_apis],
                confidence=0.8,
                priority="Medium",
                tags=["api", "endpoints"]
            )
            inv.reasoning += "\nManual validation guidance: Manually interact with these APIs to assess input validation and access controls."
            new_invs.append(inv)

        # 3. Feature flag review
        feature_flags = [s for s in js_state.symbols if s.symbol_type == "FeatureFlag"]
        if feature_flags:
            inv = JavaScriptInvestigation(
                title="Feature Flag Review",
                description="Review client-side feature flags for potential business logic exposure.",
                category="Business Logic",
                reasoning="Client-side toggles can sometimes be manipulated to access unreleased or premium features if the server does not validate the state.",
                evidence=[s.name for s in feature_flags],
                confidence=0.9,
                priority="Low",
                tags=["feature_flags", "business_logic"]
            )
            inv.reasoning += "\nManual validation guidance: Use browser dev tools to toggle these variables (e.g., from false to true) and observe application behavior."
            new_invs.append(inv)

        # 4. Client authorization review
        auth_providers = [s for s in js_state.symbols if s.symbol_type in ["AuthProvider", "OAuthProvider"]]
        if auth_providers:
            inv = JavaScriptInvestigation(
                title="Client Authorization Review",
                description="Review the integration of authentication and OAuth providers discovered in the client application.",
                category="Authentication",
                reasoning="Misconfigured client-side authentication logic can lead to token leakage or OAuth flow manipulation.",
                evidence=[s.name for s in auth_providers],
                confidence=0.8,
                priority="High",
                tags=["auth", "oauth", "identities"]
            )
            inv.reasoning += "\nManual validation guidance: Review OAuth redirect URIs, token storage mechanisms (localStorage vs HttpOnly cookies), and state parameters."
            new_invs.append(inv)
            if hasattr(mission, "authorization_investigations"):
                mission.authorization_investigations.append(inv)

        # 5. Workflow review
        workflows = [s for s in js_state.symbols if s.symbol_type == "BusinessWorkflow"]
        if workflows:
            inv = JavaScriptInvestigation(
                title="Business Workflow Review",
                description="Review extracted business workflows (e.g., payment, checkout, order processing).",
                category="Business Logic",
                reasoning="Critical business functions implemented in JavaScript should be analyzed to ensure all state and transitions are securely validated on the server.",
                evidence=[s.name for s in workflows],
                confidence=0.9,
                priority="High",
                tags=["workflow", "business_logic"]
            )
            inv.reasoning += "\nManual validation guidance: Walk through these workflows manually, altering request sequence and payload data to test state machine integrity."
            new_invs.append(inv)

        # 6. GraphQL review
        graphql_endpoints = [s for s in js_state.symbols if s.symbol_type == "GraphQLEndpoint"]
        if graphql_endpoints:
            inv = JavaScriptInvestigation(
                title="GraphQL Configuration Review",
                description="Review the discovered GraphQL integrations.",
                category="GraphQL",
                reasoning="GraphQL endpoints may be vulnerable to introspection, excessive query depth, or batching attacks if not properly secured.",
                evidence=[s.name for s in graphql_endpoints],
                confidence=0.9,
                priority="High",
                tags=["graphql", "api"]
            )
            inv.reasoning += "\nManual validation guidance: Attempt to run Introspection queries, test query depth limits, and check for field-level authorization."
            new_invs.append(inv)
            if hasattr(mission, "graphql"):
                mission.graphql.investigations.append(inv)

        # 7. WebSocket review
        if js_state.websocket:
            inv = JavaScriptInvestigation(
                title="WebSocket Security Review",
                description="Review the discovered WebSocket endpoints for secure communication and authentication.",
                category="Networking",
                reasoning="WebSockets can be susceptible to Cross-Site WebSocket Hijacking (CSWSH) and lack proper message-level authorization.",
                evidence=[ws.url for ws in js_state.websocket],
                confidence=0.9,
                priority="Medium",
                tags=["websocket", "networking"]
            )
            inv.reasoning += "\nManual validation guidance: Analyze the WebSocket handshake for Origin validation and test the authorization of individual messages sent over the socket."
            new_invs.append(inv)

        # Add all to mission investigations and priority queue
        for inv in new_invs:
            mission.investigations.add(inv)
        if hasattr(mission, "priority_queue"):
            mission.priority_queue.extend(new_invs)
        
        js_state.investigations.extend(new_invs)

    def explain(self, identifier: str) -> str:
        logger.info(f"JavaScriptSpecialist: Explaining {identifier}...")
        return "Explanation placeholder."

    def confidence(self) -> float:
        logger.info("JavaScriptSpecialist: Calculating confidence score...")
        return 0.0
