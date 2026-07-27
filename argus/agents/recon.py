from argus.agents.base import BaseAgent
from argus.analyzers import AuthenticationAnalyzer
from argus.reasoning import ReasoningEngine
from argus.intelligence import APIIntelligence
from argus.intelligence.business import BusinessObjectAnalyzer
from argus.graph.builder import KnowledgeGraphBuilder
from argus.ai.researcher import Researcher

from argus.collectors import (
    SubfinderCollector,
    HttpxCollector,
    KatanaCollector,
    JavaScriptCollector,
    NucleiCollector,
    TechnologyCollector,
)


class ReconAgent(BaseAgent):

    def __init__(self):
        super().__init__("Recon Agent")

        self.collectors = [
            SubfinderCollector(),
            HttpxCollector(),
            KatanaCollector(),
            JavaScriptCollector(),
            NucleiCollector(),
            TechnologyCollector(),
        ]

        self.authentication = AuthenticationAnalyzer()
        self.api_intelligence = APIIntelligence()
        self.business = BusinessObjectAnalyzer()
        self.graph_builder = KnowledgeGraphBuilder()
        self.researcher = Researcher()
        self.reasoning = ReasoningEngine()

    def think(self, mission):

        print(f"Target: {mission.target}")
        print("Planning reconnaissance...")

    def execute(self, mission):

        for collector in self.collectors:
            collector.collect(mission)

        self.authentication.analyze(mission)
        self.api_intelligence.analyze(mission)
        self.business.analyze(mission)
        self.graph_builder.build(mission)
        mission.ai_research = self.researcher.analyze(mission)

        mission.hypotheses = self.reasoning.generate(mission)

    def evaluate(self, mission):

        print("\nMission Summary")
        print("-------------------------")
        print(f"Subdomains : {len(mission.subdomains)}")
        print(f"Live Hosts : {len(mission.live_hosts)}")
        print(f"Endpoints  : {len(mission.endpoints)}")
        print(f"JavaScript : {len(mission.javascript)}")
        print(f"APIs       : {len(mission.apis)}")
        print(f"Evidence   : {len(mission.evidence)}")
        print(f"Findings   : {len(mission.findings)}")
        print(f"Hypotheses : {len(mission.hypotheses)}")
        print(f"API Research : {len(mission.api_intelligence)}")

        #
        # API Intelligence
        #

        if mission.api_intelligence:

            print("\n" + "=" * 60)
            print("API INTELLIGENCE")
            print("=" * 60)

            for endpoint in mission.api_intelligence:

                print()

                print(f"{endpoint.priority} ({endpoint.risk_score})")
                print()

                print(f"{endpoint.method} {endpoint.path}")

                print()
                print("Business Object")
                print("----------------")
                print(endpoint.business_object)

                print()
                print("Reason")
                print("------")

                for item in endpoint.reasoning:
                    print(f"• {item}")

                print()
                print("Manual Investigation")
                print("--------------------")

                for check in endpoint.manual_checks:
                    print(f"□ {check}")

                print()
                print("-" * 60)

        #
        # Business Objects
        #

        if getattr(mission, "business_objects", None):

            print("\n" + "=" * 60)
            print("BUSINESS OBJECTS")
            print("=" * 60)

            for bo in mission.business_objects:
                print()
                print(bo.name)

                print("\nOperations")
                for op in sorted(bo.operations):
                    print(op)

                print("\nEndpoints")
                print(len(bo.endpoints))

                if bo.priority:
                    print("\nPriority")
                    print(bo.priority)

                if bo.reasoning:
                    print("\nReasoning")
                    for item in bo.reasoning:
                        print(f"• {item}")

        #
        # Authentication Intelligence
        #

        auth = mission.authentication

        print("\n" + "=" * 60)
        print("AUTHENTICATION INTELLIGENCE")
        print("=" * 60)

        print("\nAuthentication Type")
        print("-------------------")
        print(auth.authentication_type)

        print("\nToken Type")
        print("----------")
        print(auth.token_type)

        print("\nConfidence")
        print("----------")
        print(f"{auth.confidence}%")

        if auth.observations:
            print("\nObserved")
            print("--------")
            for observation in auth.observations:
                print(f"✓ {observation}")

        if auth.reasoning:
            print("\nReasoning")
            print("---------")
            for reason in auth.reasoning:
                print(f"• {reason}")

        if auth.research_questions:
            print("\nResearch Questions")
            print("------------------")
            for question in auth.research_questions:
                print(f"• {question}")

        if auth.missing_evidence:
            print("\nMissing Evidence")
            print("----------------")
            for item in auth.missing_evidence:
                print(f"□ {item}")

        #
        # Knowledge Graph
        #

        if getattr(mission, "graph", None) and getattr(mission.graph, "nodes", None):

            print("\n" + "=" * 60)
            print("KNOWLEDGE GRAPH")
            print("=" * 60)

            print("\nNode Count")
            print(mission.graph.node_count())

            print("\nEdge Count")
            print(mission.graph.edge_count())

            stats = mission.graph.summary()
            bo_count = stats.get("BusinessObject Nodes", 0)
            ep_count = stats.get("Endpoint Nodes", 0)
            tech_count = stats.get("Technology Nodes", 0)
            auth_count = stats.get("Authentication Nodes", 0)
            ev_count = stats.get("Evidence Nodes", 0)
            
            print("\nBusiness Objects")
            print(bo_count)

            print("\nEndpoints")
            print(ep_count)
            
            print("\nTechnologies")
            print(tech_count)

            print("\nAuthentication Nodes")
            print(auth_count)

            print("\nEvidence Nodes")
            print(ev_count)
            
            print("\nTop Connected Objects")
            nodes_by_degree = sorted(
                mission.graph.nodes.values(),
                key=lambda n: len(mission.graph.edges_from(n)) + len(mission.graph.edges_to(n)),
                reverse=True
            )
            for top_node in nodes_by_degree[:5]:
                print(f"{top_node.type}: {top_node.value}")

        #
        # AI Research
        #

        if getattr(mission, "ai_research", None):

            print("\n" + "=" * 60)
            print("AI RESEARCH")
            print("=" * 60)

            ai = mission.ai_research

            print("\nExecutive Summary")
            print("-----------------")
            print(ai.executive_summary)

            if getattr(ai, "business_objects", None):
                print("\nBusiness Objects")
                print("----------------")
                for bo in ai.business_objects:
                    print(f"• {bo}")

            if getattr(ai, "business_workflows", None):
                print("\nBusiness Workflows")
                print("------------------")
                for wf in ai.business_workflows:
                    print(f"• {wf}")

            if getattr(ai, "authorization_boundaries", None):
                print("\nAuthorization Boundaries")
                print("------------------------")
                for ab in ai.authorization_boundaries:
                    print(f"• {ab}")

            if getattr(ai, "sensitive_operations", None):
                print("\nSensitive Operations")
                print("--------------------")
                for op in ai.sensitive_operations:
                    print(f"• {op}")

            if getattr(ai, "high_value_assets", None):
                print("\nHigh Value Assets")
                print("-----------------")
                for asset in ai.high_value_assets:
                    print(f"• {asset}")

            if getattr(ai, "research_questions", None):
                print("\nResearch Questions")
                print("------------------")
                for q in ai.research_questions:
                    print(f"• {q}")

            if getattr(ai, "missing_evidence", None):
                print("\nMissing Evidence")
                print("----------------")
                for m in ai.missing_evidence:
                    print(f"• {m}")

            if getattr(ai, "recommended_next_steps", None):
                print("\nRecommended Next Steps")
                print("----------------------")
                for r in ai.recommended_next_steps:
                    print(f"• {r}")

            if getattr(ai, "confidence", None):
                print("\nConfidence")
                print("----------")
                print(ai.confidence)
                    
            if getattr(ai, "unknown_areas", None):
                print("\nUnknown Areas")
                print("-------------")
                for u in ai.unknown_areas:
                    print(f"• {u}")

        #
        # Hypotheses
        #

        if mission.hypotheses:

            print("\n" + "=" * 60)
            print("MISSION HYPOTHESES")
            print("=" * 60)

            for hypothesis in mission.hypotheses:

                print(f"\n[{hypothesis.confidence:.2f}] {hypothesis.title}")

                print(hypothesis.description)

                print("\nSuggested Next Steps")

                for action in hypothesis.next_actions:
                    print(f"  • {action}")

        print("\nRecon phase complete.")
