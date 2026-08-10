import unittest
from argus.graph import KnowledgeGraph, Node, Edge
from argus.core.mission import Mission
from argus.graph.builder import KnowledgeGraphBuilder
from argus.intelligence.business_models import BusinessObject
from argus.intelligence.models import APIEndpoint
from argus.models import AuthenticationModel
from argus.evidence import EvidenceStore

class TestKnowledgeGraph(unittest.TestCase):

    def setUp(self):
        self.graph = KnowledgeGraph()

    def test_empty_graph(self):
        self.assertEqual(self.graph.node_count(), 0)
        self.assertEqual(self.graph.edge_count(), 0)
        self.assertEqual(self.graph.all(), [])

    def test_node_creation(self):
        n = Node(id="bo_User", type="BusinessObject", value="User")
        self.assertTrue(self.graph.add(n))
        self.assertEqual(self.graph.node_count(), 1)
        self.assertEqual(self.graph.get("bo_User"), n)

    def test_edge_creation(self):
        n1 = Node(id="bo_User", type="BusinessObject", value="User")
        n2 = Node(id="ep_GET /users", type="Endpoint", value="GET /users")
        self.graph.add(n1)
        self.graph.add(n2)
        
        self.assertTrue(self.graph.connect("bo_User", "ep_GET /users", "HAS_ENDPOINT"))
        self.assertEqual(self.graph.edge_count(), 1)
        self.assertEqual(self.graph.edges[0].source, "bo_User")
        self.assertEqual(self.graph.edges[0].target, "ep_GET /users")
        self.assertEqual(self.graph.edges[0].type, "HAS_ENDPOINT")

    def test_duplicate_node_handling(self):
        n1 = Node(id="bo_User", type="BusinessObject", value="User")
        n2 = Node(id="bo_User", type="BusinessObject", value="User Update")
        self.assertTrue(self.graph.add(n1))
        self.assertFalse(self.graph.add(n2))
        self.assertEqual(self.graph.node_count(), 1)
        self.assertEqual(self.graph.get("bo_User").value, "User")

    def test_duplicate_edge_handling(self):
        n1 = Node(id="bo_User", type="BusinessObject", value="User")
        n2 = Node(id="ep_GET /users", type="Endpoint", value="GET /users")
        self.graph.add(n1)
        self.graph.add(n2)
        
        self.assertTrue(self.graph.connect("bo_User", "ep_GET /users", "HAS_ENDPOINT"))
        self.assertFalse(self.graph.connect("bo_User", "ep_GET /users", "HAS_ENDPOINT"))
        
        self.assertEqual(self.graph.edge_count(), 1)

    def test_graph_traversal(self):
        n1 = Node(id="bo_User", type="BusinessObject", value="User")
        n2 = Node(id="ep_GET /users", type="Endpoint", value="GET /users")
        n3 = Node(id="ep_POST /users", type="Endpoint", value="POST /users")
        self.graph.add(n1)
        self.graph.add(n2)
        self.graph.add(n3)
        self.graph.connect("bo_User", "ep_GET /users", "HAS_ENDPOINT")
        self.graph.connect("bo_User", "ep_POST /users", "HAS_ENDPOINT")
        
        self.assertEqual(len(self.graph.edges_from(n1)), 2)
        self.assertEqual(len(self.graph.edges_to(n2)), 1)
        
        neighbors = self.graph.neighbors(n1)
        self.assertEqual(len(neighbors), 2)
        
        neighbors2 = self.graph.neighbors(n2)
        self.assertEqual(len(neighbors2), 1)
        self.assertEqual(neighbors2[0].id, "bo_User")

    def test_lookup_by_type(self):
        n1 = Node(id="bo_User", type="BusinessObject", value="User")
        n2 = Node(id="ep_GET /users", type="Endpoint", value="GET /users")
        self.graph.add(n1)
        self.graph.add(n2)
        
        bos = self.graph.nodes_by_type("BusinessObject")
        self.assertEqual(len(bos), 1)
        self.assertEqual(bos[0].id, "bo_User")

    def test_invalid_connections(self):
        n1 = Node(id="bo_User", type="BusinessObject", value="User")
        self.graph.add(n1)
        self.assertFalse(self.graph.connect("bo_User", "ep_999", "HAS_ENDPOINT"))
        self.assertFalse(self.graph.connect("ep_999", "bo_User", "HAS_ENDPOINT"))
        self.assertEqual(self.graph.edge_count(), 0)
        
    def test_statistics(self):
        n1 = Node(id="bo_User", type="BusinessObject", value="User")
        n2 = Node(id="ep_GET /users", type="Endpoint", value="GET /users")
        self.graph.add(n1)
        self.graph.add(n2)
        self.graph.connect("bo_User", "ep_GET /users", "HAS_ENDPOINT")
        
        stats = self.graph.summary()
        self.assertEqual(stats["Node Count"], 2)
        self.assertEqual(stats["Relationship Count"], 1)
        self.assertEqual(stats["BusinessObject Nodes"], 1)
        self.assertEqual(stats["Endpoint Nodes"], 1)


class TestKnowledgeGraphBuilder(unittest.TestCase):

    def test_empty_mission(self):
        mission = Mission(target="example.com")
        builder = KnowledgeGraphBuilder()
        builder.build(mission)
        
        self.assertIsNotNone(mission.graph)
        self.assertEqual(mission.graph.node_count(), 1)
        self.assertEqual(mission.graph.edge_count(), 0)
        
    def test_builder_statistics(self):
        mission = Mission(target="example.com")
        
        bo1 = BusinessObject(name="Organization")
        bo1.operations = ["READ", "CREATE"]
        ep1 = APIEndpoint(method="GET", path="/orgs", resource="org", operation="READ", business_object="Organization")
        bo1.endpoints.append(ep1)
        
        bo2 = BusinessObject(name="User")
        ep2 = APIEndpoint(method="POST", path="/users", resource="user", operation="CREATE", business_object="User")
        bo2.endpoints.append(ep2)
        
        mission.business_objects = [bo1, bo2]
        mission.api_intelligence = [ep1, ep2]
        
        mission.technologies = ["React", "GraphQL"]
        mission.authentication = AuthenticationModel(authentication_type="OAuth2", token_type="Bearer")
        
        builder = KnowledgeGraphBuilder()
        builder.build(mission)
        
        g = mission.graph
        
        self.assertIsNotNone(g)
        
        # bo(2) + ep(2) + tech(2) + auth(2) + operations(2) = 10
        self.assertEqual(g.node_count(), 10)
        
        # bo -> ep (2) + ep -> bo (2)
        # bo -> op (2)
        # bo -> tech (4) (2 bos * 2 tech)
        # bo -> auth (4) (2 bos * 2 auth)
        self.assertEqual(g.edge_count(), 14)
        
        bos = g.nodes_by_type("BusinessObject")
        self.assertEqual(len(bos), 2)
        
        techs = g.nodes_by_type("Technology")
        self.assertEqual(len(techs), 2)

if __name__ == "__main__":
    unittest.main()
