import pytest
from argus.plugins.graphql.business import BusinessKnowledgeAnalyzer
from argus.plugins.graphql.models import GraphQLSchema, GraphQLType, GraphQLField, GraphQLOperation
from argus.runtime.mission import Mission, GraphQLState
from argus.graph.graph import KnowledgeGraph

@pytest.fixture
def base_mission():
    mission = Mission("test")
    mission.graphql = GraphQLState()
    mission.graph = KnowledgeGraph()
    return mission

def test_business_objects_discovery(base_mission):
    schema = GraphQLSchema()
    schema.types["User"] = GraphQLType(name="User", kind="OBJECT")
    schema.types["Organization"] = GraphQLType(name="Organization", kind="OBJECT")
    schema.types["Query"] = GraphQLType(name="Query", kind="OBJECT")  # Should be skipped
    base_mission.graphql.schemas.append(schema)
    
    analyzer = BusinessKnowledgeAnalyzer()
    analyzer.analyze(base_mission)
    
    assert len(base_mission.graphql.business_objects) == 2
    bo_names = [bo.name for bo in base_mission.graphql.business_objects]
    assert "User" in bo_names
    assert "Organization" in bo_names
    assert "Query" not in bo_names

def test_relationship_inference(base_mission):
    schema = GraphQLSchema()
    user_type = GraphQLType(name="User", kind="OBJECT")
    user_type.fields["projects"] = GraphQLField(name="projects", type="Project", is_list=True)
    user_type.fields["organization"] = GraphQLField(name="organization", type="Organization", is_list=False)
    
    schema.types["User"] = user_type
    schema.types["Project"] = GraphQLType(name="Project", kind="OBJECT")
    schema.types["Organization"] = GraphQLType(name="Organization", kind="OBJECT")
    
    base_mission.graphql.schemas.append(schema)
    
    analyzer = BusinessKnowledgeAnalyzer()
    analyzer.analyze(base_mission)
    
    assert len(base_mission.graphql.relationships) == 2
    rels = { (r.parent, r.child): r.type for r in base_mission.graphql.relationships }
    assert rels[("User", "Project")] == "OWNS"  # ends with 's' and is_list
    assert rels[("User", "Organization")] == "BELONGS_TO"  # field name 'organization'

def test_crud_classification(base_mission):
    schema = GraphQLSchema()
    schema.mutations["createUser"] = GraphQLOperation(name="createUser", operation_type="Mutation", return_type="User")
    schema.mutations["updateProject"] = GraphQLOperation(name="updateProject", operation_type="Mutation", return_type="Project")
    schema.mutations["deleteInvoice"] = GraphQLOperation(name="deleteInvoice", operation_type="Mutation", return_type="Invoice")
    schema.queries["listRepositories"] = GraphQLOperation(name="listRepositories", operation_type="Query", return_type="Repository")
    schema.queries["searchUsers"] = GraphQLOperation(name="searchUsers", operation_type="Query", return_type="User")
    schema.queries["organization"] = GraphQLOperation(name="organization", operation_type="Query", return_type="Organization")
    
    base_mission.graphql.schemas.append(schema)
    
    analyzer = BusinessKnowledgeAnalyzer()
    analyzer.analyze(base_mission)
    
    assert len(base_mission.graphql.crud) == 6
    crud_map = { c.operation_name: c.action for c in base_mission.graphql.crud }
    assert crud_map["createUser"] == "CREATE"
    assert crud_map["updateProject"] == "UPDATE"
    assert crud_map["deleteInvoice"] == "DELETE"
    assert crud_map["listRepositories"] == "LIST"
    assert crud_map["searchUsers"] == "SEARCH"
    assert crud_map["organization"] == "READ"

def test_workflow_inference(base_mission):
    schema = GraphQLSchema()
    schema.mutations["inviteUser"] = GraphQLOperation(name="inviteUser", operation_type="Mutation", return_type="Invitation")
    schema.mutations["acceptInvitation"] = GraphQLOperation(name="acceptInvitation", operation_type="Mutation", return_type="User")
    
    base_mission.graphql.schemas.append(schema)
    
    analyzer = BusinessKnowledgeAnalyzer()
    analyzer.analyze(base_mission)
    
    assert len(base_mission.graphql.workflows) == 1
    wf = base_mission.graphql.workflows[0]
    assert wf.name == "Invitation"
    assert len(wf.states) == 2
    state_names = [s.name for s in wf.states]
    assert "inviteUser" in state_names
    assert "acceptInvitation" in state_names
    
    # Check WorkflowGraph
    assert base_mission.graphql.relationship_graph is not None
    graph_nodes = base_mission.graphql.relationship_graph.all()
    assert len(graph_nodes) == 2
