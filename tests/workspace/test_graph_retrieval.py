import pytest
from argus.workspace.context.graph import KnowledgeGraphRetriever
from argus.workspace.context.models import ContextQuery
from argus.workspace.models import Conversation, Message
from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.runtime.mission import Mission
from argus.runtime.manager import mission_manager
from argus.workspace.repository import ConversationRepository

@pytest.fixture
def test_mission():
    mission = Mission(name="Test Mission Graph", target="example.com")
    graph = KnowledgeGraph()
    # Add nodes
    ep_node = Node(id="ep_/api/users", type="Endpoint", value="/api/users")
    ev_node = Node(id="ev_123", type="Evidence", value="Screenshot 1")
    graph.add(ep_node)
    graph.add(ev_node)
    graph.connect(ep_node.id, ev_node.id, "OBSERVED_IN", {"status": "AI_INFERRED"})
    
    mission.graph = graph
    mission_manager._active_missions[mission.id] = mission
    return mission

class MockRepository:
    def __init__(self):
        self.convs = {}
    def get(self, cid):
        return self.convs.get(cid)
    def save(self, conv):
        self.convs[conv.conversation_id] = conv

@pytest.fixture
def repo():
    return MockRepository()

def test_retriever_exact_match(test_mission, repo):
    retriever = KnowledgeGraphRetriever(repository=repo)
    query = ContextQuery(conversation_id="test_conv", query="What is connected to /api/users?", mission_id=test_mission.id)
    
    sources = retriever.resolve(query)
    assert len(sources) > 0
    assert "Graph Entity: /api/users" in sources[0].title
    assert "-> OBSERVED_IN -> Evidence: Screenshot 1 [AI_INFERRED]" in sources[0].content

def test_retriever_conversational_reference(test_mission, repo):
    retriever = KnowledgeGraphRetriever(repository=repo)
    
    # Create a conversation where they talk about the endpoint
    conv = Conversation(conversation_id="conv_1", mission_id=test_mission.id)
    conv.messages.append(Message(role="user", text="I found /api/users"))
    repo.save(conv)
    
    # Query referencing "this endpoint"
    query = ContextQuery(conversation_id="conv_1", query="What is connected to this endpoint?", mission_id=test_mission.id)
    
    sources = retriever.resolve(query)
    assert len(sources) > 0
    assert "Graph Entity: /api/users" in sources[0].title

def test_retriever_no_match(test_mission, repo):
    retriever = KnowledgeGraphRetriever(repository=repo)
    query = ContextQuery(conversation_id="test_conv", query="What about /api/unknown?", mission_id=test_mission.id)
    
    sources = retriever.resolve(query)
    assert len(sources) == 0
