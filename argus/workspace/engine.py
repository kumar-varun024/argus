import datetime
from typing import List, AsyncGenerator
from argus.workspace.models import Conversation, Message, ImageAttachment
from argus.workspace.provider import AIModelProvider, MockModelProvider
from argus.workspace.repository import ConversationRepository
from argus.workspace.context.engine import ResearchContextEngine
from argus.workspace.context.models import ContextQuery

class ConversationEngine:
    """The central engine orchestrating conversational interactions."""
    
    def __init__(self, provider: AIModelProvider = None, repository: ConversationRepository = None):
        self.provider = provider or MockModelProvider()
        self.repository = repository or ConversationRepository()
        self.context_engine = ResearchContextEngine()
        
    def add_user_message(self, conversation: Conversation, text: str, attachments: List[ImageAttachment] = None) -> Message:
        msg = Message(role="user", text=text, attachments=attachments or [])
        msg.sequence_number = len(conversation.messages)
        conversation.messages.append(msg)
        
        conversation.last_message_at = datetime.datetime.utcnow().isoformat()
        conversation.updated_at = conversation.last_message_at
        self.repository.save(conversation)
        return msg
        
    def generate_response(self, conversation: Conversation) -> Message:
        """Generates a synchronous response."""
        
        latest_msg = conversation.messages[-1] if conversation.messages else None
        query_text = latest_msg.text if latest_msg else ""
        
        # Build the context query
        query = ContextQuery(
            conversation_id=conversation.conversation_id,
            query=query_text,
            mission_id=conversation.mission_id,
            project_id=conversation.project_id
        )
        
        sys_prompt = self.context_engine.resolve_context(query)
        
        # Insert system prompt into provider payload logic (mocked here)
        # We would prepend it if this was calling a real OpenAI/Anthropic SDK
        
        if latest_msg and latest_msg.attachments:
            response_text = self.provider.multimodal_generate(conversation.messages, latest_msg.attachments)
        else:
            response_text = self.provider.generate(conversation.messages)

        
        latest_msg = conversation.messages[-1] if conversation.messages else None
        
        if latest_msg and latest_msg.attachments:
            response_text = self.provider.multimodal_generate(conversation.messages, latest_msg.attachments)
        else:
            response_text = self.provider.generate(conversation.messages)
            
        assistant_msg = Message(role="assistant", text=response_text)
        assistant_msg.sequence_number = len(conversation.messages)
        conversation.messages.append(assistant_msg)
        
        conversation.last_message_at = datetime.datetime.utcnow().isoformat()
        conversation.updated_at = conversation.last_message_at
        self.repository.save(conversation)
        
        return assistant_msg
