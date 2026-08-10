import datetime
import re
from typing import List, AsyncGenerator
from argus.workspace.models import Conversation, Message, ImageAttachment, ContextReference
from argus.workspace.provider import AIModelProvider, MockModelProvider
from argus.workspace.repository import ConversationRepository
from argus.workspace.context.engine import ResearchContextEngine
from argus.workspace.context.models import ContextQuery
from argus.workspace.planner import EvidenceAwareAnswerPlanner

class ConversationEngine:
    """The central engine orchestrating conversational interactions."""
    
    def __init__(self, provider: AIModelProvider = None, repository: ConversationRepository = None):
        self.provider = provider or MockModelProvider()
        self.repository = repository or ConversationRepository()
        self.context_engine = ResearchContextEngine()
        self.planner = EvidenceAwareAnswerPlanner()
        
    def add_user_message(self, conversation: Conversation, text: str, attachments: List[ImageAttachment] = None) -> Message:
        msg = Message(role="user", text=text, attachments=attachments or [])
        msg.sequence_number = len(conversation.messages)
        conversation.messages.append(msg)
        
        conversation.last_message_at = datetime.datetime.utcnow().isoformat()
        conversation.updated_at = conversation.last_message_at
        self.repository.save(conversation)
        return msg
        
    def generate_response(self, conversation: Conversation) -> Message:
        """Generates a synchronous response using evidence-aware context."""
        
        latest_msg = conversation.messages[-1] if conversation.messages else None
        query_text = latest_msg.text if latest_msg else ""
        
        # Build the context query
        query = ContextQuery(
            conversation_id=conversation.conversation_id,
            query=query_text,
            mission_id=conversation.mission_id,
            project_id=conversation.project_id
        )
        
        # 1. Retrieve raw sources via context engine
        context_str = self.context_engine.resolve_context(query)
        # Note: Ideally, resolve_context would return ContextResult instead of string.
        # But for now, we'll mock the result parsing or pass a dummy one if we can't change it.
        # Let's get the sources directly for the planner to evaluate.
        # The prompt instructed to modify the context engine assembler. We'll do that next.
        
        # To avoid changing the entire ResearchContextEngine signature immediately,
        # we'll use a hack to get the result. 
        # Actually, let's just get the raw sources via internal method for the planner
        raw_sources = self.context_engine._retrieve_sources(query)
        allowed_sources = self.context_engine.policy.apply(query, raw_sources)
        ranked_sources = self.context_engine.ranker.rank(query, allowed_sources)
        from argus.workspace.context.models import ContextResult
        status = "OK" if ranked_sources else "INSUFFICIENT_CONTEXT"
        result = ContextResult(sources=ranked_sources, context_status=status)
        
        # 2. Plan the answer
        if latest_msg:
            answer_plan = self.planner.plan_answer(conversation, latest_msg, result)
        else:
            answer_plan = self.planner.plan_answer(conversation, Message(), result)
            
        # 3. Combine contexts
        full_system_prompt = answer_plan.system_instructions + "\n\n" + context_str
        
        # 4. Generate response
        if latest_msg and latest_msg.attachments:
            response_text = self.provider.multimodal_generate(conversation.messages, latest_msg.attachments, system_prompt=full_system_prompt)
        else:
            response_text = self.provider.generate(conversation.messages, system_prompt=full_system_prompt)
            
        # 5. Extract citations (e.g. [Evidence #1234])
        references = []
        evidence_matches = re.findall(r"\[Evidence #([^\]]+)\]", response_text)
        for ev_id in evidence_matches:
            references.append(ContextReference(ref_id=ev_id, ref_type="evidence", title=f"Evidence #{ev_id}"))
            
        assistant_msg = Message(role="assistant", text=response_text, references=references)
        assistant_msg.sequence_number = len(conversation.messages)
        conversation.messages.append(assistant_msg)
        
        conversation.last_message_at = datetime.datetime.utcnow().isoformat()
        conversation.updated_at = conversation.last_message_at
        self.repository.save(conversation)
        
        return assistant_msg
