import pytest

from argus.ai.models import ResearchCard, ResearchCardCategory, ResearchCardPriority, ResearchCardStatus
from argus.reporting.queue import ResearchQueue


def test_research_queue_sorting():
    queue = ResearchQueue()
    
    card_low = ResearchCard(
        title="Low Priority Card",
        summary="Summary",
        category=ResearchCardCategory.RECON,
        confidence=0.5
    )
    
    card_high = ResearchCard(
        title="High Priority Card",
        summary="Summary",
        category=ResearchCardCategory.AUTHORIZATION,
        confidence=0.9,
        risk_if_confirmed="BOLA / IDOR could expose all data",
        authentication="OAuth"
    )
    
    card_critical = ResearchCard(
        title="Critical RCE",
        summary="Summary",
        category=ResearchCardCategory.CUSTOM,
        confidence=1.0,
        risk_if_confirmed="RCE",
        business_object="Admin Panel",
        related_evidence=["evidence1", "evidence2", "evidence3"]
    )
    
    queue.add(card_low)
    queue.add(card_high)
    queue.add(card_critical)
    
    queue.sort_by_priority()
    
    pending = queue.pending()
    assert pending[0].id == card_critical.id
    assert pending[1].id == card_high.id
    assert pending[2].id == card_low.id
    
    assert pending[0].priority == ResearchCardPriority.CRITICAL
    assert pending[1].priority == ResearchCardPriority.HIGH
    # Depending on exact score, card_low might be LOW
    assert pending[2].priority in (ResearchCardPriority.LOW, ResearchCardPriority.MEDIUM)


def test_research_queue_filtering():
    queue = ResearchQueue()
    
    card1 = ResearchCard(
        title="Auth Issue",
        summary="Sum",
        category=ResearchCardCategory.AUTHENTICATION
    )
    
    card2 = ResearchCard(
        title="Logic Issue",
        summary="Sum",
        category=ResearchCardCategory.BUSINESS_LOGIC
    )
    
    queue.add(card1)
    queue.add(card2)
    
    auth_cards = queue.filter(category=ResearchCardCategory.AUTHENTICATION)
    assert len(auth_cards) == 1
    assert auth_cards[0].id == card1.id
    
    logic_cards = queue.filter(category=ResearchCardCategory.BUSINESS_LOGIC)
    assert len(logic_cards) == 1
    assert logic_cards[0].id == card2.id


def test_research_queue_status_management():
    queue = ResearchQueue()
    
    card1 = ResearchCard(
        title="Card 1",
        summary="Sum",
        category=ResearchCardCategory.AUTHENTICATION,
        status=ResearchCardStatus.PENDING
    )
    
    card2 = ResearchCard(
        title="Card 2",
        summary="Sum",
        category=ResearchCardCategory.AUTHENTICATION,
        status=ResearchCardStatus.COMPLETED
    )
    
    card3 = ResearchCard(
        title="Card 3",
        summary="Sum",
        category=ResearchCardCategory.AUTHENTICATION,
        status=ResearchCardStatus.DISMISSED
    )
    
    queue.add(card1)
    queue.add(card2)
    queue.add(card3)
    
    assert len(queue.pending()) == 1
    assert queue.pending()[0].id == card1.id
    
    assert len(queue.completed()) == 1
    assert queue.completed()[0].id == card2.id
    
    assert len(queue.dismissed()) == 1
    assert queue.dismissed()[0].id == card3.id
