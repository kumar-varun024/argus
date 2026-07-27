from typing import List, Optional

from argus.ai.models import ResearchCard, ResearchCardStatus, ResearchCardPriority


class ResearchQueue:
    def __init__(self):
        self._cards: List[ResearchCard] = []

    def add(self, card: ResearchCard):
        self._cards.append(card)

    def get(self, card_id: str) -> Optional[ResearchCard]:
        for card in self._cards:
            if card.id == card_id:
                return card
        return None

    def _calculate_score(self, card: ResearchCard) -> int:
        score = 0
        
        # Base confidence multiplier
        base_score = 10 * card.confidence

        score += base_score

        # Evidence is king
        score += len(card.related_evidence) * 15

        # Importance of auth boundaries and sensitive ops
        if "auth" in card.authentication.lower() or card.authentication.lower() in ("oauth", "jwt", "saml"):
            score += 20

        if "admin" in card.business_object.lower() or "org" in card.business_object.lower() or "user" in card.business_object.lower():
            score += 15

        # KB matches
        score += len(card.references) * 5

        # Risk keywords
        risk_str = card.risk_if_confirmed.lower()
        if "rce" in risk_str or "command injection" in risk_str:
            score += 50
        elif "sqli" in risk_str or "sql injection" in risk_str or "pwn" in risk_str:
            score += 40
        elif "bola" in risk_str or "idor" in risk_str or "authorization" in risk_str:
            score += 30
        elif "xss" in risk_str or "csrf" in risk_str:
            score += 20
        
        return int(score)

    def sort_by_priority(self) -> None:
        """
        Sorts the queue deterministically by computed priority score (descending).
        Updates the 'priority' field on each card as a side effect.
        """
        def update_and_get_score(c: ResearchCard):
            score = self._calculate_score(c)
            if score >= 80:
                c.priority = ResearchCardPriority.CRITICAL
            elif score >= 50:
                c.priority = ResearchCardPriority.HIGH
            elif score >= 25:
                c.priority = ResearchCardPriority.MEDIUM
            else:
                c.priority = ResearchCardPriority.LOW
            return score
            
        self._cards.sort(key=lambda c: update_and_get_score(c), reverse=True)

    def filter(self, category: Optional[str] = None, status: Optional[ResearchCardStatus] = None) -> List[ResearchCard]:
        results = self._cards
        
        if category:
            results = [c for c in results if c.category.value == category or c.category == category]
            
        if status:
            results = [c for c in results if c.status == status]
            
        return results

    def pending(self) -> List[ResearchCard]:
        return self.filter(status=ResearchCardStatus.PENDING)

    def completed(self) -> List[ResearchCard]:
        return self.filter(status=ResearchCardStatus.COMPLETED)

    def dismissed(self) -> List[ResearchCard]:
        return self.filter(status=ResearchCardStatus.DISMISSED)

    def __iter__(self):
        return iter(self._cards)

    def __len__(self):
        return len(self._cards)
