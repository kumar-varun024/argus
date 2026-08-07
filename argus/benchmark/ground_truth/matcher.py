import logging
from typing import List, Optional
from argus.benchmark.ground_truth.models import MatchResult, MatchStatus

logger = logging.getLogger(__name__)

class GroundTruthMatcher:
    """Core logic for matching expected strings/objects against actual outputs."""
    
    @staticmethod
    def match_item(category: str, expected: str, actuals: List[str]) -> MatchResult:
        """
        Attempts to match a single expected item against a list of actual findings.
        Returns a MatchResult.
        """
        if not expected:
            raise ValueError("Expected value cannot be empty.")
            
        expected_lower = expected.lower()
        actuals_lower = [a.lower() for a in actuals]
        
        # 1. Exact Match
        if expected_lower in actuals_lower:
            # Find the original case for the actual
            idx = actuals_lower.index(expected_lower)
            return MatchResult(
                category=category,
                expected=expected,
                actual=actuals[idx],
                status=MatchStatus.MATCHED,
                explanation="Exact match found.",
                confidence=1.0
            )
            
        # 2. Partial Match (Substring)
        for act in actuals:
            if expected_lower in act.lower() or act.lower() in expected_lower:
                return MatchResult(
                    category=category,
                    expected=expected,
                    actual=act,
                    status=MatchStatus.PARTIALLY_MATCHED,
                    explanation="Partial match based on substring overlap.",
                    confidence=0.5
                )
                
        # 3. Not Matched
        return MatchResult(
            category=category,
            expected=expected,
            actual=None,
            status=MatchStatus.NOT_MATCHED,
            explanation="No matching actual finding was discovered.",
            confidence=0.0
        )
        
    @staticmethod
    def identify_unexpected(category: str, expected_list: List[str], actual_list: List[str]) -> List[MatchResult]:
        """Identifies actual findings that were not expected in the ground truth."""
        unexpected = []
        expected_lower = [e.lower() for e in expected_list]
        
        for act in actual_list:
            act_lower = act.lower()
            # If actual is not exactly in expected, and no expected string is a substring of actual
            if act_lower not in expected_lower:
                is_partial = any(e in act_lower or act_lower in e for e in expected_lower)
                if not is_partial:
                    unexpected.append(MatchResult(
                        category=category,
                        expected=None,
                        actual=act,
                        status=MatchStatus.UNEXPECTED_FINDING,
                        explanation="Finding was discovered but not defined in ground truth.",
                        confidence=0.8
                    ))
        return unexpected
