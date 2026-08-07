"""
Recommendation Engine.

Converts DiscoveredPattern objects into advisory Recommendation items for the
Mission Planner.

IMPORTANT: Recommendations are NEVER applied automatically.
           Every Recommendation carries ``requires_planner_approval = True``.
           The planner must read mission.patterns and explicitly act on them.
"""
import logging
from typing import Any, List

from argus.learning.models import (
    DiscoveredPattern,
    Recommendation,
    RecommendationPriority,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pattern name → recommendation builder mapping
# ---------------------------------------------------------------------------

def _build_recommendation(pattern: DiscoveredPattern) -> Recommendation:
    """
    Map a single DiscoveredPattern to an advisory Recommendation.
    Strength drives the recommendation priority tier.
    """
    name = pattern.name
    pid = pattern.id

    priority = (
        RecommendationPriority.HIGH if pattern.strength >= 0.75
        else RecommendationPriority.MEDIUM if pattern.strength >= 0.40
        else RecommendationPriority.LOW
    )

    # -------------------------------------------------------------------
    # Authorization frequently validated
    # -------------------------------------------------------------------
    if "Authorization investigations frequently validated" in name:
        return Recommendation(
            title="Run Authorization Analysis earlier in future missions",
            description=(
                "Authorization investigations are consistently validated across missions. "
                "Scheduling Authorization analysis earlier in the research queue may "
                "surface high-value findings sooner."
            ),
            rationale=(
                f"Pattern '{name}' detected with strength {pattern.strength:.0%} "
                f"across missions: {', '.join(pattern.sample_mission_ids[:3])}."
            ),
            category="Authorization",
            priority=priority,
            source_pattern_ids=[pid],
        )

    # -------------------------------------------------------------------
    # Noisy heuristic
    # -------------------------------------------------------------------
    if "produces excessive noise" in name:
        # Extract heuristic id from pattern name: "Heuristic <id> produces..."
        parts = name.split(" ")
        heuristic_id = parts[1] if len(parts) > 1 else "unknown"
        return Recommendation(
            title=f"Review or disable heuristic {heuristic_id} to reduce noise",
            description=(
                f"Heuristic '{heuristic_id}' generates a high proportion of "
                "false-positive observations, consuming researcher attention without "
                "producing validated findings."
            ),
            rationale=(
                f"Pattern '{name}' detected with strength {pattern.strength:.0%}. "
                f"Sample missions: {', '.join(pattern.sample_mission_ids[:3])}."
            ),
            category="Heuristic Quality",
            priority=priority,
            source_pattern_ids=[pid],
        )

    # -------------------------------------------------------------------
    # Valuable plugin
    # -------------------------------------------------------------------
    if "specialist generated highest value investigations" in name:
        # Extract plugin name: "<plugin> specialist generated..."
        plugin_name = name.split(" specialist")[0]
        return Recommendation(
            title=f"Increase {plugin_name} analysis depth in future missions",
            description=(
                f"'{plugin_name}' consistently generates the highest-value validated "
                "investigations. Allocating more execution time or depth to this "
                "specialist is likely to improve research outcomes."
            ),
            rationale=(
                f"Pattern '{name}' detected with strength {pattern.strength:.0%}. "
                f"Sample missions: {', '.join(pattern.sample_mission_ids[:3])}."
            ),
            category="Plugin Performance",
            priority=priority,
            source_pattern_ids=[pid],
        )

    # -------------------------------------------------------------------
    # Coverage bottleneck
    # -------------------------------------------------------------------
    if "Coverage gaps persist" in name:
        return Recommendation(
            title="Improve coverage tooling to reduce persistent research gaps",
            description=(
                "Multiple missions reported failed research tasks, indicating that "
                "existing tooling does not adequately cover certain analysis areas. "
                "Review failed task categories and consider adding specialist plugins."
            ),
            rationale=(
                f"Pattern '{name}' detected with strength {pattern.strength:.0%}. "
                f"Sample missions: {', '.join(pattern.sample_mission_ids[:3])}."
            ),
            category="Coverage",
            priority=priority,
            source_pattern_ids=[pid],
        )

    # -------------------------------------------------------------------
    # Workflow discovery leader
    # -------------------------------------------------------------------
    if "specialist discovered most workflows" in name:
        plugin_name = name.split(" specialist")[0]
        return Recommendation(
            title=f"Prioritize {plugin_name} earlier in the research queue",
            description=(
                f"'{plugin_name}' consistently discovers the most observations per "
                "mission. Running it earlier provides richer data for downstream "
                "correlation, evidence fusion, and investigation generation."
            ),
            rationale=(
                f"Pattern '{name}' detected with strength {pattern.strength:.0%}. "
                f"Sample missions: {', '.join(pattern.sample_mission_ids[:3])}."
            ),
            category="Plugin Performance",
            priority=priority,
            source_pattern_ids=[pid],
        )

    # -------------------------------------------------------------------
    # Fallback — generic recommendation for any unrecognised pattern
    # -------------------------------------------------------------------
    return Recommendation(
        title=f"Review pattern: {name}",
        description=pattern.description,
        rationale=(
            f"Pattern '{name}' detected with strength {pattern.strength:.0%}. "
            f"Sample missions: {', '.join(pattern.sample_mission_ids[:3])}."
        ),
        category=pattern.category,
        priority=priority,
        source_pattern_ids=[pid],
    )


class RecommendationEngine:
    """
    Converts DiscoveredPattern objects into advisory Recommendation items.

    Quality gate: every recommendation must contain a non-empty ``rationale``.
    Recommendations that fail this check are logged and discarded.
    """

    def generate(
        self,
        patterns: List[DiscoveredPattern],
        mission: Any = None,
    ) -> List[Recommendation]:
        """
        Generate Recommendation objects from a list of DiscoveredPattern.

        Parameters
        ----------
        patterns : Discovered patterns from PatternDiscovery.discover().
        mission  : Optional active mission; if provided, recommendations are
                   appended to ``mission.patterns``.

        Returns
        -------
        List of valid Recommendation objects, sorted High → Low priority.
        """
        recommendations: List[Recommendation] = []

        for pattern in patterns:
            rec = _build_recommendation(pattern)

            # Quality gate
            if not rec.rationale.strip():
                logger.warning(
                    f"Recommendation '{rec.title}' rejected: empty rationale."
                )
                continue

            # Enforce immutable approval flag
            rec.requires_planner_approval = True

            recommendations.append(rec)
            logger.info(f"Recommendation created: {rec.title} (priority={rec.priority.value})")

        # Sort: High > Medium > Low
        _order = {
            RecommendationPriority.HIGH: 0,
            RecommendationPriority.MEDIUM: 1,
            RecommendationPriority.LOW: 2,
        }
        recommendations.sort(key=lambda r: _order.get(r.priority, 99))

        # Store in mission.patterns if available
        if mission is not None and hasattr(mission, "patterns"):
            if isinstance(mission.patterns, list):
                mission.patterns.extend(recommendations)

        return recommendations
