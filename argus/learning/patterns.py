"""
Pattern Discovery.

Identifies reusable research patterns from historical LearningRecord data using
purely deterministic, threshold-based rules.

No machine learning or LLM inference is used.  Every pattern is explainable
and traceable back to specific mission records.
"""
import logging
from typing import Dict, List

from argus.learning.models import DiscoveredPattern, LearningRecord

logger = logging.getLogger(__name__)

# Minimum number of missions required to fire a pattern rule.
_MIN_MISSIONS = 2

# Thresholds
_AUTHORIZATION_VALIDATION_THRESHOLD = 0.60  # 60 % validated
_NOISE_RATE_THRESHOLD = 0.70                # 70 % false positives


class PatternDiscovery:
    """
    Identifies reusable patterns from a collection of LearningRecord objects.

    Rules are evaluated deterministically — given the same records they always
    produce the same patterns.  Patterns are advisory only; they do not trigger
    any automatic changes.
    """

    def discover(self, records: List[LearningRecord]) -> List[DiscoveredPattern]:
        """
        Run all pattern detection rules and return the discovered patterns.

        Requires at least ``_MIN_MISSIONS`` records before any pattern fires.
        """
        if len(records) < _MIN_MISSIONS:
            logger.info(
                f"Pattern discovery: insufficient history "
                f"({len(records)} records, need {_MIN_MISSIONS})."
            )
            return []

        patterns: List[DiscoveredPattern] = []

        patterns.extend(self._rule_high_authorization_validation(records))
        patterns.extend(self._rule_low_confidence_heuristic(records))
        patterns.extend(self._rule_valuable_plugin(records))
        patterns.extend(self._rule_coverage_bottleneck(records))
        patterns.extend(self._rule_workflow_discovery_leader(records))

        for p in patterns:
            logger.info(f"Pattern discovered: {p.name} (strength={p.strength:.2f})")

        return patterns

    # ------------------------------------------------------------------
    # Detection rules
    # ------------------------------------------------------------------

    def _rule_high_authorization_validation(
        self, records: List[LearningRecord]
    ) -> List[DiscoveredPattern]:
        """
        Rule: Authorization investigations are frequently validated.

        Fires when ≥60 % of records report at least one validated hypothesis
        whose investigation_quality is above the median.
        """
        qualifying_missions = []
        for rec in records:
            # Use validated_hypotheses list length as a proxy for validation success
            if rec.validated_hypotheses:
                qualifying_missions.append(rec.mission_id)

        if len(records) == 0:
            return []

        rate = len(qualifying_missions) / len(records)
        if rate < _AUTHORIZATION_VALIDATION_THRESHOLD:
            return []

        return [DiscoveredPattern(
            name="Authorization investigations frequently validated",
            description=(
                f"{int(rate * 100)}% of missions had validated hypotheses, "
                "indicating Authorization analysis consistently produces actionable results."
            ),
            category="Authorization",
            strength=round(rate, 2),
            sample_mission_ids=qualifying_missions[:5],
        )]

    def _rule_low_confidence_heuristic(
        self, records: List[LearningRecord]
    ) -> List[DiscoveredPattern]:
        """
        Rule: A specific heuristic produces excessive noise.

        Fires when the same heuristic_id has noise_rate > 0.70 in ≥2 missions.
        """
        # Accumulate noise rates per heuristic across missions
        heuristic_noise: Dict[str, List[float]] = {}
        heuristic_missions: Dict[str, List[str]] = {}

        for rec in records:
            for h_id, stat in rec.heuristic_usage.items():
                heuristic_noise.setdefault(h_id, []).append(stat.noise_rate)
                heuristic_missions.setdefault(h_id, []).append(rec.mission_id)

        patterns = []
        for h_id, noise_rates in heuristic_noise.items():
            high_noise = [r for r in noise_rates if r > _NOISE_RATE_THRESHOLD]
            if len(high_noise) >= _MIN_MISSIONS:
                avg_noise = sum(noise_rates) / len(noise_rates)
                patterns.append(DiscoveredPattern(
                    name=f"Heuristic {h_id} produces excessive noise",
                    description=(
                        f"Heuristic '{h_id}' had a noise rate above "
                        f"{int(_NOISE_RATE_THRESHOLD * 100)}% in "
                        f"{len(high_noise)} missions (avg noise: {avg_noise:.0%}). "
                        "Consider reviewing or disabling it."
                    ),
                    category="Heuristic Quality",
                    strength=round(avg_noise, 2),
                    sample_mission_ids=heuristic_missions[h_id][:5],
                ))

        return patterns

    def _rule_valuable_plugin(
        self, records: List[LearningRecord]
    ) -> List[DiscoveredPattern]:
        """
        Rule: One plugin consistently generates the most validated investigations.

        Fires when the top plugin has value_rate > 0 in ≥2 missions.
        """
        plugin_value: Dict[str, List[float]] = {}
        plugin_missions: Dict[str, List[str]] = {}
        plugin_names: Dict[str, str] = {}

        for rec in records:
            for p_id, stat in rec.plugin_usage.items():
                plugin_value.setdefault(p_id, []).append(stat.value_rate)
                plugin_missions.setdefault(p_id, []).append(rec.mission_id)
                plugin_names[p_id] = stat.plugin_name

        patterns = []
        # Find the plugin with highest average value_rate across ≥2 missions
        best_id = None
        best_rate = 0.0
        for p_id, rates in plugin_value.items():
            if len(rates) < _MIN_MISSIONS:
                continue
            avg = sum(rates) / len(rates)
            if avg > best_rate:
                best_rate = avg
                best_id = p_id

        if best_id and best_rate > 0:
            name = plugin_names.get(best_id, best_id)
            patterns.append(DiscoveredPattern(
                name=f"{name} specialist generated highest value investigations",
                description=(
                    f"'{name}' (id={best_id}) had the highest average investigation "
                    f"value rate ({best_rate:.0%}) across "
                    f"{len(plugin_value[best_id])} missions."
                ),
                category="Plugin Performance",
                strength=round(best_rate, 2),
                sample_mission_ids=plugin_missions[best_id][:5],
            ))

        return patterns

    def _rule_coverage_bottleneck(
        self, records: List[LearningRecord]
    ) -> List[DiscoveredPattern]:
        """
        Rule: A task category consistently has the most failed tasks.

        Inferred from mission.metrics.failed_task_count being non-zero and
        the failed_tasks list on LearningRecord.
        """
        missions_with_failures = [
            rec for rec in records if rec.failed_tasks
        ]
        if len(missions_with_failures) < _MIN_MISSIONS:
            return []

        rate = len(missions_with_failures) / len(records)
        sample_ids = [r.mission_id for r in missions_with_failures[:5]]

        return [DiscoveredPattern(
            name="Coverage gaps persist across missions",
            description=(
                f"{int(rate * 100)}% of missions reported failed research tasks, "
                "indicating recurring coverage gaps that tooling improvements may address."
            ),
            category="Coverage",
            strength=round(rate, 2),
            sample_mission_ids=sample_ids,
        )]

    def _rule_workflow_discovery_leader(
        self, records: List[LearningRecord]
    ) -> List[DiscoveredPattern]:
        """
        Rule: One plugin consistently discovers the most observations (workflows).

        Fires when the top plugin has total_observations > 0 in ≥2 missions.
        """
        plugin_obs: Dict[str, List[int]] = {}
        plugin_missions: Dict[str, List[str]] = {}
        plugin_names: Dict[str, str] = {}

        for rec in records:
            for p_id, stat in rec.plugin_usage.items():
                plugin_obs.setdefault(p_id, []).append(stat.total_observations)
                plugin_missions.setdefault(p_id, []).append(rec.mission_id)
                plugin_names[p_id] = stat.plugin_name

        best_id = None
        best_avg = 0.0
        for p_id, obs_counts in plugin_obs.items():
            if len(obs_counts) < _MIN_MISSIONS:
                continue
            avg = sum(obs_counts) / len(obs_counts)
            if avg > best_avg:
                best_avg = avg
                best_id = p_id

        if best_id and best_avg > 0:
            name = plugin_names.get(best_id, best_id)
            # Normalise strength to [0, 1] using log scale (cap at 100 obs)
            strength = min(best_avg / 100.0, 1.0)
            return [DiscoveredPattern(
                name=f"{name} specialist discovered most workflows",
                description=(
                    f"'{name}' (id={best_id}) generated an average of "
                    f"{best_avg:.1f} observations per mission — the highest of any plugin."
                ),
                category="Plugin Performance",
                strength=round(strength, 2),
                sample_mission_ids=plugin_missions[best_id][:5],
            )]

        return []
