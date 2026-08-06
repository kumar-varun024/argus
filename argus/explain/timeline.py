from typing import List
from argus.explain.models import TimelineEvent
from argus.investigation.models import Investigation
from argus.runtime.mission import Mission
from datetime import datetime, timezone

class TimelineBuilder:
    """Builds a chronological timeline of events leading up to an investigation."""
    
    def __init__(self, mission: Mission):
        self.mission = mission

    def build_timeline(self, investigation: Investigation) -> List[TimelineEvent]:
        events = []
        
        # 1. Investigation Creation
        events.append(TimelineEvent(
            timestamp=investigation.created_at,
            event_type="Investigation Created",
            description=f"Investigation '{investigation.title}' generated.",
            source_id=str(investigation.id)
        ))
        
        seen_corrs = set()
        seen_obs = set()
        
        # 2. Evidence Bundles
        for bundle_id in investigation.evidence_bundles:
            bundle = self.mission.evidence_bundles.find(bundle_id)
            if not bundle:
                continue
            
            events.append(TimelineEvent(
                timestamp=getattr(bundle, 'created_at', datetime.now(timezone.utc)),
                event_type="Evidence Fused",
                description=f"Evidence Bundle '{bundle.title}' fused.",
                source_id=str(bundle.id)
            ))
            
            # 3. Correlations
            for corr_id in bundle.correlations:
                if corr_id in seen_corrs:
                    continue
                seen_corrs.add(corr_id)
                corr = self.mission.correlations.find(corr_id)
                if not corr:
                    continue
                
                ts = getattr(corr, 'created_at', getattr(corr, 'timestamp', datetime.now(timezone.utc)))
                events.append(TimelineEvent(
                    timestamp=ts,
                    event_type="Correlation Formed",
                    description=f"Correlation formed between {len(corr.observations)} observations.",
                    source_id=str(corr.id)
                ))
            
            # 4. Observations
            for obs_id in bundle.observations:
                if obs_id in seen_obs:
                    continue
                seen_obs.add(obs_id)
                obs = self.mission.observations.find(obs_id)
                if not obs:
                    continue
                
                ts = getattr(obs, 'timestamp', getattr(obs, 'created_at', datetime.now(timezone.utc)))
                events.append(TimelineEvent(
                    timestamp=ts,
                    event_type="Observation Recorded",
                    description=f"Observation '{obs.title}' recorded by {obs.source}.",
                    source_id=str(obs.id)
                ))
        
        # Sort chronologically
        events.sort(key=lambda e: e.timestamp)
        return events
