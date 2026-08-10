import logging
from typing import List
from argus.workspace.context.models import ContextSource, ContextQuery
from argus.runtime.manager import mission_manager

logger = logging.getLogger(__name__)

class MissionContextResolver:
    """Resolves and formats the active mission context for the AI."""
    
    def resolve(self, query: ContextQuery) -> List[ContextSource]:
        """Resolves all mission-related context sources based on the query."""
        if not query.mission_id:
            return []
            
        try:
            mission = mission_manager.get_mission(query.mission_id)
        except Exception as e:
            logger.error(f"Failed to load mission {query.mission_id}: {e}")
            return []
            
        sources = []
        
        # 1. Mission State
        sources.append(
            ContextSource(
                source_id=f"mission_{mission.id}",
                source_type="mission",
                title="Active Mission",
                content=f"Name: {mission.name}\nTarget: {mission.target}\nStatus: {mission.status.value}\nPhase: {mission.phase}",
                semantic_status="MISSION_STATE",
                mission_id=mission.id
            )
        )
        
        # 2. Scope
        scope_text = ", ".join(mission.scope) if mission.scope else "No specific scope defined."
        sources.append(
            ContextSource(
                source_id=f"scope_{mission.id}",
                source_type="mission_scope",
                title="Mission Scope",
                content=f"Authorized Targets: {scope_text}",
                semantic_status="SCOPE",
                mission_id=mission.id
            )
        )
        
        # 3. Active Investigation
        if query.investigation_id:
            try:
                # Convert string ID to UUID if it's a string, or just pass it to find which might handle it.
                import uuid
                inv_id = uuid.UUID(query.investigation_id) if isinstance(query.investigation_id, str) else query.investigation_id
                inv = mission.investigations.find(inv_id)
                if inv:
                    sources.append(
                        ContextSource(
                            source_id=f"inv_{inv.id}",
                            source_type="investigation",
                            title=f"Active Investigation: {inv.title}",
                            content=f"Summary: {inv.summary}\nCategory: {inv.category.value}\nStatus: {inv.status.value}",
                            semantic_status="INVESTIGATION_STATE",
                            mission_id=mission.id,
                            investigation_id=str(inv.id)
                        )
                    )
            except Exception as e:
                logger.error(f"Failed to load active investigation {query.investigation_id}: {e}")
                
        # 4. Findings
        if hasattr(mission, 'findings') and mission.findings:
            findings_text = "\n".join([f"- {f.title} ({f.status})" for f in mission.findings])
            sources.append(
                ContextSource(
                    source_id=f"findings_{mission.id}",
                    source_type="mission_findings",
                    title="Mission Findings",
                    content=findings_text,
                    semantic_status="FINDING",
                    mission_id=mission.id
                )
            )
            
        # 5. Hypotheses
        if hasattr(mission, 'hypotheses') and hasattr(mission.hypotheses, 'all'):
            try:
                hypotheses = mission.hypotheses.all()
                if hypotheses:
                    hyp_text = "\n".join([f"- {h.title} ({h.status.value})" for h in hypotheses])
                    sources.append(
                        ContextSource(
                            source_id=f"hypotheses_{mission.id}",
                            source_type="mission_hypotheses",
                            title="Active Hypotheses",
                            content=hyp_text,
                            semantic_status="HYPOTHESIS",
                            mission_id=mission.id
                        )
                    )
            except Exception:
                pass # Hypothesis engine might not be loaded
                
        return sources
