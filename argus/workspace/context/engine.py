import logging
from typing import List, Optional, Any
from argus.workspace.context.models import ContextQuery, ContextSource, ContextResult
from argus.workspace.context.ranker import ContextRanker
from argus.workspace.context.policy import ContextPolicy
from argus.workspace.context.assembler import ContextAssembler
from argus.workspace.context.mission import MissionContextResolver
from argus.workspace.context.graph import KnowledgeGraphRetriever
from argus.evidence.manager import EvidenceManager

logger = logging.getLogger(__name__)

class ResearchContextEngine:
    """The central orchestrator for gathering research context."""
    
    def __init__(
        self,
        ranker: Optional[ContextRanker] = None,
        policy: Optional[ContextPolicy] = None,
        assembler: Optional[ContextAssembler] = None,
        evidence_manager: Optional[EvidenceManager] = None,
        mission_resolver: Optional[MissionContextResolver] = None,
        graph_retriever: Optional[KnowledgeGraphRetriever] = None,
        vector_store: Optional[Any] = None,
        finding_search_engine: Optional[Any] = None,
        cve_knowledge_base: Optional[Any] = None,
        memory_manager: Optional[Any] = None,
        enable_semantic_retrieval: bool = True,
        min_semantic_score: float = 0.35,
        max_semantic_candidates: int = 10,
    ):
        self.ranker = ranker or ContextRanker()
        self.policy = policy or ContextPolicy()
        self.assembler = assembler or ContextAssembler()
        self.evidence_manager = evidence_manager or EvidenceManager()
        self.mission_resolver = mission_resolver or MissionContextResolver()
        self.graph_retriever = graph_retriever or KnowledgeGraphRetriever()

        self.vector_store = vector_store
        self.finding_search_engine = finding_search_engine
        self.cve_knowledge_base = cve_knowledge_base
        self.memory_manager = memory_manager
        self.enable_semantic_retrieval = enable_semantic_retrieval
        self.min_semantic_score = float(min_semantic_score)
        self.max_semantic_candidates = int(max_semantic_candidates)

    def _get_vector_store(self) -> Optional[Any]:
        if self.vector_store is None:
            try:
                from argus.vector.store import get_vector_store
                self.vector_store = get_vector_store()
            except Exception as e:
                logger.debug(f"VectorStore unavailable: {e}")
        return self.vector_store

    def _get_finding_search_engine(self) -> Optional[Any]:
        if self.finding_search_engine is None:
            try:
                vs = self._get_vector_store()
                if vs is not None:
                    from argus.reporting.vector_indexer import FindingSemanticSearchEngine
                    self.finding_search_engine = FindingSemanticSearchEngine(vector_store=vs)
            except Exception as e:
                logger.debug(f"FindingSemanticSearchEngine unavailable: {e}")
        return self.finding_search_engine

    def _get_cve_knowledge_base(self) -> Optional[Any]:
        if self.cve_knowledge_base is None:
            try:
                vs = self._get_vector_store()
                if vs is not None:
                    from argus.knowledge.cve_kb import CVEKnowledgeBase
                    self.cve_knowledge_base = CVEKnowledgeBase(vector_store=vs)
            except Exception as e:
                logger.debug(f"CVEKnowledgeBase unavailable: {e}")
        return self.cve_knowledge_base

    def _get_memory_manager(self) -> Optional[Any]:
        if self.memory_manager is None:
            try:
                vs = self._get_vector_store()
                from argus.memory.manager import MemoryManager
                if vs is not None:
                    self.memory_manager = MemoryManager(vector_store=vs)
                else:
                    self.memory_manager = MemoryManager()
            except Exception as e:
                logger.debug(f"MemoryManager unavailable: {e}")
        return self.memory_manager
        
    def _retrieve_sources(self, query: ContextQuery) -> List[ContextSource]:
        """
        Retrieves evidence, mission state, knowledge graph, and semantic vector
        context (findings, evidence, CVEs, memories) for the active query.
        """
        sources: List[ContextSource] = []
        source_by_id: dict[str, ContextSource] = {}
        
        # 1. Retrieve Evidence from EvidenceManager for active investigation
        if query.investigation_id:
            evidence_list = self.evidence_manager.get_by_investigation(query.investigation_id)
            for ev in evidence_list:
                status = "EVIDENCE" if ev.status in ["USER_REVIEWED", "CONFIRMED", "CORROBORATED"] else "OBSERVATION"
                source = ContextSource(
                    source_id=ev.evidence_id,
                    source_type=ev.source_type.lower(),
                    title=ev.title,
                    content=ev.description,
                    semantic_status=status,
                    mission_id=ev.mission_id,
                    investigation_id=ev.investigation_id,
                    project_id=ev.project_id,
                    timestamp=ev.created_at,
                    metadata={"evidence_id": ev.evidence_id, "status": ev.status},
                )
                sources.append(source)
                source_by_id[ev.evidence_id] = source
                
        # 2. Append Mission Context
        mission_sources = self.mission_resolver.resolve(query)
        for ms in mission_sources:
            sources.append(ms)
            source_by_id[ms.source_id] = ms
        
        # 3. Append Graph Context
        graph_sources = self.graph_retriever.resolve(query)
        for gs in graph_sources:
            sources.append(gs)
            source_by_id[gs.source_id] = gs
            
        # 4. Semantic Vector Retrieval
        if self.enable_semantic_retrieval and query.query and query.query.strip():
            # A. Semantic Findings
            finding_engine = self._get_finding_search_engine()
            if finding_engine is not None:
                try:
                    f_mid = query.mission_id if query.mission_id else None
                    findings_res = finding_engine.search_findings(
                        query=query.query,
                        top_k=self.max_semantic_candidates,
                        min_score=self.min_semantic_score,
                        mission_id=f_mid,
                    )
                    for res in findings_res:
                        res_raw_meta = res.metadata.get("raw_finding", {}) if isinstance(res.metadata.get("raw_finding"), dict) else {}
                        inner_meta = res_raw_meta.get("metadata", {}) if isinstance(res_raw_meta, dict) else {}
                        res_project_id = str(res.metadata.get("project_id") or inner_meta.get("project_id", "") or "")
                        if query.project_id and res_project_id and res_project_id != query.project_id:
                            continue
                        res_mission_id = str(res.mission_id or res.metadata.get("mission_id", "") or "")
                        if query.mission_id and res_mission_id and res_mission_id != query.mission_id:
                            continue

                        fid = str(res.metadata.get("finding_id") or res.id.split(":")[-1])
                        if fid in source_by_id:
                            existing = source_by_id[fid]
                            if existing.vector_score is None or res.score > existing.vector_score:
                                existing.vector_score = res.score
                                existing.metadata["vector_score"] = res.score
                        elif res.id in source_by_id:
                            existing = source_by_id[res.id]
                            if existing.vector_score is None or res.score > existing.vector_score:
                                existing.vector_score = res.score
                                existing.metadata["vector_score"] = res.score
                        else:
                            title = str(res.metadata.get("title") or f"Finding {fid}")
                            f_source = ContextSource(
                                source_id=fid,
                                source_type="vector_finding",
                                title=title,
                                content=res.content,
                                semantic_status="VECTOR_FINDING",
                                mission_id=res_mission_id,
                                project_id=res_project_id,
                                timestamp=res.created_at or "",
                                vector_score=res.score,
                                metadata=dict(res.metadata),
                            )
                            sources.append(f_source)
                            source_by_id[fid] = f_source
                            source_by_id[res.id] = f_source
                except Exception as e:
                    logger.warning(f"Error querying semantic findings: {e}")

            # B. Semantic Evidence
            if finding_engine is not None:
                try:
                    ev_mid = query.mission_id if query.mission_id else None
                    evidence_res = finding_engine.search_evidence(
                        query=query.query,
                        top_k=self.max_semantic_candidates,
                        min_score=self.min_semantic_score,
                        mission_id=ev_mid,
                    )
                    for res in evidence_res:
                        res_project_id = str(res.metadata.get("project_id", "") or "")
                        if query.project_id and res_project_id and res_project_id != query.project_id:
                            continue
                        res_mission_id = str(res.mission_id or res.metadata.get("mission_id", "") or "")
                        if query.mission_id and res_mission_id and res_mission_id != query.mission_id:
                            continue

                        eid = str(res.metadata.get("evidence_id") or res.id.split(":")[-1])
                        if eid in source_by_id:
                            existing = source_by_id[eid]
                            if existing.vector_score is None or res.score > existing.vector_score:
                                existing.vector_score = res.score
                                existing.metadata["vector_score"] = res.score
                        elif res.id in source_by_id:
                            existing = source_by_id[res.id]
                            if existing.vector_score is None or res.score > existing.vector_score:
                                existing.vector_score = res.score
                                existing.metadata["vector_score"] = res.score
                        else:
                            title = str(res.metadata.get("title") or f"Evidence {eid}")
                            ev_status = res.metadata.get("status", "CONFIRMED")
                            sem_status = "EVIDENCE" if ev_status in ["USER_REVIEWED", "CONFIRMED", "CORROBORATED"] else "VECTOR_EVIDENCE"
                            ev_source = ContextSource(
                                source_id=eid,
                                source_type="vector_evidence",
                                title=title,
                                content=res.content,
                                semantic_status=sem_status,
                                mission_id=res_mission_id,
                                project_id=res_project_id,
                                timestamp=res.created_at or "",
                                vector_score=res.score,
                                metadata=dict(res.metadata),
                            )
                            sources.append(ev_source)
                            source_by_id[eid] = ev_source
                            source_by_id[res.id] = ev_source
                except Exception as e:
                    logger.warning(f"Error querying semantic evidence: {e}")

            # C. CVE Knowledge Base
            cve_kb = self._get_cve_knowledge_base()
            if cve_kb is not None:
                try:
                    cve_res = cve_kb.search_cves(
                        query=query.query,
                        top_k=self.max_semantic_candidates,
                        min_score=self.min_semantic_score,
                    )
                    for entry, score in cve_res:
                        cid = entry.cve_id
                        if cid in source_by_id:
                            existing = source_by_id[cid]
                            if existing.vector_score is None or score > existing.vector_score:
                                existing.vector_score = score
                                existing.metadata["vector_score"] = score
                        else:
                            cve_title = entry.title if entry.title else cid
                            cve_source = ContextSource(
                                source_id=cid,
                                source_type="cve_knowledge",
                                title=cve_title,
                                content=entry.description,
                                semantic_status="CVE_KNOWLEDGE",
                                mission_id="",  # Global vulnerability intelligence
                                project_id="",  # Global vulnerability intelligence
                                vector_score=score,
                                metadata={
                                    "cve_id": cid,
                                    "cvss_score": entry.cvss_score,
                                    "severity": entry.severity,
                                    "cwes": list(entry.cwes),
                                    "affected_products": list(entry.affected_products),
                                    "references": list(entry.references),
                                }
                            )
                            sources.append(cve_source)
                            source_by_id[cid] = cve_source
                except Exception as e:
                    logger.warning(f"Error querying CVE knowledge base: {e}")

            # D. Historical Memories
            mem_mgr = self._get_memory_manager()
            if mem_mgr is not None:
                try:
                    if hasattr(mem_mgr, "recall"):
                        try:
                            from argus.memory.models import MemoryQuery
                            mq = MemoryQuery(
                                query=query.query,
                                top_k=self.max_semantic_candidates,
                                min_score=self.min_semantic_score,
                                project_id=query.project_id or None,
                                mission_id=query.mission_id or None,
                                status="active",
                                active_only=True,
                            )
                        except ImportError:
                            class _SimpleMemoryQuery:
                                def __init__(self, query, top_k, min_score, project_id=None, mission_id=None, status=None, active_only=True):
                                    self.query = query
                                    self.top_k = top_k
                                    self.min_score = min_score
                                    self.project_id = project_id
                                    self.mission_id = mission_id
                                    self.status = status or "active"
                                    self.active_only = active_only
                            mq = _SimpleMemoryQuery(
                                query=query.query,
                                top_k=self.max_semantic_candidates,
                                min_score=self.min_semantic_score,
                                project_id=query.project_id or None,
                                mission_id=query.mission_id or None,
                                status="active",
                                active_only=True,
                            )
                        try:
                            mem_results = mem_mgr.recall(mq)
                        except TypeError:
                            mem_results = mem_mgr.recall(
                                query=query.query,
                                top_k=self.max_semantic_candidates,
                                min_score=self.min_semantic_score,
                                project_id=query.project_id or None,
                                mission_id=query.mission_id or None,
                                status="active",
                                active_only=True,
                            )
                        for m_res in mem_results:
                            entry = getattr(m_res, "entry", m_res)
                            st = getattr(entry, "status", None)
                            if st is not None:
                                st_str = st.value if hasattr(st, "value") else str(st).strip().lower()
                                if st_str in ("archived", "superseded"):
                                    continue
                            mid = str(getattr(entry, "id", f"mem_{len(sources)}"))
                            m_score = getattr(m_res, "score", None)
                            mem_key = f"mem:{mid}"
                            if mem_key in source_by_id:
                                existing = source_by_id[mem_key]
                                if m_score is not None and (existing.vector_score is None or m_score > existing.vector_score):
                                    existing.vector_score = m_score
                                    existing.metadata["vector_score"] = m_score
                                continue
                            elif mid in source_by_id and source_by_id[mid].source_type == "historical_memory":
                                existing = source_by_id[mid]
                                if m_score is not None and (existing.vector_score is None or m_score > existing.vector_score):
                                    existing.vector_score = m_score
                                    existing.metadata["vector_score"] = m_score
                                continue
                            m_title = getattr(entry, "title", f"Memory {mid}")
                            m_content = getattr(entry, "content", "")
                            m_meta = dict(getattr(entry, "metadata", {}) or {})
                            m_type = getattr(entry, "memory_type", None)
                            if m_type and "memory_type" not in m_meta:
                                m_meta["memory_type"] = m_type.value if hasattr(m_type, "value") else str(m_type)
                            if "confidence" not in m_meta and hasattr(entry, "confidence"):
                                m_meta["confidence"] = entry.confidence
                            if "status" not in m_meta and hasattr(entry, "status"):
                                st = entry.status
                                m_meta["status"] = st.value if hasattr(st, "value") else str(st)
                            res_mid = str(getattr(entry, "mission_id", "") or m_meta.get("mission_id", "") or "")
                            res_pid = str(getattr(entry, "project_id", "") or m_meta.get("project_id", "") or "")
                            if query.project_id and res_pid and res_pid != query.project_id:
                                continue
                            if query.mission_id and res_mid and res_mid != query.mission_id:
                                continue
                            m_source = ContextSource(
                                source_id=mid,
                                source_type="historical_memory",
                                title=m_title,
                                content=m_content,
                                semantic_status="HISTORICAL_MEMORY",
                                mission_id=res_mid,
                                project_id=res_pid,
                                vector_score=m_score,
                                metadata=m_meta,
                            )
                            sources.append(m_source)
                            source_by_id[mem_key] = m_source
                            if mid not in source_by_id:
                                source_by_id[mid] = m_source
                except Exception as e:
                    logger.debug(f"Memory recall not available or failed: {e}")

        return sources

    def resolve_context(self, query: ContextQuery) -> str:
        """Retrieves, ranks, filters, and assembles context into a prompt string."""
        from argus.authorization.gate import authorization_gate
        
        # 0. Check Authorization
        user_id = query.user_id or "system_user"
        mission_id = query.mission_id
        project_id = query.project_id
        
        if mission_id:
            perm = authorization_gate.can_access_mission(user_id, mission_id)
            if not perm.allowed:
                return f"AUTHORIZATION DENIED: {perm.reason}"
                
        user_permission_state = "AUTHORIZED_FOR_MISSION"
        
        # 1. Retrieve raw sources
        raw_sources = self._retrieve_sources(query)
        
        # 1.5 Enforce Isolation
        isolated_sources = []
        for src in raw_sources:
            if src.mission_id and mission_id and src.mission_id != mission_id:
                continue
            if src.project_id and project_id and src.project_id != project_id:
                continue
            isolated_sources.append(src)
        
        # 2. Filter (Policy & Scope)
        allowed_sources = self.policy.apply(query, isolated_sources)
        
        # 3. Rank
        ranked_sources = self.ranker.rank(query, allowed_sources)
        
        # 4. Check for contradictions or insufficient data
        status = "OK"
        if not ranked_sources:
            status = "INSUFFICIENT_CONTEXT"
            
        result = ContextResult(
            sources=ranked_sources, 
            context_status=status,
            user_permission_state=user_permission_state,
            authorization_scope="RESTRICTED_TO_MISSION_SCOPE"
        )
        
        # 5. Assemble
        return self.assembler.assemble(result)

    resolve = resolve_context
