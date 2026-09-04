# Cluster 3 Feature Audit Report: Sections 26–37

**Cluster**: Cluster 3 — AI, Security Research RAG / Intelligence Fabric & Research Specialists  
**Scope**: Sections 26 through 37 of the Argus Feature Inventory Specification  
**Auditor**: Cluster 3 Auditor (`teamwork_preview_explorer`)  
**Audit Date**: 2026-09-04  
**Working Directory**: `/home/varun/argus/.agents/audit_cluster3`

---

## 1. Executive Summary & Status Scorecard

| Section | Feature Name | Status | Key Source Files | CLI Command | Test Coverage |
|---|---|---|---|---|---|
| **26** | **AI Research** | ✅ Implemented | `argus/ai/researcher.py`, `argus/ai/context.py`, `argus/ai/prompts.py`, `argus/ai/client.py`, `argus/ai/gemini_client.py`, `argus/ai/openai_client.py`, `argus/ai/github_client.py`, `argus/ai/models.py`, `argus/agents/recon.py` | `argus mission run <target>`, `argus research plan/queue/explain/coverage` | 35 passed (`tests/test_ai_research.py`, `tests/ai/test_ai_clients.py`) |
| **27** | **Security Research RAG / Intelligence Fabric (27.1–27.16)** | ✅ Implemented | `argus/vector/store.py`, `argus/vector/models.py`, `argus/vector/embeddings.py`, `argus/workspace/context/engine.py`, `argus/workspace/context/ranker.py`, `argus/workspace/context/assembler.py`, `argus/workspace/context/graph.py`, `argus/workspace/context/policy.py`, `argus/reporting/vector_indexer.py`, `argus/knowledge/cve_kb.py`, `argus/memory/manager.py` | `argus search <query>`, `argus search cves`, `argus search memory`, `argus search stats` | 73 passed (`tests/vector/test_rag_integration.py`, `tests/vector/test_rag_adversarial.py`, `tests/vector/test_rag_prompt_injection.py`, `tests/vector/test_embedding_robustness.py`) |
| **28** | **Research Cards** | ✅ Implemented | `argus/ai/models.py`, `argus/reporting/queue.py`, `argus/cli/queue_cli.py` | `argus queue list <mission_id>` | 3 passed (`tests/test_research_cards.py`) |
| **29** | **Vulnerability Intelligence Engine** | ✅ Implemented | `argus/intelligence/engine.py`, `argus/intelligence/models.py`, `argus/intelligence/hypothesis.py`, `argus/intelligence/confidence.py`, `argus/intelligence/prioritizer.py`, `argus/hypothesis/engine.py`, `argus/hypothesis/models.py`, `argus/hypothesis/generator.py` | `argus intelligence run/list/show/explain`, `argus hypothesis ...` | 4 passed (`tests/test_intelligence.py`) |
| **30** | **Methodology Engine & Playbooks** | ✅ Implemented | `argus/methodology/engine.py`, `argus/methodology/playbook.py`, `argus/methodology/models.py`, `argus/methodology/executor.py`, `argus/methodology/registry.py`, `argus/methodology/step.py`, `argus/cli/playbook_cli.py` | `argus playbooks list/show/run/status` | 4 passed (`tests/test_methodology.py`) |
| **31** | **Authorization Specialist** | ✅ Implemented | `argus/agents/authorization/agent.py`, `argus/agents/authorization/heuristics.py`, `argus/agents/authorization/ownership.py`, `argus/agents/authorization/roles.py`, `argus/agents/authorization/permissions.py`, `argus/authorization/analyzer.py`, `argus/authorization/graph.py`, `argus/authorization/gate.py`, `argus/collectors/access_control.py` | `argus auth show`, `argus auth analyze <mission_id>` | 7 passed (`tests/test_authorization.py`, `tests/authorization/test_authorization_gate.py`) + 9 passed in collectors |
| **32** | **Business Logic Specialist** | ✅ Implemented | `argus/agents/business_logic/agent.py`, `argus/agents/business_logic/states.py`, `argus/agents/business_logic/transitions.py`, `argus/agents/business_logic/objects.py`, `argus/agents/business_logic/workflow.py`, `argus/agents/business_logic/planner.py`, `argus/agents/business_logic/heuristics.py`, `argus/collectors/business_logic.py` | `argus business investigations <mission_id>` | 5 passed (`argus/agents/business_logic/tests/test_business_logic.py`) + 4 passed in collectors |
| **33** | **API Intelligence Specialist** | ⚠️ Partial | `argus/plugins/api/agent.py`, `argus/plugins/api/plugin.py`, `argus/plugins/api/resource_model.py`, `argus/plugins/api/operations.py`, `argus/plugins/api/relationships.py`, `argus/plugins/api/versions.py`, `argus/plugins/api/schemas.py`, `argus/collectors/api_security.py` | `argus api inventory/resources/graph/explain` | 3 passed (`argus/plugins/api/tests/test_api_intelligence.py`) + 6 passed in collectors |
| **34** | **GraphQL Specialist** | ✅ Implemented | `argus/plugins/graphql/agent.py`, `argus/plugins/graphql/discovery.py`, `argus/plugins/graphql/schema.py`, `argus/plugins/graphql/business.py`, `argus/plugins/graphql/reasoning.py`, `argus/plugins/graphql/cli.py`, `argus/collectors/graphql.py` | `argus graphql discover/schema/types/operations/relationships/workflows/business_objects/investigations/explain/priority` | 75 passed (`tests/collectors/test_graphql.py`, `tests/collectors/test_graphql_adversarial.py`, `argus/plugins/graphql/tests/test_graphql.py`) |
| **35** | **JavaScript Intelligence** | ✅ Implemented | `argus/plugins/javascript/parser.py`, `argus/plugins/javascript/agent.py`, `argus/plugins/javascript/discovery.py`, `argus/plugins/javascript/models.py`, `argus/plugins/javascript/cli.py`, `argus/analyzers/javascript.py`, `argus/collectors/javascript.py` | `argus javascript discover/analyze` | 17 passed (`tests/plugins/javascript/`) |
| **36** | **Authentication Specialist** | ✅ Implemented | `argus/plugins/authentication/agent.py`, `argus/plugins/authentication/identity.py`, `argus/plugins/authentication/sessions.py`, `argus/plugins/authentication/tokens.py`, `argus/plugins/authentication/oauth.py`, `argus/plugins/authentication/mfa.py`, `argus/collectors/auth_bypass.py`, `argus/collectors/oauth.py` | `argus authn analyze/investigations/explain/graph` | 1 passed in plugins + 101 passed in collectors (`test_auth_bypass.py`, `test_oauth.py`) |
| **37** | **File Upload Specialist** | ✅ Implemented | `argus/plugins/file_upload/agent.py`, `argus/plugins/file_upload/uploads.py`, `argus/plugins/file_upload/storage.py`, `argus/plugins/file_upload/objects.py`, `argus/plugins/file_upload/workflow.py`, `argus/plugins/file_upload/heuristics.py`, `argus/collectors/file_upload.py` | `argus upload analyze/investigations/explain/graph` | 45 passed (`argus/plugins/file_upload/tests/test_file_upload.py`, `tests/collectors/test_file_upload.py`, `tests/collectors/test_file_upload_adversarial.py`) |

**Overall Assessment**:
- **Implemented (✅)**: 11 of 12 sections (91.7%)
- **Partial (⚠️)**: 1 of 12 sections (8.3% — Section 33)
- **Missing (❌)**: 0
- **Broken (🔴)**: 0

---

## 2. Detailed Section-by-Section Audit

### Section 26: AI Research
- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/ai/researcher.py`: `Researcher` class orchestrating `client.research(prompt)`.
  - `argus/ai/context.py`: `ContextBuilder` compiling structured context from mission target, detected technologies, authentication state, business objects, workflow summaries, and `AuthorizationAnalyzer` graph boundaries.
  - `argus/ai/prompts.py`: `build_research_prompt()` incorporating strict negative constraints ("Never claim a vulnerability. Never invent evidence. Base every statement only on supplied context.") and specifying strict JSON output schema.
  - `argus/ai/client.py`: Abstract base `AIClient`, factory `get_ai_client()`, and fallback `NoOpAIClient`.
  - `argus/ai/gemini_client.py`: Google Gemini API client with Markdown fence stripping, HTTP error handling, and JSON parsing.
  - `argus/ai/openai_client.py`: OpenAI ChatCompletions client with JSON mode.
  - `argus/ai/github_client.py`: GitHub Models client via OpenAI-compatible endpoints.
  - `argus/ai/models.py`: `AIResponse` dataclass (executive_summary, business_objects, business_workflows, authorization_boundaries, sensitive_operations, high_value_assets, research_questions, missing_evidence, recommended_next_steps, confidence, unknown_areas).
  - `argus/agents/recon.py`: Lines 37, 54, 240–300 integrate `Researcher`, store output on `mission.ai_research`, and render the full AI research breakdown in mission evaluation.
- **Implementation Evidence**:
  - `ReconAgent.execute()` calls `mission.ai_research = self.researcher.analyze(mission)`.
  - Negative constraints strictly enforced in prompts to prevent hallucinations:
    ```python
    CRITICAL CONSTRAINTS:
    - Never claim a vulnerability.
    - Never invent evidence.
    - Never fabricate technologies.
    - Base every statement only on supplied context.
    - Express uncertainty when evidence is incomplete.
    ```
- **Gaps**:
  - No standalone direct `argus ai research` CLI invocation command (AI research executes as part of `argus agent run recon` or `argus mission run <target>`, while `argus research` maps to `ResearchPlanner`).
  - Real-time response streaming and interactive chat are not implemented.
- **Test Coverage**:
  - 35 tests passing: `tests/test_ai_research.py` (4 passed), `tests/ai/test_ai_clients.py` (31 passed).
- **Notes**:
  - Fully decoupled architecture allowing seamless swapping between OpenAI, Gemini, GitHub Models, or offline NoOp mode via `ARGUS_AI_PROVIDER`.

---

### Section 27: Security Research RAG / Intelligence Fabric (Subsections 27.1–27.16)
- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/vector/store.py`: Dual-engine persistent vector database (`VectorStore`) supporting native `sqlite-vec` (vec0 virtual table) acceleration and vectorized NumPy fallback over SQLite binary blobs.
  - `argus/vector/models.py`: `VectorStoreConfig`, `VectorDocument`, `SearchResult`, `VectorFilter`, `DistanceMetric`.
  - `argus/vector/embeddings.py`: `EmbeddingEngine` supporting `DeterministicEmbeddingProvider` (zero-dependency offline cybersecurity concept cluster hashing), `FastEmbedProvider`, and `SentenceTransformerProvider`.
  - `argus/workspace/context/engine.py`: `ResearchContextEngine` orchestrating multi-source blended retrieval across evidence, mission state, knowledge graph, semantic findings, CVEs, and memories.
  - `argus/workspace/context/ranker.py`: `ContextRanker` computing hybrid scores ($S_{hybrid} = w_{vec} \cdot S_{vec} + w_{lex} \cdot S_{lex} + S_{scope} + S_{type}$) and enforcing window budgets.
  - `argus/workspace/context/assembler.py`: `ContextAssembler` rendering structured, grounded prompts with explicit citations (`[Evidence #...]`, `[Finding #...]`, `[Hypothesis #...]`, `[cve_id]`, `[Memory #...]`).
  - `argus/workspace/context/graph.py`: `KnowledgeGraphRetriever` performing bounded graph traversal with per-node scope verification.
  - `argus/workspace/context/policy.py`: `ContextPolicy` enforcing project and mission isolation.
  - `argus/reporting/vector_indexer.py`: `ScanEvidenceIndexer` and `FindingSemanticSearchEngine` indexing findings, evidence items, and vulnerability reports.
  - `argus/knowledge/cve_kb.py`: `CVEKnowledgeBase` ingesting CVE records into `source_type='cve'` with semantic search and CWE/product filtering.
  - `argus/memory/manager.py` & `argus/memory/store.py`: `MemoryManager` storing and recalling historical memories under `source_type='memory'`.
  - `argus/cli/search_cli.py`: CLI search suite wired to `argus search`.
- **Subsections 27.1–27.16 Detailed Breakdown**:
  1. **27.1 Research Sources**:
     - Supported sources: Evidence, Findings, Observations, CVEs/NVD records, Historical memories (attack patterns, strategic decisions, user corrections), Knowledge Graph entities and relationships, Mission state and Authorized Scope.
     - Implemented across `ResearchContextEngine`, `ScanEvidenceIndexer`, `CVEKnowledgeBase`, `MemoryManager`, and `KnowledgeGraphRetriever`.
  2. **27.2 Ingestion Pipeline**:
     - Batch and streaming ingestion via `VectorStore.add_documents()` and `add_document()`.
     - Automatically generates missing embeddings in batches (`EmbeddingEngine.embed_batch()`) and persists float32 binary blobs.
     - Specialized indexers: `ScanEvidenceIndexer.index_finding()`, `index_evidence()`, `index_report()`; `CVEKnowledgeBase.ingest_cves()`; `MemoryManager.remember()`.
  3. **27.3 Knowledge Representations**:
     - Vectors: 384-dimensional float32 arrays/blobs.
     - Structured metadata: `VectorDocument` with `id`, `content`, `source_type`, `mission_id`, `severity`, `category`, `metadata_json`, `created_at`, `updated_at`.
     - Graph nodes and edges: `KnowledgeGraph` representation of assets, endpoints, technologies, and vulnerabilities.
     - Domain models: `CVEEntry`, `MemoryEntry`, `Finding`, `Evidence`.
  4. **27.4 Retrieval Modes**:
     - Metadata filtering: `VectorFilter` translating to SQL `WHERE` clauses for column-level index lookup (`source_type`, `mission_id`, `severity`, `category`) plus arbitrary JSON metadata matching.
     - Semantic similarity: Cosine, L2 (Euclidean), and Dot Product similarity metrics.
     - Scoped retrieval: Strict filtering by mission, project, and investigation identifiers.
  5. **27.5 Hybrid Retrieval**:
     - `ContextRanker` implements blended hybrid score:
       $$S_{hybrid} = (w_{vec} \cdot S_{vec}) + (w_{lex} \cdot S_{lex}) + S_{scope} + S_{type}$$
       where $w_{vec} = 0.6, w_{lex} = 0.4$.
     - Backward compatibility: If `vector_score` is missing or zero, $w_{vec} \to 0.0$ and $w_{lex} \to 1.0$ ensuring seamless pure-lexical fallback.
  6. **27.6 Graph RAG**:
     - `KnowledgeGraphRetriever` (`argus/workspace/context/graph.py`):
       - Identifies target entities from query text and conversation context ("this endpoint", "this evidence").
       - Extracts subgraphs via depth-1 bounded traversal (`edges_from`, `edges_to`).
       - Validates scope for each connected entity using `ScopeResolver.check_scope()`.
       - Emits formatted `ContextSource` tagged with `semantic_status="KNOWLEDGE_GRAPH"`.
  7. **27.7 Evidence RAG**:
     - Direct retrieval of verified evidence items from `EvidenceManager` by investigation ID.
     - Discriminates between verified facts (`EVIDENCE` for statuses `USER_REVIEWED`, `CONFIRMED`, `CORROBORATED`) and unverified facts (`OBSERVATION`).
     - Preserves evidence provenance, strength, and relationships in context metadata.
  8. **27.8 Research Context Builder**:
     - `ResearchContextEngine` coordinates source gathering, scope isolation, policy application, hybrid ranking, status classification, and Markdown assembly.
     - `ContextBuilder` (`argus/ai/context.py`) packages target overview, technologies, authentication state, and authorization boundaries for LLM consumption.
  9. **27.9 Reranking**:
     - `ContextRanker.rank()` computes hybrid scores, assigns categorical tiers:
       - `Critical` ($S \ge 15.0$)
       - `High` ($S \ge 10.0$)
       - `Medium` ($S \ge 5.0$)
       - `Low` ($S < 5.0$, pruned)
     - Sorts by priority tier and descending score, enforcing `max_context_sources` window budget to prevent token overflow.
  10. **27.10 Grounding/Citations**:
      - `ContextAssembler.assemble()` renders explicit bracketed citation identifiers:
        - `[Evidence #<id>]` with Quality, Provenance, and Relationship
        - `[Finding #<id>]`
        - `[Hypothesis #<id>]`
        - `[<cve_id>]` with CVSS, CWE, Affected Products
        - `[Memory #<id>]`
      - Explicitly segregates confirmed facts from unproven theories and hypotheses to mitigate hallucination risks.
  11. **27.11 RAG Confidence**:
      - Numerical hybrid score and decomposed sub-components (`vector_score_component`, `lexical_score_component`, `scope_score_component`, `type_score_component`) recorded in metadata.
      - Discrete relevance categories (`Critical`, `High`, `Medium`, `Low`).
      - Context status flag (`OK`, `INSUFFICIENT_CONTEXT`, `CONTRADICTORY_EVIDENCE`).
  12. **27.12 Knowledge Freshness**:
      - ISO-8601 UTC timestamps on all records (`created_at`, `updated_at`).
      - SQLite B-tree index `idx_documents_created_at` for temporal queries.
      - Historical memory lifecycle awareness: automatically filters out `archived` or `superseded` memories.
  13. **27.13 Privacy/Scope-Aware Retrieval**:
      - `ContextPolicy.apply()` enforces project and mission boundary isolation.
      - Upfront authorization check via `authorization_gate.can_access_mission()`.
      - Per-node scope verification in `KnowledgeGraphRetriever` via `ScopeResolver`.
  14. **27.14 Pluggable RAG Providers**:
      - Embedding engine supports `DeterministicEmbeddingProvider`, `FastEmbedProvider`, and `SentenceTransformerProvider`.
      - Offline deterministic provider maps 8 cybersecurity concept clusters (SQLi, XSS, RCE, Auth Flaws, Traversal, CSRF, SSRF, IDOR/BOLA).
      - Dual-engine storage: Native `sqlite-vec` virtual table (`vec0`) with automatic vectorized NumPy fallback.
  15. **27.15 RAG Evaluation**:
      - Tested rigorously against adversarial poison injection, deceptive CVE descriptions, embedding collisions, and prompt injection attacks.
  16. **27.16 RAG Failure Handling**:
      - `VectorStore` automatically falls back to NumPy search if `sqlite-vec` fails to load or encounters a runtime error.
      - Per-source exception isolation in `ResearchContextEngine._retrieve_sources()` ensures individual provider errors do not abort the pipeline.
      - Returns `context_status="INSUFFICIENT_CONTEXT"` when no relevant sources match instead of throwing exceptions.
- **CLI Wiring**:
  - `argus search <query>`: Semantic search across all sources with multi-field filtering (`--type`, `--severity`, `--category`, `--mission`, `--min-score`, `--top-k`, `--json`, `--verbose`).
  - `argus search cves <query>`: CVE search with CWE and product filters.
  - `argus search memory <query>`: Memory recall with memory type filter.
  - `argus search stats`: Vector index statistics (document counts by source, store path, embedding provider, dimension).
- **Gaps**:
  - None. Subsections 27.1 through 27.16 are thoroughly realized.
- **Test Coverage**:
  - 73 passed tests in `tests/vector/`:
    - `test_rag_integration.py` (28 passed)
    - `test_rag_adversarial.py` (17 passed)
    - `test_rag_prompt_injection.py` (12 passed)
    - `test_embedding_robustness.py` (16 passed)
- **Notes**:
  - The deterministic cybersecurity taxonomy embedding provider allows 100% offline functionality without requiring massive PyTorch or HuggingFace dependencies in constrained CI sandboxes.

---

### Section 28: Research Cards
- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/ai/models.py`: Dataclass `ResearchCard`, enums `ResearchCardCategory`, `ResearchCardPriority`, `ResearchCardStatus`.
  - `argus/reporting/queue.py`: `ResearchQueue` managing cards, scoring priorities, deterministic sorting, and status filtering.
  - `argus/cli/queue_cli.py`: Typer CLI `argus queue` commands.
- **Implementation Evidence**:
  - `ResearchCard` models structured research ideas with: `title`, `summary`, `category`, `priority`, `confidence`, `status`, `business_object`, `authentication`, `technology`, `related_endpoints`, `related_evidence`, `related_graph_nodes`, `reasoning`, `recommended_manual_steps`, `expected_observations`, `risk_if_confirmed`, `references`, `related_workflows`, `authorization_context`.
  - `ResearchQueue._calculate_score()` dynamically weights cards based on confidence, evidence count, authentication boundary keywords, high-value asset keywords ("admin", "org"), and risk keywords ("rce" +50, "sqli" +40, "idor"/"bola" +30, "xss" +20).
  - Priority transitions: $\ge 80 \to \text{CRITICAL}$, $\ge 50 \to \text{HIGH}$, $\ge 25 \to \text{MEDIUM}$, else $\text{LOW}$.
- **CLI Wiring**:
  - `argus queue list <mission_id>`: Displays prioritized investigation queue with colorized priority tags and manual verification steps.
- **Gaps**:
  - CLI currently implements `list`; interactive card status modification (e.g. `argus queue complete <id>`, `argus queue dismiss <id>`) is not exposed as separate CLI subcommands (though methods `completed()`, `dismissed()` exist in `ResearchQueue`).
- **Test Coverage**:
  - 3 passed tests: `tests/test_research_cards.py` (`test_research_queue_sorting`, `test_research_queue_filtering`, `test_research_queue_status_management`).
- **Notes**:
  - Clean separation between data model, prioritization queue, and CLI presentation.

---

### Section 29: Vulnerability Intelligence Engine
- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/intelligence/engine.py`: `VulnerabilityIntelligenceEngine` orchestrating hypothesis generation, confidence scoring, prioritization, and queue population.
  - `argus/intelligence/models.py`: `Investigation` dataclass with `affected_objects`, `affected_endpoints`, `workflow`, `reasoning`, `supporting_evidence`, `confidence`, `priority`, `manual_validation_steps`, `related_cwe`, `related_owasp`, `status`.
  - `argus/intelligence/hypothesis.py`: `HypothesisGenerator` applying registered heuristics.
  - `argus/intelligence/heuristics.py`: `BaseHeuristic` and heuristic implementations.
  - `argus/intelligence/confidence.py`: `ConfidenceScorer`.
  - `argus/intelligence/prioritizer.py`: `InvestigationPrioritizer`.
  - `argus/hypothesis/engine.py`: `HypothesisEngine` facade for hypothesis lifecycle, validation, and attack surface graph linking.
  - `argus/hypothesis/models.py`: `Hypothesis` Pydantic model explicitly codifying that hypotheses are unproven research questions.
  - `argus/cli/intelligence_cli.py`: Typer CLI `argus intelligence`.
- **Implementation Evidence**:
  - Explicit rule adherence: Output objects are hypotheses, not confirmed vulnerabilities. Line 93 of `intelligence_cli.py` explicitly warns: `NOTE: This is a hypothesis. It must be manually validated and does NOT claim a vulnerability exists.`
  - Generates CWE, OWASP, supporting evidence, and manual validation steps for every investigation.
- **CLI Wiring**:
  - `argus intelligence run <mission_id>`: Executes intelligence engine over mission.
  - `argus intelligence list <mission_id>`: Lists investigations by priority and confidence.
  - `argus intelligence show <mission_id> <inv_id>`: Shows affected objects and workflows.
  - `argus intelligence explain <mission_id> <inv_id>`: Displays reasoning, supporting evidence, and manual validation steps.
- **Gaps**:
  - Dual hypothesis implementations exist in the codebase: `argus/intelligence/` (`VulnerabilityIntelligenceEngine`, `Investigation`) and `argus/hypothesis/` (`HypothesisEngine`, `Hypothesis`). They operate in parallel rather than being unified into a single class hierarchy.
- **Test Coverage**:
  - 4 passed tests: `tests/test_intelligence.py` (`test_heuristic_registry`, `test_confidence_scorer`, `test_prioritizer`, `test_intelligence_engine`).
- **Notes**:
  - Rich heuristics detect cross-tenant access, vertical privilege escalation risks, and workflow shortcuts.

---

### Section 30: Methodology Engine & Playbooks
- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/methodology/engine.py`: `MethodologyEngine` coordinating playbook selection and execution across active missions.
  - `argus/methodology/playbook.py`: `get_default_playbooks()` containing all 8 standard playbooks.
  - `argus/methodology/models.py`: `Playbook`, `PlaybookStep`, `PlaybookResult`.
  - `argus/methodology/executor.py`: `PlaybookExecutor`.
  - `argus/methodology/registry.py`: `PlaybookRegistry`.
  - `argus/methodology/step.py`: `StepEvaluator` validating prerequisite evidence and workflows.
  - `argus/cli/playbook_cli.py`: Typer CLI `argus playbooks`.
- **Implementation Evidence**:
  - All 8 specified playbooks are encoded with steps, required workflows, and expected results:
    1. Authorization Review (`pb_authz_review`)
    2. Business Logic Review (`pb_business_logic`)
    3. Authentication Review (`pb_authentication`)
    4. Session Management Review (`pb_session_mgmt`)
    5. API Review (`pb_api_review`)
    6. File Upload Review (`pb_file_upload`)
    7. Workflow Review (`pb_workflow`)
    8. Information Disclosure Review (`pb_info_disclosure`)
  - `PlaybookStep` encapsulates: `id`, `title`, `description`, `required_evidence`, `required_graph_nodes`, `required_workflows`, `actions`, `expected_results`, `completion_criteria`.
- **CLI Wiring**:
  - `argus playbooks list`: Tables all available playbooks with category and step count.
  - `argus playbooks show <playbook_id>`: Displays steps and workflow prerequisites.
  - `argus playbooks run <mission_id> [playbook_id]`: Executes methodology engine on mission.
  - `argus playbooks status <mission_id>`: Shows active and completed playbooks.
- **Gaps**:
  - Some default playbooks (e.g. Session Management, File Upload) have lightweight default step sets that rely on specialist agent discovery rather than deeply nested static sub-steps.
- **Test Coverage**:
  - 4 passed tests: `tests/test_methodology.py` (`test_playbook_registry`, `test_step_evaluator`, `test_playbook_executor`, `test_methodology_engine`).
- **Notes**:
  - Extensible registry allows dynamic registration of custom playbooks.

---

### Section 31: Authorization Specialist
- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/agents/authorization/agent.py`: `AuthorizationSpecialist` executing heuristics against `AuthzContext`.
  - `argus/agents/authorization/heuristics.py`: `AUTHZ_HEURISTIC_REGISTRY`, `CrossTenantObjectHeuristic`, `MultiRoleResourceHeuristic`, `AdministrativeEndpointHeuristic`.
  - `argus/agents/authorization/ownership.py`: `OwnershipAnalyzer` tracing cross-tenant objects and ownership chains.
  - `argus/agents/authorization/roles.py`: `RoleAnalyzer` analyzing role hierarchies and admin capabilities.
  - `argus/agents/authorization/permissions.py`: `PermissionAnalyzer`.
  - `argus/agents/authorization/confidence.py`: `AuthzConfidenceScorer`.
  - `argus/authorization/analyzer.py`: `AuthorizationAnalyzer` for `AuthorizationGraph`.
  - `argus/authorization/graph.py`: `AuthorizationGraph` with node and edge types (`CAN_ACCESS`, `CAN_CREATE`, `CAN_DELETE`, `MEMBER_OF`, `OWNS`).
  - `argus/authorization/gate.py`: `authorization_gate` enforcement.
  - `argus/collectors/access_control.py`: Active access control / BOLA / BFLA vulnerability collector (17 KB).
  - `argus/cli/auth_cli.py`: Typer CLI `argus auth`.
- **Implementation Evidence**:
  - Analyzes object authorization (BOLA/cross-tenant object access), function authorization (administrative endpoint access), ownership chains (`Organization -> Project -> Repository`), role hierarchy trees (`Owner -> Admin -> Manager/Member`), and privilege boundaries.
  - Generates deduplicated `Investigation` objects with confidence and validation steps.
- **CLI Wiring**:
  - `argus auth show [mission_id]`: Renders role hierarchy tree, ownership chains, identities, and authorization boundaries.
  - `argus auth analyze <mission_id>`: Executes `AuthorizationSpecialist` over the mission.
- **Gaps**:
  - None. Models, graph, analyzer, specialist heuristics, and active collector are implemented.
- **Test Coverage**:
  - 7 passed tests: `tests/test_authorization.py` (5 passed), `tests/authorization/test_authorization_gate.py` (2 passed).
  - 9 passed tests in `tests/collectors/test_access_control.py`.
- **Notes**:
  - Clean cooperation between the graph-based analyzer in `argus/authorization/` and the heuristic-driven specialist in `argus/agents/authorization/`.

---

### Section 32: Business Logic Specialist
- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/agents/business_logic/agent.py`: `BusinessLogicSpecialist`.
  - `argus/agents/business_logic/states.py`: `StateMachineBuilder` extracting state machines from workflow steps.
  - `argus/agents/business_logic/transitions.py`: `TransitionAnalyzer` inferring valid state transitions.
  - `argus/agents/business_logic/objects.py`: `ObjectAnalyzer` identifying critical business objects.
  - `argus/agents/business_logic/workflow.py`: `WorkflowAnalyzer` extracting business rules and dependencies.
  - `argus/agents/business_logic/planner.py`: `BusinessLogicPlanner` generating investigation plans.
  - `argus/agents/business_logic/heuristics.py`: `BUSINESS_LOGIC_HEURISTIC_REGISTRY` (WorkflowShortcutHeuristic, ReplayableTransactionHeuristic, MissingPrerequisiteHeuristic).
  - `argus/agents/business_logic/confidence.py`: `BusinessLogicConfidenceScorer`.
  - `argus/collectors/business_logic.py`: Active business logic collector (71 KB) testing price tampering, parameter tampering, workflow step skips, coupon stacking.
  - `argus/cli/business_cli.py`: Typer CLI `argus business`.
- **Implementation Evidence**:
  - All 6 component modules named in the specification exist as dedicated files in `argus/agents/business_logic/`:
    `workflow.py`, `states.py`, `objects.py`, `transitions.py`, `heuristics.py`, `planner.py`.
  - Generates investigations for workflow bypasses, state skipping, and missing prerequisite conditions.
- **CLI Wiring**:
  - `argus business investigations <mission_id>`: Lists extracted business logic investigations with priority and confidence.
- **Gaps**:
  - `argus business` CLI only provides `investigations`; state machine visualization is not exposed via a dedicated CLI sub-command (e.g. `argus business states`).
- **Test Coverage**:
  - 5 passed tests: `argus/agents/business_logic/tests/test_business_logic.py` (`test_workflow_discovery`, `test_business_rule_extraction`, `test_business_logic_specialist_run`, `test_duplicate_suppression`, `test_plugin_heuristics`).
  - 4 passed tests in `tests/collectors/test_business_logic.py`.
- **Notes**:
  - Direct synergy with `argus/workflows/models.py`.

---

### Section 33: API Intelligence Specialist
- **Status**: ⚠️ Partial
- **Source Files**:
  - `argus/plugins/api/agent.py`: `APIIntelligenceSpecialist`.
  - `argus/plugins/api/plugin.py`: `APIIntelligencePlugin` inheriting from `BasePlugin`.
  - `argus/plugins/api/resource_model.py`: `APIResource`, `APICollection`, `APISingleton`.
  - `argus/plugins/api/operations.py`: `OperationAnalyzer` extracting CRUD operations, pagination (`page`, `offset`, `limit`), filtering (`filter`, `sort`), and bulk operations (`bulk_`, `batch_`).
  - `argus/plugins/api/relationships.py`: `RelationshipInferencer` identifying parent-child nested resource relationships.
  - `argus/plugins/api/versions.py`: `VersionDetector` identifying API versioning (`/v1/`, `/v2/`).
  - `argus/plugins/api/schemas.py`: `SchemaParser` grouping endpoints into collections and singletons.
  - `argus/plugins/api/heuristics.py`: `API_HEURISTIC_REGISTRY` (unversioned endpoints, missing pagination, bulk operation risks, missing DELETE protections, sensitive GET queries).
  - `argus/collectors/api_security.py`: Active REST & gRPC API collector (67 KB).
  - `argus/cli/api_cli.py`: Typer CLI `argus api`.
- **Implementation Evidence**:
  - Analyzes resources, CRUD, nested resources, parent-child relationships, schemas, versions, operations, pagination, filtering, and bulk operations.
  - `argus/collectors/api_security.py` provides extensive active security testing for REST and gRPC endpoints (parameter tampering, mass assignment, rate limiting, BOLA, HTTP method tampering).
- **Gaps (Rationale for ⚠️ Partial)**:
  - **CLI Stubs**: In `argus/cli/api_cli.py`, two subcommands are unimplemented placeholders:
    - `argus api graph`: prints `(Not fully implemented in CLI yet. Refer to relationships data in the mission object.)`
    - `argus api explain`: prints `(Detailed explanations to be implemented.)`
  - **Schema Ingestion**: `argus/plugins/api/schemas.py` only performs basic URI path splitting; it does not implement full OpenAPI 3.0 / Swagger JSON/YAML or gRPC `.proto` file parsers (though gRPC references are recognized by JS intelligence and tested by `api_security.py`).
- **Test Coverage**:
  - 3 passed tests: `argus/plugins/api/tests/test_api_intelligence.py` (`test_schema_parser`, `test_relationship_inferencer`, `test_api_intelligence_plugin`).
  - 6 passed tests in `tests/collectors/test_api_security.py`.
- **Notes**:
  - Core analytical engines and active collector work properly; CLI commands `graph`/`explain` and formal OpenAPI parsing need completion.

---

### Section 34: GraphQL Specialist
- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/plugins/graphql/agent.py`: `GraphQLSpecialist` coordinating discovery, schema analysis, business logic discovery, and reasoning.
  - `argus/plugins/graphql/discovery.py`: `GraphQLDiscovery` discovering endpoints from HTTP requests, responses, JavaScript bundles, and OpenAPI hints.
  - `argus/plugins/graphql/schema.py`: `GraphQLSchemaAnalyzer` running introspection queries, parsing schemas, handling types, fields, arguments, operations, unions, enums, interfaces.
  - `argus/plugins/graphql/business.py`: `BusinessKnowledgeAnalyzer` mapping GraphQL types to business objects and CRUD workflows.
  - `argus/plugins/graphql/reasoning.py`: `GraphQLReasoningEngine` producing `GraphQLInvestigation` objects.
  - `argus/plugins/graphql/models.py`: Full GraphQL domain model (`GraphQLSchema`, `GraphQLType`, `GraphQLField`, `GraphQLArgument`, `GraphQLOperation`, `GraphQLInvestigation`).
  - `argus/plugins/graphql/cli.py`: Comprehensive Typer CLI `argus graphql`.
  - `argus/collectors/graphql.py`: Active GraphQL security collector (74 KB) testing introspection, alias multiplexing, field suggestions, query depth attacks, circular queries, mutation injection.
- **Implementation Evidence**:
  - Models endpoints, schemas, queries, mutations, types, fields, relationships, and security-relevant structures.
  - Gap analysis for GraphQL without schemas handled via discovery inference and field suggestion extraction.
- **CLI Wiring**:
  - Full suite of 10 subcommands under `argus graphql`:
    `discover`, `schema`, `types`, `operations`, `relationships`, `workflows`, `business_objects`, `investigations`, `explain`, `priority`.
- **Gaps**:
  - None. Very extensive implementation across plugin, active collector, models, and CLI.
- **Test Coverage**:
  - 75 passed tests:
    - `argus/plugins/graphql/tests/test_graphql.py` (2 passed)
    - `tests/collectors/test_graphql.py` (33 passed)
    - `tests/collectors/test_graphql_adversarial.py` (40 passed)
- **Notes**:
  - Test execution must use `-o pythonpath=. --import-mode=importlib` to avoid module name collision between `argus/plugins/graphql/tests/test_graphql.py` and `tests/collectors/test_graphql.py`.

---

### Section 35: JavaScript Intelligence
- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/plugins/javascript/parser.py`: Pre-compiled regular expression AST-like parser (`JavaScriptParser`) extracting endpoints, routes, configs, environment variables, feature flags, frameworks, WebSockets, business workflows, types, third-party APIs.
  - `argus/plugins/javascript/agent.py`: `JavaScriptSpecialist` orchestrating discovery and AST analysis.
  - `argus/plugins/javascript/discovery.py`: `JavaScriptDiscovery` extracting script URLs, webpack/vite/nextjs manifests, source maps.
  - `argus/plugins/javascript/models.py`: `JavaScriptSymbol`, `JavaScriptRoute`, `JavaScriptFramework`, `JavaScriptModule`, `JavaScriptWebSocket`.
  - `argus/plugins/javascript/cli.py`: Typer CLI `argus javascript`.
  - `argus/analyzers/javascript.py`: Secondary JS analyzer.
  - `argus/collectors/javascript.py`: Collector for JS files.
- **Implementation Evidence**:
  - Endpoint extraction: `fetch()`, `axios.get/post/put/delete/patch`
  - Route discovery: `<Route path=...>`, `router.push()`, `navigate()`
  - Configuration discovery: `process.env.*`, `import.meta.env.*`, `NEXT_PUBLIC_*`, `REACT_APP_*`, `VITE_*`, `*Config`, `*Options`, feature flags
  - Application object discovery: Interface/type definitions, authentication provider SDKs (Auth0, Firebase, Cognito, Clerk, Supabase)
  - Technology clues: React, Vue, Nuxt, Angular, Svelte, Remix, Astro, SolidJS, Webpack, Next.js, Vite, Rollup
  - Security-relevant relationships: Connected into `KnowledgeGraph` (`Node` and `Edge`).
- **CLI Wiring**:
  - `argus javascript discover`: Discovers JS files with Rich spinner progress.
  - `argus javascript analyze`: Runs AST parsing, symbol extraction, framework detection, and investigation generation with Rich summary table.
- **Gaps**:
  - Uses regex-based AST heuristics rather than a full JavaScript tree-sitter or Esprima parser, but class-level regex patterns are comprehensive and performant.
- **Test Coverage**:
  - 17 passed tests: `tests/plugins/javascript/` (`test_agent.py`, `test_benchmark.py`, `test_discovery.py`, `test_integration.py`, `test_parser.py`, `test_plugin.py`, `test_stress.py`).
- **Notes**:
  - Memory-optimized inline deduplication prevents memory bloat during massive bundle parsing.

---

### Section 36: Authentication Specialist
- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/plugins/authentication/agent.py`: `AuthenticationIntelligenceSpecialist`.
  - `argus/plugins/authentication/identity.py`: `IdentityAnalyzer` extracting users, emails, API keys, and roles from evidence.
  - `argus/plugins/authentication/sessions.py`: `SessionAnalyzer` analyzing session cookies (flags, entropy, expiration).
  - `argus/plugins/authentication/tokens.py`: `TokenAnalyzer` parsing JWT and bearer tokens.
  - `argus/plugins/authentication/oauth.py`: `OAuthAnalyzer` detecting OAuth endpoints (`/oauth/authorize`, `/oauth/token`).
  - `argus/plugins/authentication/mfa.py`: `MFAAnalyzer` detecting MFA / 2FA workflows (`/mfa`, `/otp`, `/2fa`).
  - `argus/plugins/authentication/heuristics.py`: `AUTHN_HEURISTIC_REGISTRY` (insecure cookies, JWT weak algorithms, missing MFA, OAuth redirect flaws).
  - `argus/plugins/authentication/confidence.py`: `AuthenticationConfidenceScorer`.
  - `argus/collectors/auth_bypass.py`: Active authentication bypass collector (70 KB).
  - `argus/collectors/oauth.py`: Active OAuth vulnerability collector (67 KB).
  - `argus/cli/authn_cli.py`: Typer CLI `argus authn`.
- **Implementation Evidence**:
  - Focuses on authentication workflows, login behavior, authentication state, session relationships, and authentication investigation opportunities.
  - Active collectors validate auth header spoofing, path manipulation bypasses, and OAuth implementation weaknesses.
- **CLI Wiring**:
  - `argus authn analyze <mission_id>`: Runs authentication intelligence plugin.
  - `argus authn investigations <mission_id>`: Lists generated investigations.
  - `argus authn explain <mission_id> <inv_id>`: Explains reasoning and affected objects.
  - `argus authn graph <mission_id>`: Prints placeholder note that visual graph view is under construction.
- **Gaps**:
  - Minor CLI display gap: `argus authn graph` is a placeholder ("Graph view is under construction").
- **Test Coverage**:
  - 1 passed test: `argus/plugins/authentication/tests/test_authentication.py`.
  - 101 passed tests in collectors: `tests/collectors/test_auth_bypass.py` + `tests/collectors/test_oauth.py`.
- **Notes**:
  - Highly robust dual implementation combining passive intelligence inference and active adversarial fuzzing.

---

### Section 37: File Upload Specialist
- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/plugins/file_upload/agent.py`: `FileUploadSpecialist`.
  - `argus/plugins/file_upload/uploads.py`: `UploadAnalyzer` identifying multipart upload and download endpoints.
  - `argus/plugins/file_upload/storage.py`: `StorageBehaviorAnalyzer` inferring cloud storage (S3 buckets, Google Cloud Storage, Azure Blob, local paths).
  - `argus/plugins/file_upload/objects.py`: `FileObjectAnalyzer` classifying uploaded assets (Avatar, Document, Invoice, Media).
  - `argus/plugins/file_upload/workflow.py`: `FileUploadWorkflow` and `ContentProcessingAnalyzer`.
  - `argus/plugins/file_upload/heuristics.py`: `FILE_UPLOAD_HEURISTIC_REGISTRY` (unrestricted extensions, path traversal, executable uploads).
  - `argus/plugins/file_upload/confidence.py`: `FileUploadConfidenceScorer`.
  - `argus/collectors/file_upload.py`: Active file upload collector (64 KB) testing extension mutations, MIME bypasses, polyglots, web shell execution verification.
  - `argus/cli/upload_cli.py`: Typer CLI `argus upload`.
- **Implementation Evidence**:
  - Analyzes upload workflows, file/object relationships, validation logic, storage behavior (S3/GCS/Azure/local), content-processing workflows, and upload investigation opportunities.
- **CLI Wiring**:
  - `argus upload analyze <mission_id>`: Executes file upload specialist plugin.
  - `argus upload investigations <mission_id>`: Lists investigations by priority.
  - `argus upload explain <mission_id> <inv_id>`: Shows reasoning and remediation.
  - `argus upload graph <mission_id>`: Prints placeholder note that visual graph view is under construction.
- **Gaps**:
  - Minor CLI display gap: `argus upload graph` is a placeholder ("Graph view is under construction").
- **Test Coverage**:
  - 45 passed tests:
    - `argus/plugins/file_upload/tests/test_file_upload.py` (1 passed)
    - `tests/collectors/test_file_upload.py` (32 passed)
    - `tests/collectors/test_file_upload_adversarial.py` (12 passed)
- **Notes**:
  - Extensive adversarial testing verifies false positive rejection on safe UUID-renamed files and WAF 403 blocks.

---

## 3. Logic Chain

1. **Codebase Exploration**:
   - Inspected `argus/` directory tree and confirmed the existence of modules for AI (`argus/ai/`), Vector/RAG (`argus/vector/`, `argus/workspace/context/`), Research Cards (`argus/reporting/queue.py`), Intelligence (`argus/intelligence/`, `argus/hypothesis/`), Methodology (`argus/methodology/`), and all 7 Specialists (`argus/authorization/`, `argus/agents/business_logic/`, `argus/plugins/api/`, `argus/plugins/graphql/`, `argus/plugins/javascript/`, `argus/plugins/authentication/`, `argus/plugins/file_upload/`).
2. **Section 27 Deep Dive**:
   - Traced all 16 subsections (27.1–27.16) through `VectorStore`, `EmbeddingEngine`, `ResearchContextEngine`, `ContextRanker`, `ContextAssembler`, `KnowledgeGraphRetriever`, `ScanEvidenceIndexer`, and `CVEKnowledgeBase`.
   - Verified hybrid ranking formula ($w_{vec}=0.6, w_{lex}=0.4$), citation formatting (`[Evidence #...]`), bounded graph RAG traversal, and dual-engine storage fallback.
3. **CLI Verification**:
   - Verified that CLI subcommands are registered in `argus/cli/app.py`: `knowledge`, `queue`, `workflow`, `auth`, `agent`, `intelligence`, `playbooks`, `business`, `api`, `authn`, `upload`, `graphql`, `javascript`, `research`, `hypothesis`, `search`.
   - Tested execution of CLI commands and identified minor placeholder stubs in `argus api graph/explain`, `argus authn graph`, and `argus upload graph`.
4. **Test Suite Execution**:
   - Identified test module collision between `tests/collectors/test_graphql.py` and `argus/plugins/graphql/tests/test_graphql.py` when standard import modes are used; solved by executing tests with `--import-mode=importlib`.
   - Ran 300+ tests across `tests/vector/`, `tests/plugins/`, `tests/collectors/`, and unit test files, confirming all pass with 0 failures.
5. **Status Assignment**:
   - Sections 26, 27, 28, 29, 30, 31, 32, 34, 35, 36, 37 meet acceptance criteria and pass tests $\implies$ **✅ Implemented**.
   - Section 33 exhibits placeholder CLI commands (`graph` and `explain`) and lacks full OpenAPI/Swagger parser in `schemas.py` $\implies$ **⚠️ Partial**.

---

## 4. Caveats

1. **CLI Placeholder Subcommands**:
   - Subcommands `argus api graph`, `argus api explain`, `argus authn graph`, and `argus upload graph` output informative messages stating that graph rendering is under construction. The underlying data structures and models exist on the mission object, but visual ASCII/Rich graph trees are not rendered.
2. **Pytest Module Name Collision**:
   - Co-located test files sharing identical basenames (e.g. `test_graphql.py`) must be run with `--import-mode=importlib` to avoid pytest import mismatches.
3. **Regex-based vs Full AST Parsers**:
   - `argus/plugins/javascript/parser.py` utilizes optimized pre-compiled regular expressions rather than an external AST library like tree-sitter or Esprima. While regex patterns are thorough and fast, complex obfuscated code may not yield full AST depth.

---

## 5. Verification Method

To independently reproduce and verify the audit findings:

```bash
# 1. Verify Section 26 (AI Research)
pytest -o pythonpath=. --import-mode=importlib tests/test_ai_research.py tests/ai/test_ai_clients.py -v

# 2. Verify Section 27 (RAG Fabric Subsections 27.1–27.16)
pytest -o pythonpath=. --import-mode=importlib tests/vector/ -v

# 3. Verify Section 28 (Research Cards)
pytest -o pythonpath=. --import-mode=importlib tests/test_research_cards.py -v

# 4. Verify Section 29 (Vulnerability Intelligence Engine)
pytest -o pythonpath=. --import-mode=importlib tests/test_intelligence.py -v

# 5. Verify Section 30 (Methodology Engine & Playbooks)
pytest -o pythonpath=. --import-mode=importlib tests/test_methodology.py -v

# 6. Verify Section 31 (Authorization Specialist)
pytest -o pythonpath=. --import-mode=importlib tests/test_authorization.py tests/authorization/test_authorization_gate.py tests/collectors/test_access_control.py -v

# 7. Verify Section 32 (Business Logic Specialist)
pytest -o pythonpath=. --import-mode=importlib argus/agents/business_logic/tests/test_business_logic.py tests/collectors/test_business_logic.py -v

# 8. Verify Section 33 (API Intelligence Specialist)
pytest -o pythonpath=. --import-mode=importlib argus/plugins/api/tests/test_api_intelligence.py tests/collectors/test_api_security.py -v

# 9. Verify Section 34 (GraphQL Specialist)
pytest -o pythonpath=. --import-mode=importlib argus/plugins/graphql/tests/test_graphql.py tests/collectors/test_graphql.py tests/collectors/test_graphql_adversarial.py -v

# 10. Verify Section 35 (JavaScript Intelligence)
pytest -o pythonpath=. --import-mode=importlib tests/plugins/javascript/ -v

# 11. Verify Section 36 (Authentication Specialist)
pytest -o pythonpath=. --import-mode=importlib argus/plugins/authentication/tests/test_authentication.py tests/collectors/test_auth_bypass.py tests/collectors/test_oauth.py -v

# 12. Verify Section 37 (File Upload Specialist)
pytest -o pythonpath=. --import-mode=importlib argus/plugins/file_upload/tests/test_file_upload.py tests/collectors/test_file_upload.py tests/collectors/test_file_upload_adversarial.py -v

# 13. Verify CLI Wiring
python3 -m argus.cli.app --help
python3 -m argus.cli.app search --help
python3 -m argus.cli.app queue --help
python3 -m argus.cli.app intelligence --help
python3 -m argus.cli.app playbooks --help
python3 -m argus.cli.app auth --help
python3 -m argus.cli.app business --help
python3 -m argus.cli.app api --help
python3 -m argus.cli.app graphql --help
python3 -m argus.cli.app javascript --help
python3 -m argus.cli.app authn --help
python3 -m argus.cli.app upload --help
```
