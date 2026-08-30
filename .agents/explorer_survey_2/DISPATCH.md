## 2026-08-30T12:17:40Z
You are Explorer 2 for Sprint 13 Codebase Survey.
Your working directory is /home/varun/argus/.agents/explorer_survey_2.
Create your working directory and maintain progress.md and handoff.md in it.

Read /home/varun/argus/.agents/ORIGINAL_REQUEST.md.

Your mission is to explore Pipeline Connectivity, TaskGenerator DAG, Tool Registry, and Graph Schema in Argus:
1. Locate TaskGenerator / DAG orchestration files and analyze how collectors are scheduled after endpoint discovery.
2. Locate tool registry (registry.py or similar) and analyze how collectors/plugins are registered, configured, and exposed.
3. Locate Attack Surface Graph implementation (graph models, node types, edge types, specifically HAS_VULNERABILITY edges).
4. Analyze how findings/evidence from collectors are converted into graph nodes and HAS_VULNERABILITY edges.
5. Document all exact file paths, class names, registration decorators/dictionaries, DAG dependency definitions, and graph edge creation methods.
6. Write your detailed findings to /home/varun/argus/.agents/explorer_survey_2/handoff.md and report back via send_message to parent. Operate silently during execution.
