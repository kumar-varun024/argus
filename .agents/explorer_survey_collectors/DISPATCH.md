## 2026-08-30T11:11:00Z
You are an Explorer subagent for the ARGUS platform.
Your working directory is /home/varun/argus/.agents/explorer_survey_collectors/
Your role is to investigate the existing collector architecture and vulnerability detection mechanisms in /home/varun/argus.

MANDATORY FIRST STEP: Read the requirements in /home/varun/argus/.agents/ORIGINAL_REQUEST.md (especially section ## 2026-08-30T11:08:07Z for Sprint 11 Command Injection).

Tasks to investigate:
1. Examine existing collectors:
   - argus/collectors/sql_injection.py
   - argus/collectors/path_traversal.py
   - argus/collectors/xss.py (or whatever exists for sprint 10)
   - argus/collectors/base.py (or common collector base classes / abstractions)
2. Examine how parameter injection points are discovered, formatted, and tested (query params, POST body fields, path segments, HTTP headers).
3. Examine how evidence, severity, findings, and confidence scores are constructed (Evidence model, categories, severities like CRITICAL, HIGH, etc.).
4. Examine how mutation engines or payload generators are designed (e.g. in sql_injection.py or elsewhere).
5. Examine how time-based differential analysis and error pattern detection are implemented in existing collectors.

Deliverable:
Write a comprehensive report to /home/varun/argus/.agents/explorer_survey_collectors/handoff.md detailing:
- Exact class names, inheritance, interfaces, and method signatures used by collectors.
- Exact mechanism for parameter testing (query, body, path, headers).
- Pattern for result-based, time-based differential, and error-based detection.
- Recommendations and code layout for implementing `argus/collectors/command_injection.py` (CommandInjectionCollector).

When complete, write progress.md and handoff.md in your working directory, and send a final completion message to the orchestrator.
