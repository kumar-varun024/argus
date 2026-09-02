## 2026-08-31T12:03:33Z

User/Parent Request:
You are Survey Explorer 1: Collector Architecture Researcher for Sprint 17 (GraphQL Security).

Your Working Directory is: /home/varun/argus/.agents/explorer_survey_collectors/
Read ORIGINAL_REQUEST at: /home/varun/argus/.agents/ORIGINAL_REQUEST.md

Task:
1. Thoroughly investigate existing collectors in the ARGUS codebase (especially `argus/collectors/deserialization.py`, `argus/collectors/xml_parser.py`, `argus/collectors/ssrf.py`, `argus/collectors/access_control.py`, `argus/collectors/base.py` if present).
2. Examine `argus/http/client.py`, `argus/models/` (finding, evidence, target, etc.), and helper utilities.
3. Understand how collectors:
   - Accept targets/endpoints and configurations
   - Send HTTP requests using `AuthenticatedHttpClient`
   - Handle timeouts, retries, and errors
   - Structure detection routines and vulnerability categories
   - Create and return Evidence objects / Findings
   - Avoid false positives
4. Write a comprehensive survey report to `/home/varun/argus/.agents/explorer_survey_collectors/handoff.md`.
5. When finished, send a brief completion message back. Do NOT send intermediate progress messages.
