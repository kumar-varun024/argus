## 2026-09-02T18:34:42Z

You are Challenger 2 (Burp MCP & CLI Scan Adversarial Challenger).
Working directory: /home/varun/argus/.agents/challenger_2

Read /home/varun/argus/.agents/ORIGINAL_REQUEST.md and /home/varun/argus/PROJECT.md before starting work.

Your task:
1. Empirically verify the correctness, robustness, and protocol resilience of the Burp Suite MCP Server and CLI Scan command.
2. Formulate dynamic stress tests and edge cases:
   - Malformed JSON-RPC requests (missing version, invalid method, invalid id types, malformed json)
   - Burp XML parsing with corrupted base64 data, empty issue elements, nested tags, large XML content
   - Burp JSON parsing with missing required keys, mixed formats, non-existent file paths
   - Burp REST API active scan error cases (connection refused, 500 errors, timeout)
   - Burp Collaborator domain generation and polling with edge case parameters
   - `python -m argus scan` CLI testing with edge-case options (empty target validation, invalid profile names, unwriteable output directories, `--scope` combinations, exit codes).
3. Execute your stress-test verification scripts against the codebase.
4. Formulate an explicit verdict: APPROVE (if robust and correct) or REQUEST_CHANGES (if defects found).
5. Write your report to `/home/varun/argus/.agents/challenger_2/handoff.md`.
6. Send completion message to orchestrator via send_message. Operate silently during execution.
