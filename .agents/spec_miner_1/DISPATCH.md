## 2026-08-31T14:21:28Z
You are spec_miner_1, a WebSocket Security Specification Specialist for Sprint 18.

Working directory for your metadata: /home/varun/argus/.agents/spec_miner_1/
Read-only investigation. DO NOT modify any code or test files.

Read:
1. /home/varun/argus/ORIGINAL_REQUEST.md
2. /home/varun/argus/argus/models/
3. /home/varun/argus/argus/collectors/

Investigate and specify:
1. R1 WebSocket endpoints & handshake anatomy:
   - Typical WS endpoints: `/ws`, `/wss`, `/socket.io`, `/cable`, `/websocket`, `/graphql-ws`, `/subscriptions`, `/chat`, `/api/v1/ws`, `/stream`, etc.
   - Handshake requirements: `GET`, `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Key`, `Sec-WebSocket-Version: 13`, `Sec-WebSocket-Protocol`, `Sec-WebSocket-Extensions`.
2. R2 Multi-Vulnerability Detection details:
   - CSWSH (Cross-Site WebSocket Hijacking): Origin header variations (`Origin: null`, `Origin: https://evil.com`, `Origin: https://target.com.attacker.com`, `Origin: https://attacker-target.com`), checking if 101 Switching Protocols is returned without strict validation.
   - Unauthenticated Handshake / Token Leakage: Testing connections with no Authorization / cookie, expired tokens, tokens passed insecurely in query params (`?token=...`, `?access_token=...`).
   - Frame Fuzzing & Injection: Testing text/JSON frames for SQLi (`' OR '1'='1`), Command Injection (`; id`, `| whoami`), XSS (`<script>alert(1)</script>`), Prototype Pollution (`{"__proto__": {"admin": true}}`), and evaluating error/echo patterns.
   - WebSocket DoS & Resource Exhaustion: Testing unmasked client frames (RFC 6455 requires masking from client to server), oversized frame length headers, rapid ping/pong bursts or message floods without rate limiting.
3. R3 Bypass & Mutation Strategies (at least 5 distinct strategies):
   - Strategy 1: Origin manipulation (null, evil domain, subdomain spoof, trailing slash/prefix tricks).
   - Strategy 2: Subprotocol tampering (`Sec-WebSocket-Protocol: graphql-ws, soap, chat, binary, unauthorized-proto`).
   - Strategy 3: Hop-by-hop & Upgrade header smuggling / casing / whitespace tricks (`Connection: keep-alive, Upgrade`, `Upgrade: WebSocket`, `Upgrade: websocket; `).
   - Strategy 4: Extension & Compression fuzzing (`Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits`, malformed extensions).
   - Strategy 5: Query parameter / Header token auth manipulation (stripping tokens, malformed JWTs, expired signatures).
4. Evidence generation & False Positive suppression criteria:
   - What response signatures strictly confirm vulnerability vs properly hardened responses (e.g. 401/403 on invalid origin or missing auth, 400 on malformed upgrade, 1008 Policy Violation on unmasked/oversized frame, rate limiting 1008/429).

Write a complete, structured handoff report to /home/varun/argus/.agents/spec_miner_1/handoff.md.
Follow communication hygiene: do NOT send intermediate progress messages; send a final completion message once your handoff report is written.
