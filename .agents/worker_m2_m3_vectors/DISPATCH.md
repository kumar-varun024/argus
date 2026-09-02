## 2026-09-02T06:08:00Z

Task: Authentication Vectors & Evasion Specialist Worker for Milestone 2 & 3 of the ARGUS platform sprint: Authentication Bypass & Credential Attack Detection Module.

Working Directory: /home/varun/argus
Agent Working Directory: /home/varun/argus/.agents/worker_m2_m3_vectors
Original Request: /home/varun/argus/.agents/ORIGINAL_REQUEST.md
Project Plan: /home/varun/argus/PROJECT.md
Spec Miner Survey: /home/varun/argus/.agents/spec_miner_survey/handoff.md
M1 Core Handoff: /home/varun/argus/.agents/worker_m1_core/handoff.md

Exclusive write ownership:
- `argus/collectors/auth_bypass.py` (EDIT)

Mission Objectives:
1. R2 Multi-Vector Authentication Detection Modes (Brute force & lockout, password reset abuse, MFA bypass, session fixation, JWT manipulation, default credentials & fingerprinting)
2. R3 Session & Token Analysis (Shannon entropy, cookie security flags, session expiration/invalidation, auth state/credential leakage, credential stuffing resistance)
3. R4 Mutation & Evasion Strategies (Case sensitivity, Unicode normalization & homoglyphs, auth headers, token format/encoding, response manipulation)
4. Analyzer Strict False Positive Rejection (Suppress benign baselines, rejection codes, throttled rate limits, accurate CWE/CVSS).
