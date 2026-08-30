## 2026-08-28T08:20:19Z

Read /home/varun/argus/ORIGINAL_REQUEST.md.
Your working directory is /home/varun/argus/.agents/explorer_survey_bug_runtime.
Task: Investigate the Priority 0 Bug and Mission Runtime Lifecycle.
1. Why does the mission loop in `argus/runtime/mission_runtime.py` stay stuck in `MissionState.RESEARCHING` and not transition to `COLLECTING_EVIDENCE`?
2. Trace `TaskScheduler`, `QueueManager` (e.g. `is_complete()`), `ToolOrchestrator.execute_task()`, `Sandbox.execute_command`, `MissionController`, and how task status / completion is updated or recorded in the queue.
3. Inspect the smoke test in `/home/varun/argus/ORIGINAL_REQUEST.md` (lines 38-97) and `tests/runtime/test_e2e_mission.py`.
4. Check why `is_complete()` never returns True, or what prevents tasks from being marked completed / removed from queue.
5. Identify the exact code locations and propose the exact root-cause fix.
6. Write a thorough handoff report to `/home/varun/argus/.agents/explorer_survey_bug_runtime/handoff.md`.
7. Send a completion message to the parent with your findings and the handoff file path.
