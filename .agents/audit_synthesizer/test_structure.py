import re
import os

print("Testing environment for report generation...")
clusters = [1, 2, 3, 4, 5, 6]
for c in clusters:
    p = f"/home/varun/argus/.agents/audit_cluster{c}/handoff.md"
    assert os.path.exists(p), f"Missing {p}"
assert os.path.exists("/home/varun/argus/.agents/audit_test_runner/handoff.md"), "Missing test runner handoff"
print("All input files exist!")
