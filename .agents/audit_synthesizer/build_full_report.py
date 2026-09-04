import re
import os
import sys

def load_handoff(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

c1_text = load_handoff("/home/varun/argus/.agents/audit_cluster1/handoff.md")
c2_text = load_handoff("/home/varun/argus/.agents/audit_cluster2/handoff.md")
c3_text = load_handoff("/home/varun/argus/.agents/audit_cluster3/handoff.md")
c4_text = load_handoff("/home/varun/argus/.agents/audit_cluster4/handoff.md")
c5_text = load_handoff("/home/varun/argus/.agents/audit_cluster5/handoff.md")
c6_text = load_handoff("/home/varun/argus/.agents/audit_cluster6/handoff.md")
tr_text = load_handoff("/home/varun/argus/.agents/audit_test_runner/handoff.md")

print("All handoffs loaded successfully.")
