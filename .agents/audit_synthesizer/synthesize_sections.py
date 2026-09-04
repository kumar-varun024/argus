import re

c1 = open("/home/varun/argus/.agents/audit_cluster1/handoff.md").read()
c2 = open("/home/varun/argus/.agents/audit_cluster2/handoff.md").read()
c3 = open("/home/varun/argus/.agents/audit_cluster3/handoff.md").read()
c4 = open("/home/varun/argus/.agents/audit_cluster4/handoff.md").read()
c5 = open("/home/varun/argus/.agents/audit_cluster5/handoff.md").read()
c6 = open("/home/varun/argus/.agents/audit_cluster6/handoff.md").read()

# Let us verify Cluster 1 formatting
sec1_pat = r"### Section 1:\s*([^\n]+)(.*?)(?=### Section 2)"
m1 = re.search(sec1_pat, c1, re.DOTALL)
print("C1 Sec 1 title:", m1.group(1).strip())

# Let us verify Cluster 4 formatting
# In C4, let us inspect the summary table rows
table_start = c4.find("### Section-by-Section Feature Audit Summary")
table_end = c4.find("### Comprehensive Verification of All 34 CLI Namespaces")
table_text = c4[table_start:table_end]
c4_rows = re.findall(r"^\|\s*\*\*(\d+)\*\*\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|", table_text, re.MULTILINE)
print(f"C4 table rows: {len(c4_rows)}")

# Let us verify C4 observations
c4_obs = {}
for i in range(38, 49):
    p = rf"### Section {i}:\s*([^\n]+)(.*?)(?=### Section {i+1}|## 2\. Logic Chain|\Z)"
    m = re.search(p, c4, re.DOTALL)
    if m:
        c4_obs[i] = m.group(2).strip()
print(f"C4 obs count: {len(c4_obs)}")

# Let us verify C5 table and observations
table_start_5 = c5.find("### Cluster Status Dashboard")
table_end_5 = c5.find("## 1. Observation")
table_text_5 = c5[table_start_5:table_end_5]
c5_rows = re.findall(r"^\|\s*\*\*(\d+)\*\*\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|", table_text_5, re.MULTILINE)
print(f"C5 table rows: {len(c5_rows)}")

c5_obs = {}
for i in range(49, 58):
    p = rf"### Section {i}:\s*([^\n]+)(.*?)(?=### Section {i+1}|## 2\. Logic Chain|\Z)"
    m = re.search(p, c5, re.DOTALL)
    if m:
        c5_obs[i] = m.group(2).strip()
print(f"C5 obs count: {len(c5_obs)}")
