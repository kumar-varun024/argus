import re

c1 = open("/home/varun/argus/.agents/audit_cluster1/handoff.md").read()
c2 = open("/home/varun/argus/.agents/audit_cluster2/handoff.md").read()
c3 = open("/home/varun/argus/.agents/audit_cluster3/handoff.md").read()
c4 = open("/home/varun/argus/.agents/audit_cluster4/handoff.md").read()
c5 = open("/home/varun/argus/.agents/audit_cluster5/handoff.md").read()
c6 = open("/home/varun/argus/.agents/audit_cluster6/handoff.md").read()

sections_extracted = {}

for i in range(1, 16):
    pat = rf"### Section {i}:\s*([^\n]+)(.*?)(?=### Section {i+1}|## 5\. Verification Method|\Z)"
    m = re.search(pat, c1, re.DOTALL)
    assert m, f"C1 Sec {i} failed"
    sections_extracted[i] = (m.group(1).strip(), m.group(2).strip(), 1)

for i in range(16, 26):
    pat = rf"### Section {i}:\s*([^\n]+)(.*?)(?=### Section {i+1}|## 2\. Logic Chain|\Z)"
    m = re.search(pat, c2, re.DOTALL)
    assert m, f"C2 Sec {i} failed"
    sections_extracted[i] = (m.group(1).strip(), m.group(2).strip(), 2)

for i in range(26, 38):
    pat = rf"### Section {i}:\s*([^\n]+)(.*?)(?=### Section {i+1}|## 3\. Logic Chain|\Z)"
    m = re.search(pat, c3, re.DOTALL)
    assert m, f"C3 Sec {i} failed"
    sections_extracted[i] = (m.group(1).strip(), m.group(2).strip(), 3)

for i in range(38, 49):
    pat = rf"### Section {i}:\s*([^\n]+)(.*?)(?=### Section {i+1}|## 2\. Logic Chain|\Z)"
    m = re.search(pat, c4, re.DOTALL)
    assert m, f"C4 Sec {i} failed"
    sections_extracted[i] = (m.group(1).strip(), m.group(2).strip(), 4)

for i in range(49, 58):
    pat = rf"### Section {i}:\s*([^\n]+)(.*?)(?=### Section {i+1}|## 2\. Logic Chain|\Z)"
    m = re.search(pat, c5, re.DOTALL)
    assert m, f"C5 Sec {i} failed"
    sections_extracted[i] = (m.group(1).strip(), m.group(2).strip(), 5)

for i in range(58, 79):
    pat = rf"### Section {i}:\s*([^\n]+)(.*?)(?=### Section {i+1}|## 3\. Caveats|\Z)"
    m = re.search(pat, c6, re.DOTALL)
    assert m, f"C6 Sec {i} failed"
    sections_extracted[i] = (m.group(1).strip(), m.group(2).strip(), 6)

print(f"Total sections extracted: {len(sections_extracted)}")
assert len(sections_extracted) == 78
for i in range(1, 79):
    t, b, c = sections_extracted[i]
    print(f"Sec {i:2d} (C{c}): {t[:35]:35s} | len body: {len(b)}")
