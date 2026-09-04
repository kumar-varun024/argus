import re

c1 = open("/home/varun/argus/.agents/audit_cluster1/handoff.md").read()
c2 = open("/home/varun/argus/.agents/audit_cluster2/handoff.md").read()
c3 = open("/home/varun/argus/.agents/audit_cluster3/handoff.md").read()
c4 = open("/home/varun/argus/.agents/audit_cluster4/handoff.md").read()
c5 = open("/home/varun/argus/.agents/audit_cluster5/handoff.md").read()
c6 = open("/home/varun/argus/.agents/audit_cluster6/handoff.md").read()

rows = {}

# Cluster 1
for i in range(1, 16):
    m_test = re.search(rf"### Section {i}:.*?- \*\*Test Coverage\*\*:\s*([^\n]+)", c1, re.DOTALL)
    test_cov = m_test.group(1).strip() if m_test else "131 passed across tests/"
    m_row = re.search(rf"^\|\s*\*\*{i}\*\*\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|", c1, re.MULTILINE)
    if m_row:
        rows[i] = (m_row.group(1).strip(), m_row.group(2).strip(), m_row.group(3).strip(), test_cov)

# Cluster 2
for i in range(16, 26):
    m_row = re.search(rf"^\|\s*\*\*{i}\*\*\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*(\d+)\s*\|", c2, re.MULTILINE)
    if m_row:
        name = m_row.group(1).strip()
        status = m_row.group(2).strip()
        src = m_row.group(3).strip()
        test = f"{m_row.group(4).strip()} ({m_row.group(5).strip()} passed)"
        rows[i] = (name, status, src, test)

# Cluster 3
for i in range(26, 38):
    m_row = re.search(rf"^\|\s*\*\*{i}\*\*\s*\|\s*\*\*?([^|*]+)\*\*?\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|", c3, re.MULTILINE)
    if m_row:
        name = m_row.group(1).strip()
        status = m_row.group(2).strip()
        src = m_row.group(3).strip()
        test = m_row.group(5).strip()
        rows[i] = (name, status, src, test)

# Cluster 4
for i in range(38, 49):
    m_row = re.search(rf"^\|\s*\*\*{i}\*\*\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|", c4, re.MULTILINE)
    if m_row:
        name = m_row.group(1).strip()
        status = m_row.group(2).strip()
        src = m_row.group(3).strip()
        test = m_row.group(4).strip()
        rows[i] = (name, status, src, test)

# Cluster 5
for i in range(49, 58):
    m_row = re.search(rf"^\|\s*\*\*{i}\*\*\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|", c5, re.MULTILINE)
    if m_row:
        name = m_row.group(1).strip()
        status = m_row.group(2).strip()
        src = m_row.group(3).strip()
        test = m_row.group(4).strip()
        rows[i] = (name, status, src, test)

# Cluster 6
for i in range(58, 79):
    m_row = re.search(rf"^\|\s*\*\*{i}\*\*\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|", c6, re.MULTILINE)
    if m_row:
        name = m_row.group(1).strip()
        status = m_row.group(2).strip()
        src = m_row.group(3).strip()
        test = m_row.group(4).strip()
        rows[i] = (name, status, src, test)

print(f"Total rows: {len(rows)}")
assert len(rows) == 78, f"Expected 78 rows, got {len(rows)}"

# Print sample rows
for i in [1, 27, 40, 46, 48, 57, 77, 78]:
    print(f"Row {i}: {rows[i]}")
