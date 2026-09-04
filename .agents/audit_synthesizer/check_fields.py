import re

c1 = open("/home/varun/argus/.agents/audit_cluster1/handoff.md").read()
c2 = open("/home/varun/argus/.agents/audit_cluster2/handoff.md").read()
c3 = open("/home/varun/argus/.agents/audit_cluster3/handoff.md").read()
c4 = open("/home/varun/argus/.agents/audit_cluster4/handoff.md").read()
c5 = open("/home/varun/argus/.agents/audit_cluster5/handoff.md").read()
c6 = open("/home/varun/argus/.agents/audit_cluster6/handoff.md").read()

def check_cluster(text, start, end, name):
    print(f"=== {name} (Sec {start}-{end}) ===")
    for i in range(start, end + 1):
        p = rf"### Section {i}:?\s*([^\n]+)"
        m = re.search(p, text)
        if not m:
            print(f"  Sec {i}: Not found")

check_cluster(c1, 1, 15, "Cluster 1")
check_cluster(c2, 16, 25, "Cluster 2")
check_cluster(c3, 26, 37, "Cluster 3")
check_cluster(c4, 38, 48, "Cluster 4")
check_cluster(c5, 49, 57, "Cluster 5")
check_cluster(c6, 58, 78, "Cluster 6")
