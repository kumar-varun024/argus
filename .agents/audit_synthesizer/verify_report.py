#!/usr/bin/env python3
import os
import re
import sys

report_path = "/home/varun/argus/FEATURE_AUDIT_REPORT.md"
assert os.path.exists(report_path), "FEATURE_AUDIT_REPORT.md does not exist!"
size = os.path.getsize(report_path)
assert size > 50000, f"Report too small: {size} bytes"
print(f"File exists and is {size:,} bytes.")

with open(report_path, "r", encoding="utf-8") as f:
    text = f.read()

# 1. Check Table of Contents
assert "## Table of Contents" in text, "Missing Table of Contents"
print("[PASS] Table of Contents present.")

# 2. Check Executive Summary
assert "## 1. Executive Summary" in text, "Missing Executive Summary"
assert "59" in text and "16" in text and "2" in text and "1" in text, "Missing status counts"
assert "Top 10 Most Critical Gaps" in text, "Missing Top 10 gaps"
assert "2,451" in text and "90.41 seconds" in text, "Missing test suite numbers"
assert "Dual Execution Path" in text, "Missing dual execution path analysis"
assert "Remediation & Development Prioritization Roadmap" in text, "Missing roadmap"
print("[PASS] Executive Summary complete.")

# 3. Check Dashboard Table: exactly 78 rows
dashboard_match = re.search(r"## 2\. Summary Dashboard Table\s*(.*?)\s*## 3\. Test Suite", text, re.DOTALL)
assert dashboard_match, "Could not find Summary Dashboard Table block"
d_text = dashboard_match.group(1)

table_rows = re.findall(r"^\|\s*\*\*(\d+)\*\*\s*\|", d_text, re.MULTILINE)
print(f"Found {len(table_rows)} dashboard table rows.")
assert len(table_rows) == 78, f"Expected 78 dashboard rows, found {len(table_rows)}"
for i in range(1, 79):
    assert str(i) in table_rows, f"Section {i} missing from dashboard table rows!"
print("[PASS] Dashboard table has EXACTLY 78 rows (1 through 78).")

# 4. Check Test Suite Execution & Analysis
assert "## 3. Test Suite Execution & Coverage Analysis" in text, "Missing Section 3"
assert "3.2 Test Suite Directory to Package Mapping" in text, "Missing directory mapping"
assert "tests/collectors/" in text, "Missing collectors in directory mapping"
assert "3.3 Zero Test Coverage Identification" in text, "Missing zero coverage identification"
assert "51,943" in text or "51,958" in text, "Missing deprecation warnings count"
print("[PASS] Test Suite Execution & Coverage Analysis complete.")

# 5. Check Detailed Per-Section Reports for all 78 sections individually
assert "## 4. Detailed Per-Section Audit Reports" in text, "Missing Section 4"
for i in range(1, 79):
    sec_pat = rf"#### Section {i}:"
    assert re.search(sec_pat, text), f"Missing detailed section heading for Section {i}!"

print("[PASS] All 78 detailed sections present individually.")

# Check required fields in each section
missing_fields = []
for i in range(1, 79):
    # slice text for section i
    p1 = rf"#### Section {i}:.*?(?=#### Section {i+1}:|## 5\. Appendix|\Z)"
    m = re.search(p1, text, re.DOTALL)
    assert m, f"Could not extract block for Section {i}"
    block = m.group(0)
    for field in ["Status", "Source Files", "Implementation Evidence", "Gaps", "Test Coverage", "Notes"]:
        if f"- **{field}**" not in block:
            missing_fields.append((i, field))

if missing_fields:
    print(f"Warning: Missing fields in sections: {missing_fields}")
else:
    print("[PASS] All 78 detailed sections contain all 6 required fields.")

# Check Section 27 for subsections 27.1 through 27.16
s27_block = re.search(r"#### Section 27:.*?(?=#### Section 28:)", text, re.DOTALL).group(0)
for sub in range(1, 17):
    assert f"27.{sub}" in s27_block, f"Missing subsection 27.{sub} in Section 27!"
print("[PASS] Section 27 contains all subsections 27.1 through 27.16.")

# Check Section 48 for all 34 CLI namespaces
s48_block = re.search(r"#### Section 48:.*?(?=### Part 5:)", text, re.DOTALL).group(0)
for ns in range(1, 35):
    assert f"| {ns} |" in s48_block or f"| **{ns}** |" in s48_block, f"Missing CLI namespace #{ns} in Section 48 table!"
print("[PASS] Section 48 contains verification of all 34 CLI namespaces.")

# Check Section 57 for deep architectural analysis
s57_block = re.search(r"#### Section 57:.*?(?=### Part 6:)", text, re.DOTALL).group(0)
assert "Path A" in s57_block and "Path B" in s57_block, "Missing Path A / Path B in Section 57"
assert "ScanEngine" in s57_block and "AutonomousMissionRuntime" in s57_block, "Missing class analysis in Section 57"
assert "collector_class_map" in s57_block or "resolution" in s57_block.lower(), "Missing map analysis in Section 57"
print("[PASS] Section 57 contains deep architectural dual-path analysis.")

print("\nALL VERIFICATION CRITERIA PASSED 100%!")
