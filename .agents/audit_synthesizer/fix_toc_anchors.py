import re

with open("/home/varun/argus/FEATURE_AUDIT_REPORT.md", "r") as f:
    text = f.read()

# Extract links in Table of Contents
toc_match = re.search(r"## Table of Contents\s*(.*?)\s*---", text, re.DOTALL)
toc_text = toc_match.group(1)
links = re.findall(r"\[([^\]]+)\]\(#([^)]+)\)", toc_text)

for label, target in links:
    # If target not already defined as <a id="target"></a>
    if f'<a id="{target}">' not in text:
        # Find heading containing label (stripped of leading numbers or prefix)
        # E.g. "1.1 Platform Overview & Maturity Assessment"
        search_label = label.split(" (")[0] # remove status like (✅ Implemented)
        # Search for heading line
        escaped_label = re.escape(search_label)
        pattern = rf"(^#+\s+.*{escaped_label}.*$)"
        m = re.search(pattern, text, re.MULTILINE)
        if m:
            heading_line = m.group(1)
            replacement = f'<a id="{target}"></a>\n{heading_line}'
            text = text.replace(heading_line, replacement, 1)

with open("/home/varun/argus/FEATURE_AUDIT_REPORT.md", "w") as f:
    f.write(text)

print("TOC anchors injected.")
