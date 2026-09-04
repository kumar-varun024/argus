import re

# Test normalization regex on Cluster 6 text
sample = """
- **Status:** ✅ Implemented
- **Source Files:**
  - `argus/intelligence/engine.py`
- **Implementation Evidence:**
  - Classes...
- **Gaps:** None
- **Test Coverage:** Passed
- **Notes:** Full working
"""

normalized = re.sub(r"- \*\*([A-Za-z ]+):\*\*", r"- **\1**:", sample)
print(normalized)
