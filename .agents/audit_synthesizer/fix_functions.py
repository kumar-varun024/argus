with open("/home/varun/argus/.agents/audit_synthesizer/make_report.py", "r") as f:
    code = f.read()

part3_correct = '''def build_part3_sections():
    out = []
    out.append("### Part 3: AI Research, RAG Fabric & Domain Specialists (Sections 26–37)\\n")
    out.append(
        "This section evaluates the AI research reasoning engine, the comprehensive Security Research RAG and Intelligence Fabric "
        "(including Subsections 27.1 through 27.16), research cards, the vulnerability intelligence engine, methodology playbooks, "
        "and domain-specific research specialists (Authorization, Business Logic, API Intelligence, GraphQL, JavaScript, Authentication, File Upload).\\n"
    )
    
    for i in range(26, 38):
        pat = rf"### Section {i}:\\s*([^\\n]+)(.*?)(?=### Section {i+1}|## 3\\. Logic Chain|\\Z)"
        m = re.search(pat, c3, re.DOTALL)
        if m:
            title = m.group(1).strip()
            body = m.group(2).strip()
            s_title = f"Section {i}: {SECTION_TITLES.get(i, title)}"
            s_anchor = make_anchor(s_title)
            out.append(f"<a id=\\"{s_anchor}\\"></a>")
            out.append(f"#### Section {i}: {SECTION_TITLES.get(i, title)}\\n")
            
            # Normalize Section 27 and 33
            if i == 27:
                body = body.replace("- **Subsections 27.1–27.16 Detailed Breakdown**:", "- **Implementation Evidence**:\\n  - **Subsections 27.1–27.16 Detailed Breakdown**:")
            elif i == 33:
                body = body.replace("- **Gaps (Rationale for Partial)**:", "- **Gaps**:")
                
            out.append(body)
            out.append("\\n---\\n")
            
    return "\\n".join(out)'''

part6_correct = '''def build_part6_sections():
    out = []
    out.append("### Part 6: Advanced Research Roadmap & Evolution (Sections 58–78)\\n")
    out.append(
        "This section evaluates the future roadmap and advanced research capabilities of Argus, covering Phases 9 through 26: "
        "advanced security research specialists, continuous investigation loops, adaptive prioritization, cross-specialist correlation, "
        "stateful research, differential response analysis, finding validation and false-positive reduction frameworks, "
        "RAG knowledge bases, technology-aware investigation, researcher feedback loops, evidence-first reporting, reproducibility, "
        "mission replay, research benchmarks, production hardening, the recommended development order (Section 77), "
        "and the core success criteria and final platform vision (Section 78).\\n"
    )

    for i in range(58, 79):
        pat = rf"### Section {i}:\\s*([^\\n]+)(.*?)(?=### Section {i+1}|## 3\\. Caveats|\\Z)"
        m = re.search(pat, c6, re.DOTALL)
        if m:
            title = m.group(1).strip()
            body = m.group(2).strip()
            s_title = f"Section {i}: {SECTION_TITLES.get(i, title)}"
            s_anchor = make_anchor(s_title)
            out.append(f"<a id=\\"{s_anchor}\\"></a>")
            out.append(f"#### Section {i}: {SECTION_TITLES.get(i, title)}\\n")
            
            # Normalize bold colons from Cluster 6 to match standard - **Field**:
            norm_body = re.sub(r"- \\*\\*([A-Za-z ]+):\\*\\*", r"- **\\1**:", body)
            out.append(norm_body)
            out.append("\\n---\\n")

    return "\\n".join(out)'''

import re
p3_pat = r"def build_part3_sections\(\):.*?return \"\\n\"\.join\(out\)"
code = re.sub(p3_pat, lambda m: part3_correct, code, flags=re.DOTALL)

p6_pat = r"def build_part6_sections\(\):.*?return \"\\n\"\.join\(out\)"
code = re.sub(p6_pat, lambda m: part6_correct, code, flags=re.DOTALL)

with open("/home/varun/argus/.agents/audit_synthesizer/make_report.py", "w") as f:
    f.write(code)

print("Replacement complete successfully.")
