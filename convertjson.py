import json
import re

input_file = r"C:\sri\trisulauto\Improved_Network_Issues_Detailed.txt"
output_file = r"C:\sri\trisulauto\network_issue_rules.json"

# Mapping from phrases in the document to short metric codes
METRIC_MAP = {
    "Latency": "LAT",
    "Retransmitted packets": "RPKT",
    "Retransmission rate": "R%",
    "Poor quality flows": "PQF",
    "Timeout": "TO",
    "Unidirectional": "UNI"
}

def detect_metrics(section_text):
    """Return list of metric codes detected in a section."""
    metrics = set()
    for phrase, code in METRIC_MAP.items():
        if re.search(phrase, section_text, re.IGNORECASE):
            metrics.add(code)
    return sorted(metrics)

with open(input_file, "r", encoding="utf-8") as f:
    text = f.read()

sections = re.split(r"### ", text)

rules = []

for section in sections:
    if not section.strip():
        continue

    lines = section.splitlines()
    title = lines[0].strip()

    issue_name = title.split("(")[0].strip()

    problem_match = re.search(r"\*\*What's going wrong:\*\*(.*?)\*\*Where to find the issue:\*\*", section, re.S)
    diag_match = re.search(r"\*\*Where to find the issue:\*\*(.*?)\*\*How to fix:\*\*", section, re.S)
    fix_match = re.search(r"\*\*How to fix:\*\*(.*)", section, re.S)

    problem = problem_match.group(1).strip() if problem_match else ""

    diagnostics = []
    if diag_match:
        diagnostics = [line.strip("- ").strip() for line in diag_match.group(1).splitlines() if line.strip()]

    fixes = []
    if fix_match:
        fixes = [line.strip("- ").strip() for line in fix_match.group(1).splitlines() if line.strip()]

    metrics = detect_metrics(section)

    rule = {
        "issue_name": issue_name,
        "metrics": metrics,
        "problem": problem,
        "diagnostics": diagnostics,
        "fix": fixes
    }

    rules.append(rule)

knowledge_base = {
    "rules": rules
}

with open(output_file, "w", encoding="utf-8") as f:
    json.dump(knowledge_base, f, indent=4)

print("Structured rule JSON created at:")
print(output_file)