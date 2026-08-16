import json
from pathlib import Path


LOG_FILE = Path("logs/attacks.jsonl")
REPORT_FILE = Path("logs/report.json")


def generate_report():
    entries = []

    if LOG_FILE.exists():
        with LOG_FILE.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    entries.append(json.loads(line))

    total = len(entries)
    blocked = sum(1 for e in entries if e["action"] == "BLOCK")
    warned = sum(1 for e in entries if e["action"] == "WARN")
    allowed = sum(1 for e in entries if e["action"] == "ALLOW")

    report = {
        "total_prompts": total,
        "blocked": blocked,
        "warnings": warned,
        "allowed": allowed,
        "detections": entries,
    }

    with REPORT_FILE.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    return report
