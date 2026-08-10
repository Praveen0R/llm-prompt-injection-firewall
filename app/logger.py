import json
from datetime import datetime
from pathlib import Path


LOG_FILE = Path("logs/attacks.jsonl")


def log_detection(prompt, result):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "timestamp": datetime.now().isoformat(),
        "prompt": prompt,
        "score": result.score,
        "action": result.action,
        "threat_types": result.threat_types,
        "matched_rules": result.matched_rules,
    }

    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
