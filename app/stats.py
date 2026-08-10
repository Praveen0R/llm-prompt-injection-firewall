import json
from collections import Counter
from pathlib import Path


LOG_FILE = Path("logs/attacks.jsonl")


def show_stats():
    entries = []

    if LOG_FILE.exists():
        with LOG_FILE.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    entries.append(json.loads(line))

    total = len(entries)
    blocked = sum(e["action"] == "BLOCK" for e in entries)
    warned = sum(e["action"] == "WARN" for e in entries)
    allowed = sum(e["action"] == "ALLOW" for e in entries)

    threats = Counter()

    for entry in entries:
        for threat in entry["threat_types"]:
            threats[threat] += 1

    print()
    print("======================================")
    print("       FIREWALL SECURITY STATS")
    print("======================================")
    print(f"Total Prompts : {total}")
    print(f"Blocked       : {blocked}")
    print(f"Warnings      : {warned}")
    print(f"Allowed       : {allowed}")
    print()

    print("Threat Types:")
    if threats:
        for threat, count in threats.most_common():
            print(f"  {threat:<25} {count}")
    else:
        print("  NONE")

    print("======================================")
