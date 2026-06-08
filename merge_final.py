import json
from pathlib import Path

base = Path.home() / "Projects/jeTT"
all_data = []

files = [
    ("jett_training_data_full.json", "Round 1 training"),
    ("jett_kb_training.json", "Knowledge base"),
    ("jett_intelligence_training.json", "Intelligence repos"),
]

for fname, label in files:
    path = base / fname
    if path.exists():
        with open(path) as f:
            d = json.load(f)
        all_data.extend(d)
        print(f"[+] {label}: {len(d)} pairs")

print(f"\n[+] TOTAL: {len(all_data)} pairs")
print("[*] Saving jett_round2_training.json...")
with open(base / "jett_round2_training.json", "w") as f:
    json.dump(all_data, f)
print("[+] DONE - Round 2 ready!")
