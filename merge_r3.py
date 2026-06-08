import json
from pathlib import Path

base = Path.home() / "Projects/jeTT"
all_data = []

files = [
    ("jett_round2_training.json", "Round 2 dataset"),
    ("jett_allow_training.json", "ALLOW balance dataset"),
]

for fname, label in files:
    path = base / fname
    if path.exists():
        with open(path) as f:
            d = json.load(f)
        all_data.extend(d)
        print(f"[+] {label}: {len(d)} pairs")

print(f"\n[+] TOTAL: {len(all_data)} pairs")
print("[*] Saving jett_round3_training.json...")
with open(base / "jett_round3_training.json", "w") as f:
    json.dump(all_data, f)
print("[+] DONE - Round 3 ready!")
