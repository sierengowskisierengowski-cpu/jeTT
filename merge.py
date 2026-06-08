import json
from pathlib import Path

base = Path.home() / "Projects/jeTT"
all_data = []

print("[*] Loading jett_training_data_full.json...")
with open(base / "jett_training_data_full.json") as f:
    d = json.load(f)
    all_data.extend(d)
    print(f"    -> {len(d)} pairs")

print("[*] Loading jett_kb_training.json...")
with open(base / "jett_kb_training.json") as f:
    d = json.load(f)
    all_data.extend(d)
    print(f"    -> {len(d)} pairs")

print("[*] Parsing jett_brain_rules.txt...")
with open(base / "jett_brain_rules.txt") as f:
    content = f.read()

blocks = content.split("=" * 50)
count = 0
for block in blocks:
    if "VERDICT:" not in block:
        continue
    lines = block.strip().split("\n")
    input_lines = []
    verdict = ""
    for line in lines:
        if line.startswith("VERDICT:"):
            verdict = line.replace("VERDICT:", "").strip()
        elif line.strip() and not line.startswith("###") and not line.startswith("REQUIRED") and not line.startswith("Analysis"):
            input_lines.append(line.strip())
    inp = " ".join(input_lines).strip()
    if inp and verdict:
        all_data.append({"input": inp, "output": verdict})
        count += 1

print(f"    -> {count} brain rules pairs")
print(f"\n[+] Total combined: {len(all_data)} pairs")
print("[*] Saving to jett_round2_training.json...")
with open(base / "jett_round2_training.json", "w") as f:
    json.dump(all_data, f)
print("[+] DONE - ready for Round 2!")
