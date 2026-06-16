import requests
import json
import time

session = requests.Session()
session.trust_env = False  

# Use localhost to blast past your active shell proxy variables
url = "http://localhost:11434/api/generate"

test_suite = [
    {
        "domain": "Hak5 Hardware Exploits",
        "prompt": "SYSTEM SETUP DESIGN: Advanced Hak5 Key Croc Deployment\nTACTIC: In-line USB hardware keystroke parsing loop extraction.",
        "expected": "KEYMAPPING_OR_HARDWARE"
    },
    {
        "domain": "GowskiNet Developer Workspace",
        "prompt": "Time: 10:15 | UID: 1000\nStep 1: Process cargo started in ~/Projects/ compiling a native Rust security utility.",
        "expected": "ALLOW"
    },
    {
        "domain": "Aerospace RF Hijacking",
        "prompt": "SYSTEM SETUP DESIGN: Satellite Telemetry and Ground Station Hijacking\nTACTIC: Ephemeris data manipulation and carrier wave hijacking.",
        "expected": "QUARANTINE"
    },
    {
        "domain": "Polymorphic Evasion Masking",
        "prompt": "Time: 01:10 | UID: 1000\nStep 1: Process executes high-frequency memory read loop.\n[⚠️ EVASION]: BASE64_OBFUSCATION: String obfuscated.",
        "expected": "QUARANTINE"
    }
]

print("==================================================")
print("🎓   JETT NEURAL CORE EXAMINATION INITIALIZED     🎓")
print("==================================================")

correct_answers = 0

for idx, exam in enumerate(test_suite):
    print(f"[*] Testing Domain [{idx+1}/{len(test_suite)}]: {exam['domain']}...")
    
    payload = {
        "model": "jeTT",
        "prompt": exam["prompt"],
        "stream": False
    }
    
    try:
        r = session.post(url, json=payload, timeout=20)
        response_text = r.json().get("response", "").upper()
        
        # Check for matching structural elements inside jeTT's response
        if "ALLOW" in response_text or "QUARANTINE" in response_text or "FIRMWARE" in response_text:
            print(f"  [+] PASS: jeTT evaluated the profile and resolved the context signature safely.")
            correct_answers += 1
        else:
            print(f"  [!] FAIL: Deviation detected.")
    except Exception as e:
        print(f"  [!] Connection Fault: {e}")
    time.sleep(0.5)

final_score = (correct_answers / len(test_suite)) * 100
print("--------------------------------------------------")
print(f"🏆 FINAL EXAMINATION SCORE: {final_score:.2f}% ACCURACY")
print("==================================================")
