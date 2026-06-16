import json
import os
import glob

DATASET_FILE = "jett_training_data.json"

# UNIFIED REAL DATA LOOKUPS: Targets every real-world log cache found on your laptop
HONEYPOT_REAL_DATA_PATHS = [
    "/home/cosmic/Docs/Honeypot/Daily/botnet_*.txt",
    "/home/cosmic/GowskiNet-Vault/Security/honeypot/honeypot/logs/*-bridge.log",
    "/home/cosmic/GowskiNet-Vault/Security/honeypot/honeypot/data/dionaea/log/dionaea/dionaea.log",
    "/home/cosmic/GowskiNet-Vault/Security/honeypot/honeypot/data/conpot/log/conpot.log",
    "/home/cosmic/Projects/honeypot/logs/*-bridge.log",
    "/home/cosmic/Projects/honeypot/data/dionaea/log/dionaea/dionaea.log",
    "/home/cosmic/Projects/honeypot/data/conpot/log/conpot.log"
]

def load_dataset():
    if os.path.exists(DATASET_FILE):
        with open(DATASET_FILE, "r") as f:
            return json.load(f)
    return []

def harvest_all_honeypot_repositories():
    print("[📡 ADVANCED VAULT INGESTION] Aggregating all persistent honeynet files across your hard drive...")
    data = load_dataset()
    
    real_log_files_found = []
    for path_pattern in HONEYPOT_REAL_DATA_PATHS:
        real_log_files_found.extend(glob.glob(path_pattern))
        
    if not real_log_files_found:
        print("[!] Warning: Could not locate logs via active patterns. Verify directories.")
        return
        
    print(f"[+] Found {len(real_log_files_found)} unique tracking log files. Sucking in telemetry strings...")
    added_count = 0
    
    for log_path in real_log_files_found:
        try:
            with open(log_path, 'r', errors='ignore') as f:
                content = f.read().strip()
                
            if len(content) < 15:
                continue # Ignore tiny files or initialization logs
                
            # Intelligently divide long text streams into clean 1500-character segments
            chunks = [content[i:i+1500] for i in range(0, min(len(content), 30000), 1500)]
            
            for idx, chunk in enumerate(chunks):
                input_block = f"DECEPTION CAPTURE: Real GowskiNet Threat Telemetry\nFile Origin: {log_path}\nRAW ATTACK RECORD [Block {idx}]:\n{chunk}"
                output_block = f"Analysis Matrix:\n- Threat Context: Real-World In-the-Wild Intrusion Capture\n- Incident Profiling: Botnet tracking campaign or automated scanner exploit attempt captured inside your network decoy structures.\nVERDICT: QUARANTINE"
                
                data.append({
                    "input": input_block,
                    "output": output_block
                })
                added_count += 1
        except Exception as e:
            print(f"[!] Error parsing log target {log_path}: {e}")
            
    with open(DATASET_FILE, "w") as f:
        json.dump(data, f, indent=4)
        
    print(f"\n[🏆 MASTER PARSE SUCCESSFUL] Appended {added_count} real-world telemetry training profiles directly into your database!")

if __name__ == "__main__":
    harvest_all_honeypot_repositories()
