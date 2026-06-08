import json
import os
import random

DATASET_FILE = "jett_training_data_full.json"

def load_dataset():
    if os.path.exists(DATASET_FILE):
        with open(DATASET_FILE, "r") as f:
            return json.load(f)
    return []

def run_permutation_mutation():
    print("[🧬 MUTATION ENGINE] Initializing Variant Permutation Matrix...")
    data = load_dataset()
    
    # Filter out your existing malicious entries to use as mutation seeds
    malicious_seeds = [d for d in data if "QUARANTINE" in d.get("output", "")]
    
    if not malicious_seeds:
        print("[!] No malicious seeds found to mutate. Run your dataset generators first.")
        return

    print(f"[+] Found {len(malicious_seeds)} threat profiles. Generating mutated variants...")
    
    mutated_records = []
    
    # Structural Mutation Layouts to simulate advanced bypass attempts
    bypass_styles = [
        "BASE64_ENCODED_WRAPPER: Payload obfuscated via native string encryption layers.",
        "HEX_PATH_OBFUSCATION: Binary path modified using hexadecimal directory syntax.",
        "LOW_AND_SLOW_TIMING: Time signature stretched across wide logging intervals to hide spikes.",
        "MASQUERADED_ENVIRONMENT: Command executed directly out of your safe ~/Projects/ folder to test camouflage."
    ]

    # Generate 5,000 mutated variants to aggressively train the AI on evasive tactics
    for i in range(5000):
        seed = random.choice(malicious_seeds)
        style = bypass_styles[i % len(bypass_styles)]
        
        # Inject the mutation wrapper right into the telemetry text block
        mutated_input = f"{seed['input']}\n[⚠️ EVASION ATTEMPT]: {style} __mutation_node_{i}"
        
        # Enhance the output matrix to explicitly teach jeTT how to see through the bypass trick
        mutated_output = (
            f"Analysis Matrix:\n"
            f"- Threat Profiling: Polymorphic Evasion Masking Detected\n"
            f"- Tactical Bypass Method: {style.split(':')[0]}\n"
            f"- Behavioral Assessment: Intruder attempted to bypass security layer via string obfuscation or safe folder hijacking. Masking neutralized.\n"
            f"VERDICT: QUARANTINE"
        )
        
        mutated_records.append({
            "input": mutated_input,
            "output": mutated_output
        })

    # Append the fresh mutations right into your main dataset pool
    data.extend(mutated_records)
    
    with open(DATASET_FILE, "w") as f:
        json.dump(data, f, indent=4)
        
    print(f"[🏆 MUTATION COMPLETE] Successfully injected 5,000 advanced bypass mutation profiles into your core dataset!")

if __name__ == "__main__":
    run_permutation_mutation()
