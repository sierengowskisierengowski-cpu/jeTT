#!/usr/bin/env python3
"""
jeTT Intelligence Converter
Converts all downloaded git repos in intelligence/ into training pairs
Output: ~/Projects/jeTT/jett_intelligence_training.json
"""

import json
import os
from pathlib import Path

INTEL_BASE = Path.home() / "Projects/jeTT/intelligence"
OUTPUT_FILE = Path.home() / "Projects/jeTT/jett_intelligence_training.json"

# File extensions to process
TEXT_EXTS = {'.md', '.txt', '.py', '.c', '.cpp', '.h', '.rs', '.go', '.sh',
             '.yaml', '.yml', '.json', '.csv', '.rb', '.ps1', '.bat', '.asm',
             '.yar', '.yara', '.rule', '.conf', '.cfg', '.toml', '.sig'}

# Skip these directories
SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.github', 'vendor',
             'third_party', 'test', 'tests', 'docs/images', 'assets'}

training_data = []

def add_pair(input_text, output_text):
    if input_text.strip() and output_text.strip() and len(input_text) > 20:
        training_data.append({
            "input": input_text.strip()[:2000],
            "output": output_text.strip()[:1000]
        })

def should_skip(path):
    for part in path.parts:
        if part in SKIP_DIRS:
            return True
    return False

def get_category(folder_name):
    categories = {
        "raw_redteam": "red team offensive security",
        "raw_blueteam": "blue team defensive security",
        "raw_kali": "penetration testing",
        "raw_hak5": "hardware hacking and payload delivery",
        "raw_exploitdb": "exploit development and vulnerability research",
        "raw_exploitdev": "exploit development and binary exploitation",
        "raw_mitre": "MITRE ATT&CK threat intelligence",
    }
    return categories.get(folder_name, "security research")

def process_markdown(content, filename, category, repo_name):
    """Extract meaningful sections from markdown files"""
    lines = content.split('\n')
    sections = []
    current_section = []
    current_header = ""

    for line in lines:
        if line.startswith('#'):
            if current_section and current_header:
                sections.append((current_header, '\n'.join(current_section)))
            current_header = line.strip('#').strip()
            current_section = []
        else:
            current_section.append(line)

    if current_section and current_header:
        sections.append((current_header, '\n'.join(current_section)))

    for header, body in sections[:10]:
        body = body.strip()
        if len(body) < 50:
            continue
        add_pair(
            f"Security knowledge from {repo_name} [{category}] - {header}:\n{body[:800]}",
            f"This is {category} knowledge about '{header}' from {repo_name}. Key information: {body[:500]}"
        )

def process_script(content, filename, category, repo_name):
    """Process shell scripts, Python, Ruby payloads"""
    ext = Path(filename).suffix
    lang_map = {'.py': 'Python', '.sh': 'Bash', '.rb': 'Ruby',
                '.ps1': 'PowerShell', '.bat': 'Batch', '.c': 'C',
                '.go': 'Go', '.rs': 'Rust'}
    lang = lang_map.get(ext, 'script')

    # Check if it looks like a payload/exploit
    dangerous_keywords = ['exec', 'shell', 'payload', 'exploit', 'reverse',
                         'bind', 'chmod +x', 'curl', 'wget', 'nc ', 'netcat',
                         'meterpreter', 'shellcode', 'overflow', 'rop',
                         'ld_preload', 'ptrace', 'mmap', 'memfd']

    is_dangerous = any(kw in content.lower() for kw in dangerous_keywords)

    if is_dangerous:
        add_pair(
            f"Process executing {lang} code with these characteristics detected on GowskiNet:\n{content[:600]}",
            f"QUARANTINE — This {lang} code from {repo_name} contains {category} techniques. Suspicious execution patterns detected."
        )

    add_pair(
        f"Explain this {lang} {category} tool from {repo_name} ({filename}):\n{content[:800]}",
        f"This is a {lang} {category} script from {repo_name}. It implements: {content[:400]}"
    )

def process_yara(content, filename, repo_name):
    """Process YARA rules"""
    rules = content.split('rule ')
    for rule in rules[1:10]:
        rule_name = rule.split('\n')[0].split('{')[0].strip()
        add_pair(
            f"File matches YARA rule '{rule_name}' from {repo_name}. jeTT verdict?",
            f"QUARANTINE — YARA rule '{rule_name}' matched. This indicates malicious or suspicious file characteristics."
        )
        add_pair(
            f"What does YARA rule '{rule_name}' detect?",
            f"YARA rule '{rule_name}' from {repo_name} detects: {rule[:400]}"
        )

def process_sigma(content, filename, repo_name):
    """Process Sigma detection rules"""
    try:
        rule = json.loads(content) if content.strip().startswith('{') else {}
        if not rule:
            import re
            title = re.search(r'title:\s*(.+)', content)
            desc = re.search(r'description:\s*(.+)', content)
            detection = re.search(r'detection:(.*?)(?:condition:|falsepositives:)', content, re.DOTALL)
            title = title.group(1).strip() if title else filename
            desc = desc.group(1).strip() if desc else ""
            det = detection.group(1).strip()[:300] if detection else ""
            add_pair(
                f"Sigma rule '{title}' triggered on GowskiNet. jeTT verdict?",
                f"QUARANTINE — Sigma detection rule '{title}' matched. {desc}. Detection pattern: {det}"
            )
            add_pair(
                f"What does Sigma rule '{title}' detect?",
                f"Sigma rule '{title}': {desc}. Detection: {det}"
            )
    except:
        pass

def process_nuclei(content, filename, repo_name):
    """Process Nuclei templates"""
    try:
        import re
        name = re.search(r'name:\s*(.+)', content)
        severity = re.search(r'severity:\s*(.+)', content)
        desc = re.search(r'description:\s*(.+)', content)
        name = name.group(1).strip() if name else filename
        severity = severity.group(1).strip() if severity else "unknown"
        desc = desc.group(1).strip() if desc else ""
        add_pair(
            f"Nuclei template '{name}' matched on GowskiNet target. Severity: {severity}. jeTT verdict?",
            f"{'QUARANTINE' if severity in ['critical', 'high'] else 'ALERT'} — Nuclei detected '{name}' ({severity}). {desc}"
        )
    except:
        pass

def process_file(filepath, category, repo_name):
    """Process a single file based on type"""
    try:
        content = filepath.read_text(errors='ignore')
        if not content.strip() or len(content) < 30:
            return

        fname = filepath.name
        ext = filepath.suffix.lower()

        if ext in {'.yar', '.yara', '.rule'}:
            process_yara(content, fname, repo_name)
        elif ext in {'.yml', '.yaml'} and 'sigma' in str(filepath).lower():
            process_sigma(content, fname, repo_name)
        elif ext in {'.yml', '.yaml'} and 'nuclei' in str(filepath).lower():
            process_nuclei(content, fname, repo_name)
        elif ext == '.md':
            process_markdown(content, fname, category, repo_name)
        elif ext in {'.py', '.sh', '.rb', '.ps1', '.bat', '.c', '.go', '.rs'}:
            process_script(content, fname, category, repo_name)
        elif ext == '.csv':
            lines = content.split('\n')[:20]
            add_pair(
                f"Security data from {repo_name} [{category}]:\n{chr(10).join(lines[:10])}",
                f"This is {category} data from {repo_name}: {chr(10).join(lines[:5])}"
            )
        elif ext in {'.json'} and len(content) < 50000:
            add_pair(
                f"Security intelligence from {repo_name} [{category}] file {fname}:\n{content[:600]}",
                f"This {category} data from {repo_name} contains: {content[:400]}"
            )

    except Exception as e:
        pass

# Process all intelligence folders
for folder in sorted(INTEL_BASE.iterdir()):
    if not folder.is_dir() or folder.name == "raw_manpages":
        continue

    category = get_category(folder.name)
    print(f"\n[*] Processing {folder.name} [{category}]")
    file_count = 0

    for repo in sorted(folder.iterdir()):
        if not repo.is_dir():
            continue

        repo_name = repo.name
        repo_files = 0

        for filepath in repo.rglob("*"):
            if not filepath.is_file():
                continue
            if should_skip(filepath.relative_to(repo)):
                continue
            if filepath.suffix.lower() not in TEXT_EXTS:
                continue
            if filepath.stat().st_size > 500000:  # Skip files > 500KB
                continue

            process_file(filepath, category, repo_name)
            repo_files += 1

        print(f"    → {repo_name}: {repo_files} files processed")
        file_count += repo_files

    print(f"  [{folder.name}] total: {file_count} files")

print(f"\n[+] Total intelligence training pairs: {len(training_data)}")
print(f"[*] Saving to {OUTPUT_FILE}...")

with open(OUTPUT_FILE, 'w') as f:
    json.dump(training_data, f)

print(f"[+] DONE. Ready to merge into Round 2 dataset.")
