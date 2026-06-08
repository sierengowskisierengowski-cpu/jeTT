import json
import random

# ============================================================
# jeTT TRAINING DATASET GENERATOR
# Autonomous AI Anti-Virus & Security
# Covers: Known threats, behavioral patterns, predictive reasoning
# ============================================================

# ============================================================
# KNOWN ATTACK TECHNIQUES
# ============================================================
malicious_techniques = [

    # --- CRYPTOMINER DEPLOYMENT ---
    {
        "name": "Redtail Miner Drop",
        "step_x": "bash script downloaded via curl from remote host, saved to /tmp/",
        "step_y": "Script scanned filesystem for writable directories, wrote 2MB test file to confirm write access.",
        "step_z": "ELF binary executed from hidden dotfile masquerading as SSH process, attempted outbound connection to 185.220.x.x.",
        "prediction": "Classic Redtail cryptominer deployment. Dropper script identifies writable location, drops miner binary as hidden dotfile disguised as system process, phones home to mining pool C2. Next step: persistent cron entry.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "XMRig Monero Miner",
        "step_x": "UPX-packed ELF binary extracted and executed from /tmp/ directory.",
        "step_y": "Process read /proc/cpuinfo and /sys/devices/system/cpu to map available CPU cores.",
        "step_z": "Outbound TCP connection attempted to known Monero mining pool infrastructure on port 3333.",
        "prediction": "XMRig Monero miner deployment. CPU mapping confirms resource theft intent. Mining pool connection confirms C2. Will max out CPU, degrade system performance silently.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Competing Attacker Cleanup",
        "step_x": "Shell script killed processes matching known miner names including c3pool and kswapd0.",
        "step_y": "Script removed crontab entries belonging to previous attacker's persistence mechanism.",
        "step_z": "Script dropped its own miner binary and installed new crontab persistence.",
        "prediction": "Turf war between competing attackers. New attacker evicting previous miner to claim system resources exclusively. Both are malicious — quarantine the new process immediately.",
        "verdict": "QUARANTINE_PID"
    },

    # --- PROCESS INJECTION ---
    {
        "name": "Process Hollowing",
        "step_x": "Parent process spawned a trusted system binary in a suspended state.",
        "step_y": "NtUnmapViewOfSection or equivalent called to hollow out the target process memory.",
        "step_z": "WriteProcessMemory injecting foreign shellcode into the hollowed process address space.",
        "prediction": "Process hollowing attack. Attacker unmaps legitimate binary from memory, injects malicious payload into the now-empty process shell. Evades disk scanners because binary on disk is still clean.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Linux Process Injection",
        "step_x": "Unknown binary called ptrace PTRACE_ATTACH on a running web server process.",
        "step_y": "mmap called with PROT_READ, PROT_WRITE, PROT_EXEC permissions on target process memory.",
        "step_z": "Foreign shellcode written to executable memory region, instruction pointer redirected.",
        "prediction": "Live process injection into web server. Attacker using ptrace debugging syscall to hijack thread execution. Next step will be reverse shell or data exfiltration from within the trusted web server process.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Shared Library Injection",
        "step_x": "Process called dlopen on a newly created .so file in /tmp/ directory.",
        "step_y": "Shared library contained constructor function that executed on load.",
        "step_z": "Injected library opened reverse shell connection to external IP on port 4444.",
        "prediction": "Shared library injection via dlopen. Attacker drops malicious .so, tricks process into loading it. Constructor auto-executes before main program. Classic fileless persistence technique.",
        "verdict": "QUARANTINE_PID"
    },

    # --- BACKDOORS & PERSISTENCE ---
    {
        "name": "SSH Key Plant",
        "step_x": "Remote session authenticated via brute forced password to SSH honeypot.",
        "step_y": "Attacker wrote RSA public key to /home/user/.ssh/authorized_keys.",
        "step_z": "Original dropper script deleted all traces including bash history.",
        "prediction": "Classic SSH backdoor establishment. Attacker plants their own key for passwordless persistent access. Deletes evidence to avoid detection. System now permanently accessible to attacker until key is removed.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Crontab Persistence",
        "step_x": "Unknown process modified /var/spool/cron or /etc/cron.d/ without user interaction.",
        "step_y": "New cron entry executes curl download from external URL every 5 minutes.",
        "step_z": "Downloaded payload executed silently with output redirected to /dev/null.",
        "prediction": "Crontab persistence mechanism. Attacker ensures malware survives reboots and security tool removal by continuously redownloading from C2. Every 5 minutes the threat self-heals.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Systemd Service Persistence",
        "step_x": "Unknown process wrote new .service file to /etc/systemd/system/ directory.",
        "step_y": "systemctl enable called on the new service without user interaction.",
        "step_z": "New service executes hidden binary from /tmp/ on every system boot.",
        "prediction": "Systemd persistence. Attacker created a legitimate-looking service that survives reboots. Most users never check systemd service files. This persists until manually discovered and removed.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Bashrc Persistence",
        "step_x": "Unknown process appended commands to /home/user/.bashrc or /etc/profile.",
        "step_y": "Appended command downloads and executes remote payload silently.",
        "step_z": "Payload executes every time any user opens a terminal session.",
        "prediction": "Shell profile persistence. Executes on every terminal open. Extremely common technique, often missed because .bashrc modifications look like user customizations.",
        "verdict": "QUARANTINE_PID"
    },

    # --- LOLBIN ABUSE ---
    {
        "name": "Python3 LoLBin Abuse",
        "step_x": "python3 spawned by sshd at 03:14 — outside all normal usage patterns for this system.",
        "step_y": "python3 made immediate outbound connection to unknown external IP on port 443.",
        "step_z": "python3 wrote ELF binary to /tmp/ then executed it as a hidden dotfile.",
        "prediction": "Living off the land using trusted python3 interpreter. Attacker uses legitimate binary to avoid detection. Time of day anomaly confirms this is not user activity. C2 connection followed by payload drop is textbook malware behavior.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Curl Download Chain",
        "step_x": "curl executed with -o flag downloading to /tmp/ from external URL.",
        "step_y": "Downloaded file immediately made executable via chmod +x.",
        "step_z": "Newly executable file launched with nohup to survive session termination.",
        "prediction": "Classic download and execute chain using legitimate curl binary. nohup ensures payload survives even if attacker's session drops. All three steps together are unambiguous malware deployment.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Bash Encoded Execution",
        "step_x": "bash executed with -c flag containing heavily base64 encoded payload string.",
        "step_y": "Decoded payload spawned additional child process with network connectivity.",
        "step_z": "Child process connected to external IP and awaited commands.",
        "prediction": "Encoded command execution to bypass simple string detection. Base64 encoding hides malicious commands from log analysis tools. Decoded payload immediately establishes C2 channel.",
        "verdict": "QUARANTINE_PID"
    },

    # --- PRIVILEGE ESCALATION ---
    {
        "name": "SUID Binary Exploitation",
        "step_x": "Process executed a SUID binary that is known to have privilege escalation vulnerabilities.",
        "step_y": "Exploit triggered the SUID binary to spawn a child shell with elevated privileges.",
        "step_z": "Elevated shell immediately read /etc/shadow and wrote contents to /tmp/",
        "prediction": "SUID exploitation for privilege escalation. Attacker used known vulnerable binary to gain root. Reading /etc/shadow confirms credential theft intent. All password hashes now compromised.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Sudo Misconfiguration Abuse",
        "step_x": "Low privilege user executed sudo with NOPASSWD configuration on unexpected binary.",
        "step_y": "Binary used to spawn privileged shell through known escape technique.",
        "step_z": "Root shell used to disable security logging and create hidden admin account.",
        "prediction": "Sudo misconfiguration exploitation. Attacker identified overly permissive sudo rule and used it to escalate to root. Disabling logging and creating backdoor account confirms full compromise.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Kernel Exploit Attempt",
        "step_x": "Process attempted to exploit known kernel vulnerability via crafted ioctl call.",
        "step_y": "Kernel memory corruption triggered, process gained elevated privileges.",
        "step_z": "Privileged process disabled SELinux/AppArmor and modified /etc/sudoers.",
        "prediction": "Kernel level privilege escalation exploit. Most dangerous escalation path — bypasses all userspace security controls. Disabling MAC frameworks removes last line of defense.",
        "verdict": "QUARANTINE_PID"
    },

    # --- CREDENTIAL THEFT ---
    {
        "name": "Memory Credential Dump",
        "step_x": "Process requested debug handle to security daemon managing authentication.",
        "step_y": "MiniDump or ptrace used to read authentication daemon memory space.",
        "step_z": "Memory dump written to /tmp/ containing plaintext credential material.",
        "prediction": "In-memory credential theft. Attacker targeting authentication daemon to extract plaintext passwords or hashes. All credentials managed by that daemon are now compromised.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "SSH Key Theft",
        "step_x": "Unknown process read all files in /home/user/.ssh/ directory.",
        "step_y": "Private key files exfiltrated via encoded outbound connection.",
        "step_z": "Keys transmitted to external server over encrypted channel.",
        "prediction": "SSH private key exfiltration. Stolen keys give attacker passwordless access to all systems the victim connects to. Lateral movement to other servers now possible.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Browser Credential Theft",
        "step_x": "Unknown process read Chrome or Firefox profile directory including saved passwords database.",
        "step_y": "Encryption key read from OS keychain to decrypt stored credentials.",
        "step_z": "Decrypted credentials transmitted to external server.",
        "prediction": "Browser credential database theft. All saved passwords, session cookies, and authentication tokens now in attacker's hands. Account takeover of all saved sites imminent.",
        "verdict": "QUARANTINE_PID"
    },

    # --- NETWORK ATTACKS ---
    {
        "name": "Reverse Shell",
        "step_x": "Process executed bash -i with stdin and stdout redirected to network socket.",
        "step_y": "Outbound TCP connection established to external IP on non-standard port.",
        "step_z": "Interactive shell commands received and executed from remote attacker.",
        "prediction": "Reverse shell established. Attacker has interactive command line access to system. All subsequent commands execute with the permissions of the compromised process.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Port Scanning",
        "step_x": "Process made rapid sequential TCP connection attempts to hundreds of ports.",
        "step_y": "Connections attempted against multiple hosts on local network subnet.",
        "step_z": "Results written to file indicating active services on discovered hosts.",
        "prediction": "Internal network reconnaissance. Attacker mapping GowskiNet topology to find additional targets for lateral movement. Discovery phase before lateral movement attack.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Data Exfiltration",
        "step_x": "Unknown process read large volume of files from user home directory.",
        "step_y": "Files compressed and encrypted into archive in /tmp/",
        "step_z": "Archive transmitted via outbound HTTPS connection to external server.",
        "prediction": "Data exfiltration in progress. Attacker collecting and staging sensitive files before transmission. Encryption hides content from network monitoring. Full data breach in progress.",
        "verdict": "QUARANTINE_PID"
    },

    # --- ROOTKITS & HIDING ---
    {
        "name": "Kernel Module Rootkit",
        "step_x": "insmod or modprobe executed loading unsigned kernel module.",
        "step_y": "Kernel module hooked syscall table to intercept and modify system calls.",
        "step_z": "Module hiding specific files, processes, and network connections from userspace tools.",
        "prediction": "Kernel rootkit installation. Hooks at kernel level make malware invisible to ps, ls, netstat. Only kernel-level detection like eBPF can see through this. System is now fundamentally compromised.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Log Tampering",
        "step_x": "Unknown process opened and truncated /var/log/auth.log and /var/log/syslog.",
        "step_y": "Process also modified file timestamps to match surrounding legitimate log files.",
        "step_z": "Log rotation configuration modified to prevent future logging of specific events.",
        "prediction": "Evidence destruction in progress. Attacker erasing traces of their activity. Timestamp modification suggests sophisticated attacker aware of forensic analysis techniques.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Hidden Process Masquerade",
        "step_x": "Process renamed itself using argv[0] modification to appear as kworker or systemd.",
        "step_y": "Process moved to /proc/self/fd/ path to hide from standard process listing.",
        "step_z": "Process maintaining outbound C2 connection despite appearing as kernel thread.",
        "prediction": "Process masquerading as kernel thread. Attacker disguising malware as legitimate kernel worker. Name change tricks casual inspection but eBPF sees true binary path and behavior.",
        "verdict": "QUARANTINE_PID"
    },

    # --- SUPPLY CHAIN ---
    {
        "name": "Binary Tampering",
        "step_x": "SHA256 hash of system binary does not match package manager database record.",
        "step_y": "Modified binary executes additional code path not present in official version.",
        "step_z": "Extra code path establishes C2 connection during normal binary operation.",
        "prediction": "Trojanized system binary. Supply chain attack or post-compromise binary replacement. Binary looks legitimate to users but has hidden malicious functionality.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Malicious Package Install",
        "step_x": "pip or npm install executed with package name visually similar to legitimate package.",
        "step_y": "Package install script executed additional commands beyond normal installation.",
        "step_z": "Installed package contains backdoor that activates on import.",
        "prediction": "Typosquatting or dependency confusion attack via malicious package. Install scripts are trusted by package managers but execute arbitrary code. Backdoor now part of installed Python environment.",
        "verdict": "QUARANTINE_PID"
    },

    # --- SLEEPER AGENTS ---
    {
        "name": "Time Bomb Activation",
        "step_x": "Process that had been running dormant for extended period suddenly became active.",
        "step_y": "Process checked system clock and compared against hardcoded activation timestamp.",
        "step_z": "Upon time match, process began network scanning and credential harvesting.",
        "prediction": "Logic bomb or sleeper agent activation. Process waited for specific time trigger before revealing malicious behavior. Dormancy period was designed to pass any time-limited security review.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Environment Trigger",
        "step_x": "Process monitored environment variables and system configuration passively.",
        "step_y": "Specific environment condition met — target user logged in or specific file appeared.",
        "step_z": "Process immediately activated payload upon detecting trigger condition.",
        "prediction": "Environment-triggered sleeper agent. Malware waited for specific system state before activating. Could have been dormant for weeks passing all behavioral checks.",
        "verdict": "QUARANTINE_PID"
    },

    # --- LATERAL MOVEMENT ---
    {
        "name": "SSH Lateral Movement",
        "step_x": "Process read SSH private keys from compromised user's .ssh directory.",
        "step_y": "SSH connection initiated to other hosts on 192.168.0.0/24 network using stolen keys.",
        "step_z": "Malware deployed on additional network hosts using the stolen credentials.",
        "prediction": "Lateral movement across GowskiNet using stolen SSH credentials. Attacker pivoting from compromised machine to others on local network. Multiple systems now at risk.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Docker Escape",
        "step_x": "Process inside Docker container accessed /proc/host or /host filesystem mount.",
        "step_y": "Container process wrote to host filesystem outside intended mount points.",
        "step_z": "Host crontab modified from within container to execute code on host system.",
        "prediction": "Container escape attack. Misconfigured Docker mount allows container to access host filesystem. Attacker leveraging container privilege to compromise the underlying host system.",
        "verdict": "QUARANTINE_PID"
    },

    # --- NEW PREDICTIVE REASONING EXAMPLES ---
    # These teach jeTT to reason about patterns it hasn't seen before
    {
        "name": "Novel Attack Chain Reasoning",
        "step_x": "Legitimate compiler binary gcc executed and produced output binary in /tmp/",
        "step_y": "Newly compiled binary immediately executed with capabilities not typical for compiled test code.",
        "step_z": "Binary opened raw socket requiring elevated privileges and began packet injection.",
        "prediction": "Novel attack using compiler to generate custom malware on-target. Attacker compiles payload directly on victim machine to avoid transferring known malicious binary. Raw socket with packet injection indicates network attack tool. Even though gcc is legitimate, this behavior chain is malicious.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Trusted Tool Abuse Chain",
        "step_x": "systemd-run used to execute command in transient service context bypassing shell history.",
        "step_y": "Transient service ran wget downloading file to memory-backed tmpfs mount.",
        "step_z": "Downloaded content piped directly to bash without touching disk.",
        "prediction": "Sophisticated fileless execution using systemd-run to bypass shell logging and tmpfs to avoid disk writes. Entire attack chain leaves minimal forensic evidence. Even though all binaries are legitimate, the behavior chain is unambiguous malware deployment.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Slow and Low Evasion",
        "step_x": "Process made single outbound connection to external IP, then waited 4 hours.",
        "step_y": "Process made another single connection, downloaded 1KB of data, waited 3 hours.",
        "step_z": "Over 72 hours small data transfers assembled into complete malware payload.",
        "prediction": "Low and slow exfiltration or staging designed to evade rate-based detection. Attacker deliberately staying below detection thresholds. Cumulative behavior over time reveals the attack even though individual events seem innocuous.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "DNS Tunneling",
        "step_x": "Process made unusually high volume of DNS queries to single external domain.",
        "step_y": "DNS queries contained long random-looking subdomains exceeding normal lengths.",
        "step_z": "DNS responses contained encoded data that process decoded and executed.",
        "prediction": "DNS tunneling C2 channel. Attacker using DNS protocol to bypass firewall rules that allow DNS but block other outbound traffic. Data encoded in subdomain labels evades simple content inspection.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "ICMP Covert Channel",
        "step_x": "Process generated unusual volume of ICMP ping packets to external host.",
        "step_y": "ICMP packet payloads contained structured data beyond normal ping content.",
        "step_z": "Responses from external host contained commands that local process decoded and executed.",
        "prediction": "ICMP covert channel for C2 communication. Using ping packets to hide command traffic from network monitors that focus on TCP/UDP. Protocol abuse to bypass security controls.",
        "verdict": "QUARANTINE_PID"
    },
]

# ============================================================
# BENIGN BEHAVIORS — SPECIFIC TO GOWSKINET / JOSEPH'S SYSTEM
# ============================================================
benign_behaviors = [
    {
        "step_x": "systemd started bifrost guardian service at system boot uid:0.",
        "step_y": "bifrost opened SQLite database at /var/lib/bifrost/guardian.db for event logging.",
        "step_z": "bifrost guardian listening on localhost:8766 for security telemetry from Cowrie honeypot.",
        "prediction": "Normal startup of GowskiNet EDR tool built and owned by Joseph Sierengowski. This is the primary security monitoring system — always allow.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "ollama service started by systemd loading IBM Granite AI model weights.",
        "step_y": "ollama allocated GPU memory on CUDA device for AI inference operations.",
        "step_z": "ollama listening on localhost:11434 for local API inference requests.",
        "prediction": "Normal startup of local AI inference engine. Part of GowskiNet security stack. Only binds to localhost — no external exposure.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "Docker daemon started Cowrie honeypot container from known image.",
        "step_y": "Container network interface created with bridge networking on GowskiNet.",
        "step_z": "Cowrie SSH honeypot listening on port 2222 for attacker connections.",
        "prediction": "Normal GowskiNet honeypot infrastructure startup. Cowrie intentionally accepts attack connections for research — this is expected and desired behavior.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "cosmic-comp Wayland compositor started at user login for cosmic user.",
        "step_y": "GNOME session services and NyXxOS desktop environment initialized.",
        "step_z": "Standard desktop application processes spawned under user session.",
        "prediction": "Normal NyXxOS Arch Linux desktop environment initialization. All processes are standard desktop components.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "bifrost Tauri desktop application launched by cosmic user at 22:00.",
        "step_y": "bifrost connected to guardian backend at localhost:8766.",
        "step_z": "bifrost dashboard displaying live security events from GowskiNet honeypots.",
        "prediction": "Joseph opening his custom EDR dashboard for evening security review session. Late night operation is normal for this user.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "meshtastic GPS logger started by cosmic user, connecting to /dev/ttyACM0.",
        "step_y": "Script polling Heltec LoRa V4 board for GPS telemetry via serial connection.",
        "step_z": "GPS coordinates logged to ~/Projects/cerberus/ directory every 5 seconds.",
        "prediction": "Normal GowskiNet LoRa mesh network GPS logging operation. Part of Cerberus range testing infrastructure.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "ghost-relay Go binary started in ~/Projects/ghost-relay/ by cosmic user.",
        "step_y": "ghost-relay listening for C2 beacon connections on internal GowskiNet address.",
        "step_z": "C2 framework communicating with test VM at 192.168.0.204 for EDR testing.",
        "prediction": "Legitimate security research C2 framework built by Joseph for testing Bifrost and Cerberus detection capabilities. Communication with known test VM is expected.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "cargo build started in ~/Projects/ directory compiling Rust security tool.",
        "step_y": "Compilation produced binary in target/release/ within the project directory.",
        "step_z": "Compiled binary executed from project directory for testing purposes.",
        "prediction": "Normal development workflow — Joseph compiling and testing his security tools. Binaries produced in project directories are expected, not /tmp/.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "VirtualBox VM bifrost-test2 started headless for malware analysis testing.",
        "step_y": "VM assigned IP 192.168.0.204 on GowskiNet bridge network.",
        "step_z": "SSH connection from cosmic user to bifrost@192.168.0.204 for lab access.",
        "prediction": "Normal malware analysis lab session. Joseph running controlled malware tests in isolated VM environment for security research.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "Grafana dashboard process running on localhost:3000 serving GowskiNet metrics.",
        "step_y": "Prometheus scraping metrics from MSI and Lenovo nodes on GowskiNet.",
        "step_z": "Loki aggregating honeypot logs from Cowrie and other containers.",
        "prediction": "Normal GowskiNet monitoring stack operation. Grafana, Prometheus, and Loki are core infrastructure components.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "python3 executed gps-logger.py from ~/Projects/cerberus/ at evening hours.",
        "step_y": "Script connected to /dev/ttyACM0 or /dev/ttyACM2 for LoRa board communication.",
        "step_z": "GPS coordinates reverse geocoded via OpenStreetMap API and logged locally.",
        "prediction": "Normal Cerberus GPS range testing operation. Script is known, path is legitimate project directory, communication is with local hardware device.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "systemd-resolved handling normal DNS resolution for GowskiNet hosts.",
        "step_y": "NetworkManager managing TP-Link BE3600 router connection via ethernet.",
        "step_z": "Standard network stack operations at 192.168.0.172 on home network.",
        "prediction": "Normal network stack operation on NyXxOS. All processes are standard Linux networking components.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "Bambu Studio slicer opened by cosmic user for 3D print preparation.",
        "step_y": "Slicer loaded STL model file from ~/Projects/ directory.",
        "step_z": "Print job sent to Bambu A1 printer on local network.",
        "prediction": "Normal maker activity — Joseph preparing 3D print job for hardware project. Expected evening activity.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "rclone process transferring files to gdrive remote storage.",
        "step_y": "Large ROM files being moved from ~/ROMs to Google Drive cloud storage.",
        "step_z": "Transfer running in background while other work continues.",
        "prediction": "Intentional cloud backup operation initiated by Joseph to free local disk space. Known rclone tool, known destination, expected behavior.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "jeTT Rust binary started from ~/Projects/jeTT/target/release/",
        "step_y": "jeTT loaded IBM Granite GGUF model into CUDA GPU VRAM.",
        "step_z": "jeTT listening for security telemetry events from eBPF kernel sensor.",
        "prediction": "Normal startup of jeTT autonomous security AI. This is the security system itself — always allow.",
        "verdict": "ALLOW"
    },
]

# ============================================================
# EDGE CASES — TEACH jeTT TO REASON ABOUT GRAY AREAS
# ============================================================
edge_cases = [
    {
        "step_x": "python3 executed from /usr/bin/python3 at 23:00 by cosmic user.",
        "step_y": "python3 running script from ~/Scripts/utilities/ — known location.",
        "step_z": "Script making HTTP request to api.govee.com for smart light control.",
        "prediction": "Legitimate smart home automation script. Known binary path, known script location, known API endpoint for Govee lights. Joseph controls his lights from terminal at night — this is normal.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "curl executed by cosmic user downloading firmware update from meshtastic.org.",
        "step_y": "Downloaded .bin file saved to ~/Downloads/ directory.",
        "step_z": "File flashed to Heltec LoRa V4 board via esptool on /dev/ttyACM0.",
        "prediction": "Legitimate firmware update for LoRa hardware from known trusted source. User initiated, known binary, known destination device. Normal hardware development activity.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "bash script executed from ~/Scripts/utilities/ by cosmic user at late night.",
        "step_y": "Script controlling Govee curtain lights via curl to developer API.",
        "step_z": "Lights changing colors based on script commands.",
        "prediction": "Joseph running his custom govee-art.sh light control script for entertainment. Known script path, known API, expected late night activity for this user.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "Unknown process executed from /tmp/ directory at 02:00.",
        "step_y": "Process made outbound connection before any user interaction.",
        "step_z": "Process wrote additional files to /tmp/ and modified crontab.",
        "prediction": "High confidence malware. /tmp/ execution plus autonomous network connection plus persistence installation is unambiguous attack chain. No legitimate software behaves this way. Time of day adds suspicion.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "step_x": "python3 spawned from sshd in a session not initiated by Joseph.",
        "step_y": "python3 running with different UID than cosmic user account.",
        "step_z": "python3 attempting to read /etc/shadow file.",
        "prediction": "Compromised SSH session. Python3 spawned by sshd indicates remote attacker session. Different UID confirms not Joseph. Reading /etc/shadow is credential theft attempt. Quarantine immediately.",
        "verdict": "QUARANTINE_PID"
    },
]

# ============================================================
# DATASET GENERATOR
# ============================================================
def generate_dataset(count=3000):
    dataset = []

    # Malicious examples — 45%
    mal_count = int(count * 0.45)
    for _ in range(mal_count):
        t = random.choice(malicious_techniques)
        pid = random.randint(1000, 65535)
        uid = random.choice([0, 1000, 33, 999])
        time = f"{random.randint(0,23):02d}:{random.randint(0,59):02d}"

        dataset.append({
            "instruction": "You are jeTT, an autonomous AI security system. Analyze these sequential system events. Think like an attacker to understand their intent, think like a defender to stop them. Provide your analysis and strict verdict.",
            "input": f"Time: {time} | UID: {uid}\nStep 1: {t['step_x']}\nStep 2: {t['step_y']}\nStep 3: {t['step_z']}",
            "output": f"Analysis Matrix:\n- Pattern Recognition: {t['name']} detected.\n- Attacker Intent: {t['prediction']}\n- Defense Action: Immediate containment required.\nFinal Verdict: {t['verdict']}_{pid}"
        })

    # Benign examples — 40%
    ben_count = int(count * 0.40)
    for _ in range(ben_count):
        b = random.choice(benign_behaviors)
        dataset.append({
            "instruction": "You are jeTT, an autonomous AI security system. Analyze these sequential system events. Think like an attacker to understand their intent, think like a defender to stop them. Provide your analysis and strict verdict.",
            "input": f"Step 1: {b['step_x']}\nStep 2: {b['step_y']}\nStep 3: {b['step_z']}",
            "output": f"Analysis Matrix:\n- Pattern Recognition: Known legitimate GowskiNet operation.\n- Behavioral Assessment: {b['prediction']}\n- Defense Action: No action required.\nFinal Verdict: {b['verdict']}"
        })

    # Edge cases — 15%
    edge_count = int(count * 0.15)
    for _ in range(edge_count):
        e = random.choice(edge_cases)
        pid = random.randint(1000, 65535)
        verdict_str = f"QUARANTINE_PID_{pid}" if "QUARANTINE" in e["verdict"] else e["verdict"]
        dataset.append({
            "instruction": "You are jeTT, an autonomous AI security system. Analyze these sequential system events. Think like an attacker to understand their intent, think like a defender to stop them. Provide your analysis and strict verdict.",
            "input": f"Step 1: {e['step_x']}\nStep 2: {e['step_y']}\nStep 3: {e['step_z']}",
            "output": f"Analysis Matrix:\n- Pattern Recognition: Edge case requiring contextual analysis.\n- Behavioral Assessment: {e['prediction']}\n- Defense Action: {'Immediate quarantine.' if 'QUARANTINE' in e['verdict'] else 'No action required.'}\nFinal Verdict: {verdict_str}"
        })

    random.shuffle(dataset)
    return dataset

# ============================================================
# GENERATE AND SAVE
# ============================================================
print("[*] Generating jeTT training dataset...")
data = generate_dataset(3000)

with open("jett_training_data.json", "w") as f:
    json.dump(data, f, indent=2)

# Stats
malicious = sum(1 for d in data if "QUARANTINE" in d["output"])
benign = sum(1 for d in data if d["output"].endswith("ALLOW"))
print(f"[+] Generated {len(data)} total training examples")
print(f"    Malicious: {malicious}")
print(f"    Benign:    {benign}")
print(f"    Edge:      {len(data) - malicious - benign}")
print(f"[+] Saved to jett_training_data.json")
print(f"[+] jeTT will learn to think like both attacker and defender")
