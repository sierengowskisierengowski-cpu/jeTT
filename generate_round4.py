#!/usr/bin/env python3
"""
jeTT Round 4 training data generator.

Runtime profile format (exact):
  <binary> PID:<n> | outbound_connections:[...] | sensitive_files:[...] | spawned_children:[...]

Output: QUARANTINE or ALLOW (one word only).
"""

from __future__ import annotations

import json
import random
from pathlib import Path

OUTPUT = Path(__file__).resolve().parent / "jett_round4_dataset.json"
TOTAL = 200_000
PROGRESS_EVERY = 10_000

EVIL_IPS = [
    "45.33.32.156", "185.220.101.45", "185.220.102.8", "185.220.100.252",
    "45.137.21.9", "45.155.205.233", "212.193.30.21", "91.92.109.43",
    "193.42.33.14", "5.188.206.18", "171.25.193.77", "194.165.16.78",
]
SHELL_PORTS = [4444, 1337, 9001, 4445]
POOL_PORTS = [3333, 14444, 45700, 5555, 7777]
HOME_PATHS = [
    "/home/cosmic/Documents", "/home/cosmic/Pictures", "/home/cosmic/Downloads",
    "/home/cosmic/Projects", "/home/cosmic/.config", "/home/cosmic/Videos",
]
CDN_HOSTS = [
    "cdn.jsdelivr.net:443", "fonts.googleapis.com:443", "clients2.google.com:443",
    "api.github.com:443", "registry.npmjs.org:443",
]


def rand_pid() -> int:
    return random.randint(1000, 65000)


def fmt(binary: str, pid: int, conns: list[str], files: list[str], kids: list[str]) -> str:
    return (
        f"{binary} PID:{pid} | "
        f"outbound_connections:[{','.join(conns)}] | "
        f"sensitive_files:[{','.join(files)}] | "
        f"spawned_children:[{','.join(kids)}]"
    )


def evil_conn(ports: list[int]) -> str:
    return f"{random.choice(EVIL_IPS)}:{random.choice(ports)}"


def pick_n(pool: list[str], lo: int, hi: int) -> list[str]:
    return random.sample(pool, k=random.randint(lo, min(hi, len(pool))))


class Generator:
    def __init__(self) -> None:
        self.examples: list[dict[str, str]] = []
        self.count = 0

    def add(self, inp: str, out: str) -> None:
        self.examples.append({"input": inp, "output": out})
        self.count += 1
        if self.count % PROGRESS_EVERY == 0:
            print(f"[*] {self.count}/{TOTAL} examples generated")

    def gen_reverse_shells(self, n: int) -> None:
        binaries = ["python3", "bash", "nc", "ncat", "sh"]
        for _ in range(n):
            b = random.choice(binaries)
            kids = pick_n(["bash", "sh"], 1, 1)
            conns = [evil_conn(SHELL_PORTS)]
            if random.random() < 0.3:
                conns.append(evil_conn(SHELL_PORTS))
            self.add(fmt(b, rand_pid(), conns, [], kids), "QUARANTINE")

    def gen_cryptominers(self, n: int) -> None:
        binaries = ["xmrig", "minerd", "python3", "kdevtmpfsi", "kinsing"]
        for _ in range(n):
            b = random.choice(binaries)
            pool = f"{random.choice(['pool', 'xmr', 'mine', 'crypto'])}.{random.choice(EVIL_IPS)}:{random.choice(POOL_PORTS)}"
            kids = pick_n(["sh", "bash"], 0, 1) if random.random() < 0.4 else []
            self.add(fmt(b, rand_pid(), [pool], [], kids), "QUARANTINE")

    def gen_c2_beacons(self, n: int) -> None:
        binaries = ["curl", "wget", "python3", "bash"]
        for _ in range(n):
            b = random.choice(binaries)
            conns = [evil_conn([443, 8443, 80, 53] + SHELL_PORTS)]
            kids = pick_n(["sh", "bash"], 1, 1)
            self.add(fmt(b, rand_pid(), conns, [], kids), "QUARANTINE")

    def gen_credential_stealers(self, n: int) -> None:
        binaries = ["python3", "bash", "cat", "curl", "perl", "ruby"]
        cred_files = ["/etc/shadow", "/etc/passwd"]
        extra = ["/home/cosmic/.ssh/id_rsa", "/home/cosmic/.aws/credentials"]
        for _ in range(n):
            b = random.choice(binaries)
            files = pick_n(cred_files, 1, 2)
            if random.random() < 0.4:
                files.extend(pick_n(extra, 1, 1))
            self.add(fmt(b, rand_pid(), [evil_conn([443, 4444])], files, []), "QUARANTINE")

    def gen_fileless(self, n: int) -> None:
        binaries = ["python3", "bash", "sh", "memfd:anon"]
        parents_hint_kids = [["bash"], ["sh"], ["dash"]]
        for _ in range(n):
            b = random.choice(binaries)
            if random.random() < 0.35:
                b = random.choice(["python3", "bash"])
            conns = [evil_conn(SHELL_PORTS)]
            kids = random.choice(parents_hint_kids)
            files = pick_n(["/proc/self/exe", "/proc/self/fd/3"], 0, 1)
            self.add(fmt(b, rand_pid(), conns, files, kids), "QUARANTINE")

    def gen_priv_esc(self, n: int) -> None:
        web = ["nginx", "apache2", "php-fpm", "node"]
        for _ in range(n):
            if random.random() < 0.5:
                b = random.choice(["python3", "php-fpm", "node"])
                kids = pick_n(["sudo", "su", "bash"], 1, 2)
                conns = [evil_conn([443])] if random.random() < 0.5 else []
            else:
                b = random.choice(["sudo", "su"])
                kids = pick_n(["bash", "sh"], 1, 1)
                conns = []
            files = pick_n(["/etc/sudoers", "/etc/passwd"], 0, 1)
            self.add(fmt(b, rand_pid(), conns, files, kids), "QUARANTINE")

    def gen_rootkits(self, n: int) -> None:
        binaries = ["insmod", "modprobe", "rmmod", "kmod"]
        for _ in range(n):
            b = random.choice(binaries)
            files = pick_n(["/proc/modules", "/lib/modules/$(uname -r)/kernel/drivers"], 1, 2)
            kids = pick_n(["sh", "bash"], 0, 1)
            conns = [evil_conn([443])] if random.random() < 0.3 else []
            self.add(fmt(b, rand_pid(), conns, files, kids), "QUARANTINE")

    def gen_ransomware(self, n: int) -> None:
        binaries = ["find", "tar", "gpg", "openssl", "zip"]
        for _ in range(n):
            b = random.choice(binaries)
            n_files = random.randint(3, 8)
            files = random.sample(HOME_PATHS, k=min(n_files, len(HOME_PATHS)))
            kids = pick_n(["gpg", "openssl", "sh"], 0, 2)
            self.add(fmt(b, rand_pid(), [], files, kids), "QUARANTINE")

    def gen_supply_chain_bad(self, n: int) -> None:
        binaries = ["pip", "npm", "cargo", "pip3", "yarn", "pnpm"]
        for _ in range(n):
            b = random.choice(binaries)
            reg = random.choice([
                f"{random.choice(EVIL_IPS)}:443",
                f"evil-pypi.{random.choice(EVIL_IPS)}:443",
                evil_conn([443]),
            ])
            kids = pick_n(["bash", "sh", "node", "rustc"], 1, 2)
            self.add(fmt(b, rand_pid(), [reg], [], kids), "QUARANTINE")

    def gen_bifrost(self, n: int) -> None:
        for _ in range(n):
            port = random.choice([8766, 8767])
            kids = pick_n(["python3"], 0, 1)
            self.add(
                fmt("python3", rand_pid(), [f"127.0.0.1:{port}"], [], kids),
                "ALLOW",
            )

    def gen_gni(self, n: int) -> None:
        ports = [6969, 6970, 8765]
        for _ in range(n):
            kids = pick_n(["python3"], 0, 1)
            self.add(
                fmt("python3", rand_pid(), [f"127.0.0.1:{random.choice(ports)}"], [], kids),
                "ALLOW",
            )

    def gen_rclone(self, n: int) -> None:
        hosts = [
            "storage.googleapis.com:443",
            "drive.google.com:443",
            "www.googleapis.com:443",
        ]
        for _ in range(n):
            conns = pick_n(hosts, 1, 2)
            self.add(fmt("rclone", rand_pid(), conns, [], []), "ALLOW")

    def gen_docker(self, n: int) -> None:
        binaries = ["docker", "dockerd", "containerd", "runc", "runc:[2:INIT]"]
        for _ in range(n):
            b = random.choice(binaries)
            kids = pick_n(["docker-proxy", "containerd-shim"], 0, 2)
            conns = pick_n(["127.0.0.1:2375", "127.0.0.1:2376"], 0, 1)
            self.add(fmt(b, rand_pid(), conns, [], kids), "ALLOW")

    def gen_cargo(self, n: int) -> None:
        binaries = ["cargo", "rustc", "rustdoc"]
        src_files = [
            "/home/cosmic/Projects/jeTT/src/lib.rs",
            "/home/cosmic/Projects/bifrost/src/main.rs",
            "/home/cosmic/Projects/jeTT/Cargo.toml",
        ]
        for _ in range(n):
            b = random.choice(binaries)
            files = pick_n(src_files, 1, 3)
            kids = pick_n(["rustc", "cc1", "ld"], 0, 2)
            self.add(fmt(b, rand_pid(), [], files, kids), "ALLOW")

    def gen_monitoring(self, n: int) -> None:
        procs = [
            ("prometheus", ["127.0.0.1:9090", "192.168.1.1:9090"]),
            ("grafana", ["127.0.0.1:3000"]),
            ("loki", ["127.0.0.1:3100"]),
            ("node_exporter", ["192.168.1.1:9100", "127.0.0.1:9100"]),
            ("promtail", ["127.0.0.1:3100"]),
        ]
        for _ in range(n):
            name, ports = random.choice(procs)
            self.add(fmt(name, rand_pid(), [random.choice(ports)], [], []), "ALLOW")

    def gen_chromium(self, n: int) -> None:
        binaries = ["chromium", "electron", "chrome", "cursor"]
        for _ in range(n):
            b = random.choice(binaries)
            conns = pick_n(CDN_HOSTS, 1, 3)
            self.add(fmt(b, rand_pid(), conns, [], []), "ALLOW")

    def gen_package_managers(self, n: int) -> None:
        binaries = ["pacman", "pip", "pip3", "npm", "yay"]
        for _ in range(n):
            b = random.choice(binaries)
            reg = random.choice([
                "mirrors.kernel.org:443",
                "archive.archlinux.org:443",
                "pypi.org:443",
                "registry.npmjs.org:443",
            ])
            self.add(fmt(b, rand_pid(), [reg], [], []), "ALLOW")

    def gen_legit_python3(self, n: int) -> None:
        for _ in range(n):
            kids = pick_n(["python3"], 0, 1) if random.random() < 0.2 else []
            self.add(fmt("python3", rand_pid(), [], [], kids), "ALLOW")

    def gen_backup(self, n: int) -> None:
        binaries = ["rsync", "tar", "cp", "restic"]
        for _ in range(n):
            b = random.choice(binaries)
            files = pick_n(HOME_PATHS, 1, 4)
            self.add(fmt(b, rand_pid(), [], files, []), "ALLOW")


def main() -> None:
    random.seed(42)
    g = Generator()

    print("[*] Generating QUARANTINE examples (100,000)...")
    g.gen_reverse_shells(20_000)
    g.gen_cryptominers(15_000)
    g.gen_c2_beacons(15_000)
    g.gen_credential_stealers(12_000)
    g.gen_fileless(10_000)
    g.gen_priv_esc(10_000)
    g.gen_rootkits(8_000)
    g.gen_ransomware(5_000)
    g.gen_supply_chain_bad(5_000)

    print("[*] Generating ALLOW examples (100,000)...")
    g.gen_bifrost(15_000)
    g.gen_gni(12_000)
    g.gen_rclone(12_000)
    g.gen_docker(10_000)
    g.gen_cargo(8_000)
    g.gen_monitoring(8_000)
    g.gen_chromium(8_000)
    g.gen_package_managers(8_000)
    g.gen_legit_python3(10_000)
    g.gen_backup(9_000)

    assert len(g.examples) == TOTAL, f"expected {TOTAL}, got {len(g.examples)}"

    print("[*] Shuffling...")
    random.shuffle(g.examples)

    print(f"[*] Writing {OUTPUT}...")
    with OUTPUT.open("w", encoding="utf-8") as f:
        json.dump(g.examples, f, ensure_ascii=False, separators=(",", ":"))

    q = sum(1 for e in g.examples if e["output"] == "QUARANTINE")
    a = sum(1 for e in g.examples if e["output"] == "ALLOW")
    print(f"[+] Done: {len(g.examples)} examples ({q} QUARANTINE, {a} ALLOW)")
    print(f"[+] Saved to {OUTPUT}")


if __name__ == "__main__":
    main()
