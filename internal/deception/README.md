# internal/deception — Optional Deception Layer

> **Status: OPTIONAL / EXPERIMENTAL** — Not part of the core jeTT runtime.

This directory contains scripts and data for setting up a deception/honeypot
overlay that can lure automated attackers into a controlled observation zone.

## Scripts

| Script | Purpose |
|--------|---------|
| `deploy_maze.sh` | Creates a volatile tmpfs honeypot directory tree. Must be run as root. Set `MAZE_REPO_ROOT` to override the default repo-relative path. |
| `spawn_mirror.sh` | Spawns additional mirror nodes inside the maze. |

## shadow_layer/

Runtime directory populated by `deploy_maze.sh`.  All content inside is
mounted on tmpfs and is discarded on unmount/reboot.  **Do not commit
runtime-generated files here** (symlinks, runtime output, etc.).

## Opt-in usage

These scripts are entirely optional.  To enable:

```bash
sudo MAZE_REPO_ROOT=/path/to/jeTT ./internal/deception/deploy_maze.sh
```

To tear down:

```bash
sudo umount /path/to/jeTT/internal/deception/shadow_layer
```
