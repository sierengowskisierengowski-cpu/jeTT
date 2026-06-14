//! Built-in red-team mode orchestration (paths + preflight checks).

use std::path::{Path, PathBuf};

/// Scripts invoked by unified red-team mode.
#[derive(Debug, Clone)]
pub struct RedTeamScripts {
    pub art_smoke: PathBuf,
    pub adversarial_eval: PathBuf,
    pub enforce_smoke: PathBuf,
}

impl RedTeamScripts {
    /// Resolve script paths relative to repo root.
    pub fn from_repo_root(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref();
        Self {
            art_smoke: root.join("scripts/art_jett_smoke.sh"),
            adversarial_eval: root.join("scripts/run_adversarial_eval.sh"),
            enforce_smoke: root.join("scripts/enforce_smoke.sh"),
        }
    }

    pub fn all_exist(&self) -> bool {
        self.art_smoke.exists() && self.adversarial_eval.exists() && self.enforce_smoke.exists()
    }

    /// Ordered phases for `jett redteam`.
    pub fn phases(&self) -> [(&str, &Path); 3] {
        [
            ("art_smoke", &self.art_smoke),
            ("adversarial_eval_preflight", &self.adversarial_eval),
            ("enforce_smoke", &self.enforce_smoke),
        ]
    }
}

/// Arguments for enforce smoke preflight.
pub fn enforce_smoke_args() -> &'static [&'static str] {
    &["--enforce-check"]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripts_resolve_from_repo() {
        // Walk up from src/ to repo root in tests via CARGO_MANIFEST_DIR
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let scripts = RedTeamScripts::from_repo_root(&root);
        assert!(scripts.art_smoke.ends_with("scripts/art_jett_smoke.sh"));
        assert!(scripts.all_exist());
    }

    #[test]
    fn enforce_preflight_args() {
        assert_eq!(enforce_smoke_args(), &["--enforce-check"]);
    }
}
