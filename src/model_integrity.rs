//! GGUF integrity verification at startup — optional pin file or env.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const DEFAULT_PIN: &str = "/etc/jett/model.sha256";

fn home_pin_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(format!("{}/.config/jett/model.sha256", home))
}

/// Streaming SHA-256 of a file (safe for multi-GB GGUF).
pub fn sha256_file(path: &Path) -> Result<String, String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|e| format!("open {}: {}", path.display(), e))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1024 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("read {}: {}", path.display(), e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect())
}

fn parse_expected_hash(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let token = line
            .strip_prefix("sha256:")
            .unwrap_or(line)
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(token);
        }
    }
    None
}

fn expected_hash_from_pin_file(path: &Path) -> Option<String> {
    parse_expected_hash(&std::fs::read_to_string(path).ok()?)
}

fn configured_expected_hash() -> Option<String> {
    if std::env::var("JETT_MODEL_VERIFY").ok().as_deref() == Some("0") {
        return None;
    }
    if let Ok(hash) = std::env::var("JETT_MODEL_SHA256") {
        let h = hash.trim().to_ascii_lowercase();
        if h.len() == 64 {
            return Some(h);
        }
    }
    if let Ok(pin) = std::env::var("JETT_MODEL_PIN") {
        if !pin.is_empty() {
            return expected_hash_from_pin_file(Path::new(&pin));
        }
    }
    if let Some(h) = expected_hash_from_pin_file(Path::new(DEFAULT_PIN)) {
        return Some(h);
    }
    expected_hash_from_pin_file(&home_pin_path())
}

/// Verify model file against configured pin. No-op when no pin is configured.
pub fn verify_model_integrity(model_path: &str) -> Result<Option<String>, String> {
    let path = Path::new(model_path);
    if !path.is_file() {
        return Err(format!("model not found: {}", model_path));
    }

    let Some(expected) = configured_expected_hash() else {
        return Ok(None);
    };

    eprintln!("[jett] verifying model SHA-256...");
    let actual = sha256_file(path)?;
    if actual != expected {
        return Err(format!(
            "model SHA-256 mismatch\n  expected: {}\n  actual:   {}\n  file:     {}",
            expected, actual, model_path
        ));
    }
    eprintln!("[jett] model SHA-256 OK ({})", &actual[..16]);
    Ok(Some(actual))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pin_file_hash() {
        let text = "# production r6\nsha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
        let h = parse_expected_hash(text).unwrap();
        assert_eq!(h.len(), 64);
        assert!(h.starts_with("01234567"));
    }

    #[test]
    fn sha256_empty_file() {
        let dir = std::env::temp_dir().join("jett_model_integrity_test");
        std::fs::write(&dir, b"test").unwrap();
        let h = sha256_file(&dir).unwrap();
        assert_eq!(h.len(), 64);
        let _ = std::fs::remove_file(dir);
    }
}
