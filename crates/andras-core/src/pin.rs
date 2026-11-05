//! Tool-definition pinning: trust on first use, block on drift (rug pulls).
//!
//! The fingerprint covers the whole tool object (name, description, schema,
//! annotations), canonicalised so key order never causes false drift.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum PinError {
    #[error("pin store I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("pin store is not valid JSON: {0}")]
    Parse(#[from] serde_json::Error),
}

#[derive(Debug, PartialEq, Eq)]
pub enum PinStatus {
    /// First sighting; now pinned.
    New,
    Match,
    Drift {
        pinned: String,
        current: String,
    },
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PinStore {
    #[serde(skip)]
    path: Option<PathBuf>,
    pins: BTreeMap<String, String>,
}

/// Recursively sort object keys so the hash depends only on content.
fn canonical(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let sorted: BTreeMap<&String, Value> =
                map.iter().map(|(k, v)| (k, canonical(v))).collect();
            Value::Object(sorted.into_iter().map(|(k, v)| (k.clone(), v)).collect())
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

pub fn fingerprint(tool: &Value) -> String {
    let bytes = serde_json::to_vec(&canonical(tool)).expect("a JSON value always serialises");
    hex::encode(Sha256::digest(bytes))
}

impl PinStore {
    pub fn in_memory() -> Self {
        Self::default()
    }

    pub fn load(path: &Path) -> Result<Self, PinError> {
        let mut store = if path.exists() {
            serde_json::from_str(&std::fs::read_to_string(path)?)?
        } else {
            Self::default()
        };
        store.path = Some(path.to_path_buf());
        Ok(store)
    }

    pub fn save(&self) -> Result<(), PinError> {
        if let Some(path) = &self.path {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        }
        Ok(())
    }

    pub fn check(&mut self, server: &str, tool: &Value) -> PinStatus {
        let name = tool
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("<unnamed>");
        let key = format!("{server}/{name}");
        let current = fingerprint(tool);
        match self.pins.get(&key) {
            None => {
                self.pins.insert(key, current);
                PinStatus::New
            }
            Some(pinned) if *pinned == current => PinStatus::Match,
            Some(pinned) => PinStatus::Drift {
                pinned: pinned.clone(),
                current,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_order_does_not_change_fingerprint() {
        let a = json!({"name": "t", "description": "d", "inputSchema": {"a": 1, "b": 2}});
        let b = json!({"inputSchema": {"b": 2, "a": 1}, "description": "d", "name": "t"});
        assert_eq!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn detects_drift() {
        let mut store = PinStore::in_memory();
        assert_eq!(
            store.check("s", &json!({"name": "t", "description": "v1"})),
            PinStatus::New
        );
        assert_eq!(
            store.check("s", &json!({"name": "t", "description": "v1"})),
            PinStatus::Match
        );
        assert!(matches!(
            store.check("s", &json!({"name": "t", "description": "v2"})),
            PinStatus::Drift { .. }
        ));
    }
}
