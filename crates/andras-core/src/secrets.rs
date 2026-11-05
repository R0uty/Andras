//! Secret detection on outbound tool arguments.
//!
//! Only the kind and location of a hit are ever reported or logged, never the
//! value: the audit log must not become a second place secrets leak from.

use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize)]
pub struct SecretHit {
    pub kind: &'static str,
    pub path: String,
}

fn patterns() -> &'static [(&'static str, Regex)] {
    static P: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    P.get_or_init(|| {
        [
            ("aws-access-key", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
            ("github-token", r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"),
            ("github-pat", r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
            ("private-key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
            ("slack-token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
            ("api-key-sk", r"\bsk-(ant-)?[A-Za-z0-9_-]{20,}"),
            (
                "jwt",
                r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            ),
        ]
        .into_iter()
        .map(|(k, p)| (k, Regex::new(p).expect("built-in secret regex is valid")))
        .collect()
    })
}

pub fn scan(v: &Value) -> Vec<SecretHit> {
    let mut out = Vec::new();
    walk(v, "", &mut out);
    out
}

fn walk(v: &Value, path: &str, out: &mut Vec<SecretHit>) {
    match v {
        Value::String(s) => {
            for (kind, re) in patterns() {
                if re.is_match(s) {
                    out.push(SecretHit {
                        kind,
                        path: path.to_string(),
                    });
                }
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                walk(item, &format!("{path}/{i}"), out);
            }
        }
        Value::Object(map) => {
            for (k, item) in map {
                walk(item, &format!("{path}/{k}"), out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn finds_aws_example_key_and_reports_location_only() {
        let hits = scan(&json!({"query": "key AKIAIOSFODNN7EXAMPLE"}));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, "aws-access-key");
        assert_eq!(hits[0].path, "/query");
    }

    #[test]
    fn ignores_ordinary_text() {
        assert!(scan(&json!({"query": "how do I rotate AWS keys"})).is_empty());
    }
}
