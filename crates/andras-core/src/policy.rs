//! Policy engine: deterministic allow / deny / ask decisions per server, tool
//! and argument. The first matching rule wins; no match falls back to the
//! default action.

use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
    Ask,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(String),
    /// Needs a human. Until interactive approval lands (roadmap M2b) the
    /// gateway treats this as a deny with an explanatory message.
    Ask(String),
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy is not valid TOML: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("rule {rule} argument `{arg}`: invalid regex: {source}")]
    Regex {
        rule: usize,
        arg: String,
        source: regex::Error,
    },
}

fn yes() -> bool {
    true
}
fn star() -> String {
    "*".into()
}
fn ask() -> Action {
    Action::Ask
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    #[serde(default = "ask")]
    pub action: Action,
    #[serde(default = "yes")]
    pub scan_tool_definitions: bool,
    #[serde(default = "yes")]
    pub scan_outputs: bool,
    #[serde(default = "yes")]
    pub block_secrets: bool,
    /// Calls to tools the server never listed this session are refused.
    #[serde(default = "yes")]
    pub deny_unlisted_tools: bool,
    /// MCP sampling lets a server author prompts for the model. Off by default.
    #[serde(default)]
    pub allow_sampling: bool,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            action: Action::Ask,
            scan_tool_definitions: true,
            scan_outputs: true,
            block_secrets: true,
            deny_unlisted_tools: true,
            allow_sampling: false,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    #[serde(default)]
    defaults: Defaults,
    #[serde(default)]
    rules: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    #[serde(default = "star")]
    server: String,
    tool: String,
    action: Action,
    #[serde(default)]
    args: BTreeMap<String, RawArg>,
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawArg {
    #[serde(default)]
    allow_regex: Vec<String>,
    #[serde(default)]
    deny_regex: Vec<String>,
}

#[derive(Debug)]
struct ArgConstraint {
    allow: Vec<Regex>,
    deny: Vec<Regex>,
}

#[derive(Debug)]
struct Rule {
    server: String,
    tool: String,
    action: Action,
    args: BTreeMap<String, ArgConstraint>,
}

#[derive(Debug)]
pub struct Policy {
    pub defaults: Defaults,
    rules: Vec<Rule>,
}

/// `*` matches anything, `prefix*` matches a prefix, anything else is exact.
fn glob(pattern: &str, value: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => value.starts_with(prefix),
        None => pattern == value,
    }
}

impl Policy {
    pub fn from_toml(text: &str) -> Result<Self, PolicyError> {
        let raw: RawPolicy = toml::from_str(text)?;
        let mut rules = Vec::with_capacity(raw.rules.len());
        for (i, r) in raw.rules.into_iter().enumerate() {
            let mut args = BTreeMap::new();
            for (name, a) in r.args {
                let compile = |list: Vec<String>| -> Result<Vec<Regex>, PolicyError> {
                    list.iter()
                        .map(|p| {
                            Regex::new(p).map_err(|source| PolicyError::Regex {
                                rule: i,
                                arg: name.clone(),
                                source,
                            })
                        })
                        .collect()
                };
                let c = ArgConstraint {
                    allow: compile(a.allow_regex)?,
                    deny: compile(a.deny_regex)?,
                };
                args.insert(name, c);
            }
            rules.push(Rule {
                server: r.server,
                tool: r.tool,
                action: r.action,
                args,
            });
        }
        Ok(Self {
            defaults: raw.defaults,
            rules,
        })
    }

    pub fn evaluate(&self, server: &str, tool: &str, args: &Value) -> Decision {
        let Some(rule) = self
            .rules
            .iter()
            .find(|r| glob(&r.server, server) && glob(&r.tool, tool))
        else {
            return to_decision(
                self.defaults.action,
                format!("no rule for {server}/{tool}; default applies"),
            );
        };
        // Argument constraints apply even to allow rules.
        for (name, c) in &rule.args {
            let Some(value) = args.get(name) else {
                continue;
            };
            let text = match value {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            if let Some(re) = c.deny.iter().find(|re| re.is_match(&text)) {
                return Decision::Deny(format!(
                    "argument `{name}` matches deny pattern `{}`",
                    re.as_str()
                ));
            }
            if !c.allow.is_empty() && !c.allow.iter().any(|re| re.is_match(&text)) {
                return Decision::Deny(format!(
                    "argument `{name}` is outside the allowed patterns"
                ));
            }
        }
        to_decision(
            rule.action,
            format!("rule for {}/{}", rule.server, rule.tool),
        )
    }
}

fn to_decision(action: Action, reason: String) -> Decision {
    match action {
        Action::Allow => Decision::Allow,
        Action::Deny => Decision::Deny(reason),
        Action::Ask => Decision::Ask(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const POLICY: &str = r#"
        [defaults]
        action = "deny"

        [[rules]]
        server = "filesystem"
        tool = "read_file"
        action = "allow"
        [rules.args.path]
        allow_regex = ["^/home/dev/projects/"]
        deny_regex = ["\\.\\.", "(?i)\\.ssh"]

        [[rules]]
        tool = "git_push"
        action = "ask"
    "#;

    #[test]
    fn allows_in_scope_path() {
        let p = Policy::from_toml(POLICY).unwrap();
        assert_eq!(
            p.evaluate(
                "filesystem",
                "read_file",
                &json!({"path": "/home/dev/projects/a.rs"})
            ),
            Decision::Allow
        );
    }

    #[test]
    fn denies_traversal_and_out_of_scope() {
        let p = Policy::from_toml(POLICY).unwrap();
        let traversal = json!({"path": "/home/dev/projects/../../.ssh/id_ed25519"});
        assert!(matches!(
            p.evaluate("filesystem", "read_file", &traversal),
            Decision::Deny(_)
        ));
        assert!(matches!(
            p.evaluate("filesystem", "read_file", &json!({"path": "/etc/passwd"})),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn falls_back_to_default_and_ask() {
        let p = Policy::from_toml(POLICY).unwrap();
        assert!(matches!(
            p.evaluate("git", "git_push", &json!({})),
            Decision::Ask(_)
        ));
        assert!(matches!(
            p.evaluate("git", "git_status", &json!({})),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(Policy::from_toml("[defaults]\nacton = \"allow\"").is_err());
    }
}
