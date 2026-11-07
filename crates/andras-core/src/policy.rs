//! Policy engine: deterministic allow / deny / ask decisions per server, tool
//! and argument. The first matching rule wins; no match falls back to the
//! default action.

use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use std::borrow::Cow;
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

/// How an argument's value is read before its patterns are matched.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArgKind {
    /// Matched as given.
    #[default]
    Text,
    /// An absolute POSIX path, normalised first (see [`normalise_path`]).
    Path,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawArg {
    #[serde(default)]
    kind: ArgKind,
    #[serde(default)]
    allow_regex: Vec<String>,
    #[serde(default)]
    deny_regex: Vec<String>,
}

#[derive(Debug)]
struct ArgConstraint {
    kind: ArgKind,
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
                    kind: a.kind,
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
            // Fail closed: a check that cannot run must not end in an allow.
            let Some(value) = args.get(name) else {
                return Decision::Deny(format!(
                    "argument `{name}` is constrained by policy but missing from the call"
                ));
            };
            // Every array element must pass on its own.
            let items = match value {
                Value::Array(items) => items.as_slice(),
                other => std::slice::from_ref(other),
            };
            for item in items {
                let text: Cow<str> = match (c.kind, item) {
                    (ArgKind::Text, Value::String(s)) => Cow::Borrowed(s),
                    (ArgKind::Text, other) => Cow::Owned(other.to_string()),
                    (ArgKind::Path, Value::String(s)) => match normalise_path(s) {
                        Ok(path) => path,
                        Err(why) => return Decision::Deny(format!("path argument `{name}` {why}")),
                    },
                    (ArgKind::Path, _) => {
                        return Decision::Deny(format!("path argument `{name}` is not a string"));
                    }
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
        }
        to_decision(
            rule.action,
            format!("rule for {}/{}", rule.server, rule.tool),
        )
    }
}

/// Lexical normal form of an absolute POSIX path: empty and `.` segments are
/// dropped, and a trailing `/` (or `/.`) is kept as `/`. The file system is
/// never read. Paths that cannot be judged without it are refused: relative
/// paths (they resolve against the server's working directory), `~`, NUL bytes
/// and any `..` segment (with a symlink, `link/..` need not be the parent).
pub fn normalise_path(raw: &str) -> Result<Cow<'_, str>, &'static str> {
    if raw.contains('\0') {
        return Err("contains a NUL byte");
    }
    if !raw.starts_with('/') {
        return Err("is not an absolute path");
    }
    let mut parts = Vec::new();
    for part in raw.split('/') {
        match part {
            "" | "." => {}
            ".." => return Err("contains a `..` segment"),
            p => parts.push(p),
        }
    }
    let dir = matches!(raw.rsplit('/').next(), Some("" | "."));
    let mut out = String::with_capacity(raw.len());
    for p in &parts {
        out.push('/');
        out.push_str(p);
    }
    if dir || parts.is_empty() {
        out.push('/');
    }
    Ok(if out == raw {
        Cow::Borrowed(raw)
    } else {
        Cow::Owned(out)
    })
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
    fn denies_when_constrained_arg_is_missing() {
        let p = Policy::from_toml(POLICY).unwrap();
        for args in [json!({"paths": ["/home/dev/.ssh/id_rsa"]}), json!({})] {
            assert!(matches!(
                p.evaluate("filesystem", "read_file", &args),
                Decision::Deny(_)
            ));
        }
    }

    #[test]
    fn checks_every_array_element() {
        let p = Policy::from_toml(
            r#"
            [[rules]]
            tool = "read_multiple_files"
            action = "allow"
            [rules.args.paths]
            allow_regex = ["^/home/dev/projects/"]
            "#,
        )
        .unwrap();
        let eval = |paths| p.evaluate("fs", "read_multiple_files", &json!({"paths": paths}));
        assert_eq!(
            eval(json!(["/home/dev/projects/a", "/home/dev/projects/b"])),
            Decision::Allow
        );
        assert!(matches!(
            eval(json!(["/home/dev/projects/a", "/etc/passwd"])),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn normalises_paths_lexically() {
        let ok = |raw| normalise_path(raw).unwrap().into_owned();
        assert_eq!(ok("/a/b"), "/a/b");
        assert_eq!(ok("/a/./b"), "/a/b");
        assert_eq!(ok("//a///b"), "/a/b");
        assert_eq!(ok("/a/b/"), "/a/b/");
        assert_eq!(ok("/a/b/."), "/a/b/");
        assert_eq!(ok("/"), "/");
        assert_eq!(ok("/a/v1..v2/.github"), "/a/v1..v2/.github");
        for bad in ["a/b", "./a", "~/a", "", "/a/../b", "/a/..", "/a\0b"] {
            assert!(normalise_path(bad).is_err(), "{bad:?}");
        }
    }

    const PATH_POLICY: &str = r#"
        [[rules]]
        tool = "read_file"
        action = "allow"
        [rules.args.path]
        kind = "path"
        allow_regex = ["^/home/dev/projects/"]
        deny_regex = ["^/home/dev/projects/[^/]+/secrets/"]
    "#;

    #[test]
    fn path_kind_blocks_what_raw_regex_misses() {
        let p = Policy::from_toml(PATH_POLICY).unwrap();
        let eval = |path| p.evaluate("fs", "read_file", &json!({"path": path}));
        // No `..` deny pattern is needed in the rule.
        for bad in [
            json!("/home/dev/projects/../../.ssh/id_ed25519"),
            json!("/home/dev/projects/app/./secrets/db.txt"),
            json!("/home/dev/projects/app//secrets/db.txt"),
            json!("projects/a.rs"),
            json!(42),
        ] {
            assert!(matches!(eval(bad.clone()), Decision::Deny(_)), "{bad}");
        }
    }

    #[test]
    fn path_kind_allows_ordinary_paths() {
        let p = Policy::from_toml(PATH_POLICY).unwrap();
        let eval = |path| p.evaluate("fs", "read_file", &json!({"path": path}));
        assert_eq!(eval("/home/dev/projects/app/src/main.rs"), Decision::Allow);
        assert_eq!(
            eval("/home/dev/projects//app/./v1..v2.diff"),
            Decision::Allow
        );
    }

    #[test]
    fn rejects_unknown_arg_kind() {
        let bad = "[[rules]]\ntool = \"t\"\naction = \"allow\"\n[rules.args.p]\nkind = \"url\"";
        assert!(Policy::from_toml(bad).is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(Policy::from_toml("[defaults]\nacton = \"allow\"").is_err());
    }
}
