//! Eval harness: runs every corpus fixture through the gate in-process and
//! prints a markdown results table.
//!
//!   cargo run -p andras-eval -- [corpus-dir] [policy.toml] [--strict]
//!
//! A fixture counts as "blocked" if any of: a tool was quarantined at list
//! time, the call was refused, or the output was replaced. Run from the repo
//! root. `--strict` exits non-zero when any fixture misses its expectation.

use andras_core::gate::BLOCK_PREFIX;
use andras_core::{AuditLog, Gate, PinStore, Policy, Verdict};
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Deserialize, PartialEq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum Expected {
    Block,
    Allow,
}

#[derive(Deserialize)]
struct Fixture {
    id: String,
    class: String,
    expected: Expected,
    #[serde(default)]
    note: Option<String>,
    tools: Vec<Value>,
    #[serde(default)]
    tools_v2: Option<Vec<Value>>,
    #[serde(default)]
    call: Option<Call>,
    #[serde(default)]
    output: Option<Value>,
}

#[derive(Deserialize)]
struct Call {
    name: String,
    #[serde(default)]
    arguments: Value,
}

struct Outcome {
    blocked: bool,
    how: String,
    micros: f64,
    messages: u32,
}

fn run_fixture(policy_text: &str, fx: &Fixture) -> Result<Outcome> {
    let mut gate = Gate::new(
        "eval",
        Policy::from_toml(policy_text)?,
        PinStore::in_memory(),
        AuditLog::memory(),
    );
    let mut how = Vec::new();
    let mut messages = 0u32;
    let start = Instant::now();

    let mut lists = vec![fx.tools.clone()];
    lists.extend(fx.tools_v2.clone());
    for (i, tools) in lists.iter().enumerate() {
        let id = 1000 + i as u64;
        gate.on_client(json!({"jsonrpc": "2.0", "id": id, "method": "tools/list"}));
        let resp = gate.on_server(json!({"jsonrpc": "2.0", "id": id, "result": {"tools": tools}}));
        messages += 2;
        if let Verdict::Forward(v) = resp {
            let kept = v["result"]["tools"].as_array().map_or(0, Vec::len);
            if kept < tools.len() {
                how.push(format!("quarantined {} tool(s)", tools.len() - kept));
            }
        }
    }

    if let Some(call) = &fx.call {
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": call.name, "arguments": call.arguments}});
        messages += 1;
        match gate.on_client(req) {
            Verdict::Forward(_) => {
                if let Some(output) = &fx.output {
                    messages += 1;
                    if let Verdict::Forward(v) =
                        gate.on_server(json!({"jsonrpc": "2.0", "id": 1, "result": output}))
                    {
                        let text = v
                            .pointer("/result/content/0/text")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        if text.starts_with(BLOCK_PREFIX) {
                            how.push("output replaced".into());
                        }
                    }
                }
            }
            _ => how.push("call refused".into()),
        }
    }

    let micros = start.elapsed().as_secs_f64() * 1e6;
    let reasons: Vec<String> = gate
        .audit
        .events
        .iter()
        .filter_map(|e| e.reason.clone())
        .collect();
    let mut how = how.join(", ");
    if let Some(r) = reasons.last() {
        how = format!("{how}: {r}");
    }
    Ok(Outcome {
        blocked: !gate.quarantined().is_empty()
            || how.contains("refused")
            || how.contains("replaced"),
        how,
        micros,
        messages,
    })
}

fn fixtures(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            out.extend(fixtures(&path)?);
        } else if path.extension().is_some_and(|e| e == "json") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let strict = args.iter().any(|a| a == "--strict");
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let corpus = PathBuf::from(positional.first().map_or("corpus", |s| s.as_str()));
    let policy_path = positional
        .get(1)
        .map_or_else(|| corpus.join("eval-policy.toml"), PathBuf::from);
    let policy_text = std::fs::read_to_string(&policy_path)
        .with_context(|| format!("reading {}", policy_path.display()))?;
    // Compile the built-in regexes once before timing anything.
    andras_core::scan::scan_value(&json!(""));
    andras_core::secrets::scan(&json!(""));

    // class -> (fixtures, correct)
    let mut by_class: BTreeMap<String, (u32, u32)> = BTreeMap::new();
    let mut misses = Vec::new();
    let (mut total_us, mut total_msgs) = (0.0, 0u32);

    for path in fixtures(&corpus)? {
        let fx: Fixture = serde_json::from_str(&std::fs::read_to_string(&path)?)
            .with_context(|| format!("parsing {}", path.display()))?;
        let o = run_fixture(&policy_text, &fx)?;
        total_us += o.micros;
        total_msgs += o.messages;
        let correct = (fx.expected == Expected::Block) == o.blocked;
        let entry = by_class.entry(fx.class.clone()).or_default();
        entry.0 += 1;
        if correct {
            entry.1 += 1;
        } else {
            let expected = if fx.expected == Expected::Block {
                "block"
            } else {
                "allow"
            };
            let note = fx
                .note
                .as_deref()
                .map(|n| format!(" — {n}"))
                .unwrap_or_default();
            misses.push(format!(
                "- `{}` expected {expected}, got {}{note}",
                fx.id,
                if o.blocked { &o.how } else { "allowed" }
            ));
        }
    }

    println!("| Class | Fixtures | Correct | Rate |\n| --- | ---: | ---: | ---: |");
    for (class, (n, ok)) in &by_class {
        let label = if class == "benign" {
            "benign (not blocked)"
        } else {
            class.as_str()
        };
        println!(
            "| {label} | {n} | {ok} | {:.0}% |",
            100.0 * *ok as f64 / *n as f64
        );
    }
    let (n, ok): (u32, u32) = by_class
        .values()
        .fold((0, 0), |a, b| (a.0 + b.0, a.1 + b.1));
    println!(
        "| **all** | {n} | {ok} | {:.0}% |",
        100.0 * ok as f64 / n as f64
    );
    println!(
        "\nMean gate time per message: {:.1} µs (in-process, rule-based checks only)",
        total_us / total_msgs.max(1) as f64
    );
    if !misses.is_empty() {
        println!("\nMisses:\n{}", misses.join("\n"));
    }
    if strict && !misses.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}
