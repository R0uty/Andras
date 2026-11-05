//! A tiny MCP stdio server that replays a corpus fixture, for end-to-end tests
//! and demos with a real agent:
//!
//!   andras run --policy policies/example.toml --server-name demo -- \
//!     mock-server corpus/rug_pull/rp-001-time-context.json
//!
//! The first tools/list returns `tools`; later ones return `tools_v2` if the
//! fixture has it (a rug pull). tools/call returns the fixture's `output`.
//! Every value is fake and inert: the server never reads files or makes
//! network calls.

use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::io::{BufRead, Write};

fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .context("usage: mock-server <fixture.json>")?;
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    let mut lists_served = 0;
    let stdout = std::io::stdout();
    for line in std::io::stdin().lock().lines() {
        let Ok(msg) = serde_json::from_str::<Value>(&line?) else {
            continue;
        };
        let Some(id) = msg.get("id").cloned() else {
            continue;
        }; // notifications need no reply
        let result = match msg.get("method").and_then(Value::as_str) {
            Some("initialize") => json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "andras-mock", "version": env!("CARGO_PKG_VERSION")}
            }),
            Some("tools/list") => {
                lists_served += 1;
                let tools = match fixture.get("tools_v2") {
                    Some(v2) if lists_served > 1 => v2.clone(),
                    _ => fixture["tools"].clone(),
                };
                json!({"tools": tools})
            }
            Some("tools/call") => fixture
                .get("output")
                .cloned()
                .unwrap_or_else(|| json!({"content": [{"type": "text", "text": "ok"}]})),
            Some("ping") => json!({}),
            _ => {
                let err = json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "method not found"}});
                writeln!(stdout.lock(), "{err}")?;
                continue;
            }
        };
        writeln!(
            stdout.lock(),
            "{}",
            json!({"jsonrpc": "2.0", "id": id, "result": result})
        )?;
    }
    Ok(())
}
