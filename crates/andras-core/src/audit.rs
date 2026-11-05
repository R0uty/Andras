//! Append-only JSONL audit log: one line per security-relevant decision.
//! Tool arguments are never written, only tool names, decisions and findings.

use crate::scan::Finding;
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub ts_ms: u128,
    pub server: String,
    /// e.g. `tools/list`, `tools/call`, `tool-output`, `sampling`, `batch`
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// `allow`, `block`, `quarantine`, `pinned`, `warn`
    pub decision: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<Finding>,
}

impl Event {
    pub fn new(server: &str, kind: &'static str, decision: &'static str) -> Self {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        Self {
            ts_ms,
            server: server.to_string(),
            kind,
            tool: None,
            decision,
            reason: None,
            findings: Vec::new(),
        }
    }
    pub fn tool(mut self, tool: &str) -> Self {
        self.tool = Some(tool.to_string());
        self
    }
    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
    pub fn findings(mut self, findings: Vec<Finding>) -> Self {
        self.findings = findings;
        self
    }
}

#[derive(Debug, Default)]
pub struct AuditLog {
    file: Option<File>,
    /// Kept in memory as well, so tests and the eval harness can inspect it.
    pub events: Vec<Event>,
    keep_in_memory: bool,
}

impl AuditLog {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Some(file),
            events: Vec::new(),
            keep_in_memory: false,
        })
    }

    /// No file; events are kept in memory only.
    pub fn memory() -> Self {
        Self {
            file: None,
            events: Vec::new(),
            keep_in_memory: true,
        }
    }

    pub fn record(&mut self, event: Event) {
        if let Some(f) = &mut self.file
            && let Ok(line) = serde_json::to_string(&event)
        {
            // Best effort: a failed audit write must not take the proxy down.
            let _ = writeln!(f, "{line}");
        }
        if self.keep_in_memory {
            self.events.push(event);
        }
    }
}
