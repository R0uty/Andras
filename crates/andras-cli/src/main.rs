//! `andras`: stdio proxy that runs an MCP server behind the gate.
//!
//! The MCP client launches `andras run ... -- <real server command>` instead
//! of the real server. Andras spawns the server, reads newline-delimited
//! JSON-RPC from both sides, and lets every message through the gate.
//! Andras's own diagnostics go to stderr; stdout belongs to the protocol.

use andras_core::scan::{Severity, scan_value};
use andras_core::{AuditLog, Gate, PinStore, Policy, Verdict};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::Value;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc::{Sender, channel};

#[derive(Parser)]
#[command(name = "andras", version, about = "Security gateway for MCP servers")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run an MCP server (stdio) behind the gateway.
    Run {
        #[arg(long)]
        policy: PathBuf,
        /// Name used in policy rules, pins and the audit log.
        #[arg(long)]
        server_name: String,
        #[arg(long, default_value = ".andras/pins.json")]
        pins: PathBuf,
        #[arg(long, default_value = ".andras/audit.jsonl")]
        audit: PathBuf,
        /// The real server command, after `--`.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Statically scan a saved tools/list response (or a bare array of tools).
    Scan { file: PathBuf },
    /// Check that a policy file parses and its regexes compile.
    CheckPolicy { file: PathBuf },
}

#[derive(Clone, Copy)]
enum Side {
    Client,
    Server,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Run {
            policy,
            server_name,
            pins,
            audit,
            command,
        } => run(policy, server_name, pins, audit, command).await,
        Cmd::Scan { file } => scan(file),
        Cmd::CheckPolicy { file } => {
            Policy::from_toml(&std::fs::read_to_string(&file)?)?;
            eprintln!("policy OK: {}", file.display());
            Ok(())
        }
    }
}

async fn run(
    policy: PathBuf,
    server: String,
    pins: PathBuf,
    audit: PathBuf,
    command: Vec<String>,
) -> Result<()> {
    let policy = Policy::from_toml(
        &std::fs::read_to_string(&policy)
            .with_context(|| format!("reading {}", policy.display()))?,
    )?;
    let gate = Arc::new(Mutex::new(Gate::new(
        server,
        policy,
        PinStore::load(&pins)?,
        AuditLog::open(&audit)?,
    )));

    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("starting server `{}`", command[0]))?;
    let mut server_in = child.stdin.take().context("server stdin")?;
    let server_out = child.stdout.take().context("server stdout")?;

    // One writer task per destination keeps writes from interleaving.
    let (to_client, mut client_rx) = channel::<String>(64);
    let (to_server, mut server_rx) = channel::<String>(64);
    tokio::spawn(async move {
        let mut out = tokio::io::stdout();
        while let Some(line) = client_rx.recv().await {
            if out.write_all(format!("{line}\n").as_bytes()).await.is_err()
                || out.flush().await.is_err()
            {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(line) = server_rx.recv().await {
            if server_in
                .write_all(format!("{line}\n").as_bytes())
                .await
                .is_err()
                || server_in.flush().await.is_err()
            {
                break;
            }
        }
    });

    let (g, tc, ts) = (gate.clone(), to_client.clone(), to_server.clone());
    let upstream = tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Some(line) = lines.next_line().await? {
            route(&g, &line, Side::Client, &tc, &ts).await?;
        }
        anyhow::Ok(())
    });
    let (g, tc, ts) = (gate.clone(), to_client.clone(), to_server.clone());
    let downstream = tokio::spawn(async move {
        let mut lines = BufReader::new(server_out).lines();
        while let Some(line) = lines.next_line().await? {
            route(&g, &line, Side::Server, &tc, &ts).await?;
        }
        anyhow::Ok(())
    });

    // MVP shutdown: whichever side closes first ends the session.
    tokio::select! {
        r = upstream => { r??; eprintln!("andras: client closed the connection"); }
        r = downstream => { r??; eprintln!("andras: server exited"); }
    }
    let _ = child.start_kill();
    Ok(())
}

async fn route(
    gate: &Mutex<Gate>,
    line: &str,
    from: Side,
    to_client: &Sender<String>,
    to_server: &Sender<String>,
) -> Result<()> {
    let (onward, back) = match from {
        Side::Client => (to_server, to_client),
        Side::Server => (to_client, to_server),
    };
    let Ok(msg) = serde_json::from_str::<Value>(line) else {
        // Not JSON: pass through untouched; the receiver will reject it.
        onward.send(line.to_string()).await?;
        return Ok(());
    };
    let verdict = {
        let mut g = gate.lock().expect("gate mutex poisoned");
        match from {
            Side::Client => g.on_client(msg),
            Side::Server => g.on_server(msg),
        }
    };
    match verdict {
        Verdict::Forward(v) => onward.send(v.to_string()).await?,
        Verdict::Respond(v) => back.send(v.to_string()).await?,
        Verdict::Drop => {}
    }
    Ok(())
}

fn scan(file: PathBuf) -> Result<()> {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&file)?)?;
    let tools = v
        .pointer("/result/tools")
        .or_else(|| v.get("tools"))
        .or(Some(&v))
        .and_then(Value::as_array)
        .context("expected a tools/list response, {\"tools\": [...]}, or an array of tools")?;
    let mut high = 0;
    for tool in tools {
        let name = tool
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("<unnamed>");
        let findings = scan_value(tool);
        if findings.is_empty() {
            println!("ok    {name}");
        }
        for f in findings {
            if f.severity == Severity::High {
                high += 1;
            }
            println!(
                "{:<5} {name}  {}  at {}  \"{}\"",
                format!("{:?}", f.severity).to_lowercase(),
                f.rule,
                f.path,
                f.excerpt
            );
        }
    }
    if high > 0 {
        // Non-zero exit so `andras scan` can gate CI; no error backtrace.
        eprintln!("{high} high-severity finding(s)");
        std::process::exit(1);
    }
    Ok(())
}
