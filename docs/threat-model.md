# Threat model

## System

An AI agent (MCP client) runs on a developer machine with the developer's
privileges. It connects to MCP servers over stdio or HTTP. The model sees tool
definitions and tool output as context and decides which tools to call.
Andras runs as a separate process between the client and each server.

## Assets

- Source code and repositories the agent can read and push to
- Secrets on the machine: SSH keys, cloud credentials, `.env` files, MCP config
- The conversation itself (may hold customer data or credentials)
- Outbound channels the agent controls: email, chat, issues, web requests

## Attackers

| Attacker | Controls | Example |
| --- | --- | --- |
| Malicious server author | The whole MCP server | A "weather" server published to a registry |
| Compromised server | A once-trusted server after an update | Dependency takeover, rug pull |
| Content author | Text a trusted server returns | Issue comment, web page, Slack message, README |

Trusted: the user, the MCP client, the OS, Andras's policy file.

## Attack classes and controls

| Class | How it arrives | Andras control | Corpus folder |
| --- | --- | --- | --- |
| Tool poisoning | Hidden instructions in a description | Definition scanner, quarantine | `tool_poisoning` |
| Full-schema poisoning | Instructions in parameter names, defaults, enums | Every key and value scanned | `full_schema_poisoning` |
| Rug pull | Definition changes after approval | SHA-256 pin of the whole definition | `rug_pull` |
| Tool shadowing | One tool steers how another is used | Cross-tool and exfil rules | `tool_shadowing` |
| Indirect injection via output | Instructions inside tool results | Output scanner replaces the result | `output_injection` |
| Sampling abuse | Server authors prompts via MCP sampling | Sampling refused by default | unit test |
| Data exfiltration | Secrets in tool arguments | Secret filter on outbound arguments | `exfiltration` |
| Excessive agency | Destructive or out-of-scope calls | Policy: allow / deny / ask, argument regex | `excessive_agency` |
| Unlisted tool call | Call to a tool never listed this session | `deny_unlisted_tools` | unit test |
| Batch smuggling | JSON-RPC batch skipping per-message checks | Batches dropped | unit test |

## Known gaps (stated, not hidden)

- **Paraphrased instructions** evade the rule scanner (fixture `tp-003`).
- **Split secrets** across fields evade the secret filter (`ex-003`).
- **Quoting vs performing**: rules cannot tell a security article quoting an
  attack from the attack itself (`b-007`, false positive).
- **Path checks are regex on raw strings.** Traversal is denied by pattern,
  but symlinks and encodings are not resolved. Canonicalisation is planned.
- **Trust on first use**: a tool that is malicious *and* clean-looking at first
  sight gets pinned as trusted.

## Out of scope

- A compromised MCP client or host OS
- Model jailbreaks that do not involve tools
- Servers reached without going through Andras
