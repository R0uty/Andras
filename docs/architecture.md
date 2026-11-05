# Architecture

```
 MCP client (agent)
      |  stdin / stdout, newline-delimited JSON-RPC
      v
 +--------------------------- andras run ---------------------------+
 |  upstream task  ──> Gate::on_client ──> Forward | Respond | Drop    |
 |  downstream task ─> Gate::on_server ──> Forward | Respond | Drop    |
 |                                                                     |
 |  Gate = PinStore + Policy + scan + secrets + AuditLog (JSONL)       |
 +---------------------------------------------------------------------+
      |  spawns the real server as a child process
      v
 MCP server
```

## Crates

| Crate | Kind | Role |
| --- | --- | --- |
| `andras-core` | lib | All checks. Synchronous, no I/O except pin and audit files. |
| `andras-cli` (`andras`) | bin | Stdio proxy (`run`), static `scan`, `check-policy`. tokio. |
| `andras-eval` | bin | Runs the corpus through the gate in-process; prints a results table. |
| `mock-server` | bin | Replays a corpus fixture as an MCP server, for end-to-end demos. |

## Message flow

**Client to server**

- `tools/list`: request id remembered, forwarded.
- `tools/call`: refused if the tool is quarantined, unlisted, carries a
  secret, or the policy says deny / ask. A refusal is answered by Andras as a
  tool result with `isError: true`, so the model sees why and can continue.
- Anything else: forwarded.

**Server to client**

- Response to a remembered `tools/list`: each tool is pinned and scanned.
  Drifted tools and tools with high-severity findings are removed from the list
  and quarantined for the session.
- Response to an allowed `tools/call`: output scanned for instruction rules;
  on a hit the result is replaced with a block message.
- `sampling/createMessage`: answered with a JSON-RPC error unless allowed.
- Batches (arrays): dropped and logged.

## Why raw JSON-RPC, not SDK types

The gate works on `serde_json::Value`, not on `rmcp` model types:

- It must see exactly what the model sees, including unknown fields where
  full-schema poisoning hides.
- It must not break or silently drop data when the spec adds fields.
- It stays transport-agnostic, so the same gate serves stdio, HTTP and the eval.

`rmcp` (the official Rust SDK) is planned for the Streamable HTTP transport,
where session handling is worth reusing. See `docs/decisions.md`.

## Concurrency

One `Mutex<Gate>`, locked only for the synchronous check of one message, never
across an `.await`. One writer task per destination stops interleaved writes.
Checks take tens of microseconds, so the lock is not a bottleneck for a single
agent session.

## Files

- Pins: `.andras/pins.json`, key `server/tool` to SHA-256 of the canonical
  definition (keys sorted recursively).
- Audit: `.andras/audit.jsonl`, one event per decision. Tool arguments are
  never logged.
