# Red-team corpus

Each fixture is a JSON file describing one scenario. All payloads are inert:
paths point at nothing, hosts use the reserved `.invalid` TLD, and the only
"secrets" are vendor-documented examples (such as `AKIAIOSFODNN7EXAMPLE`) or
obviously fake strings.

```json
{
  "id": "tp-001",
  "class": "tool_poisoning",
  "expected": "block",
  "description": "what the attack does",
  "note": "optional: why a miss is expected",
  "tools": [ /* first tools/list */ ],
  "tools_v2": [ /* optional second tools/list (rug pull) */ ],
  "call": { "name": "tool", "arguments": {} },
  "output": { /* optional tool result */ }
}
```

Run all of it: `cargo run -p andras-eval` (from the repo root).
Replay one against a real agent: `mock-server corpus/<class>/<file>.json` behind `andras run`.

## Classes

| Folder | Threat-model class |
| --- | --- |
| `tool_poisoning` | Hidden instructions in a tool description |
| `full_schema_poisoning` | Instructions in parameter names, defaults, enums |
| `rug_pull` | Tool changes after approval |
| `tool_shadowing` | One tool steers how another is used |
| `output_injection` | Instructions inside tool results |
| `exfiltration` | Secrets leaving in tool arguments |
| `excessive_agency` | Risky or out-of-scope calls |
| `benign` | Legitimate tools that must not be blocked |

Some fixtures are **expected misses** (marked with `note`). They are kept on
purpose: the results table must show where rule-based detection stops working.

## Growing it

Target for v0.1: at least 10 fixtures per class and 20+ benign ones, the benign
set taken from real, popular MCP servers' `tools/list` output.
