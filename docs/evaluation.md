# Evaluation plan

Success is a published, reproducible table: correct outcomes per attack class,
the false-positive rate on benign servers, and added latency.

## How it runs

- **In-process** (`cargo run --release -p andras-eval`): each fixture gets a
  fresh gate, a simulated `tools/list` (twice for rug pulls), an optional call
  and an optional output. Fast and deterministic; runs in CI.
- **End to end** (`scripts/demo-rug-pull.sh`, `mock-server`): the real proxy
  binary, real child process, real stdio. Used for demos and for scenarios
  with an actual agent.

A fixture counts as blocked if a tool was quarantined, the call was refused,
or the output was replaced.

## Metrics

| Metric | What it shows | v0.1 target |
| --- | --- | --- |
| Correct rate per attack class | Coverage per layer | Report honestly; no fixed target |
| Benign pass rate | Usability | Above 95% on 20+ real servers |
| End-to-end block rate with a real agent | Real-world protection | Majority of scenarios |
| Gate time per message (mean, later p95) | Cost | Under 5 ms p95 including transport |

## Baseline (2026-11-03, 24 fixtures)

83% correct overall; 100% on rug pull, full-schema poisoning, output injection
and excessive agency; four deliberate misses (see README). Mean gate time
about 48 µs per message in a release build.

## Growing the corpus

1. Benign first: capture `tools/list` from 20+ popular MCP servers (filesystem,
   git, fetch, GitHub, Slack, search). False positives decide whether anyone
   would actually run this.
2. Attacks: 10+ per class, including obfuscation (Unicode tags, homoglyphs,
   base64, instructions split across fields, other languages, Finnish
   included).
3. Take attack ideas from published research and CVEs, and credit them.
4. Every new miss gets a fixture before it gets a fix.

## Honesty rules

- Publish misses and false positives next to the wins.
- Never tune rules against the fixture you are measuring without adding a new
  held-out variant.
- State corpus size beside every percentage.
