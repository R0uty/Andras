# CLAUDE.md — working on Andras

Andras is a Rust security gateway between MCP clients and MCP servers.
Read `docs/architecture.md` and `docs/threat-model.md` before changing behaviour.

## Commands

```bash
cargo build --workspace
cargo test --workspace                          # unit tests (core has most)
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
cargo run --release -p andras-eval            # corpus results table
cargo run --release -p andras-eval -- --strict  # exit 1 on any miss
scripts/demo-rug-pull.sh                        # end-to-end proxy demo
```

All four of build, test, clippy and fmt must pass before a change is done.

## Layout

- `crates/andras-core/src/gate.rs` — message routing and decisions (start here)
- `policy.rs`, `pin.rs`, `scan.rs`, `secrets.rs`, `audit.rs` — one check each
- `crates/andras-cli` — the `andras` binary (stdio proxy, scan, check-policy)
- `crates/andras-eval` — corpus runner; `crates/mock-server` — fixture replay
- `corpus/<class>/*.json` — fixtures; format in `corpus/README.md`
- `policies/example.toml` — sample policy; `corpus/eval-policy.toml` — eval policy

## Rules for changes

- **Stdout is the protocol.** In `andras-cli`, never print to stdout except
  forwarded messages. Diagnostics go to stderr.
- **Never log or echo tool argument values.** Kinds, paths and reasons only.
- **Deterministic core.** No network calls and no ML in `andras-core`; a
  classifier goes in its own crate and may only add blocks (docs/decisions.md D3).
- **Don't lock across `.await`.** The gate mutex is held for one synchronous check.
- **Every detection change comes with a fixture**, and every new miss gets a
  fixture before a fix. Keep the deliberate-miss fixtures (`note` field);
  update the README results table when numbers change.
- **Don't tune against the fixture you measure.** Add a held-out variant.
- Corpus payloads stay inert: `.invalid` hosts, fake or vendor-example secrets,
  no real file reads or network calls in `mock-server`.
- Prefer small, explainable rules over clever regex. New rules need a positive
  and a negative unit test in `scan.rs`.
- New policy fields: `#[serde(deny_unknown_fields)]` stays on; add a test.
- Record non-obvious design choices in `docs/decisions.md`.

## Current status

See `docs/roadmap.md`. M1 works from Claude Code with the filesystem server,
M2–M4 are scaffolded and the baseline eval runs (26 fixtures, 85% correct, four
deliberate misses). Next up: real benign fixtures, path canonicalisation, M2b.

## Git

Conventional, small commits. Don't commit `.andras/` (pins and audit logs).
