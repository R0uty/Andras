# Roadmap

Estimates assume evenings and weekends. Each milestone ends in something
public. Done = merged, tested, and reflected in the README.

| # | Milestone | Est. | Deliverable | Status |
| --- | --- | --- | --- | --- |
| M1 | Transparent stdio proxy | 2 wk | Works unchanged in front of a real server | Scripted run works; real client not yet tried |
| M2 | Pinning + policy | 2 wk | Rug-pull demo blocked | Scaffolded, demo works |
| M2b | Interactive approval for `ask` | 1 wk | Prompt on a TTY or desktop notification; approve once / always | Not started |
| M3 | Scanners + secret filter | 2–3 wk | First numbers on the corpus | Baseline done |
| M4 | Corpus + eval harness | 2 wk | 10+ per class, 20+ real benign servers, CI table | Harness done, corpus 26 |
| M5 | Packaging | 1–2 wk | README GIF, blog post, crates.io v0.1 | Not started |
| M6 | Local classifier | 3 wk | Small ONNX model or local LLM judge, off the hot path, can only add blocks | Not started |
| M7 | Streamable HTTP transport | 2 wk | Proxy remote servers via `rmcp` | Not started |
| M8 | Ops | 2 wk | `andras pins approve`, OpenTelemetry export, signed policies | Not started |

## Next five tasks

1. Run `andras run` in front of the reference filesystem server from Claude
   Code and record what breaks.
2. Capture real `tools/list` output from 10 popular servers into `corpus/benign`.
3. Path canonicalisation for path arguments (resolve `..`, reject symlinks
   outside the allowed root) before the regex check.
4. M2b: approval prompt on `/dev/tty`, decision cached per session.
5. Survey existing MCP gateways and scanners; write a one-paragraph
   comparison for the README.

## Out of scope for v0.1

Dashboard, multi-tenant deployment, Windows-specific packaging.
