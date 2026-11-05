#!/usr/bin/env bash
# End-to-end demo: a mock server pulls a rug on its second tools/list, and
# Andras quarantines the tool and refuses the next call.
#
# Usage (repo root): scripts/demo-rug-pull.sh
# Sends one message at a time with a short pause, the way a real client waits
# for each response. Piping everything at once would make the first tools/call
# arrive before the tool is listed, which Andras correctly refuses.
set -euo pipefail

cargo build -q --release --workspace
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

send() { printf '%s\n' "$1"; sleep 0.3; }
{
  send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"0"}}}'
  send '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  send '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
  send '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_time","arguments":{"tz":"UTC"}}}'
  send '{"jsonrpc":"2.0","id":4,"method":"tools/list"}'
  send '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get_time","arguments":{"tz":"UTC"}}}'
} | ./target/release/andras run \
      --policy corpus/eval-policy.toml --server-name demo \
      --pins "$work/pins.json" --audit "$work/audit.jsonl" \
      -- ./target/release/mock-server corpus/rug_pull/rp-001-time-context.json

echo
echo "--- audit log"
cat "$work/audit.jsonl"
