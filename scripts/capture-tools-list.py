#!/usr/bin/env python3
"""Start an MCP stdio server, run initialize + tools/list, save the result.

    scripts/capture-tools-list.py NAME OUT_DIR WORK_DIR CMD...
    e.g. scripts/capture-tools-list.py memory /tmp/out /tmp/empty npx -y @modelcontextprotocol/server-memory

This runs the server's code. Use an empty WORK_DIR. The tokens below are
placeholders so servers that check for one at startup will list their tools.
"""
import json, subprocess, sys, select, time, os
name, out_dir, cwd, *cmd = sys.argv[1:]
env = dict(os.environ, GITHUB_PERSONAL_ACCESS_TOKEN="fake-not-a-token", BRAVE_API_KEY="fake",
           SLACK_BOT_TOKEN="fake", SLACK_TEAM_ID="T0000000", GOOGLE_MAPS_API_KEY="fake",
           GITLAB_PERSONAL_ACCESS_TOKEN="fake", SENTRY_AUTH_TOKEN="fake", npm_config_yes="true")
p = subprocess.Popen(cmd, cwd=cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
def send(m): p.stdin.write(json.dumps(m) + "\n"); p.stdin.flush()
def recv(want, deadline):
    while time.time() < deadline:
        r, _, _ = select.select([p.stdout], [], [], 1)
        if r:
            line = p.stdout.readline()
            if not line: return None
            try: m = json.loads(line)
            except ValueError: continue
            if m.get("id") == want: return m
        elif p.poll() is not None: return None
    return None
try:
    send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "andras-capture", "version": "0"}}})
    init = recv(1, time.time() + 150)
    if not init: raise SystemExit(f"{name}: no initialize response; stderr: {p.stderr.read()[-300:] if p.poll() is not None else ''}")
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    lst = recv(2, time.time() + 30)
    if not lst or "result" not in lst: raise SystemExit(f"{name}: no tools/list result: {lst}")
    info = init["result"].get("serverInfo", {})
    json.dump({"server": info, "tools": lst["result"]["tools"]}, open(f"{out_dir}/{name}.json", "w"), indent=2)
    print(f"{name}: {info.get('name')} {info.get('version')}, {len(lst['result']['tools'])} tools")
finally:
    p.kill()
