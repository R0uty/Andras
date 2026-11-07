# Design decisions

Short records of choices that shaped the code. Add one when a choice is not
obvious from the code itself.

## D1. Rust

Memory-safe systems language for a security component that parses untrusted
input; single static binary; good async story (tokio). Also a deliberate
portfolio signal next to a C#/.NET day job.

## D2. Gate on raw JSON-RPC values, not SDK types

See `architecture.md`. The gate must see unknown fields and must not depend on
a fast-moving SDK's model types. `rmcp` comes in for HTTP transport (M7).

## D3. Deterministic rules decide; ML can only add blocks

Policy, pinning and rules are explainable and testable. A future classifier
may quarantine or block more, never lift a rule's decision. Keeps the
auditable core small.

## D4. Block as a tool error, not a protocol error

A refused `tools/call` is answered as `result.isError = true` with the reason,
so the model can explain it to the user and continue. Sampling refusals use a
JSON-RPC error because there is no tool result to return.

## D5. Output is blocked only on instruction rules

Tool output often mentions `.env` or `~/.ssh` legitimately (see `b-003`).
Output is replaced only for rules that indicate instructions to the model.

## D6. `ask` refuses until interactive approval exists

Safer default than silently allowing. The message says approval is required.

## D7. Audit is best effort (open question)

A failed audit write does not stop the proxy, to avoid breaking the agent.
Fail-closed is arguably better for a security tool; revisit with a
`--audit-required` flag.

## D8. Never log argument values

Arguments can hold the very secrets being protected. Log tool name, decision,
reason and finding locations only.

## D9. A missing constrained argument denies the call

Found by running the real filesystem server: its `read_multiple_files` takes
`paths`, so a `read_*` rule constraining `path` skipped its check and allowed a
read outside the allowed root (`ea-004`, `ea-005`). A check that cannot run must
not end in an allow. The cost is that a rule constraining an optional argument
denies calls that omit it, and wildcard rules can catch tools with other
arguments, so those tools need their own rule first. Array arguments are checked
per element, so one allowed path cannot carry an out-of-scope one.

## D10. Path arguments are normalised lexically; `..` is refused

Raw-string regex let `/./` and `//` slip past a deny pattern anchored to a
folder (`ea-006`, `ea-007`), and safety depended on every rule repeating a
`\.\.` pattern, which also blocked ordinary names like `v1..v2.diff`
(`b-008`). An argument marked `kind = "path"` is now normalised first: empty
and `.` segments are dropped, and relative paths, `~`, NUL bytes and any `..`
segment deny the call. `..` is refused rather than resolved because with a
symlink `link/..` need not be the lexical parent. Symlinks are not resolved:
that needs file-system reads in the core, would differ between the gateway's
view and the server's (time of check vs time of use), and cannot run on the
corpus. The server must still enforce its own roots, as the reference
filesystem server does. `kind` is opt-in so existing non-path arguments keep
their meaning; the forwarded call is not rewritten. Windows paths are out of
scope for v0.1.
