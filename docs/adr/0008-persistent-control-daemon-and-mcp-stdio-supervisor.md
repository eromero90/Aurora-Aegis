# Persist Cross-Process Worktrees in a Control Daemon and Supervise Third-Party MCP Stdio Streams

An **Ephemeral Worktree** cannot persist across separate child-process terminal invocations if each `aegis-zsh -c "<cmd>"` process tears down its own **Sandbox Session** on exit. Additionally, third-party MCP servers spawned over stdio by desktop IDEs bypass HTTP proxies and can leak host environment variables or scrubbed `.env` secrets directly in JSON-RPC tool responses back to the host model. We separate cross-command **Sandbox Session** custody into `AegisControlDaemon` over a user-scoped Unix domain socket (`0o600`) and supervise third-party MCP subprocesses via `aegis mcp-wrap`.

## Consequences

- Consecutive OS invocations of `aegis-zsh` (such as IDE agent terminal tool calls) share the same workspace-keyed **Ephemeral Worktree**, dirty-baseline delta tracking, and aborted/canary tripwire state until explicit `daemon harvest` or `daemon stop`.
- `aegis integrate <mcp.json>` wraps existing MCP server commands under `aegis mcp-wrap` (preserving a `.bak` backup), sanitizing spawned subprocess environments and scanning live stdio chunks with `[AEGIS_REDACTED_SECRET]` redaction and immediate `SIGKILL` termination on **Canary Honeytoken** emission.
