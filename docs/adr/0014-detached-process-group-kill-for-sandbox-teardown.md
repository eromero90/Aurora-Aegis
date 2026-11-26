# Terminate Detached Sandbox Process Groups via Negative PID Signaling

Sending `SIGKILL` only to the direct child PID of a sandbox wrapper (`sandbox-exec`, `bwrap`, or `/bin/sh`) can leave forked subshells and grandchild runtimes alive after a timeout or Canary abort. We spawn sandboxed processes with `detached: true` so each command leads its own process group, and `killProcessTree` signals `-pid` with `SIGKILL` to terminate the entire descendant tree atomically.

## Consequences

- Aborted or timed-out commands cannot leak orphaned background processes or hold open worktree file descriptors.
