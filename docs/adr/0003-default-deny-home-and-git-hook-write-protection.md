# Enforce Default-Deny Home Directory Reads and Git Hook Write Guards

A naive Seatbelt or `bubblewrap` policy that uses `(allow default)` with a small blocklist (`~/.ssh`, `~/.aws`) still exposes hundreds of credential locations across `~/.config`, `~/Library/Application Support`, `~/.kube`, `~/.npmrc`, and `.env` files, and allowing full writes to a linked Git repository lets a jailed process escape the sandbox by writing a malicious script to `.git/hooks/post-checkout` that the host IDE later executes unsandboxed. We enforce a **Default-Deny Home Read Policy** (denying all `file-read*` under `$HOME` except explicitly whitelisted read-only toolchain caches and the active **Ephemeral Worktree**) and a mandatory **Git Hook Guard** that grants write access only to `<repo>/.git/worktrees/<session-id>` while explicitly denying writes to `<repo>/.git/hooks`, `<repo>/.git/config`, and `<repo>/.git/refs/heads/*`.

## Consequences

- All filesystem paths compiled into Seatbelt or `bubblewrap` profiles must first be canonicalized with `fs.realpathSync()` so macOS symlinked paths (`/tmp` -> `/private/tmp`, `/var` -> `/private/var`) cannot bypass subpath rules.
- Host `.env` files are excluded or scrubbed during worktree initialization and replaced with **Phantom Credentials** so secrets cannot be read directly from disk.
