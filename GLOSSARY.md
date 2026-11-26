# Aurora-Aegis

Aurora-Aegis is a local security boundary and execution runtime that isolates untrusted AI coding agent actions from the host machine's sensitive files, credentials, and network.

## Language

### Planes & Boundaries

**Control Plane**:
The trusted host environment where agent orchestration, user interfaces, credential vault access, and policy enforcement execute.
_Avoid_: Host system, parent process, orchestrator host

**Execution Plane**:
The untrusted, disposable jail where agent-invoked commands, scripts, and language toolchains execute.
_Avoid_: Container, guest, child environment, runtime box

**Sandbox Session**:
A single bounded lifecycle of an isolated workspace, its active kernel policy, and its dedicated egress proxy channel created for one agent task.
_Avoid_: Instance, run, job, container session

**Isolation Tier**:
The enforcement mechanism selected for a Sandbox Session based on whether the workload requires user-space toolchain execution (Tier 1 Kernel Jail) or privileged system modification (Tier 2 MicroVM).
_Avoid_: Security level, sandbox mode, driver type

### Workspace & Filesystem

**Ephemeral Worktree**:
A temporary, detached Git working tree linked to the host repository where an agent performs all file modifications in isolation from the user's active working tree.
_Avoid_: Clone, scratch folder, temp repo, shadow copy

**CoW Clone**:
An instant, zero-duplicate-block copy of heavy dependency directories (such as `node_modules` or `.venv`) into an Ephemeral Worktree using filesystem copy-on-write primitives.
_Avoid_: Symlink farm, cache mount, folder copy

**Harvest**:
The controlled extraction of verified diffs or commits from an Ephemeral Worktree back into the host repository before the worktree is destroyed.
_Avoid_: Sync, merge back, export, commit transfer

**Git Hook Guard**:
The mandatory write-lock placed on the host repository's `.git/hooks`, `.git/config`, and primary branch refs so a jailed process cannot plant persistent host-side execution triggers.
_Avoid_: Git read-only mode, repo lock

### Network & Credentials

**Egress Firewall**:
The host-side TLS-inspecting proxy that intercepts all outbound traffic from a Sandbox Session to enforce domain/method rules and scan payloads.
_Avoid_: Network filter, proxy server, traffic router

**Phantom Credential**:
A synthetic, zero-privilege placeholder token injected into the Execution Plane that the Egress Firewall swaps for the real secret in transit only when the destination host is explicitly authorized.
_Avoid_: Dummy key, mock token, alias secret, fake env var

**Secret Fingerprint**:
A set of normalized representations (raw, Base64, Base64url, hex, URL-encoded) derived from a host secret and used by the Egress Firewall to block outbound exfiltration without exposing the secret to the Execution Plane.
_Avoid_: Blacklist string, secret hash, DLP rule

**Canary Honeytoken**:
A synthetic, high-enticement decoy credential planted inside the Execution Plane whose read access or partial outbound transmission immediately terminates the Sandbox Session.
_Avoid_: Fake file, trap key, dummy secret

**Persistence Vector**:
A file within a repository (such as `.gitattributes`, `.gitmodules`, `.vscode/tasks.json`, or package lifecycle hooks) that can cause the Control Plane to execute attacker-controlled code after a Harvest.
_Avoid_: Build script, config file, autorun hook

### Integration

**Asymmetric Sandboxing**:
The integration pattern in which a graphical IDE or desktop harness runs unrestricted in the Control Plane while only its spawned agent shells and tool subprocesses enter the Execution Plane.
_Avoid_: Partial sandboxing, hybrid wrapping, app jailing

**Shell Shim**:
A drop-in executable replacement for a system shell (`sbox-zsh` or `sbox-sh`) configured in an IDE that transparently routes every agent terminal command into a Sandbox Session.
_Avoid_: Wrapper script, proxy shell, fake terminal
