# Split Control Plane and Execution Plane on the Local Host

AI coding agents require access to LLM APIs, IDE state, and user credentials to plan work, yet execute arbitrary shell commands and untrusted dependencies that can compromise the machine. We keep agent orchestration, credential custody, and TLS egress inspection in the host **Control Plane**, and restrict the **Execution Plane** strictly to jailed subprocesses operating inside an **Ephemeral Worktree**. This prevents a compromised dependency, prompt injection, or malicious test script from reading host credentials or mutating the developer's active branch while preserving native local execution speed.

## Consequences

- Real secrets never enter the Execution Plane environment or filesystem; they are either withheld in the Control Plane or substituted in transit via **Phantom Credentials**.
- Every tool invocation crosses a deterministic boundary (`Control Plane -> Kernel Jail -> Ephemeral Worktree`), enabling full auditability of filesystem diffs and outbound network calls.
