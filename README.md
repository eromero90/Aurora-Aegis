# Aurora-Aegis (`aegis`)

**Zero-Latency, Kernel-Enforced Local Execution Sandbox & Egress DLP Firewall for AI Coding Agents**

> [!NOTE]
> **Public Alpha (`v0.1.0`)**: Aurora-Aegis is ready to try from source on macOS and Linux. Feedback, threat-model critiques, and bug reports are welcome via [GitHub Issues](https://github.com/eromero90/Aurora-Aegis/issues).

Aurora-Aegis separates the **Control Plane** (host orchestration, IDE UI, credential custody, and signed provenance) from the **Execution Plane** (ephemeral Copy-on-Write Git worktrees synced from your working tree, locked inside macOS Seatbelt / Linux `bubblewrap` kernel jails or MicroVMs, and routed exclusively through a TLS-MITM Egress Firewall with Multi-Encoding DLP, Phantom Credentials, Canary Honeytokens, and Supply-Chain Registry Inspection).

---

## Install from Source

Requires **Node.js >= 22**, **pnpm**, and **macOS (`sandbox-exec`)** or **Linux (`bwrap`)**.

```bash
git clone https://github.com/eromero90/Aurora-Aegis.git
cd Aurora-Aegis
pnpm install
pnpm build
pnpm test

# Link `aegis` and `aegis-zsh` globally
pnpm --filter @aegis/cli link --global
```

## Try It in 30 Seconds

Inside any Git repository you want to protect:

```bash
# 1. Audit your repo for exposed secrets, active git hooks, and persistence vectors
aegis audit

# 2. Scaffold a repository aegis.policy.json (auto-detects node_modules/.venv)
aegis init

# 3. Run a command or AI coding agent inside a kernel-isolated Ephemeral Worktree
aegis wrap -- pnpm test
aegis wrap -i -- claude
```

---

## Platform Support

| Isolation Tier / Platform | Status | Notes |
| :--- | :--- | :--- |
| **macOS (`Seatbelt` / `sandbox-exec`)** | Verified | Default Tier 1 kernel MAC jail; full 15-vector red-team suite verified end-to-end. |
| **Linux (`bubblewrap` / `bwrap` + UDS bridge)** | Implemented | Tier 1 namespace jail and UDS proxy bridge implemented and unit-tested; requires `bwrap`. |
| **Tier 2 MicroVM (`vfkit` / `Firecracker`)** | Experimental | Launch-spec adapter requiring user-supplied guest kernel (`vmlinux`) and `rootfs.ext4` images. |

---

## Daily-Driver CLI Reference

* **`aegis init [--force] [--no-lockfile] [dir]`** — Scaffolds a versioned [`aegis.policy.json`](./docs/adr/0009-policy-as-code-and-cryptographic-audit-attestation.md) with auto-discovered `cowDirectories` (`node_modules`, `.venv`) and supply-chain lockfile enforcement (`packagePolicy.enforceLockfile`).
* **`aegis wrap [-i | --interactive] [--] <command...>`** — Launches a **Sandbox Session**, syncs uncommitted host edits into the **Ephemeral Worktree**, runs `<command>` (streaming live stdio when `-i` / `--interactive` is passed), blocks secret exfiltration or typosquatted package downloads, and harvests only clean session deltas back to your working tree.
* **`aegis daemon <start | status | harvest | stop> [--socket <path>] [repoDir]`** — Starts and manages `AegisControlDaemon` over a `0o600` Unix domain socket (default `<tmpdir>/aegis-daemon-<uid>.sock`) so multi-step `aegis-zsh` terminal commands persist across a single **Ephemeral Worktree** until `harvest` or `stop`.
* **`aegis-zsh -c "<command>"`** — Drop-in IDE shell shim for Cursor / Antigravity terminal profiles (connects to `AEGIS_DAEMON_SOCKET` when set).
* **`aegis integrate <mcp-config.json>`** — Safely wraps third-party MCP server commands under `aegis mcp-wrap` (preserving a `.bak` backup) to scrub host secrets and monitor stdio for **Canary Honeytoken** leaks.
* **`aegis audit [--sarif] [repoDir]`** — Audits a repository for plaintext secrets, active `.git/hooks`, **Persistence Vectors**, and malformed `aegis.policy.json` (emits OASIS SARIF v2.1.0 with `--sarif`).
* **`aegis verify <artifact.json | audit-ledger.jsonl>`** — Offline cryptographic verification for signed `HarvestAttestation` files, `HarvestResult` bundles, and SHA-256 hash-chained `SessionAuditLedger` JSONL logs.

---

## Documentation Index

* **[Domain Glossary (`GLOSSARY.md`)](./GLOSSARY.md)** — Canonical ubiquitous language for Aurora-Aegis.
* **[System Architecture Specification (`docs/ARCHITECTURE.md`)](./docs/ARCHITECTURE.md)** — Full architecture, hardened security model, Mermaid diagrams, and core TypeScript domain contracts.
* **[AI-Agent Execution Milestones (`docs/AGENT_MILESTONES.md`)](./docs/AGENT_MILESTONES.md)** — Contract-first DAG roadmap, file ownership boundaries, and deterministic verification gates.

### Architectural Decision Records (`docs/adr/`)

1. **[ADR-0001: Split Control Plane and Execution Plane on the Local Host](./docs/adr/0001-control-execution-plane-split.md)**
2. **[ADR-0002: Use Dual-Tier Kernel MAC and MicroVM Isolation Instead of Standard Docker](./docs/adr/0002-dual-tier-kernel-mac-and-microvm-isolation.md)**
3. **[ADR-0003: Enforce Default-Deny Home Directory Reads and Git Hook Write Guards](./docs/adr/0003-default-deny-home-and-git-hook-write-protection.md)**
4. **[ADR-0004: Force All Sandbox Traffic Through a Per-Session MITM Egress Firewall with Phantom Credentials](./docs/adr/0004-loopback-mitm-egress-dlp-and-phantom-credentials.md)**
5. **[ADR-0005: Use Asymmetric Sandboxing for Desktop IDEs and MCP Hosts](./docs/adr/0005-asymmetric-ide-sandboxing.md)**
6. **[ADR-0006: Bridge Linux Unshared Network Namespaces to the Host Egress Firewall via Unix Domain Socket](./docs/adr/0006-unix-socket-bridge-for-linux-netns-egress.md)**
7. **[ADR-0007: Block Non-Filesystem Secret Vectors via Env Scrubbing, IPC Lockdown, Anti-SSRF, and Canary Honeytokens](./docs/adr/0007-active-secret-defense-ipc-lockdown-and-canaries.md)**
8. **[ADR-0008: Persist Cross-Process Worktrees in a Control Daemon and Supervise Third-Party MCP Stdio Streams](./docs/adr/0008-persistent-control-daemon-and-mcp-stdio-supervisor.md)**
9. **[ADR-0009: Enforce Versioned Policy-as-Code with Cryptographic Harvest Attestations and Hash-Chained Audit Ledgers](./docs/adr/0009-policy-as-code-and-cryptographic-audit-attestation.md)**
10. **[ADR-0010: Inspect Package Registry Egress to Block Typosquatting and Unpinned Supply-Chain Installs](./docs/adr/0010-supply-chain-package-registry-egress-guard.md)**

---

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).
