# Enforce Versioned Policy-as-Code with Cryptographic Harvest Attestations and Hash-Chained Audit Ledgers

Ad-hoc CLI flags do not provide repository-governed security policy or verifiable proof of what occurred during an autonomous **Sandbox Session**. Every repository may declare a versioned `aegis.policy.json` (`version: 1`) that merges monotonically toward tighter bounds (`Math.min` budgets/timeouts, intersection/allowlist narrowing), is kernel-write-locked inside the Execution Plane (`POLICY_FILE_TAMPER`), and feeds signed execution telemetry into every **Harvest** result and `SessionAuditLedger`.

## Consequences

- `EgressFirewall`, drivers, and `runSecurityAudit` fail closed on malformed or invalid `aegis.policy.json` configurations and surface audit diagnostics in standard JSON or OASIS SARIF v2.1.0 (`aegis audit --sarif`).
- Every **Sandbox Session** generates an in-memory Ed25519 keypair to sign both a `HarvestAttestation` (`patchSha256`, command count, DLP/canary/hook status) and a SHA-256 hash-chained `audit-ledger.jsonl` stream, verifiable offline in CI/CD merge gates via `aegis verify <artifact>`.
