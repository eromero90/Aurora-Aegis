# Force All Sandbox Traffic Through a Per-Session MITM Egress Firewall with Phantom Credentials

Environment variable proxies (`HTTPS_PROXY`) alone are trivially bypassed by scripts opening raw TCP/UDP sockets, and passing real API keys into a sandbox allows exfiltration over allowed domains. We block all direct outbound network syscalls at the kernel layer—allowing connections solely to a per-session loopback **Egress Firewall**—which terminates TLS using an ephemeral session CA, enforces per-domain HTTP method policies, scans decoded request paths, headers, and decompressed bodies against **Secret Fingerprints**, and swaps **Phantom Credentials** for real host secrets only when the target hostname matches the credential's authorized origin.

## Consequences

- Direct UDP/DNS and raw TCP sockets from inside the Execution Plane fail at the kernel boundary (`EPERM`/`EACCES`), eliminating DNS tunneling and raw socket bypasses.
- Each **Sandbox Session** binds its own ephemeral local port and proxy session token so concurrent agents cannot cross-contaminate credentials or policies.
