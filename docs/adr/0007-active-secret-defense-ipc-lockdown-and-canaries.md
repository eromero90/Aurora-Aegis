# Block Non-Filesystem Secret Vectors via Env Scrubbing, IPC Lockdown, Anti-SSRF, and Canary Honeytokens

Blocking filesystem reads on `$HOME` and scanning HTTP bodies is insufficient against malicious agents or poisoned dependencies that harvest secrets from inherited `process.env` variables, read the OS clipboard (`pbpaste`), hijack live `SSH_AUTH_SOCK` or Docker sockets, pivot to localhost services via proxy SSRF (`127.0.0.1:9222`), plant delayed execution triggers in harvested diffs (`.vscode/tasks.json`, `.gitattributes`), or obfuscate secrets via custom ciphers before exfiltration. We enforce six active secret-defense controls across every **Sandbox Session**: zero-trust environment allowlisting, Mach/IPC and agent-socket lockdown, Egress Firewall private-IP/SSRF blackholing, **Canary Honeytoken** tripwires, pre-harvest **Persistence Vector** inspection, and inbound indirect prompt-injection sanitization.

## Consequences

- Jailed processes never inherit raw `process.env`, `SSH_AUTH_SOCK`, `GPG_AGENT_INFO`, or OS clipboard/Keychain Mach services (`com.apple.pasteboard.1`, `com.apple.SecurityServer`).
- Accessing a planted **Canary Honeytoken** or transmitting any substring of it immediately kills the process tree (`SIGKILL`) and aborts the **Sandbox Session**, catching custom-encoded exfiltration that static regexes cannot detect.
