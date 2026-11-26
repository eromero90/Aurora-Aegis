# Prioritize Canary Tripwires, Fingerprint Unpadded Base64, and Window Only High-Entropy Canary Bytes

Evaluating **Canary Honeytoken** tripwires after routine DLP or byte-budget rules would let a compromised process hit a benign `403` block instead of triggering an immediate session abort; meanwhile, sliding 6/8-character tripwire windows across shared token prefixes like `aegis_` would false-trigger on legitimate **Phantom Credentials**, and standard padded Base64 fingerprinting misses stripped-padding exfiltration. We evaluate Canary tripwires first in `DlpScanner.scanRequest`, slide 6/8-character windows exclusively over the high-entropy core of each canary token, and include padding-stripped Base64 (`base64NoPad`) in every `SecretFingerprint`.

## Consequences

- Any egress attempt containing a Canary Honeytoken immediately aborts the **Sandbox Session** regardless of byte budgets or domain rules.
- Shared `aegis_` prefixes between Phantom Credentials and Canary Honeytokens never produce false-positive session terminations.
