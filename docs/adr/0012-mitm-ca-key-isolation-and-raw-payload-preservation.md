# Isolate Ephemeral CA Private Keys Outside Session Temp and Preserve Unmutated Compressed Payloads

Storing the **Egress Firewall** MITM Root CA private key (`ca.key`) inside `sessionTmpDir` would allow a sandboxed process to read the key and forge arbitrary TLS certificates; conversely, unconditionally re-encoding every inspected HTTP request body breaks upstream integrity checks and adds avoidable compression overhead. We store `ca.key` strictly in a `0o700` **Control Plane** directory outside `sessionTmpDir`, and after DLP inspection we forward the original raw compressed request bytes untouched whenever no **Phantom Credential** substitution mutated the body.

## Consequences

- The **Execution Plane** receives only the public `aegis-ca.pem` certificate and can never access `ca.key`.
- Compressed requests without Phantom substitutions reach upstream servers byte-for-byte intact without re-compression or `Content-Encoding` stripping.
