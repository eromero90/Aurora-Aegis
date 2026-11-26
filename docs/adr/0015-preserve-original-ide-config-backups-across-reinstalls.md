# Preserve Original IDE and MCP Config Backups Across Repeated Install Runs

Users frequently re-run IDE/MCP installation commands after upgrading or adding servers. Overwriting the `.bak` backup file on subsequent runs would replace the user's original unpatched configuration with an already-wrapped Aegis configuration, making clean rollback impossible. We only write `<config>.bak` when no backup file already exists.

## Consequences

- Repeated runs of `aegis ide-install` / MCP config patching remain idempotent and always preserve the pre-Aegis baseline config for restoration.
