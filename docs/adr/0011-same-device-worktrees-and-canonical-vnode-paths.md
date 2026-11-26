# Resolve Policy Paths to Canonical Vnodes and Place Ephemeral Worktrees on the Same Device

Kernel MAC sandboxes (macOS Seatbelt vnode matching and Linux `bubblewrap` bind mounts) fail to match rules when given unresolved symlink paths such as macOS `/tmp` (`-> /private/tmp`) or `/var` (`-> /private/var`), and Copy-on-Write dependency cloning (`cp -cR` on APFS, `cp -a --reflink=always` on Btrfs/XFS) fails with `EXDEV` if the **Ephemeral Worktree** lives on a different filesystem device than the repository. We require all policy paths to be canonicalized via `fs.realpathSync.native`—walking up to the nearest existing ancestor when a leaf path does not yet exist on disk—and we compare `fs.statSync(repoRoot).dev` against `os.tmpdir().dev`, falling back to `<repoParent>/.aegis-worktrees/` whenever the system temp directory is on another volume.

## Consequences

- Sandbox policy rules always match kernel-resolved vnodes, even for not-yet-created session output paths.
- Heavy dependency directories (`node_modules`, `.venv`, `target`) clone in near-constant time without cross-device `EXDEV` degradation when `/tmp` is mounted on a separate `tmpfs` or volume.
