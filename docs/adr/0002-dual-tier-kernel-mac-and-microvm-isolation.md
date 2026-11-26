# Use Dual-Tier Kernel MAC and MicroVM Isolation Instead of Standard Docker

Standard Docker (`runc`) shares the host Linux kernel on Linux and runs inside a shared utility VM with heavy `virtiofs` I/O overhead on macOS, making it both an incomplete security boundary and too slow for `node_modules`-heavy daily coding. We use a **Dual-Tier Isolation** model: **Tier 1** enforces OS kernel mandatory access control (macOS Seatbelt `sandbox-exec` and Linux `bubblewrap` + `seccomp-bpf`) over **CoW Clones** for `<10ms` daily coding, while **Tier 2** routes privileged or root-requiring sessions into hardware-virtualized MicroVMs (`Virtualization.framework` / `vfkit` on macOS, `Firecracker` on Linux) over `virtio-vsock`.

## Considered Options

- **Standard Docker (`runc`)**: Rejected due to shared-kernel escape surface on Linux, slow `virtiofs` bind mounts on macOS, and daemon-level root privileges.
- **MicroVM-only**: Rejected for Tier 1 daily tasks because booting a guest kernel and syncing host toolchains adds unnecessary friction when user-space compilers and interpreters can run safely under kernel MAC.
- **WASI / WebAssembly**: Rejected as primary runtime because mainstream native toolchains (`node-gyp`, Rust `cargo`, Python C-extensions, Go) cannot run unmodified in WASI.
