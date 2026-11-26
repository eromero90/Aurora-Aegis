import { type ChildProcess, spawn } from 'node:child_process';
import type {
  CommandResult,
  DriverExecOptions,
  IsolationTier,
  SandboxDriver,
  SandboxInteractiveSpawnOptions,
  SandboxPolicy,
  WorkspaceDescriptor,
} from '../src/types/contracts.js';
import { canonicalizePath, isSubpathOf } from '../src/utils/paths.js';
import { killProcessTree } from '../src/utils/process-tree.js';

export class TestShellDriver implements SandboxDriver {
  readonly tier: IsolationTier = 'tier1-kernel-mac';

  private policy: SandboxPolicy | undefined;
  private workspace: WorkspaceDescriptor | undefined;
  private readonly activeProcesses = new Set<ChildProcess>();

  async prepare(policy: SandboxPolicy, workspace: WorkspaceDescriptor, _proxyPort: number): Promise<void> {
    this.policy = policy;
    this.workspace = workspace;
  }

  private resolveCwd(rawCwd?: string): string {
    if (!this.policy || !this.workspace) {
      throw new Error('TestShellDriver invoked before prepare().');
    }
    const cwd = canonicalizePath(rawCwd ?? this.workspace.worktreePath);
    if (!isSubpathOf(cwd, this.workspace.worktreePath)) {
      throw new Error(`Execution cwd "${cwd}" escapes Ephemeral Worktree "${this.workspace.worktreePath}"`);
    }
    return cwd;
  }

  spawnInteractive(options: SandboxInteractiveSpawnOptions): ChildProcess {
    const cwd = this.resolveCwd(options.cwd);
    const child = spawn('/bin/sh', ['-c', options.command], {
      cwd,
      env: { ...options.env },
      detached: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    this.activeProcesses.add(child);
    const untrack = () => {
      this.activeProcesses.delete(child);
    };
    child.once('close', untrack);
    child.once('error', untrack);
    return child;
  }

  async exec(
    options: DriverExecOptions,
  ): Promise<Omit<CommandResult, 'blockedEgressEvents' | 'canaryTriggered'>> {
    const cwd = this.resolveCwd(options.cwd);
    const timeoutMs = options.timeoutMs ?? this.policy!.timeoutMs;
    const startTime = Date.now();

    return new Promise((resolve) => {
      const child = spawn('/bin/sh', ['-c', options.command], {
        cwd,
        env: { ...options.env },
        detached: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      this.activeProcesses.add(child);

      let stdout = '';
      let stderr = '';
      let settled = false;

      const timer = setTimeout(() => {
        if (!settled) {
          stderr += `\nAegis: Command timed out after ${timeoutMs}ms.`;
          killProcessTree(child);
        }
      }, timeoutMs);

      child.stdout.on('data', (chunk: Buffer) => {
        stdout += chunk.toString('utf8');
      });
      child.stderr.on('data', (chunk: Buffer) => {
        stderr += chunk.toString('utf8');
      });

      child.on('error', (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.activeProcesses.delete(child);
        resolve({
          exitCode: -1,
          stdout,
          stderr: `${stderr}\n${err.message}`.trim(),
          durationMs: Date.now() - startTime,
        });
      });

      child.on('close', (code) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.activeProcesses.delete(child);
        resolve({
          exitCode: code ?? -1,
          stdout,
          stderr,
          durationMs: Date.now() - startTime,
        });
      });
    });
  }

  killActiveProcesses(): void {
    for (const child of this.activeProcesses) {
      killProcessTree(child);
    }
    this.activeProcesses.clear();
  }

  async cleanup(): Promise<void> {
    this.killActiveProcesses();
  }
}
