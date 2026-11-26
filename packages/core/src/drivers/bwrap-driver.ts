import { type ChildProcess, spawn } from 'node:child_process';
import type {
  CommandResult,
  DriverExecOptions,
  IsolationTier,
  SandboxDriver,
  SandboxInteractiveSpawnOptions,
  SandboxPolicy,
  WorkspaceDescriptor,
} from '../types/contracts.js';
import { canonicalizePath, isSubpathOf } from '../utils/paths.js';
import { killProcessTree } from '../utils/process-tree.js';
import { compileBwrapArgs } from './bwrap-compiler.js';

export class BwrapDriver implements SandboxDriver {
  readonly tier: IsolationTier = 'tier1-kernel-mac';

  private policy: SandboxPolicy | undefined;
  private workspace: WorkspaceDescriptor | undefined;
  private readonly activeProcesses = new Set<ChildProcess>();

  async prepare(
    policy: SandboxPolicy,
    workspace: WorkspaceDescriptor,
    _proxyPort: number,
  ): Promise<void> {
    this.policy = policy;
    this.workspace = workspace;
  }

  private prepareLaunchArgs(options: {
    readonly command: string;
    readonly cwd?: string | undefined;
    readonly udsSocketPath?: string | undefined;
  }): { cwd: string; args: readonly string[] } {
    if (!this.policy || !this.workspace) {
      throw new Error('BwrapDriver invoked before prepare().');
    }
    if (process.platform !== 'linux') {
      throw new Error(`BwrapDriver requires Linux (current platform: ${process.platform}).`);
    }
    if (!options.udsSocketPath) {
      throw new Error('BwrapDriver requires options.udsSocketPath for --unshare-net egress bridge.');
    }

    const cwd = canonicalizePath(options.cwd ?? this.workspace.worktreePath);
    if (!isSubpathOf(cwd, this.workspace.worktreePath)) {
      throw new Error(
        `Execution cwd "${cwd}" escapes Ephemeral Worktree "${this.workspace.worktreePath}"`,
      );
    }

    return {
      cwd,
      args: compileBwrapArgs(this.policy, this.workspace, options.udsSocketPath, options.command),
    };
  }

  spawnInteractive(options: SandboxInteractiveSpawnOptions): ChildProcess {
    const { cwd, args } = this.prepareLaunchArgs(options);
    const child = spawn('bwrap', args, {
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
    const { cwd, args } = this.prepareLaunchArgs(options);
    const timeoutMs = options.timeoutMs ?? this.policy!.timeoutMs;
    const startTime = Date.now();

    return new Promise((resolve) => {
      const child = spawn('bwrap', args, {
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
