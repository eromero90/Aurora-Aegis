import { type ChildProcess, spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
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
import { compileSeatbeltProfile } from './seatbelt-compiler.js';

export class SeatbeltDriver implements SandboxDriver {
  readonly tier: IsolationTier = 'tier1-kernel-mac';

  private policy: SandboxPolicy | undefined;
  private workspace: WorkspaceDescriptor | undefined;
  private profilePath: string | undefined;
  private readonly activeProcesses = new Set<ChildProcess>();

  async prepare(
    policy: SandboxPolicy,
    workspace: WorkspaceDescriptor,
    proxyPort: number,
  ): Promise<void> {
    this.policy = policy;
    this.workspace = workspace;

    const profileContent = compileSeatbeltProfile(policy, workspace, proxyPort);
    const targetPath = path.join(workspace.sessionTmpDir, `aegis-${policy.sessionId}.sb`);
    fs.writeFileSync(targetPath, profileContent, { mode: 0o600 });
    this.profilePath = canonicalizePath(targetPath);
  }

  private prepareLaunchSpec(command: string, rawCwd?: string): { cwd: string; executable: string; args: string[] } {
    if (!this.policy || !this.workspace || !this.profilePath) {
      throw new Error('SeatbeltDriver invoked before prepare().');
    }

    const cwd = canonicalizePath(rawCwd ?? this.workspace.worktreePath);
    if (!isSubpathOf(cwd, this.workspace.worktreePath)) {
      throw new Error(
        `Execution cwd "${cwd}" escapes Ephemeral Worktree "${this.workspace.worktreePath}"`,
      );
    }

    if (process.platform !== 'darwin') {
      throw new Error(`SeatbeltDriver requires macOS (current platform: ${process.platform}).`);
    }

    return {
      cwd,
      executable: '/usr/bin/sandbox-exec',
      args: ['-f', this.profilePath, '/bin/zsh', '-c', command],
    };
  }

  spawnInteractive(options: SandboxInteractiveSpawnOptions): ChildProcess {
    const { cwd, executable, args } = this.prepareLaunchSpec(options.command, options.cwd);
    const child = spawn(executable, args, {
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
    const { cwd, executable, args } = this.prepareLaunchSpec(options.command, options.cwd);
    const timeoutMs = options.timeoutMs ?? this.policy!.timeoutMs;
    const startTime = Date.now();

    return new Promise((resolve) => {
      const child = spawn(executable, args, {
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
    if (this.profilePath && fs.existsSync(this.profilePath)) {
      fs.rmSync(this.profilePath, { force: true });
    }
    this.profilePath = undefined;
  }
}
