import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { compileSeatbeltProfile } from '../../src/drivers/seatbelt-compiler.js';
import { SeatbeltDriver } from '../../src/drivers/seatbelt-driver.js';
import type { SandboxPolicy } from '../../src/types/contracts.js';
import { EphemeralWorktreeManager } from '../../src/workspace/worktree-manager.js';

describe('SeatbeltCompiler & SeatbeltDriver', () => {
  let tempRoot: string;
  let repoRoot: string;
  const manager = new EphemeralWorktreeManager();

  beforeEach(() => {
    tempRoot = fs.realpathSync.native(
      fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-sb-test-')),
    );
    repoRoot = path.join(tempRoot, 'repo');
    fs.mkdirSync(repoRoot, { recursive: true });

    execFileSync('git', ['init'], { cwd: repoRoot, stdio: 'ignore' });
    execFileSync('git', ['config', 'user.email', 'test@aegis.local'], { cwd: repoRoot });
    execFileSync('git', ['config', 'user.name', 'Aegis Test'], { cwd: repoRoot });
    fs.writeFileSync(path.join(repoRoot, 'README.md'), '# Seatbelt Test\n');
    execFileSync('git', ['add', 'README.md'], { cwd: repoRoot });
    execFileSync('git', ['commit', '-m', 'init'], { cwd: repoRoot, stdio: 'ignore' });
  });

  afterEach(() => {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  it('compiles hardened Seatbelt profile with Home default-deny, Git Hook Guard, and Mach IPC locks', async () => {
    const workspace = await manager.create(repoRoot, 'sb_compile_01', []);
    try {
      const policy: SandboxPolicy = {
        sessionId: 'sb_compile_01',
        repoRootPath: workspace.repoRootPath,
        tier: 'tier1-kernel-mac',
        cowDirectories: [],
        readOnlyToolchainPaths: [],
        egressRules: [],
        phantomCredentials: [],
        protectedSecrets: [],
        timeoutMs: 5000,
      };

      const sbpl = compileSeatbeltProfile(policy, workspace, 8899);
      const realHome = fs.realpathSync.native(os.homedir());

      expect(sbpl).toContain(`(deny file-read* file-write*\n  (subpath "${realHome}"))`);
      expect(sbpl).toContain(`(subpath "${workspace.repoGitDir}/hooks")`);
      expect(sbpl).toContain(`(literal "${workspace.repoGitDir}/config")`);
      expect(sbpl).toContain(`(subpath "${workspace.repoGitDir}/refs/heads")`);
      expect(sbpl).toContain('(deny network*)');
      expect(sbpl).toContain('(remote tcp "localhost:8899")');
      expect(sbpl).toContain('(global-name "com.apple.pasteboard.1")');
      expect(sbpl).toContain('(global-name "com.apple.SecurityServer")');
      expect(sbpl).toContain('(literal "/var/run/docker.sock")');
    } finally {
      await manager.destroy(workspace);
    }
  });

  it('enforces kernel write allow/deny boundaries and home read denial via sandbox-exec on macOS', async () => {
    const workspace = await manager.create(repoRoot, 'sb_exec_01', []);
    const driver = new SeatbeltDriver();

    try {
      const policy: SandboxPolicy = {
        sessionId: 'sb_exec_01',
        repoRootPath: workspace.repoRootPath,
        tier: 'tier1-kernel-mac',
        cowDirectories: [],
        readOnlyToolchainPaths: [],
        egressRules: [],
        phantomCredentials: [],
        protectedSecrets: [],
        timeoutMs: 5000,
      };

      await driver.prepare(policy, workspace, 8899);

      const env = {
        PATH: process.env['PATH'] ?? '/usr/bin:/bin',
        HOME: workspace.sessionHomeDir,
        TMPDIR: workspace.sessionTmpDir,
      };

      if (process.platform !== 'darwin') {
        await expect(
          driver.exec({
            command: 'echo "allowed"',
            env,
            proxyPort: 8899,
            caCertPath: path.join(workspace.sessionTmpDir, 'ca.pem'),
          }),
        ).rejects.toThrow(/SeatbeltDriver requires macOS/);
        return;
      }

      const writeRes = await driver.exec({
        command: 'echo "allowed" > allowed.txt && cat allowed.txt',
        env,
        proxyPort: 8899,
        caCertPath: path.join(workspace.sessionTmpDir, 'ca.pem'),
      });
      expect(writeRes.exitCode).toBe(0);
      expect(writeRes.stdout.trim()).toBe('allowed');

      const hookRes = await driver.exec({
        command: `echo "pwn" > "${workspace.repoGitDir}/hooks/post-checkout"`,
        env,
        proxyPort: 8899,
        caCertPath: path.join(workspace.sessionTmpDir, 'ca.pem'),
      });
      expect(hookRes.exitCode).not.toBe(0);
      expect(fs.existsSync(path.join(workspace.repoGitDir, 'hooks', 'post-checkout'))).toBe(false);

      const homeReadRes = await driver.exec({
        command: `ls "${fs.realpathSync.native(os.homedir())}"`,
        env,
        proxyPort: 8899,
        caCertPath: path.join(workspace.sessionTmpDir, 'ca.pem'),
      });
      expect(homeReadRes.exitCode).not.toBe(0);
    } finally {
      await driver.cleanup();
      await manager.destroy(workspace);
    }
  });
});
