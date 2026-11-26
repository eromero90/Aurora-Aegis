import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  CoWCloner,
  DEFAULT_EGRESS_HOSTS,
  type RuntimeDiagnostic,
  SandboxSessionOrchestrator,
  type SandboxPolicy,
  canonicalizePath,
  discoverDefaultCowDirectories,
  discoverHostToolchainPaths,
  isForbiddenHomeSecretPath,
} from '../../src/index.js';
import { TestShellDriver } from '../../test-helpers/test-shell-driver.js';

const tempDirs: string[] = [];

function createTempDir(prefix: string): string {
  const dir = canonicalizePath(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  tempDirs.push(dir);
  return dir;
}

function createTempGitRepo(files: Record<string, string>): string {
  const repoDir = createTempDir('aegis-m11-repo-');
  execFileSync('git', ['init', '-b', 'main'], { cwd: repoDir, stdio: 'pipe' });
  execFileSync('git', ['config', 'user.email', 'm11@aurora-aegis.local'], { cwd: repoDir, stdio: 'pipe' });
  execFileSync('git', ['config', 'user.name', 'Aegis M11 Test'], { cwd: repoDir, stdio: 'pipe' });

  for (const [relPath, content] of Object.entries(files)) {
    const absPath = path.join(repoDir, relPath);
    fs.mkdirSync(path.dirname(absPath), { recursive: true });
    fs.writeFileSync(absPath, content, 'utf8');
  }

  execFileSync('git', ['add', '-A'], { cwd: repoDir, stdio: 'pipe' });
  execFileSync('git', ['commit', '-m', 'init'], { cwd: repoDir, stdio: 'pipe' });
  return repoDir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir && fs.existsSync(dir)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

describe('Daily-Driver Ergonomics & Zero-Config Readiness', () => {
  it('syncs uncommitted tracked edits and untracked host files into worktrees and harvests only session deltas', async () => {
    const repoDir = createTempGitRepo({
      'app.ts': 'export const a = 1;\n',
    });

    fs.writeFileSync(path.join(repoDir, 'app.ts'), 'export const a = 2;\n', 'utf8');
    fs.writeFileSync(path.join(repoDir, 'untracked-host.ts'), 'export const hostOnly = true;\n', 'utf8');
    fs.writeFileSync(path.join(repoDir, '.env'), 'HOST_SECRET=topsecret_do_not_copy\n', 'utf8');

    const policy: SandboxPolicy = {
      sessionId: 'm11-dirty-sync',
      repoRootPath: repoDir,
      tier: 'tier1-kernel-mac',
      cowDirectories: [],
      readOnlyToolchainPaths: [path.dirname(process.execPath)],
      egressRules: DEFAULT_EGRESS_HOSTS.map((domain) => ({ domain, allowedMethods: ['GET'] })),
      phantomCredentials: [],
      protectedSecrets: [],
      timeoutMs: 30_000,
    };

    const orchestrator = new SandboxSessionOrchestrator({
      policy,
      driver: process.platform === 'darwin' ? undefined : new TestShellDriver(),
    });

    try {
      await orchestrator.start();

      const script = [
        'const fs = require("node:fs");',
        'const app = fs.readFileSync("app.ts", "utf8");',
        'const untracked = fs.readFileSync("untracked-host.ts", "utf8");',
        'if (!app.includes("export const a = 2;") || !untracked.includes("hostOnly")) process.exit(2);',
        'fs.writeFileSync("app.ts", app + "export const b = 3;\\n", "utf8");',
        'fs.writeFileSync("agent-new.ts", "export const fromAgent = 42;\\n", "utf8");',
      ].join(' ');

      const cmdRes = await orchestrator.exec(`${JSON.stringify(process.execPath)} -e ${JSON.stringify(script)}`);
      expect(cmdRes.exitCode).toBe(0);

      const harvest = await orchestrator.harvest(true);
      expect(harvest.appliedToHost).toBe(true);
      expect([...harvest.changedFiles].sort()).toEqual(['agent-new.ts', 'app.ts']);

      expect(fs.readFileSync(path.join(repoDir, 'app.ts'), 'utf8')).toBe('export const a = 2;\nexport const b = 3;\n');
      expect(fs.readFileSync(path.join(repoDir, 'agent-new.ts'), 'utf8')).toBe('export const fromAgent = 42;\n');
      expect(fs.readFileSync(path.join(repoDir, '.env'), 'utf8')).toBe('HOST_SECRET=topsecret_do_not_copy\n');
    } finally {
      await orchestrator.close();
    }
  });

  it('auto-discovers safe HOME toolchains and CoW dirs while keeping credential dirs forbidden', () => {
    const fakeHome = createTempDir('aegis-m11-home-');
    const nvmDir = path.join(fakeHome, '.nvm');
    const cargoDir = path.join(fakeHome, '.cargo');
    const localBinDir = path.join(fakeHome, '.local', 'bin');
    const sshDir = path.join(fakeHome, '.ssh');
    const awsDir = path.join(fakeHome, '.aws');
    const keychainsDir = path.join(fakeHome, 'Library', 'Keychains');

    fs.mkdirSync(nvmDir, { recursive: true });
    fs.mkdirSync(cargoDir, { recursive: true });
    fs.mkdirSync(localBinDir, { recursive: true });
    fs.mkdirSync(sshDir, { recursive: true });
    fs.mkdirSync(awsDir, { recursive: true });
    fs.mkdirSync(keychainsDir, { recursive: true });

    expect(isForbiddenHomeSecretPath(fakeHome, fakeHome)).toBe(true);
    expect(isForbiddenHomeSecretPath(sshDir, fakeHome)).toBe(true);
    expect(isForbiddenHomeSecretPath(awsDir, fakeHome)).toBe(true);
    expect(isForbiddenHomeSecretPath(keychainsDir, fakeHome)).toBe(true);
    expect(isForbiddenHomeSecretPath(nvmDir, fakeHome)).toBe(false);

    const discovered = discoverHostToolchainPaths({
      homeDir: fakeHome,
      pathEnv: `${sshDir}${path.delimiter}${localBinDir}`,
    });

    expect(discovered).toContain(canonicalizePath(path.dirname(process.execPath)));
    expect(discovered).toContain(canonicalizePath(nvmDir));
    expect(discovered).toContain(canonicalizePath(cargoDir));
    expect(discovered).toContain(canonicalizePath(localBinDir));
    expect(discovered).not.toContain(canonicalizePath(fakeHome));
    expect(discovered).not.toContain(canonicalizePath(sshDir));
    expect(discovered).not.toContain(canonicalizePath(awsDir));
    expect(discovered).not.toContain(canonicalizePath(keychainsDir));

    const repoDir = createTempDir('aegis-m11-cow-');
    fs.mkdirSync(path.join(repoDir, 'node_modules'), { recursive: true });
    fs.mkdirSync(path.join(repoDir, '.venv'), { recursive: true });
    fs.writeFileSync(path.join(repoDir, 'venv'), 'not-a-directory', 'utf8');

    expect(discoverDefaultCowDirectories(repoDir)).toEqual(['node_modules', '.venv']);
  });

  it('records teardown errors in the audit ledger and emits CoW diagnostics without silent swallowing', async () => {
    const repoDir = createTempGitRepo({ 'index.ts': 'export const ok = true;\n' });
    const failingDriver = new TestShellDriver();
    failingDriver.cleanup = async () => {
      throw new Error('simulated driver cleanup failure');
    };

    const orchestrator = new SandboxSessionOrchestrator({
      policy: {
        sessionId: 'm11-diag-teardown',
        repoRootPath: repoDir,
        tier: 'tier1-kernel-mac',
        cowDirectories: [],
        readOnlyToolchainPaths: [path.dirname(process.execPath)],
        egressRules: [],
        phantomCredentials: [],
        protectedSecrets: [],
        timeoutMs: 10_000,
      },
      driver: failingDriver,
    });

    await orchestrator.start();
    await orchestrator.close();

    const diagnostics = orchestrator
      .getAuditLedger()
      .filter((entry) => entry.eventType === 'SESSION_DIAGNOSTIC');
    expect(
      diagnostics.some(
        (entry) =>
          entry.details['source'] === 'SandboxSessionOrchestrator.performClose.driver' &&
          String(entry.details['message']).includes('simulated driver cleanup failure'),
      ),
    ).toBe(true);

    const clonerDiagnostics: RuntimeDiagnostic[] = [];
    const cloner = new CoWCloner((diag) => clonerDiagnostics.push(diag));
    expect(cloner.getDiagnostics()).toEqual([]);
    expect(clonerDiagnostics).toEqual([]);
  });
});
