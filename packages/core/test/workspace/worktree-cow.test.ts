import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { assertCanonicalAbsolutePath } from '../../src/utils/paths.js';
import { EphemeralWorktreeManager } from '../../src/workspace/worktree-manager.js';

describe('EphemeralWorktreeManager & CoWCloner', () => {
  let tempRoot: string;
  let repoRoot: string;
  const manager = new EphemeralWorktreeManager();

  beforeEach(() => {
    tempRoot = fs.realpathSync.native(
      fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-wt-test-')),
    );
    repoRoot = path.join(tempRoot, 'sample-repo');
    fs.mkdirSync(repoRoot, { recursive: true });

    execFileSync('git', ['init'], { cwd: repoRoot, stdio: 'ignore' });
    execFileSync('git', ['config', 'user.email', 'test@aegis.local'], { cwd: repoRoot });
    execFileSync('git', ['config', 'user.name', 'Aegis Test'], { cwd: repoRoot });

    fs.writeFileSync(path.join(repoRoot, 'README.md'), '# Sample Repo\n');
    execFileSync('git', ['add', 'README.md'], { cwd: repoRoot });
    execFileSync('git', ['commit', '-m', 'Initial commit'], { cwd: repoRoot, stdio: 'ignore' });

    const pkgDir = path.join(repoRoot, 'node_modules', 'pkg');
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(path.join(pkgDir, 'index.js'), 'export const val = 1;\n');
  });

  afterEach(() => {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  it('provisions canonical worktree paths, clones CoW node_modules without mutating host, and cleans up', async () => {
    const workspace = await manager.create(repoRoot, 'wt_test_01', ['node_modules']);

    assertCanonicalAbsolutePath(workspace.repoRootPath);
    assertCanonicalAbsolutePath(workspace.repoGitDir);
    assertCanonicalAbsolutePath(workspace.worktreePath);
    assertCanonicalAbsolutePath(workspace.worktreeGitDir);
    assertCanonicalAbsolutePath(workspace.sessionTmpDir);
    assertCanonicalAbsolutePath(workspace.sessionHomeDir);

    expect(workspace.clonedCowDirs).toEqual(['node_modules']);

    const clonedPkgFile = path.join(workspace.worktreePath, 'node_modules', 'pkg', 'index.js');
    const hostPkgFile = path.join(repoRoot, 'node_modules', 'pkg', 'index.js');

    expect(fs.existsSync(clonedPkgFile)).toBe(true);
    expect(fs.readFileSync(clonedPkgFile, 'utf8')).toBe('export const val = 1;\n');

    fs.writeFileSync(clonedPkgFile, 'export const val = 999;\n');
    expect(fs.readFileSync(hostPkgFile, 'utf8')).toBe('export const val = 1;\n');

    await manager.destroy(workspace);
    expect(fs.existsSync(workspace.worktreePath)).toBe(false);
    expect(fs.existsSync(workspace.sessionTmpDir)).toBe(false);
    expect(fs.existsSync(workspace.sessionHomeDir)).toBe(false);
  });
});
