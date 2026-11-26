import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { WorkspaceDescriptor, WorktreeManager } from '../types/contracts.js';
import {
  type DiagnosticReporter,
  formatErrorMessage,
  getErrnoCode,
  isExpectedErrno,
} from '../utils/error-codes.js';
import { canonicalizePath } from '../utils/paths.js';
import { CoWCloner } from './cow-cloner.js';

const VALID_SESSION_ID_REGEX = /^[a-zA-Z0-9_-]+$/;
const EXPECTED_TEARDOWN_ERRNOS = new Set(['ENOENT']);
const EXPECTED_GIT_TEARDOWN_PATTERN = /is not a working tree|not a git repository|does not exist/i;

function extractExecStderr(error: unknown): string {
  if (error !== null && typeof error === 'object' && 'stderr' in error) {
    const stderr = (error as { readonly stderr?: unknown }).stderr;
    if (typeof stderr === 'string') return stderr.trim();
    if (Buffer.isBuffer(stderr)) return stderr.toString('utf8').trim();
  }
  return '';
}

export class EphemeralWorktreeManager implements WorktreeManager {
  private readonly cowCloner: CoWCloner;

  constructor(
    cowCloner?: CoWCloner,
    private readonly onDiagnostic?: DiagnosticReporter,
  ) {
    this.cowCloner = cowCloner ?? new CoWCloner(onDiagnostic);
  }

  async create(
    repoRootPath: string,
    sessionId: string,
    cowDirectories: readonly string[],
  ): Promise<WorkspaceDescriptor> {
    if (!VALID_SESSION_ID_REGEX.test(sessionId)) {
      throw new Error(`Invalid sessionId "${sessionId}": must match /^[a-zA-Z0-9_-]+$/`);
    }

    const canonicalRepoRoot = canonicalizePath(repoRootPath);
    const rawCommonDir = execFileSync('git', ['rev-parse', '--git-common-dir'], {
      cwd: canonicalRepoRoot,
      encoding: 'utf8',
    }).trim();
    const repoGitDir = canonicalizePath(path.resolve(canonicalRepoRoot, rawCommonDir));

    const sessionBaseDir = this.resolveSessionBaseDir(canonicalRepoRoot, sessionId);
    const rawTmpDir = path.join(sessionBaseDir, 'tmp');
    const rawHomeDir = path.join(sessionBaseDir, 'home');
    const rawWorktreePath = path.join(sessionBaseDir, 'worktree');

    fs.mkdirSync(rawTmpDir, { recursive: true });
    fs.mkdirSync(rawHomeDir, { recursive: true });

    execFileSync('git', ['worktree', 'add', '--detach', rawWorktreePath, 'HEAD'], {
      cwd: canonicalRepoRoot,
      stdio: 'pipe',
    });

    const worktreePath = canonicalizePath(rawWorktreePath);
    const sessionTmpDir = canonicalizePath(rawTmpDir);
    const sessionHomeDir = canonicalizePath(rawHomeDir);

    this.syncDirtyHostWorkingTree(canonicalRepoRoot, worktreePath, cowDirectories);

    const rawWorktreeGitDir = execFileSync('git', ['rev-parse', '--git-dir'], {
      cwd: worktreePath,
      encoding: 'utf8',
    }).trim();
    const worktreeGitDir = canonicalizePath(path.resolve(worktreePath, rawWorktreeGitDir));

    const clonedCowDirs = await this.cowCloner.cloneDirectories(
      canonicalRepoRoot,
      worktreePath,
      cowDirectories,
    );

    return {
      sessionId,
      repoRootPath: canonicalRepoRoot,
      repoGitDir,
      worktreePath,
      worktreeGitDir,
      sessionTmpDir,
      sessionHomeDir,
      clonedCowDirs,
    };
  }

  async destroy(workspace: WorkspaceDescriptor): Promise<void> {
    try {
      execFileSync('git', ['worktree', 'remove', '--force', workspace.worktreePath], {
        cwd: workspace.repoRootPath,
        stdio: 'pipe',
      });
    } catch (err) {
      const stderrText = extractExecStderr(err);
      if (!isExpectedErrno(err, EXPECTED_TEARDOWN_ERRNOS) && !EXPECTED_GIT_TEARDOWN_PATTERN.test(stderrText)) {
        this.onDiagnostic?.({
          source: 'EphemeralWorktreeManager.destroy.remove',
          code: getErrnoCode(err),
          message: stderrText.length > 0 ? stderrText : formatErrorMessage(err),
        });
      }
    }

    try {
      execFileSync('git', ['worktree', 'prune'], {
        cwd: workspace.repoRootPath,
        stdio: 'pipe',
      });
    } catch (err) {
      const stderrText = extractExecStderr(err);
      if (!isExpectedErrno(err, EXPECTED_TEARDOWN_ERRNOS) && !EXPECTED_GIT_TEARDOWN_PATTERN.test(stderrText)) {
        this.onDiagnostic?.({
          source: 'EphemeralWorktreeManager.destroy.prune',
          code: getErrnoCode(err),
          message: stderrText.length > 0 ? stderrText : formatErrorMessage(err),
        });
      }
    }

    const sessionBaseDir = path.dirname(workspace.worktreePath);
    fs.rmSync(sessionBaseDir, { recursive: true, force: true });
  }

  private resolveSessionBaseDir(canonicalRepoRoot: string, sessionId: string): string {
    const canonicalTmp = canonicalizePath(os.tmpdir());
    const repoDev = fs.statSync(canonicalRepoRoot).dev;
    const tmpDev = fs.statSync(canonicalTmp).dev;

    if (repoDev === tmpDev) {
      return path.join(canonicalTmp, `aegis-session-${sessionId}`);
    }

    return path.join(
      path.dirname(canonicalRepoRoot),
      '.aegis-worktrees',
      `aegis-session-${sessionId}`,
    );
  }

  private syncDirtyHostWorkingTree(
    repoRootPath: string,
    worktreePath: string,
    cowDirectories: readonly string[],
  ): void {
    const normalizedCow = cowDirectories
      .map((dir) => dir.replace(/\/+$/g, ''))
      .filter((dir) => dir.length > 0);

    const exclusions = [
      ':(exclude).env',
      ':(exclude).env.*',
      ':(exclude).npmrc',
      ':(exclude)aegis.policy.json',
      ':(exclude).aegis-worktrees',
      ...normalizedCow.map((dir) => `:(exclude)${dir}`),
    ];

    const trackedPatch = execFileSync('git', ['diff', 'HEAD', '--binary', '--', '.', ...exclusions], {
      cwd: repoRootPath,
      encoding: 'utf8',
    });

    const untrackedRaw = execFileSync(
      'git',
      ['ls-files', '--others', '--exclude-standard', '-z', '--', '.', ...exclusions],
      {
        cwd: repoRootPath,
        encoding: 'utf8',
      },
    );

    const untrackedFiles = untrackedRaw
      .split('\0')
      .filter((relFile) => relFile.length > 0)
      .filter(
        (relFile) =>
          relFile !== '.env' &&
          !relFile.startsWith('.env.') &&
          relFile !== '.npmrc' &&
          relFile !== 'aegis.policy.json' &&
          relFile !== '.aegis-worktrees' &&
          !relFile.startsWith('.aegis-worktrees/') &&
          !normalizedCow.some((cowDir) => relFile === cowDir || relFile.startsWith(`${cowDir}/`)),
      );

    if (trackedPatch.trim().length === 0 && untrackedFiles.length === 0) {
      return;
    }

    if (trackedPatch.trim().length > 0) {
      const patchFile = path.join(path.dirname(worktreePath), 'tmp', 'host-dirty-baseline.patch');
      fs.writeFileSync(patchFile, trackedPatch, 'utf8');
      try {
        execFileSync('git', ['apply', '--whitespace=nowarn', patchFile], {
          cwd: worktreePath,
          stdio: 'pipe',
        });
      } finally {
        if (fs.existsSync(patchFile)) {
          fs.unlinkSync(patchFile);
        }
      }
    }

    for (const relFile of untrackedFiles) {
      const srcPath = path.join(repoRootPath, relFile);
      if (!fs.existsSync(srcPath)) {
        continue;
      }
      const stat = fs.lstatSync(srcPath);
      if (stat.isSymbolicLink() || !stat.isFile()) {
        continue;
      }
      const dstPath = path.join(worktreePath, relFile);
      fs.mkdirSync(path.dirname(dstPath), { recursive: true });
      fs.copyFileSync(srcPath, dstPath);
    }

    execFileSync('git', ['add', '-A'], { cwd: worktreePath, stdio: 'pipe' });
    execFileSync(
      'git',
      [
        '-c',
        'user.name=Aurora Aegis Baseline',
        '-c',
        'user.email=aegis-baseline@aurora-aegis.local',
        'commit',
        '--no-verify',
        '--no-gpg-sign',
        '--allow-empty',
        '-m',
        'aegis: dirty working tree baseline',
      ],
      { cwd: worktreePath, stdio: 'pipe' },
    );
  }
}
