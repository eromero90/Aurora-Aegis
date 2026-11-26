import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import type {
  DiffHarvesterContract,
  HarvestResult,
  WorkspaceDescriptor,
} from '../types/contracts.js';
import { GitHookIntegrityVerifier, type GitIntegritySnapshot } from './hook-verifier.js';
import { PersistenceScanner } from './persistence-scanner.js';

export class DiffHarvester implements DiffHarvesterContract {
  constructor(
    private readonly baselineSnapshot?: GitIntegritySnapshot,
    private readonly hookVerifier = new GitHookIntegrityVerifier(),
    private readonly persistenceScanner = new PersistenceScanner(),
  ) {}

  async harvest(workspace: WorkspaceDescriptor, applyToHost: boolean): Promise<HarvestResult> {
    const exclusions = this.buildExclusions(workspace);

    const untrackedRaw = execFileSync(
      'git',
      ['ls-files', '--others', '--exclude-standard', '-z', '--', '.', ...exclusions],
      {
        cwd: workspace.worktreePath,
        encoding: 'utf8',
      },
    );
    const untrackedFiles = untrackedRaw.split('\0').filter((filePath) => filePath.length > 0);
    for (let i = 0; i < untrackedFiles.length; i += 200) {
      execFileSync('git', ['add', '-N', '--', ...untrackedFiles.slice(i, i + 200)], {
        cwd: workspace.worktreePath,
        stdio: 'pipe',
      });
    }

    const nameOnlyRaw = execFileSync(
      'git',
      ['diff', 'HEAD', '--name-only', '--', '.', ...exclusions],
      {
        cwd: workspace.worktreePath,
        encoding: 'utf8',
      },
    ).trim();

    const changedFiles = nameOnlyRaw.length > 0 ? nameOnlyRaw.split(/\r?\n/).filter(Boolean) : [];

    const patchDiff = execFileSync(
      'git',
      ['diff', 'HEAD', '--binary', '--', '.', ...exclusions],
      {
        cwd: workspace.worktreePath,
        encoding: 'utf8',
      },
    );

    const hookIntegrityVerified = this.baselineSnapshot
      ? this.hookVerifier.verifySnapshot(this.baselineSnapshot, workspace.repoGitDir).verified
      : true;

    const persistenceFindings = this.persistenceScanner.scanDiff(changedFiles, patchDiff);

    let appliedToHost = false;
    if (
      applyToHost &&
      hookIntegrityVerified &&
      persistenceFindings.length === 0 &&
      patchDiff.trim().length > 0
    ) {
      const patchFile = path.join(workspace.sessionTmpDir, 'harvest.patch');
      fs.writeFileSync(patchFile, patchDiff, 'utf8');
      execFileSync('git', ['apply', '--whitespace=nowarn', patchFile], {
        cwd: workspace.repoRootPath,
        stdio: 'pipe',
      });
      appliedToHost = true;
    }

    return {
      sessionId: workspace.sessionId,
      patchDiff,
      changedFiles,
      hookIntegrityVerified,
      persistenceFindings,
      appliedToHost,
    };
  }

  private buildExclusions(workspace: WorkspaceDescriptor): string[] {
    const exclusions = workspace.clonedCowDirs.map((dir) => `:(exclude)${dir}`);

    for (const envCandidate of ['.env', '.env.local', '.env.development', '.env.production', '.npmrc']) {
      if (fs.existsSync(path.join(workspace.worktreePath, envCandidate))) {
        exclusions.push(`:(exclude)${envCandidate}`);
      }
    }

    return exclusions;
  }
}
