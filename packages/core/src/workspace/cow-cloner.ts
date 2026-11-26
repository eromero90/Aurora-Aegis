import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import {
  type DiagnosticReporter,
  type RuntimeDiagnostic,
  formatErrorMessage,
  getErrnoCode,
} from '../utils/error-codes.js';
import { canonicalizePath, isSubpathOf } from '../utils/paths.js';

const COW_DEGRADATION_ERRNOS = new Set(['EXDEV', 'ENOTSUP', 'EOPNOTSUPP', 'EINVAL']);
const COW_DEGRADATION_STDERR_PATTERN =
  /cross-device link|operation not supported|not supported|invalid argument|reflink/i;

function extractStderrText(error: unknown): string {
  if (error !== null && typeof error === 'object' && 'stderr' in error) {
    const stderr = (error as { readonly stderr?: unknown }).stderr;
    if (typeof stderr === 'string') {
      return stderr.trim();
    }
    if (Buffer.isBuffer(stderr)) {
      return stderr.toString('utf8').trim();
    }
  }
  return '';
}

export class CoWCloner {
  private readonly diagnostics: RuntimeDiagnostic[] = [];

  constructor(private readonly onDiagnostic?: DiagnosticReporter) {}

  public getDiagnostics(): readonly RuntimeDiagnostic[] {
    return [...this.diagnostics];
  }

  private emitDiagnostic(diagnostic: RuntimeDiagnostic): void {
    this.diagnostics.push(diagnostic);
    this.onDiagnostic?.(diagnostic);
  }

  async cloneDirectories(
    repoRootPath: string,
    worktreePath: string,
    directories: readonly string[],
  ): Promise<readonly string[]> {
    const canonicalRepo = canonicalizePath(repoRootPath);
    const canonicalWorktree = canonicalizePath(worktreePath);
    const cloned: string[] = [];

    for (const relDir of directories) {
      if (relDir.length === 0 || path.isAbsolute(relDir)) {
        continue;
      }

      const candidateSrc = path.join(canonicalRepo, relDir);
      if (!fs.existsSync(candidateSrc)) {
        continue;
      }

      const canonicalSrc = canonicalizePath(candidateSrc);
      if (!isSubpathOf(canonicalSrc, canonicalRepo)) {
        continue;
      }

      const dstPath = path.join(canonicalWorktree, relDir);
      if (!isSubpathOf(dstPath, canonicalWorktree)) {
        continue;
      }

      fs.mkdirSync(path.dirname(dstPath), { recursive: true });
      if (fs.existsSync(dstPath)) {
        fs.rmSync(dstPath, { recursive: true, force: true });
      }

      this.cloneSingleDirectory(canonicalSrc, dstPath);
      cloned.push(relDir);
    }

    return cloned;
  }

  private cloneSingleDirectory(srcPath: string, dstPath: string): void {
    if (process.platform === 'darwin') {
      try {
        execFileSync('cp', ['-cR', srcPath, dstPath], { stdio: 'pipe' });
        return;
      } catch (err) {
        this.reportCowFallback(err, srcPath, dstPath);
      }
    } else if (process.platform === 'linux') {
      try {
        execFileSync('cp', ['-a', '--reflink=always', srcPath, dstPath], { stdio: 'pipe' });
        return;
      } catch (err) {
        this.reportCowFallback(err, srcPath, dstPath);
      }
    }

    fs.cpSync(srcPath, dstPath, { recursive: true, verbatimSymlinks: true });
  }

  private reportCowFallback(error: unknown, srcPath: string, dstPath: string): void {
    const code = getErrnoCode(error);
    const stderrText = extractStderrText(error);
    const detail = stderrText.length > 0 ? stderrText : formatErrorMessage(error);
    const isDegradation =
      (code !== undefined && COW_DEGRADATION_ERRNOS.has(code)) ||
      COW_DEGRADATION_STDERR_PATTERN.test(detail);

    if (code === 'EACCES' || code === 'EPERM' || code === 'ENOENT') {
      this.emitDiagnostic({
        source: 'CoWCloner',
        code,
        message: `CoW clone failed (${code}) for "${srcPath}" -> "${dstPath}": ${detail}`,
      });
      throw error;
    }

    this.emitDiagnostic({
      source: 'CoWCloner',
      ...(code !== undefined ? { code } : {}),
      message: isDegradation
        ? `CoW clone degraded to full recursive copy for "${srcPath}" -> "${dstPath}": ${detail}`
        : `Unexpected CoW clone failure for "${srcPath}" -> "${dstPath}", falling back to recursive copy: ${detail}`,
    });
  }
}
