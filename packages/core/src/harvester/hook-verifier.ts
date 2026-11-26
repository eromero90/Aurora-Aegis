import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { canonicalizePath } from '../utils/paths.js';

export interface GitIntegritySnapshot {
  readonly repoGitDir: string;
  readonly fileHashes: Readonly<Record<string, string>>;
}

export interface GitIntegrityVerificationResult {
  readonly verified: boolean;
  readonly tamperedPaths: readonly string[];
}

export class GitHookIntegrityVerifier {
  captureSnapshot(repoGitDir: string): GitIntegritySnapshot {
    const canonicalGitDir = canonicalizePath(repoGitDir);
    const fileHashes: Record<string, string> = {};

    const singleFiles = ['config', 'packed-refs'];
    for (const rel of singleFiles) {
      const fullPath = path.join(canonicalGitDir, rel);
      if (fs.existsSync(fullPath) && fs.statSync(fullPath).isFile()) {
        fileHashes[rel] = this.hashFile(fullPath);
      }
    }

    const dirs = ['hooks', path.join('refs', 'heads')];
    for (const relDir of dirs) {
      const fullDir = path.join(canonicalGitDir, relDir);
      if (fs.existsSync(fullDir)) {
        this.walkAndHash(canonicalGitDir, fullDir, fileHashes);
      }
    }

    return {
      repoGitDir: canonicalGitDir,
      fileHashes,
    };
  }

  verifySnapshot(
    baseline: GitIntegritySnapshot,
    repoGitDir?: string,
  ): GitIntegrityVerificationResult {
    const current = this.captureSnapshot(repoGitDir ?? baseline.repoGitDir);
    const allKeys = new Set([
      ...Object.keys(baseline.fileHashes),
      ...Object.keys(current.fileHashes),
    ]);

    const tamperedPaths: string[] = [];
    for (const key of allKeys) {
      if (baseline.fileHashes[key] !== current.fileHashes[key]) {
        tamperedPaths.push(key);
      }
    }

    return {
      verified: tamperedPaths.length === 0,
      tamperedPaths: tamperedPaths.sort(),
    };
  }

  private walkAndHash(
    rootGitDir: string,
    currentDir: string,
    output: Record<string, string>,
  ): void {
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        this.walkAndHash(rootGitDir, fullPath, output);
      } else if (entry.isFile() || entry.isSymbolicLink()) {
        const relKey = path.relative(rootGitDir, fullPath).split(path.sep).join('/');
        output[relKey] = this.hashFile(fullPath);
      }
    }
  }

  private hashFile(filePath: string): string {
    const stat = fs.lstatSync(filePath);
    if (stat.isSymbolicLink()) {
      const target = fs.readlinkSync(filePath);
      return crypto.createHash('sha256').update(`symlink:${target}`).digest('hex');
    }
    const content = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(content).digest('hex');
  }
}
