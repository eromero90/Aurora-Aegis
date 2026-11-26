import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  type DiagnosticReporter,
  formatErrorMessage,
  getErrnoCode,
  isExpectedErrno,
} from '../utils/error-codes.js';
import { canonicalizePath } from '../utils/paths.js';

const EXPECTED_PROBE_ERRNOS = new Set(['ENOENT', 'ENOTDIR']);

export const DEFAULT_EGRESS_HOSTS: readonly string[] = [
  'registry.npmjs.org',
  'registry.yarnpkg.com',
  'pypi.org',
  'files.pythonhosted.org',
  'crates.io',
  'static.crates.io',
  'api.github.com',
  'api.anthropic.com',
  'api.openai.com',
  'generativelanguage.googleapis.com',
];

export const FORBIDDEN_HOME_SECRET_REL_PATHS: readonly string[] = [
  '.ssh',
  '.aws',
  '.gnupg',
  '.kube',
  '.config/gcloud',
  '.azure',
  '.docker',
  'Library/Keychains',
];

const HOME_TOOLCHAIN_CANDIDATES: readonly string[] = [
  '.nvm',
  '.fnm',
  '.volta',
  '.asdf',
  '.mise',
  '.local/share/pnpm',
  '.local/share/fnm',
  '.local/share/mise',
  '.local/bin',
  'Library/pnpm',
  '.bun',
  '.deno',
  '.cargo',
  '.rustup',
  '.pyenv',
  '.uv',
  '.sdkman',
];

function isPathEqualOrInside(targetPath: string, baseDir: string): boolean {
  const rel = path.relative(baseDir, targetPath);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

export function isForbiddenHomeSecretPath(candidatePath: string, homeDir = os.homedir()): boolean {
  const realHome = canonicalizePath(homeDir);
  const realCandidate = canonicalizePath(candidatePath);

  if (realCandidate === realHome) {
    return true;
  }

  for (const relSecret of FORBIDDEN_HOME_SECRET_REL_PATHS) {
    const secretAbs = canonicalizePath(path.join(realHome, relSecret));
    if (isPathEqualOrInside(realCandidate, secretAbs) || isPathEqualOrInside(secretAbs, realCandidate)) {
      return true;
    }
  }

  return false;
}

export interface DiscoverToolchainOptions {
  readonly homeDir?: string | undefined;
  readonly pathEnv?: string | undefined;
  readonly onDiagnostic?: DiagnosticReporter | undefined;
}

export function discoverHostToolchainPaths(options: DiscoverToolchainOptions = {}): string[] {
  const discovered = new Set<string>([canonicalizePath(path.dirname(process.execPath))]);
  const realHome = canonicalizePath(options.homeDir ?? os.homedir());

  for (const relCandidate of HOME_TOOLCHAIN_CANDIDATES) {
    const fullPath = path.join(realHome, relCandidate);
    if (!fs.existsSync(fullPath)) {
      continue;
    }
    try {
      const realCandidate = canonicalizePath(fullPath);
      if (fs.statSync(realCandidate).isDirectory() && !isForbiddenHomeSecretPath(realCandidate, realHome)) {
        discovered.add(realCandidate);
      }
    } catch (err) {
      if (!isExpectedErrno(err, EXPECTED_PROBE_ERRNOS)) {
        options.onDiagnostic?.({
          source: 'discoverHostToolchainPaths',
          code: getErrnoCode(err),
          message: `Failed to inspect toolchain candidate "${fullPath}": ${formatErrorMessage(err)}`,
        });
      }
    }
  }

  const rawPath = options.pathEnv ?? process.env['PATH'] ?? '';
  for (const segment of rawPath.split(path.delimiter)) {
    const trimmed = segment.trim();
    if (trimmed.length === 0 || !fs.existsSync(trimmed)) {
      continue;
    }
    try {
      const realEntry = canonicalizePath(trimmed);
      if (
        fs.statSync(realEntry).isDirectory() &&
        isPathEqualOrInside(realEntry, realHome) &&
        !isForbiddenHomeSecretPath(realEntry, realHome)
      ) {
        discovered.add(realEntry);
      }
    } catch (err) {
      if (!isExpectedErrno(err, EXPECTED_PROBE_ERRNOS)) {
        options.onDiagnostic?.({
          source: 'discoverHostToolchainPaths',
          code: getErrnoCode(err),
          message: `Failed to inspect PATH segment "${trimmed}": ${formatErrorMessage(err)}`,
        });
      }
    }
  }

  return [...discovered];
}

export function discoverDefaultCowDirectories(
  repoRootPath: string,
  onDiagnostic?: DiagnosticReporter,
): string[] {
  const canonicalRepo = canonicalizePath(repoRootPath);
  const detected: string[] = [];

  for (const candidate of ['node_modules', '.venv', 'venv']) {
    const fullPath = path.join(canonicalRepo, candidate);
    if (!fs.existsSync(fullPath)) {
      continue;
    }
    try {
      if (fs.lstatSync(fullPath).isDirectory()) {
        detected.push(candidate);
      }
    } catch (err) {
      if (!isExpectedErrno(err, EXPECTED_PROBE_ERRNOS)) {
        onDiagnostic?.({
          source: 'discoverDefaultCowDirectories',
          code: getErrnoCode(err),
          message: `Failed to inspect CoW directory candidate "${fullPath}": ${formatErrorMessage(err)}`,
        });
      }
    }
  }

  return detected;
}
