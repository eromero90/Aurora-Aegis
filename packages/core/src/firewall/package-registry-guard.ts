import fs from 'node:fs';
import path from 'node:path';
import type { PackageRegistryPolicy } from '../types/contracts.js';
import { formatErrorMessage, getErrnoCode } from '../utils/error-codes.js';
import { canonicalizePath } from '../utils/paths.js';

export interface RegistryPackageRequest {
  readonly ecosystem: 'npm' | 'pypi';
  readonly packageName: string;
}

export interface PackageGuardDecision {
  readonly allowed: boolean;
  readonly request?: RegistryPackageRequest | undefined;
  readonly matchedRule?: string | undefined;
}

export interface LockfileDiagnostic {
  readonly filePath: string;
  readonly code?: string | undefined;
  readonly message: string;
}

export interface LockfileDiscoveryResult {
  readonly packages: ReadonlySet<string>;
  readonly diagnostics: readonly LockfileDiagnostic[];
}

const POPULAR_PROTECTED_PACKAGES: readonly string[] = [
  'express',
  'lodash',
  'axios',
  'react',
  'typescript',
  'vitest',
  'next',
  'chalk',
  'commander',
  'zod',
  'requests',
  'urllib3',
  'fastapi',
  'pydantic',
  'numpy',
  'pandas',
  'cryptography',
  'boto3',
  'torch',
];

const BUILT_IN_DENIED_PACKAGES = new Set<string>(['crossenv', 'event-stream-malicious', 'urllib4']);

function normalizePypiName(rawName: string): string {
  return rawName.trim().toLowerCase().replace(/[-_.]+/g, '-');
}

function normalizeRulePattern(pattern: string, ecosystem: 'npm' | 'pypi'): string {
  const lower = pattern.trim().toLowerCase();
  return ecosystem === 'pypi' ? normalizePypiName(lower) : lower;
}

function matchesPackageRuleList(
  rules: readonly string[],
  packageName: string,
  ecosystem: 'npm' | 'pypi',
): boolean {
  for (const rawRule of rules) {
    const trimmed = rawRule.trim().toLowerCase();
    if (trimmed.length === 0) {
      continue;
    }
    if (trimmed.endsWith('/*')) {
      const prefix = trimmed.slice(0, -1);
      if (packageName.startsWith(prefix)) {
        return true;
      }
      continue;
    }
    if (normalizeRulePattern(trimmed, ecosystem) === packageName) {
      return true;
    }
  }
  return false;
}

export function extractRegistryPackageRequest(
  hostname: string,
  pathname: string,
): RegistryPackageRequest | null {
  const host = hostname.toLowerCase();
  let decodedPath = pathname;
  try {
    decodedPath = decodeURIComponent(pathname);
  } catch {
    decodedPath = pathname;
  }

  if (host === 'registry.npmjs.org' || host === 'registry.yarnpkg.com') {
    const trimmed = decodedPath.replace(/^\/+|\/+$/g, '');
    if (trimmed.length === 0 || trimmed.startsWith('-/')) {
      return null;
    }
    const parts = trimmed.split('/');
    if (trimmed.startsWith('@')) {
      if (parts.length >= 2 && parts[0] && parts[1]) {
        return {
          ecosystem: 'npm',
          packageName: `${parts[0].toLowerCase()}/${parts[1].toLowerCase()}`,
        };
      }
      return null;
    }
    if (parts[0]) {
      return {
        ecosystem: 'npm',
        packageName: parts[0].toLowerCase(),
      };
    }
    return null;
  }

  if (host === 'pypi.org') {
    const match = decodedPath.match(/^\/(?:simple|pypi)\/([^/]+)/i);
    if (!match?.[1]) {
      return null;
    }
    return {
      ecosystem: 'pypi',
      packageName: normalizePypiName(match[1]),
    };
  }

  if (host === 'files.pythonhosted.org') {
    const baseName = path.posix.basename(decodedPath);
    if (!baseName) {
      return null;
    }
    const strippedExt = baseName.replace(/\.(?:whl|tar\.gz|zip)$/i, '');
    const match = strippedExt.match(/^([A-Za-z0-9_.-]+?)-\d/);
    if (!match?.[1]) {
      return null;
    }
    return {
      ecosystem: 'pypi',
      packageName: normalizePypiName(match[1]),
    };
  }

  return null;
}

export function discoverRepoLockedPackagesWithDiagnostics(repoRootPath: string): LockfileDiscoveryResult {
  const locked = new Set<string>();
  const diagnostics: LockfileDiagnostic[] = [];

  const recordDiagnostic = (filePath: string, error: unknown) => {
    const code = getErrnoCode(error);
    diagnostics.push({
      filePath,
      ...(code !== undefined ? { code } : {}),
      message: formatErrorMessage(error),
    });
  };

  let canonicalRepo: string;
  try {
    canonicalRepo = canonicalizePath(repoRootPath);
  } catch (err) {
    recordDiagnostic(repoRootPath, err);
    return { packages: locked, diagnostics };
  }

  const pkgJsonPath = path.join(canonicalRepo, 'package.json');
  if (fs.existsSync(pkgJsonPath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8')) as Record<string, unknown>;
      for (const section of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
        const deps = parsed[section];
        if (deps && typeof deps === 'object' && !Array.isArray(deps)) {
          for (const depName of Object.keys(deps as Record<string, unknown>)) {
            locked.add(depName.toLowerCase());
          }
        }
      }
    } catch (err) {
      recordDiagnostic(pkgJsonPath, err);
    }
  }

  const pkgLockPath = path.join(canonicalRepo, 'package-lock.json');
  if (fs.existsSync(pkgLockPath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(pkgLockPath, 'utf8')) as Record<string, unknown>;
      const legacyDeps = parsed['dependencies'];
      if (legacyDeps && typeof legacyDeps === 'object' && !Array.isArray(legacyDeps)) {
        for (const depName of Object.keys(legacyDeps as Record<string, unknown>)) {
          locked.add(depName.toLowerCase());
        }
      }
      const packagesMap = parsed['packages'];
      if (packagesMap && typeof packagesMap === 'object' && !Array.isArray(packagesMap)) {
        for (const pkgPath of Object.keys(packagesMap as Record<string, unknown>)) {
          const marker = 'node_modules/';
          const lastIdx = pkgPath.lastIndexOf(marker);
          if (lastIdx !== -1) {
            const name = pkgPath.slice(lastIdx + marker.length).trim().toLowerCase();
            if (name.length > 0) {
              locked.add(name);
            }
          }
        }
      }
    } catch (err) {
      recordDiagnostic(pkgLockPath, err);
    }
  }

  const pnpmLockPath = path.join(canonicalRepo, 'pnpm-lock.yaml');
  if (fs.existsSync(pnpmLockPath)) {
    try {
      const content = fs.readFileSync(pnpmLockPath, 'utf8');
      for (const line of content.split(/\r?\n/)) {
        const pkgMatch = line.match(/^\s{2,4}['"]?\/?((?:@[A-Za-z0-9_.-]+\/)?[A-Za-z0-9_.-]+)@/);
        if (pkgMatch?.[1]) {
          locked.add(pkgMatch[1].toLowerCase());
        }
      }
    } catch (err) {
      recordDiagnostic(pnpmLockPath, err);
    }
  }

  const requirementsPath = path.join(canonicalRepo, 'requirements.txt');
  if (fs.existsSync(requirementsPath)) {
    try {
      const content = fs.readFileSync(requirementsPath, 'utf8');
      for (const line of content.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (trimmed.length === 0 || trimmed.startsWith('#') || trimmed.startsWith('-')) {
          continue;
        }
        const reqMatch = trimmed.match(/^([A-Za-z0-9_.-]+)/);
        if (reqMatch?.[1]) {
          locked.add(normalizePypiName(reqMatch[1]));
        }
      }
    } catch (err) {
      recordDiagnostic(requirementsPath, err);
    }
  }

  return { packages: locked, diagnostics };
}

export function discoverRepoLockedPackages(repoRootPath: string): ReadonlySet<string> {
  return discoverRepoLockedPackagesWithDiagnostics(repoRootPath).packages;
}

export function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;

  let prev = new Array<number>(n + 1);
  let curr = new Array<number>(n + 1);
  for (let j = 0; j <= n; j += 1) {
    prev[j] = j;
  }

  for (let i = 1; i <= m; i += 1) {
    curr[0] = i;
    for (let j = 1; j <= n; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j]! + 1, curr[j - 1]! + 1, prev[j - 1]! + cost);
    }
    const tmp = prev;
    prev = curr;
    curr = tmp;
  }

  return prev[n]!;
}

function isSingleAdjacentTransposition(a: string, b: string): boolean {
  if (a.length !== b.length || a.length < 2) {
    return false;
  }
  const diffs: number[] = [];
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      diffs.push(i);
      if (diffs.length > 2) {
        return false;
      }
    }
  }
  if (diffs.length !== 2) {
    return false;
  }
  const i = diffs[0]!;
  const j = diffs[1]!;
  return j === i + 1 && a[i] === b[j] && a[j] === b[i];
}

export function detectProtectedPackageTyposquat(packageName: string): string | null {
  const normalized = packageName.trim().toLowerCase();
  const unscoped = normalized.startsWith('@') && normalized.includes('/')
    ? normalized.slice(normalized.indexOf('/') + 1)
    : normalized;

  if (unscoped.length < 3) {
    return null;
  }

  for (const target of POPULAR_PROTECTED_PACKAGES) {
    if (unscoped === target) {
      continue;
    }
    if (levenshteinDistance(unscoped, target) === 1 || isSingleAdjacentTransposition(unscoped, target)) {
      return target;
    }
  }

  return null;
}

export class PackageRegistryGuard {
  private readonly lockedPackages: ReadonlySet<string>;
  private readonly lockfileDiagnostics: readonly LockfileDiagnostic[];
  private readonly policy: PackageRegistryPolicy | undefined;

  constructor(repoRootPath: string, policy?: PackageRegistryPolicy) {
    const discovery = discoverRepoLockedPackagesWithDiagnostics(repoRootPath);
    this.lockedPackages = discovery.packages;
    this.lockfileDiagnostics = discovery.diagnostics;
    this.policy = policy;
  }

  public getLockedPackages(): ReadonlySet<string> {
    return this.lockedPackages;
  }

  public getLockfileDiagnostics(): readonly LockfileDiagnostic[] {
    return this.lockfileDiagnostics;
  }

  public evaluateRequest(hostname: string, pathname: string): PackageGuardDecision {
    const request = extractRegistryPackageRequest(hostname, pathname);
    if (!request) {
      return { allowed: true };
    }

    const deniedList = this.policy?.deniedPackages ?? [];
    if (
      BUILT_IN_DENIED_PACKAGES.has(request.packageName) ||
      matchesPackageRuleList(deniedList, request.packageName, request.ecosystem)
    ) {
      return {
        allowed: false,
        request,
        matchedRule: `DENIED_PACKAGE:${request.packageName}`,
      };
    }

    const allowedList = this.policy?.allowedPackages;
    if (allowedList !== undefined) {
      if (matchesPackageRuleList(allowedList, request.packageName, request.ecosystem)) {
        return { allowed: true, request };
      }
      return {
        allowed: false,
        request,
        matchedRule: `UNLISTED_PACKAGE:${request.packageName}`,
      };
    }

    if (this.policy?.enforceLockfile === true && this.lockfileDiagnostics.length > 0) {
      return {
        allowed: false,
        request,
        matchedRule: `LOCKFILE_PARSE_ERROR:${path.basename(this.lockfileDiagnostics[0]!.filePath)}`,
      };
    }

    const isLocked = this.lockedPackages.has(request.packageName);
    if (this.policy?.enforceLockfile === true && !isLocked) {
      return {
        allowed: false,
        request,
        matchedRule: `LOCKFILE_UNPINNED_PACKAGE:${request.packageName}`,
      };
    }

    if (!isLocked) {
      const suspectTarget = detectProtectedPackageTyposquat(request.packageName);
      if (suspectTarget) {
        return {
          allowed: false,
          request,
          matchedRule: `TYPOSQUAT_SUSPECT:${request.packageName}->${suspectTarget}`,
        };
      }
    }

    return { allowed: true, request };
  }
}
