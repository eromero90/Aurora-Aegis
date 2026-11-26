import fs from 'node:fs';
import path from 'node:path';
import type {
  EgressDomainRule,
  HttpMethod,
  IsolationTier,
  PackageRegistryPolicy,
  SandboxPolicy,
} from '../types/contracts.js';
import { canonicalizePath } from '../utils/paths.js';

export const AEGIS_POLICY_FILENAME = 'aegis.policy.json';

const VALID_HTTP_METHODS = new Set<HttpMethod>([
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'HEAD',
  'OPTIONS',
]);

export interface AegisPolicyFileSchema {
  readonly version: 1;
  readonly tier?: IsolationTier | undefined;
  readonly cowDirectories?: readonly string[] | undefined;
  readonly readOnlyToolchainPaths?: readonly string[] | undefined;
  readonly egressRules?: readonly EgressDomainRule[] | undefined;
  readonly protectedSecrets?: readonly string[] | undefined;
  readonly outboundByteBudget?: number | undefined;
  readonly packagePolicy?: PackageRegistryPolicy | undefined;
  readonly timeoutMs?: number | undefined;
}

function validatePackagePolicy(value: unknown): PackageRegistryPolicy {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`Invalid "packagePolicy" in ${AEGIS_POLICY_FILENAME}: expected object.`);
  }
  const rec = value as Record<string, unknown>;
  const allowedPackages =
    rec['allowedPackages'] !== undefined
      ? assertStringArray(rec['allowedPackages'], 'packagePolicy.allowedPackages')
      : undefined;
  const deniedPackages =
    rec['deniedPackages'] !== undefined
      ? assertStringArray(rec['deniedPackages'], 'packagePolicy.deniedPackages')
      : undefined;

  let enforceLockfile: boolean | undefined;
  if (rec['enforceLockfile'] !== undefined) {
    if (typeof rec['enforceLockfile'] !== 'boolean') {
      throw new Error(`Invalid "packagePolicy.enforceLockfile" in ${AEGIS_POLICY_FILENAME}: expected boolean.`);
    }
    enforceLockfile = rec['enforceLockfile'];
  }

  return {
    ...(allowedPackages !== undefined ? { allowedPackages } : {}),
    ...(deniedPackages !== undefined ? { deniedPackages } : {}),
    ...(enforceLockfile !== undefined ? { enforceLockfile } : {}),
  };
}

function assertStringArray(value: unknown, fieldName: string): readonly string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    throw new Error(`Invalid "${fieldName}" in ${AEGIS_POLICY_FILENAME}: expected array of strings.`);
  }
  return value as string[];
}

function validateEgressRules(value: unknown): readonly EgressDomainRule[] {
  if (!Array.isArray(value)) {
    throw new Error(`Invalid "egressRules" in ${AEGIS_POLICY_FILENAME}: expected array.`);
  }

  return value.map((item, idx) => {
    if (item === null || typeof item !== 'object' || Array.isArray(item)) {
      throw new Error(`Invalid "egressRules[${idx}]" in ${AEGIS_POLICY_FILENAME}: expected object.`);
    }
    const record = item as Record<string, unknown>;
    const domain = record['domain'];
    const rawMethods = record['allowedMethods'];
    if (typeof domain !== 'string' || domain.trim().length === 0) {
      throw new Error(`Invalid "egressRules[${idx}].domain" in ${AEGIS_POLICY_FILENAME}: expected non-empty string.`);
    }
    if (!Array.isArray(rawMethods) || rawMethods.length === 0) {
      throw new Error(
        `Invalid "egressRules[${idx}].allowedMethods" in ${AEGIS_POLICY_FILENAME}: expected non-empty array.`,
      );
    }
    for (const method of rawMethods) {
      if (typeof method !== 'string' || !VALID_HTTP_METHODS.has(method as HttpMethod)) {
        throw new Error(
          `Invalid HTTP method "${String(method)}" in ${AEGIS_POLICY_FILENAME} egressRules[${idx}].`,
        );
      }
    }
    return {
      domain: domain.trim(),
      allowedMethods: [...new Set(rawMethods as HttpMethod[])],
    };
  });
}

export function loadRepositoryPolicyFile(repoRootPath: string): AegisPolicyFileSchema | null {
  const canonicalRepo = canonicalizePath(repoRootPath);
  const policyPath = path.join(canonicalRepo, AEGIS_POLICY_FILENAME);
  if (!fs.existsSync(policyPath)) {
    return null;
  }

  let rawJson: unknown;
  try {
    rawJson = JSON.parse(fs.readFileSync(policyPath, 'utf8'));
  } catch (err) {
    throw new Error(
      `Failed to parse ${AEGIS_POLICY_FILENAME} at "${policyPath}": ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  if (rawJson === null || typeof rawJson !== 'object' || Array.isArray(rawJson)) {
    throw new Error(`Invalid ${AEGIS_POLICY_FILENAME}: root value must be a JSON object.`);
  }

  const record = rawJson as Record<string, unknown>;
  if (record['version'] !== 1) {
    throw new Error(`Invalid "version" in ${AEGIS_POLICY_FILENAME}: expected 1.`);
  }

  let tier: IsolationTier | undefined;
  if (record['tier'] !== undefined) {
    if (record['tier'] !== 'tier1-kernel-mac' && record['tier'] !== 'tier2-microvm') {
      throw new Error(`Invalid "tier" in ${AEGIS_POLICY_FILENAME}: "${String(record['tier'])}".`);
    }
    tier = record['tier'];
  }

  const cowDirectories =
    record['cowDirectories'] !== undefined ? assertStringArray(record['cowDirectories'], 'cowDirectories') : undefined;
  const readOnlyToolchainPaths =
    record['readOnlyToolchainPaths'] !== undefined
      ? assertStringArray(record['readOnlyToolchainPaths'], 'readOnlyToolchainPaths')
      : undefined;
  const protectedSecrets =
    record['protectedSecrets'] !== undefined
      ? assertStringArray(record['protectedSecrets'], 'protectedSecrets')
      : undefined;
  const egressRules =
    record['egressRules'] !== undefined ? validateEgressRules(record['egressRules']) : undefined;

  let outboundByteBudget: number | undefined;
  if (record['outboundByteBudget'] !== undefined) {
    const val = record['outboundByteBudget'];
    if (typeof val !== 'number' || !Number.isFinite(val) || val <= 0) {
      throw new Error(`Invalid "outboundByteBudget" in ${AEGIS_POLICY_FILENAME}: expected positive number.`);
    }
    outboundByteBudget = Math.floor(val);
  }

  let timeoutMs: number | undefined;
  if (record['timeoutMs'] !== undefined) {
    const val = record['timeoutMs'];
    if (typeof val !== 'number' || !Number.isFinite(val) || val <= 0) {
      throw new Error(`Invalid "timeoutMs" in ${AEGIS_POLICY_FILENAME}: expected positive number.`);
    }
    timeoutMs = Math.floor(val);
  }

  const packagePolicy =
    record['packagePolicy'] !== undefined ? validatePackagePolicy(record['packagePolicy']) : undefined;

  return {
    version: 1,
    ...(tier !== undefined ? { tier } : {}),
    ...(cowDirectories !== undefined ? { cowDirectories } : {}),
    ...(readOnlyToolchainPaths !== undefined ? { readOnlyToolchainPaths } : {}),
    ...(egressRules !== undefined ? { egressRules } : {}),
    ...(protectedSecrets !== undefined ? { protectedSecrets } : {}),
    ...(outboundByteBudget !== undefined ? { outboundByteBudget } : {}),
    ...(packagePolicy !== undefined ? { packagePolicy } : {}),
    ...(timeoutMs !== undefined ? { timeoutMs } : {}),
  };
}

function mergePackagePolicies(
  base?: PackageRegistryPolicy,
  repo?: PackageRegistryPolicy,
): PackageRegistryPolicy | undefined {
  if (!base && !repo) {
    return undefined;
  }

  const hasDenied = base?.deniedPackages !== undefined || repo?.deniedPackages !== undefined;
  const deniedPackages = hasDenied
    ? [...new Set([...(base?.deniedPackages ?? []), ...(repo?.deniedPackages ?? [])])]
    : undefined;

  let allowedPackages: readonly string[] | undefined;
  if (base?.allowedPackages !== undefined && repo?.allowedPackages !== undefined) {
    const repoSet = new Set(repo.allowedPackages.map((pkg) => pkg.toLowerCase()));
    allowedPackages = base.allowedPackages.filter((pkg) => repoSet.has(pkg.toLowerCase()));
  } else {
    allowedPackages = base?.allowedPackages ?? repo?.allowedPackages;
  }

  const enforceLockfile =
    base?.enforceLockfile !== undefined || repo?.enforceLockfile !== undefined
      ? Boolean(base?.enforceLockfile || repo?.enforceLockfile)
      : undefined;

  return {
    ...(allowedPackages !== undefined ? { allowedPackages } : {}),
    ...(deniedPackages !== undefined ? { deniedPackages } : {}),
    ...(enforceLockfile !== undefined ? { enforceLockfile } : {}),
  };
}

function mergeEgressRules(
  baseRules: readonly EgressDomainRule[],
  repoRules?: readonly EgressDomainRule[],
): readonly EgressDomainRule[] {
  if (!repoRules || repoRules.length === 0) {
    return baseRules;
  }
  const merged = new Map<string, Set<HttpMethod>>();
  for (const rule of [...baseRules, ...repoRules]) {
    const key = rule.domain.toLowerCase();
    const methods = merged.get(key) ?? new Set<HttpMethod>();
    for (const m of rule.allowedMethods) {
      methods.add(m);
    }
    merged.set(key, methods);
  }
  return [...merged.entries()].map(([domain, methods]) => ({
    domain,
    allowedMethods: [...methods],
  }));
}

export function mergePolicyWithRepoConfig(
  basePolicy: SandboxPolicy,
  repoConfig: AegisPolicyFileSchema | null,
): SandboxPolicy {
  if (!repoConfig) {
    return basePolicy;
  }

  const outboundByteBudget =
    basePolicy.outboundByteBudget !== undefined && repoConfig.outboundByteBudget !== undefined
      ? Math.min(basePolicy.outboundByteBudget, repoConfig.outboundByteBudget)
      : (repoConfig.outboundByteBudget ?? basePolicy.outboundByteBudget);

  const timeoutMs =
    repoConfig.timeoutMs !== undefined ? Math.min(basePolicy.timeoutMs, repoConfig.timeoutMs) : basePolicy.timeoutMs;
  const mergedPackagePolicy = mergePackagePolicies(basePolicy.packagePolicy, repoConfig.packagePolicy);

  return {
    ...basePolicy,
    tier: repoConfig.tier ?? basePolicy.tier,
    cowDirectories: [...new Set([...basePolicy.cowDirectories, ...(repoConfig.cowDirectories ?? [])])],
    readOnlyToolchainPaths: [
      ...new Set([...basePolicy.readOnlyToolchainPaths, ...(repoConfig.readOnlyToolchainPaths ?? [])]),
    ],
    egressRules: mergeEgressRules(basePolicy.egressRules, repoConfig.egressRules),
    protectedSecrets: [...new Set([...basePolicy.protectedSecrets, ...(repoConfig.protectedSecrets ?? [])])],
    ...(outboundByteBudget !== undefined ? { outboundByteBudget } : {}),
    ...(mergedPackagePolicy !== undefined ? { packagePolicy: mergedPackagePolicy } : {}),
    timeoutMs,
  };
}
