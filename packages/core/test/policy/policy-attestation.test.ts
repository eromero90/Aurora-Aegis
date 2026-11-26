import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  AEGIS_POLICY_FILENAME,
  PersistenceScanner,
  SandboxSessionOrchestrator,
  type SandboxPolicy,
  canonicalizePath,
  loadRepositoryPolicyFile,
  mergePolicyWithRepoConfig,
  verifyHarvestAttestation,
} from '../../src/index.js';
import { TestShellDriver } from '../../test-helpers/test-shell-driver.js';

const tempDirs: string[] = [];

function createTempRepo(files: Record<string, string>): string {
  const dir = canonicalizePath(fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-m8-')));
  tempDirs.push(dir);
  execFileSync('git', ['init', '-b', 'main'], { cwd: dir, stdio: 'pipe' });
  execFileSync('git', ['config', 'user.email', 'm8-test@aurora-aegis.local'], { cwd: dir, stdio: 'pipe' });
  execFileSync('git', ['config', 'user.name', 'Aegis M8 Test'], { cwd: dir, stdio: 'pipe' });

  for (const [relPath, content] of Object.entries(files)) {
    const absPath = path.join(dir, relPath);
    fs.mkdirSync(path.dirname(absPath), { recursive: true });
    fs.writeFileSync(absPath, content, 'utf8');
  }

  execFileSync('git', ['add', '-A'], { cwd: dir, stdio: 'pipe' });
  execFileSync('git', ['commit', '-m', 'initial commit'], { cwd: dir, stdio: 'pipe' });
  return dir;
}

function buildBasePolicy(repoRootPath: string, sessionId: string): SandboxPolicy {
  return {
    sessionId,
    repoRootPath,
    tier: 'tier1-kernel-mac',
    cowDirectories: [],
    readOnlyToolchainPaths: [path.dirname(process.execPath)],
    egressRules: [{ domain: 'registry.npmjs.org', allowedMethods: ['GET'] }],
    phantomCredentials: [],
    protectedSecrets: [],
    outboundByteBudget: 65_536,
    timeoutMs: 60_000,
  };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir && fs.existsSync(dir)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

describe('Policy-as-Code & Harvest Attestation', () => {
  it('loads valid aegis.policy.json, tightens bounds on merge, and fails closed on invalid schemas', () => {
    const validRepo = createTempRepo({
      'README.md': '# policy test\n',
      [AEGIS_POLICY_FILENAME]: JSON.stringify({
        version: 1,
        egressRules: [{ domain: 'api.github.com', allowedMethods: ['GET', 'POST'] }],
        protectedSecrets: ['MY_API_KEY'],
        outboundByteBudget: 4096,
        timeoutMs: 12_000,
      }),
    });

    const parsed = loadRepositoryPolicyFile(validRepo);
    expect(parsed).not.toBeNull();
    expect(parsed?.version).toBe(1);

    const basePolicy = buildBasePolicy(validRepo, 'm8-merge-test');
    const merged = mergePolicyWithRepoConfig(basePolicy, parsed);
    expect(merged.timeoutMs).toBe(12_000);
    expect(merged.outboundByteBudget).toBe(4096);
    expect(merged.protectedSecrets).toContain('MY_API_KEY');
    expect(merged.egressRules.map((rule) => rule.domain)).toContain('api.github.com');
    expect(merged.egressRules.map((rule) => rule.domain)).toContain('registry.npmjs.org');

    const badJsonRepo = createTempRepo({
      [AEGIS_POLICY_FILENAME]: '{ invalid json',
    });
    expect(() => loadRepositoryPolicyFile(badJsonRepo)).toThrow(/Failed to parse aegis\.policy\.json/);

    const badSchemaRepo = createTempRepo({
      [AEGIS_POLICY_FILENAME]: JSON.stringify({ version: 2, timeoutMs: -5 }),
    });
    expect(() => loadRepositoryPolicyFile(badSchemaRepo)).toThrow(/Invalid "version"/);
  });

  it('locks aegis.policy.json in-sandbox on Seatbelt hosts and detects policy tampering in PersistenceScanner', async () => {
    const originalPolicyText = JSON.stringify(
      {
        version: 1,
        egressRules: [{ domain: 'api.github.com', allowedMethods: ['GET'] }],
        outboundByteBudget: 8192,
        timeoutMs: 20_000,
      },
      null,
      2,
    );
    const repo = createTempRepo({
      'src/index.ts': 'export const ok = true;\n',
      [AEGIS_POLICY_FILENAME]: originalPolicyText,
    });

    const orchestrator = new SandboxSessionOrchestrator({
      policy: buildBasePolicy(repo, 'm8-lock-test'),
    });

    try {
      const workspace = await orchestrator.start();
      const effective = orchestrator.getEffectivePolicy();
      expect(effective.timeoutMs).toBe(20_000);
      expect(effective.outboundByteBudget).toBe(8192);
      expect(effective.egressRules.map((rule) => rule.domain)).toContain('api.github.com');

      if (process.platform === 'darwin' && fs.existsSync('/usr/bin/sandbox-exec')) {
        const tamperCmd = await orchestrator.exec(
          `${JSON.stringify(process.execPath)} -e "require('node:fs').writeFileSync('aegis.policy.json', 'tampered')"`,
        );
        expect(tamperCmd.exitCode).not.toBe(0);
        const worktreePolicyPath = path.join(workspace.worktreePath, AEGIS_POLICY_FILENAME);
        expect(fs.readFileSync(worktreePolicyPath, 'utf8')).toBe(originalPolicyText);
      }
    } finally {
      await orchestrator.close();
    }

    const scanner = new PersistenceScanner();
    const policyFindings = scanner.scanDiff([AEGIS_POLICY_FILENAME], '');
    expect(policyFindings.some((finding) => finding.category === 'POLICY_FILE_TAMPER')).toBe(true);
  });

  it('signs every HarvestResult with Ed25519 attestation and rejects tampered payloads', async () => {
    const repo = createTempRepo({
      'app.txt': 'v1\n',
    });

    const orchestrator = new SandboxSessionOrchestrator({
      policy: buildBasePolicy(repo, 'm8-attest-test'),
      driver: process.platform === 'darwin' ? undefined : new TestShellDriver(),
    });

    try {
      await orchestrator.start();
      const cmdResult = await orchestrator.exec(
        `${JSON.stringify(process.execPath)} -e "require('node:fs').writeFileSync('feature.txt', 'hello aegis\\n')"`,
      );
      expect(cmdResult.exitCode).toBe(0);

      const harvest = await orchestrator.harvest(true);
      expect(harvest.appliedToHost).toBe(true);
      expect(harvest.changedFiles).toEqual(['feature.txt']);
      expect(harvest.attestation).toBeDefined();

      const attestation = harvest.attestation!;
      expect(attestation.schemaVersion).toBe('1.0');
      expect(attestation.sessionId).toBe('m8-attest-test');
      expect(attestation.repoRootPath).toBe(repo);
      expect(attestation.executedCommandCount).toBe(1);
      expect(attestation.hookIntegrityVerified).toBe(true);
      expect(attestation.canaryTriggered).toBe(false);
      expect(attestation.appliedToHost).toBe(true);
      expect(verifyHarvestAttestation(attestation)).toBe(true);

      expect(verifyHarvestAttestation({ ...attestation, patchSha256: '0'.repeat(64) })).toBe(false);
      expect(verifyHarvestAttestation({ ...attestation, appliedToHost: false })).toBe(false);
      expect(verifyHarvestAttestation({ ...attestation, canaryTriggered: true })).toBe(false);
      expect(verifyHarvestAttestation({ ...attestation, hookIntegrityVerified: false })).toBe(false);

      orchestrator.triggerCanaryTripwire('simulated canary leak');
      const abortedHarvest = await orchestrator.harvest(true);
      expect(abortedHarvest.appliedToHost).toBe(false);
      expect(abortedHarvest.attestation).toBeDefined();
      expect(abortedHarvest.attestation?.canaryTriggered).toBe(true);
      expect(verifyHarvestAttestation(abortedHarvest.attestation!)).toBe(true);
    } finally {
      await orchestrator.close();
    }
  });
});
