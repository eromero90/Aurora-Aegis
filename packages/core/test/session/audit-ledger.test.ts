import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  type AuditLedgerEntry,
  GENESIS_PREV_SHA256,
  SandboxSessionOrchestrator,
  type SandboxPolicy,
  canonicalizePath,
  parseAndVerifyAuditLedgerJsonl,
  verifyAuditLedgerEntries,
} from '../../src/index.js';
import { TestShellDriver } from '../../test-helpers/test-shell-driver.js';

const tempDirs: string[] = [];

function createTempRepo(files: Record<string, string>): string {
  const dir = canonicalizePath(fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-m9-')));
  tempDirs.push(dir);
  execFileSync('git', ['init', '-b', 'main'], { cwd: dir, stdio: 'pipe' });
  execFileSync('git', ['config', 'user.email', 'm9-test@aurora-aegis.local'], { cwd: dir, stdio: 'pipe' });
  execFileSync('git', ['config', 'user.name', 'Aegis M9 Test'], { cwd: dir, stdio: 'pipe' });

  for (const [relPath, content] of Object.entries(files)) {
    const absPath = path.join(dir, relPath);
    fs.mkdirSync(path.dirname(absPath), { recursive: true });
    fs.writeFileSync(absPath, content, 'utf8');
  }

  execFileSync('git', ['add', '-A'], { cwd: dir, stdio: 'pipe' });
  execFileSync('git', ['commit', '-m', 'init'], { cwd: dir, stdio: 'pipe' });
  return dir;
}

function buildPolicy(repoRootPath: string, sessionId: string): SandboxPolicy {
  return {
    sessionId,
    repoRootPath,
    tier: 'tier1-kernel-mac',
    cowDirectories: [],
    readOnlyToolchainPaths: [path.dirname(process.execPath)],
    egressRules: [{ domain: 'registry.npmjs.org', allowedMethods: ['GET'] }],
    phantomCredentials: [],
    protectedSecrets: [],
    timeoutMs: 30_000,
  };
}

function serializeCore(entry: AuditLedgerEntry): Buffer {
  const sortObj = (val: unknown): unknown => {
    if (Array.isArray(val)) {
      return val.map(sortObj);
    }
    if (val !== null && typeof val === 'object') {
      const sorted: Record<string, unknown> = {};
      for (const k of Object.keys(val as Record<string, unknown>).sort()) {
        const v = (val as Record<string, unknown>)[k];
        if (v !== undefined) {
          sorted[k] = sortObj(v);
        }
      }
      return sorted;
    }
    return val;
  };
  return Buffer.from(
    JSON.stringify({
      sequence: entry.sequence,
      sessionId: entry.sessionId,
      timestamp: entry.timestamp,
      eventType: entry.eventType,
      details: sortObj(entry.details),
      prevEntrySha256: entry.prevEntrySha256,
    }),
    'utf8',
  );
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir && fs.existsSync(dir)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

describe('Tamper-Evident Session Audit Ledger', () => {
  it('records hash-chained and Ed25519-signed lifecycle, execution, and harvest events to JSONL', async () => {
    const repo = createTempRepo({ 'file.txt': 'initial\n' });
    const orchestrator = new SandboxSessionOrchestrator({
      policy: buildPolicy(repo, 'm9-ledger-session'),
      driver: process.platform === 'darwin' ? undefined : new TestShellDriver(),
    });

    const workspace = await orchestrator.start();
    try {
      const execResult = await orchestrator.exec(
        `${JSON.stringify(process.execPath)} -e "require('node:fs').writeFileSync('output.txt', 'ok\\n')"`,
      );
      expect(execResult.exitCode).toBe(0);

      const harvestResult = await orchestrator.harvest(true);
      expect(harvestResult.appliedToHost).toBe(true);
      expect(harvestResult.auditLedgerEntries).toBeDefined();

      const ledgerEntries = orchestrator.getAuditLedger();
      expect(ledgerEntries.length).toBeGreaterThanOrEqual(6);
      expect(harvestResult.auditLedgerEntries).toEqual(ledgerEntries);
      expect(ledgerEntries[0]?.prevEntrySha256).toBe(GENESIS_PREV_SHA256);

      const eventTypes = ledgerEntries.map((entry) => entry.eventType);
      expect(eventTypes).toContain('SESSION_STATE_CHANGED');
      expect(eventTypes).toContain('COMMAND_EXECUTED');
      expect(eventTypes).toContain('HARVEST_COMPLETED');

      for (let i = 1; i < ledgerEntries.length; i += 1) {
        expect(ledgerEntries[i]!.sequence).toBe(i);
        expect(ledgerEntries[i]!.prevEntrySha256).toBe(ledgerEntries[i - 1]!.entrySha256);
      }

      const memoryCheck = verifyAuditLedgerEntries(ledgerEntries);
      expect(memoryCheck.valid).toBe(true);
      expect(memoryCheck.entryCount).toBe(ledgerEntries.length);
      expect(memoryCheck.sessionId).toBe('m9-ledger-session');

      const ledgerFilePath = path.join(workspace.sessionTmpDir, 'audit-ledger.jsonl');
      expect(fs.existsSync(ledgerFilePath)).toBe(true);
      const diskJsonl = fs.readFileSync(ledgerFilePath, 'utf8');
      const diskCheck = parseAndVerifyAuditLedgerJsonl(diskJsonl);
      expect(diskCheck.valid).toBe(true);
      expect(diskCheck.entryCount).toBe(ledgerEntries.length);
    } finally {
      await orchestrator.close();
    }

    const exportedAfterClose = orchestrator.exportAuditLedgerJsonl();
    const postCloseCheck = parseAndVerifyAuditLedgerJsonl(exportedAfterClose);
    expect(postCloseCheck.valid).toBe(true);
    expect(exportedAfterClose).toContain('"to":"cleaned-up"');
  });

  it('rejects payload mutation, hash recomputation without private key, gaps, swaps, and rogue key substitution', async () => {
    const repo = createTempRepo({ 'a.txt': 'hello\n' });
    const orchestrator = new SandboxSessionOrchestrator({
      policy: buildPolicy(repo, 'm9-tamper-session'),
      driver: process.platform === 'darwin' ? undefined : new TestShellDriver(),
    });

    try {
      await orchestrator.start();
      await orchestrator.exec(`${JSON.stringify(process.execPath)} -e "process.exit(0)"`);
      await orchestrator.harvest(false);
    } finally {
      await orchestrator.close();
    }

    const baseline = orchestrator.getAuditLedger();
    expect(verifyAuditLedgerEntries(baseline).valid).toBe(true);

    const targetIdx = baseline.findIndex((entry) => entry.eventType === 'COMMAND_EXECUTED');
    expect(targetIdx).toBeGreaterThan(0);
    const targetEntry = baseline[targetIdx]!;

    const detailsMutated = baseline.map((entry, idx) =>
      idx === targetIdx ? { ...entry, details: { ...entry.details, exitCode: 99 } } : entry,
    );
    const detailsMutatedResult = verifyAuditLedgerEntries(detailsMutated);
    expect(detailsMutatedResult.valid).toBe(false);
    expect(detailsMutatedResult.brokenAtSequence).toBe(targetEntry.sequence);

    const forgedDetailsEntry: AuditLedgerEntry = {
      ...targetEntry,
      details: { ...targetEntry.details, exitCode: 99 },
    };
    const forgedHash = crypto.createHash('sha256').update(serializeCore(forgedDetailsEntry)).digest('hex');
    const rehashedWithoutKey = baseline.map((entry, idx) =>
      idx === targetIdx ? { ...forgedDetailsEntry, entrySha256: forgedHash } : entry,
    );
    const rehashedResult = verifyAuditLedgerEntries(rehashedWithoutKey);
    expect(rehashedResult.valid).toBe(false);
    expect(rehashedResult.brokenAtSequence).toBe(targetEntry.sequence);

    const removedMiddle = baseline.filter((_, idx) => idx !== targetIdx);
    const removedResult = verifyAuditLedgerEntries(removedMiddle);
    expect(removedResult.valid).toBe(false);

    const swapped = [...baseline];
    const swapA = swapped[1]!;
    const swapB = swapped[2]!;
    swapped[1] = swapB;
    swapped[2] = swapA;
    expect(verifyAuditLedgerEntries(swapped).valid).toBe(false);

    const lastIdx = baseline.length - 1;
    const tailEntry = baseline[lastIdx]!;
    const rogueKeys = crypto.generateKeyPairSync('ed25519');
    const roguePubPem = rogueKeys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const rogueCore = serializeCore(tailEntry);
    const rogueHash = crypto.createHash('sha256').update(rogueCore).digest('hex');
    const rogueSig = crypto
      .sign(null, Buffer.from(`${rogueCore.toString('utf8')}:${rogueHash}`, 'utf8'), rogueKeys.privateKey)
      .toString('base64');

    const rogueReplaced = baseline.map((entry, idx) =>
      idx === lastIdx
        ? {
            ...entry,
            entrySha256: rogueHash,
            publicKeyPem: roguePubPem,
            signatureBase64: rogueSig,
          }
        : entry,
    );
    const rogueResult = verifyAuditLedgerEntries(rogueReplaced);
    expect(rogueResult.valid).toBe(false);
    expect(rogueResult.brokenAtSequence).toBe(tailEntry.sequence);
  });
});
