import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { AttestationSigner } from '../harvester/attestation.js';
import type {
  AuditLedgerEntry,
  AuditLedgerEventType,
  AuditLedgerVerificationResult,
} from '../types/contracts.js';

export const GENESIS_PREV_SHA256 = '0'.repeat(64);

type LedgerEntryCoreFields = Omit<AuditLedgerEntry, 'entrySha256' | 'publicKeyPem' | 'signatureBase64'>;

function canonicalizeDetails(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => canonicalizeDetails(item));
  }
  if (value !== null && typeof value === 'object') {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const entryValue = (value as Record<string, unknown>)[key];
      if (entryValue !== undefined) {
        sorted[key] = canonicalizeDetails(entryValue);
      }
    }
    return sorted;
  }
  return value;
}

function serializeLedgerEntryCore(fields: LedgerEntryCoreFields): Buffer {
  const canonical = JSON.stringify({
    sequence: fields.sequence,
    sessionId: fields.sessionId,
    timestamp: fields.timestamp,
    eventType: fields.eventType,
    details: canonicalizeDetails(fields.details),
    prevEntrySha256: fields.prevEntrySha256,
  });
  return Buffer.from(canonical, 'utf8');
}

function buildSignedLedgerBytes(coreBytes: Buffer, entrySha256: string): Buffer {
  return Buffer.from(`${coreBytes.toString('utf8')}:${entrySha256}`, 'utf8');
}

function isLedgerEntryShape(value: unknown): value is AuditLedgerEntry {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const rec = value as Record<string, unknown>;
  return (
    typeof rec['sequence'] === 'number' &&
    typeof rec['sessionId'] === 'string' &&
    typeof rec['timestamp'] === 'string' &&
    typeof rec['eventType'] === 'string' &&
    rec['details'] !== null &&
    typeof rec['details'] === 'object' &&
    !Array.isArray(rec['details']) &&
    typeof rec['prevEntrySha256'] === 'string' &&
    typeof rec['entrySha256'] === 'string' &&
    typeof rec['publicKeyPem'] === 'string' &&
    typeof rec['signatureBase64'] === 'string'
  );
}

export class SessionAuditLedger {
  private readonly sessionId: string;
  private readonly signer: AttestationSigner;
  private readonly entries: AuditLedgerEntry[] = [];
  private lastEntrySha256 = GENESIS_PREV_SHA256;
  private ledgerFilePath: string | undefined;

  constructor(sessionId: string, signer: AttestationSigner, ledgerFilePath?: string) {
    this.sessionId = sessionId;
    this.signer = signer;
    this.ledgerFilePath = ledgerFilePath;
  }

  public setLedgerFilePath(filePath: string): void {
    this.ledgerFilePath = filePath;
    if (fs.existsSync(path.dirname(filePath))) {
      fs.writeFileSync(filePath, this.exportJsonl(), 'utf8');
    }
  }

  public getLedgerFilePath(): string | undefined {
    return this.ledgerFilePath;
  }

  public append(
    eventType: AuditLedgerEventType,
    details: Readonly<Record<string, unknown>>,
    timestamp?: string,
  ): AuditLedgerEntry {
    const coreFields: LedgerEntryCoreFields = {
      sequence: this.entries.length,
      sessionId: this.sessionId,
      timestamp: timestamp ?? new Date().toISOString(),
      eventType,
      details: canonicalizeDetails(details) as Readonly<Record<string, unknown>>,
      prevEntrySha256: this.lastEntrySha256,
    };

    const coreBytes = serializeLedgerEntryCore(coreFields);
    const entrySha256 = crypto.createHash('sha256').update(coreBytes).digest('hex');
    const signatureBase64 = this.signer.signPayload(buildSignedLedgerBytes(coreBytes, entrySha256));

    const entry: AuditLedgerEntry = {
      ...coreFields,
      entrySha256,
      publicKeyPem: this.signer.getPublicKeyPem(),
      signatureBase64,
    };

    this.entries.push(entry);
    this.lastEntrySha256 = entrySha256;

    if (this.ledgerFilePath && fs.existsSync(path.dirname(this.ledgerFilePath))) {
      fs.appendFileSync(this.ledgerFilePath, `${JSON.stringify(entry)}\n`, 'utf8');
    }

    return entry;
  }

  public getEntries(): readonly AuditLedgerEntry[] {
    return [...this.entries];
  }

  public exportJsonl(): string {
    if (this.entries.length === 0) {
      return '';
    }
    return `${this.entries.map((entry) => JSON.stringify(entry)).join('\n')}\n`;
  }
}

export function verifyAuditLedgerEntries(entries: readonly AuditLedgerEntry[]): AuditLedgerVerificationResult {
  if (entries.length === 0) {
    return {
      valid: false,
      entryCount: 0,
      failureReason: 'Audit ledger contains zero entries.',
    };
  }

  const expectedSessionId = entries[0]!.sessionId;
  const expectedPublicKeyPem = entries[0]!.publicKeyPem;
  let expectedPrevHash = GENESIS_PREV_SHA256;

  for (let idx = 0; idx < entries.length; idx += 1) {
    const entry = entries[idx]!;
    if (!isLedgerEntryShape(entry)) {
      return {
        valid: false,
        entryCount: entries.length,
        sessionId: expectedSessionId,
        brokenAtSequence: idx,
        failureReason: `Malformed audit ledger entry at index ${idx}.`,
      };
    }

    if (entry.sequence !== idx) {
      return {
        valid: false,
        entryCount: entries.length,
        sessionId: expectedSessionId,
        brokenAtSequence: entry.sequence,
        failureReason: `Sequence mismatch at index ${idx}: expected ${idx}, found ${entry.sequence}.`,
      };
    }

    if (entry.sessionId !== expectedSessionId) {
      return {
        valid: false,
        entryCount: entries.length,
        sessionId: expectedSessionId,
        brokenAtSequence: entry.sequence,
        failureReason: `Session ID mismatch at sequence ${entry.sequence}.`,
      };
    }

    if (entry.publicKeyPem !== expectedPublicKeyPem) {
      return {
        valid: false,
        entryCount: entries.length,
        sessionId: expectedSessionId,
        brokenAtSequence: entry.sequence,
        failureReason: `Signer public key changed mid-chain at sequence ${entry.sequence}.`,
      };
    }

    if (entry.prevEntrySha256 !== expectedPrevHash) {
      return {
        valid: false,
        entryCount: entries.length,
        sessionId: expectedSessionId,
        brokenAtSequence: entry.sequence,
        failureReason: `Broken hash chain link at sequence ${entry.sequence}.`,
      };
    }

    const coreBytes = serializeLedgerEntryCore(entry);
    const computedSha256 = crypto.createHash('sha256').update(coreBytes).digest('hex');
    if (entry.entrySha256 !== computedSha256) {
      return {
        valid: false,
        entryCount: entries.length,
        sessionId: expectedSessionId,
        brokenAtSequence: entry.sequence,
        failureReason: `Entry SHA-256 digest mismatch at sequence ${entry.sequence}.`,
      };
    }

    let signatureValid = false;
    try {
      signatureValid = crypto.verify(
        null,
        buildSignedLedgerBytes(coreBytes, entry.entrySha256),
        entry.publicKeyPem,
        Buffer.from(entry.signatureBase64, 'base64'),
      );
    } catch {
      signatureValid = false;
    }

    if (!signatureValid) {
      return {
        valid: false,
        entryCount: entries.length,
        sessionId: expectedSessionId,
        brokenAtSequence: entry.sequence,
        failureReason: `Invalid Ed25519 signature at sequence ${entry.sequence}.`,
      };
    }

    expectedPrevHash = entry.entrySha256;
  }

  return {
    valid: true,
    entryCount: entries.length,
    sessionId: expectedSessionId,
  };
}

export function parseAndVerifyAuditLedgerJsonl(jsonlContent: string): AuditLedgerVerificationResult {
  const lines = jsonlContent
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  if (lines.length === 0) {
    return {
      valid: false,
      entryCount: 0,
      failureReason: 'Audit ledger contains zero entries.',
    };
  }

  const parsedEntries: AuditLedgerEntry[] = [];
  for (let idx = 0; idx < lines.length; idx += 1) {
    try {
      const parsed = JSON.parse(lines[idx]!) as unknown;
      if (!isLedgerEntryShape(parsed)) {
        return {
          valid: false,
          entryCount: lines.length,
          brokenAtSequence: idx,
          failureReason: `Malformed audit ledger JSON object on line ${idx + 1}.`,
        };
      }
      parsedEntries.push(parsed);
    } catch (err) {
      return {
        valid: false,
        entryCount: lines.length,
        brokenAtSequence: idx,
        failureReason: `Invalid JSON on line ${idx + 1}: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }

  return verifyAuditLedgerEntries(parsedEntries);
}
