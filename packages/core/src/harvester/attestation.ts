import crypto from 'node:crypto';
import type { HarvestAttestation } from '../types/contracts.js';

export interface SignHarvestInput {
  readonly sessionId: string;
  readonly repoRootPath: string;
  readonly patchDiff: string;
  readonly changedFiles: readonly string[];
  readonly executedCommandCount: number;
  readonly hookIntegrityVerified: boolean;
  readonly persistenceFindingCount: number;
  readonly dlpViolationCount: number;
  readonly canaryTriggered: boolean;
  readonly appliedToHost: boolean;
  readonly timestamp?: string | undefined;
}

type AttestationPayloadFields = Omit<HarvestAttestation, 'publicKeyPem' | 'signatureBase64'>;

function serializeAttestationPayload(fields: AttestationPayloadFields): Buffer {
  const canonical = JSON.stringify({
    schemaVersion: fields.schemaVersion,
    sessionId: fields.sessionId,
    timestamp: fields.timestamp,
    repoRootPath: fields.repoRootPath,
    patchSha256: fields.patchSha256,
    changedFiles: [...fields.changedFiles],
    executedCommandCount: fields.executedCommandCount,
    hookIntegrityVerified: fields.hookIntegrityVerified,
    persistenceFindingCount: fields.persistenceFindingCount,
    dlpViolationCount: fields.dlpViolationCount,
    canaryTriggered: fields.canaryTriggered,
    appliedToHost: fields.appliedToHost,
  });
  return Buffer.from(canonical, 'utf8');
}

export class AttestationSigner {
  private readonly privateKey: crypto.KeyObject;
  private readonly publicKeyPem: string;

  constructor() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    this.privateKey = privateKey;
    this.publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  }

  public getPublicKeyPem(): string {
    return this.publicKeyPem;
  }

  public signPayload(payload: Buffer): string {
    return crypto.sign(null, payload, this.privateKey).toString('base64');
  }

  public signHarvest(input: SignHarvestInput): HarvestAttestation {
    const patchSha256 = crypto.createHash('sha256').update(input.patchDiff, 'utf8').digest('hex');
    const payloadFields: AttestationPayloadFields = {
      schemaVersion: '1.0',
      sessionId: input.sessionId,
      timestamp: input.timestamp ?? new Date().toISOString(),
      repoRootPath: input.repoRootPath,
      patchSha256,
      changedFiles: [...input.changedFiles],
      executedCommandCount: input.executedCommandCount,
      hookIntegrityVerified: input.hookIntegrityVerified,
      persistenceFindingCount: input.persistenceFindingCount,
      dlpViolationCount: input.dlpViolationCount,
      canaryTriggered: input.canaryTriggered,
      appliedToHost: input.appliedToHost,
    };

    const signatureBase64 = crypto
      .sign(null, serializeAttestationPayload(payloadFields), this.privateKey)
      .toString('base64');

    return {
      ...payloadFields,
      publicKeyPem: this.publicKeyPem,
      signatureBase64,
    };
  }
}

export function verifyHarvestAttestation(attestation: HarvestAttestation): boolean {
  try {
    const payload = serializeAttestationPayload(attestation);
    return crypto.verify(
      null,
      payload,
      attestation.publicKeyPem,
      Buffer.from(attestation.signatureBase64, 'base64'),
    );
  } catch {
    return false;
  }
}
