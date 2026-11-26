import crypto from 'node:crypto';
import type { PhantomCredentialRule, SecretFingerprint } from '../types/contracts.js';

export class SecretFingerprinter {
  createFingerprint(secret: string, id: string, envVarName?: string): SecretFingerprint {
    const rawBuf = Buffer.from(secret, 'utf8');
    const base64 = rawBuf.toString('base64');
    const hexLower = rawBuf.toString('hex');

    return {
      id,
      envVarName,
      raw: secret,
      base64,
      base64NoPad: base64.replace(/=+$/, ''),
      base64Url: rawBuf.toString('base64url'),
      hexLower,
      hexUpper: hexLower.toUpperCase(),
      urlEncoded: encodeURIComponent(secret),
    };
  }

  createFingerprints(
    secrets: readonly string[],
    phantomRules: readonly PhantomCredentialRule[] = [],
  ): readonly SecretFingerprint[] {
    const seen = new Set<string>();
    const result: SecretFingerprint[] = [];

    for (const rule of phantomRules) {
      if (rule.realSecret.length < 6 || seen.has(rule.realSecret)) {
        continue;
      }
      seen.add(rule.realSecret);
      const digest = crypto.createHash('sha256').update(rule.realSecret).digest('hex').slice(0, 8);
      result.push(this.createFingerprint(rule.realSecret, `phantom-${digest}`, rule.envVarName));
    }

    for (const secret of secrets) {
      if (secret.length < 6 || seen.has(secret)) {
        continue;
      }
      seen.add(secret);
      const digest = crypto.createHash('sha256').update(secret).digest('hex').slice(0, 8);
      result.push(this.createFingerprint(secret, `secret-${digest}`));
    }

    return result;
  }
}
