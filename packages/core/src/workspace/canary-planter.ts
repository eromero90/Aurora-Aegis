import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { CanaryHoneytoken } from '../types/contracts.js';
import { canonicalizePath } from '../utils/paths.js';

export class CanaryPlanter {
  buildTripwireSubstrings(secretCore: string): readonly string[] {
    const substrings = new Set<string>();

    if (secretCore.length >= 6) {
      for (let i = 0; i <= secretCore.length - 6; i += 2) {
        substrings.add(secretCore.slice(i, i + 6));
      }
    }
    if (secretCore.length >= 8) {
      for (let i = 0; i <= secretCore.length - 8; i += 2) {
        substrings.add(secretCore.slice(i, i + 8));
      }
    }

    substrings.add(Buffer.from(secretCore, 'utf8').toString('base64').replace(/=+$/, ''));
    substrings.add(Buffer.from(secretCore, 'utf8').toString('hex'));

    return [...substrings];
  }

  private buildFullAndEntropyTripwires(fullToken: string, entropyCore: string): readonly string[] {
    return [...new Set([fullToken, ...this.buildTripwireSubstrings(fullToken).filter((s) => s.length > 8), ...this.buildTripwireSubstrings(entropyCore)])];
  }

  plantCanaries(sessionHomeDir: string, sessionId: string): readonly CanaryHoneytoken[] {
    const canonicalHome = canonicalizePath(sessionHomeDir);
    const awsDir = path.join(canonicalHome, '.aws');
    const sshDir = path.join(canonicalHome, '.ssh');

    fs.mkdirSync(awsDir, { recursive: true });
    fs.mkdirSync(sshDir, { recursive: true, mode: 0o700 });

    const awsEntropy = crypto.randomBytes(10).toString('hex');
    const awsSecretCore = `aegis_canary_aws_${awsEntropy}`;
    const awsCredsPath = path.join(awsDir, 'credentials');
    fs.writeFileSync(
      awsCredsPath,
      [
        '[default]',
        'aws_access_key_id = AKIAIOSFODNN7CANARY',
        `aws_secret_access_key = ${awsSecretCore}`,
        '',
      ].join('\n'),
      { mode: 0o600 },
    );

    const sshEntropy = crypto.randomBytes(10).toString('hex');
    const sshSecretCore = `aegis_canary_ssh_${sshEntropy}`;
    const sshKeyPath = path.join(sshDir, 'id_ed25519');
    fs.writeFileSync(
      sshKeyPath,
      [
        '-----BEGIN OPENSSH PRIVATE KEY-----',
        Buffer.from(`openssh-key-v1:${sshSecretCore}`, 'utf8').toString('base64'),
        sshSecretCore,
        '-----END OPENSSH PRIVATE KEY-----',
        '',
      ].join('\n'),
      { mode: 0o600 },
    );

    const envEntropy = crypto.randomBytes(10).toString('hex');
    const envTokenCore = `aegis_canary_env_${envEntropy}`;

    return [
      {
        id: `canary-aws-${sessionId}`,
        label: 'aws-decoy-credentials',
        filePath: canonicalizePath(awsCredsPath),
        tokenValue: awsSecretCore,
        tripwireSubstrings: this.buildFullAndEntropyTripwires(awsSecretCore, awsEntropy),
      },
      {
        id: `canary-ssh-${sessionId}`,
        label: 'ssh-decoy-private-key',
        filePath: canonicalizePath(sshKeyPath),
        tokenValue: sshSecretCore,
        tripwireSubstrings: this.buildFullAndEntropyTripwires(sshSecretCore, sshEntropy),
      },
      {
        id: `canary-env-${sessionId}`,
        label: 'env-decoy-vault-token',
        envVarName: 'AEGIS_INTERNAL_VAULT_TOKEN',
        tokenValue: envTokenCore,
        tripwireSubstrings: this.buildFullAndEntropyTripwires(envTokenCore, envEntropy),
      },
    ];
  }
}
