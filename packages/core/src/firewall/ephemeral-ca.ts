import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { canonicalizePath } from '../utils/paths.js';

export interface LeafCertificatePair {
  readonly key: string;
  readonly cert: string;
}

const SAFE_HOSTNAME_REGEX = /^[a-zA-Z0-9._:-]+$/;

export class EphemeralCA {
  readonly caCertPath: string;

  private readonly privateKeyDir: string;
  private readonly caKeyPath: string;
  private readonly leafCache = new Map<string, LeafCertificatePair>();
  private initialized = false;

  constructor(private readonly sessionTmpDir: string) {
    const canonicalTmp = canonicalizePath(sessionTmpDir);
    this.caCertPath = path.join(canonicalTmp, 'aegis-ca.pem');
    this.privateKeyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-ca-priv-'));
    fs.chmodSync(this.privateKeyDir, 0o700);
    this.caKeyPath = path.join(this.privateKeyDir, 'ca.key');
  }

  init(): string {
    if (this.initialized) {
      return this.caCertPath;
    }

    execFileSync(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:prime256v1',
        '-keyout',
        this.caKeyPath,
        '-out',
        this.caCertPath,
        '-days',
        '1',
        '-nodes',
        '-subj',
        '/CN=Aurora-Aegis Ephemeral Session CA',
        '-addext',
        'basicConstraints=critical,CA:TRUE',
        '-addext',
        'keyUsage=critical,keyCertSign,cRLSign',
      ],
      { stdio: 'ignore' },
    );

    fs.chmodSync(this.caKeyPath, 0o600);
    this.initialized = true;
    return this.caCertPath;
  }

  getLeafCertificate(hostname: string): LeafCertificatePair {
    if (!this.initialized) {
      this.init();
    }

    const cleanHost = hostname.replace(/^\[|\]$/g, '').toLowerCase();
    if (!SAFE_HOSTNAME_REGEX.test(cleanHost)) {
      throw new Error(`Unsafe hostname for leaf certificate generation: "${hostname}"`);
    }

    const cached = this.leafCache.get(cleanHost);
    if (cached) {
      return cached;
    }

    const id = crypto.randomBytes(6).toString('hex');
    const leafKeyPath = path.join(this.privateKeyDir, `leaf-${id}.key`);
    const leafCsrPath = path.join(this.privateKeyDir, `leaf-${id}.csr`);
    const leafCertPath = path.join(this.privateKeyDir, `leaf-${id}.crt`);
    const extPath = path.join(this.privateKeyDir, `leaf-${id}.ext`);

    try {
      execFileSync(
        'openssl',
        [
          'req',
          '-newkey',
          'ec',
          '-pkeyopt',
          'ec_paramgen_curve:prime256v1',
          '-keyout',
          leafKeyPath,
          '-out',
          leafCsrPath,
          '-nodes',
          '-subj',
          `/CN=${cleanHost}`,
        ],
        { stdio: 'ignore' },
      );

      const san = net.isIP(cleanHost)
        ? `IP:${cleanHost}`
        : `DNS:${cleanHost},IP:127.0.0.1`;

      fs.writeFileSync(
        extPath,
        [
          `subjectAltName=${san}`,
          'basicConstraints=CA:FALSE',
          'keyUsage=digitalSignature,keyEncipherment',
          'extendedKeyUsage=serverAuth',
          '',
        ].join('\n'),
      );

      execFileSync(
        'openssl',
        [
          'x509',
          '-req',
          '-in',
          leafCsrPath,
          '-CA',
          this.caCertPath,
          '-CAkey',
          this.caKeyPath,
          '-CAcreateserial',
          '-out',
          leafCertPath,
          '-days',
          '1',
          '-sha256',
          '-extfile',
          extPath,
        ],
        { stdio: 'ignore' },
      );

      const pair: LeafCertificatePair = {
        key: fs.readFileSync(leafKeyPath, 'utf8'),
        cert: fs.readFileSync(leafCertPath, 'utf8'),
      };
      this.leafCache.set(cleanHost, pair);
      return pair;
    } finally {
      for (const tempFile of [leafKeyPath, leafCsrPath, leafCertPath, extPath]) {
        if (fs.existsSync(tempFile)) {
          fs.rmSync(tempFile, { force: true });
        }
      }
    }
  }

  destroy(): void {
    this.leafCache.clear();
    fs.rmSync(this.privateKeyDir, { recursive: true, force: true });
    if (fs.existsSync(this.caCertPath)) {
      fs.rmSync(this.caCertPath, { force: true });
    }
    this.initialized = false;
  }
}
