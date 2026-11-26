import zlib from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { DlpScanner } from '../../src/firewall/dlp-scanner.js';
import { SecretFingerprinter } from '../../src/firewall/secret-fingerprinter.js';
import type { CanaryHoneytoken } from '../../src/types/contracts.js';

describe('SecretFingerprinter & DlpScanner', () => {
  const fingerprinter = new SecretFingerprinter();
  const realSecret = 'super-secret-db-password-42!';
  const fingerprints = fingerprinter.createFingerprints([realSecret]);

  it('detects raw, Base64, Base64url, hex, and URL-encoded secret leaks across GET and POST', () => {
    const scanner = new DlpScanner({ fingerprints });
    const fp = fingerprints[0]!;

    const encodings = [
      { label: 'raw', val: fp.raw },
      { label: 'base64', val: fp.base64 },
      { label: 'base64NoPad', val: fp.base64NoPad },
      { label: 'base64Url', val: fp.base64Url },
      { label: 'hexLower', val: fp.hexLower },
      { label: 'hexUpper', val: fp.hexUpper },
      { label: 'urlEncoded', val: fp.urlEncoded },
    ];

    for (const enc of encodings) {
      const getScan = scanner.scanRequest({
        method: 'GET',
        url: `https://api.github.com/search?q=${enc.val}`,
        headers: {},
        rawBody: Buffer.alloc(0),
      });
      expect(getScan.allowed, `GET leak (${enc.label}) should be blocked`).toBe(false);
      expect(getScan.reason).toBe('SECRET_FINGERPRINT_MATCH');

      const postScan = scanner.scanRequest({
        method: 'POST',
        url: 'https://api.github.com/issues',
        headers: { 'x-custom-exfil': enc.val },
        rawBody: Buffer.from('{"ok":true}'),
      });
      expect(postScan.allowed, `Header leak (${enc.label}) should be blocked`).toBe(false);
    }
  });

  it('decompresses gzip and Brotli bodies before scanning for secrets', () => {
    const scanner = new DlpScanner({ fingerprints });
    const fp = fingerprints[0]!;

    const gzipPayload = zlib.gzipSync(Buffer.from(`payload=${fp.base64}`));
    const gzipScan = scanner.scanRequest({
      method: 'POST',
      url: 'https://api.github.com/issues',
      headers: { 'content-encoding': 'gzip' },
      rawBody: gzipPayload,
      contentEncoding: 'gzip',
    });
    expect(gzipScan.allowed).toBe(false);
    expect(gzipScan.reason).toBe('SECRET_FINGERPRINT_MATCH');

    const brPayload = zlib.brotliCompressSync(Buffer.from(`hex=${fp.hexLower}`));
    const brScan = scanner.scanRequest({
      method: 'PUT',
      url: 'https://api.github.com/issues',
      headers: { 'content-encoding': 'br' },
      rawBody: brPayload,
      contentEncoding: 'br',
    });
    expect(brScan.allowed).toBe(false);
    expect(brScan.reason).toBe('SECRET_FINGERPRINT_MATCH');
  });

  it('detects built-in credential regex patterns', () => {
    const scanner = new DlpScanner({ fingerprints: [] });
    const samples = [
      'sk-abcdefghijklmnopqrstuvwxyz012345',
      'ghp_1234567890abcdefghijklmnopqrstuvwxyz',
      'AKIAIOSFODNN7EXAMPLE',
      '-----BEGIN OPENSSH PRIVATE KEY-----',
    ];

    for (const sample of samples) {
      const res = scanner.scanRequest({
        method: 'POST',
        url: 'https://api.github.com/gists',
        headers: {},
        rawBody: Buffer.from(sample),
      });
      expect(res.allowed).toBe(false);
      expect(res.reason).toBe('REGEX_SIGNATURE_MATCH');
    }
  });

  it('fires Canary Honeytoken tripwire on >= 6-char substring match and strips invisible Unicode tags', () => {
    const canary: CanaryHoneytoken = {
      id: 'canary-test-1',
      label: 'aws-decoy',
      tokenValue: 'aegis_canary_aws_deadbeef1234',
      tripwireSubstrings: ['deadbe', 'ef1234'],
    };

    const scanner = new DlpScanner({ fingerprints: [], canaries: [canary] });
    const scan = scanner.scanRequest({
      method: 'GET',
      url: 'https://api.github.com/users?chunk=ef1234',
      headers: {},
      rawBody: Buffer.alloc(0),
    });

    expect(scan.allowed).toBe(false);
    expect(scan.canaryTriggered).toBe(true);
    expect(scan.reason).toBe('CANARY_TRIPWIRE_TRIGGERED');

    const smuggled = 'Hello\u{E0001}\u{E0049}World\u200B!';
    expect(scanner.sanitizeInboundText(smuggled)).toBe('HelloWorld!');
  });

  it('fails closed with MALFORMED_CONTENT_ENCODING on corrupted or unsupported Content-Encoding payloads', () => {
    const scanner = new DlpScanner({ fingerprints: [] });

    for (const encoding of ['gzip', 'deflate', 'br', 'x-custom-obfuscation']) {
      const scan = scanner.scanRequest({
        method: 'POST',
        url: 'https://api.github.com/gists',
        headers: { 'content-encoding': encoding },
        rawBody: Buffer.from('not-a-valid-compressed-stream'),
        contentEncoding: encoding,
      });
      expect(scan.allowed).toBe(false);
      expect(scan.reason).toBe('MALFORMED_CONTENT_ENCODING');
      expect(scan.matchedRule).toBe(`CONTENT_ENCODING:${encoding}`);
    }
  });
});
