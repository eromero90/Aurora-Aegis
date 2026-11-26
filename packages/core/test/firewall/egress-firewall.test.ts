import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import zlib from 'node:zlib';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { EgressFirewall } from '../../src/firewall/egress-firewall.js';
import type { DlpViolationEvent, SandboxPolicy } from '../../src/types/contracts.js';

function httpViaProxy(options: {
  proxyPort: number;
  targetUrl: string;
  method?: string;
  headers?: Record<string, string>;
  body?: Buffer | string;
}): Promise<{ statusCode: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: options.proxyPort,
        method: options.method ?? 'GET',
        path: options.targetUrl,
        headers: options.headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      },
    );
    req.on('error', reject);
    if (options.body) {
      req.write(options.body);
    }
    req.end();
  });
}

function httpsMitmViaProxy(options: {
  proxyPort: number;
  caCertPem: string;
  hostname: string;
  path: string;
  method?: string;
  headers?: Record<string, string>;
  body?: Buffer | string;
}): Promise<{ statusCode: number; body: string }> {
  return new Promise((resolve, reject) => {
    const connectReq = http.request({
      host: '127.0.0.1',
      port: options.proxyPort,
      method: 'CONNECT',
      path: `${options.hostname}:443`,
    });

    connectReq.on('connect', (connectRes, socket) => {
      if (connectRes.statusCode !== 200) {
        socket.destroy();
        resolve({ statusCode: connectRes.statusCode ?? 403, body: '' });
        return;
      }

      const tlsSocket = tls.connect({
        socket,
        ca: options.caCertPem,
        servername: options.hostname,
      });
      tlsSocket.on('error', reject);

      const agent = new http.Agent({ keepAlive: false });
      (agent as unknown as { createConnection: () => tls.TLSSocket }).createConnection = () =>
        tlsSocket;

      const tlsReq = http.request(
        {
          host: options.hostname,
          path: options.path,
          method: options.method ?? 'GET',
          headers: options.headers,
          agent,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () => {
            resolve({
              statusCode: res.statusCode ?? 0,
              body: Buffer.concat(chunks).toString('utf8'),
            });
          });
        },
      );
      tlsReq.on('error', reject);
      if (options.body) {
        tlsReq.write(options.body);
      }
      tlsReq.end();
    });

    connectReq.on('error', reject);
    connectReq.end();
  });
}

describe('EgressFirewall & EphemeralCA', () => {
  let tempRoot: string;
  let mockUpstream: http.Server;
  let mockPort: number;
  let lastUpstreamAuthHeader: string | undefined;
  let firewall: EgressFirewall;

  const realGhToken = 'ghp_realSecretTokenValue1234567890abcdef12';
  const phantomGhToken = 'aegis_phantom_gh_99887766';
  const protectedHostSecret = 'db_master_pass_99112233!';

  beforeEach(async () => {
    tempRoot = fs.realpathSync.native(
      fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-fw-test-')),
    );
    lastUpstreamAuthHeader = undefined;

    mockUpstream = http.createServer((req, res) => {
      lastUpstreamAuthHeader = req.headers.authorization;
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({
            ok: true,
            echoedAuth: lastUpstreamAuthHeader ?? '',
            smuggled: 'clean\u{E0001}text',
          }),
        );
      });
    });

    await new Promise<void>((resolve) => {
      mockUpstream.listen(0, '127.0.0.1', resolve);
    });
    const addr = mockUpstream.address();
    if (!addr || typeof addr === 'string') {
      throw new Error('Failed to start mock upstream');
    }
    mockPort = addr.port;
  });

  afterEach(async () => {
    await firewall.stop();
    mockUpstream.closeAllConnections();
    await new Promise<void>((resolve) => mockUpstream.close(() => resolve()));
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  it('enforces domain/method rules, anti-SSRF, gzip-DLP, HTTPS MITM phantom swap, and canary callbacks', async () => {
    const policy: SandboxPolicy = {
      sessionId: 'fw-test-01',
      repoRootPath: tempRoot,
      tier: 'tier1-kernel-mac',
      cowDirectories: [],
      readOnlyToolchainPaths: [],
      egressRules: [
        { domain: 'registry.npmjs.org', allowedMethods: ['GET'] },
        { domain: 'api.github.com', allowedMethods: ['GET', 'POST'] },
      ],
      phantomCredentials: [
        {
          envVarName: 'GITHUB_TOKEN',
          phantomToken: phantomGhToken,
          realSecret: realGhToken,
          allowedHosts: ['api.github.com'],
        },
      ],
      protectedSecrets: [protectedHostSecret],
      canaries: [
        {
          id: 'canary-aws-fw',
          label: 'aws-decoy',
          tokenValue: 'aegis_canary_aws_feedface',
          tripwireSubstrings: ['feedfa', 'face'],
        },
      ],
      timeoutMs: 5000,
    };

    firewall = new EgressFirewall({
      policy,
      sessionTmpDir: tempRoot,
      upstreamOverrides: {
        'registry.npmjs.org': { protocol: 'http:', host: '127.0.0.1', port: mockPort },
        'api.github.com': { protocol: 'http:', host: '127.0.0.1', port: mockPort },
      },
    });

    const canaryEvents: DlpViolationEvent[] = [];
    firewall.onCanaryTriggered((ev) => canaryEvents.push(ev));

    const { port, caCertPath } = await firewall.start();
    const caCertPem = fs.readFileSync(caCertPath, 'utf8');

    const evilRes = await httpViaProxy({
      proxyPort: port,
      targetUrl: 'http://evil.example.com/steal',
    });
    expect(evilRes.statusCode).toBe(403);

    const npmGet = await httpViaProxy({
      proxyPort: port,
      targetUrl: 'http://registry.npmjs.org/vitest',
    });
    expect(npmGet.statusCode).toBe(200);

    const npmPost = await httpViaProxy({
      proxyPort: port,
      targetUrl: 'http://registry.npmjs.org/vitest',
      method: 'POST',
      body: '{}',
    });
    expect(npmPost.statusCode).toBe(403);

    const ssrfMeta = await httpViaProxy({
      proxyPort: port,
      targetUrl: 'http://169.254.169.254/latest/meta-data',
    });
    expect(ssrfMeta.statusCode).toBe(403);

    const ssrfLocal = await httpViaProxy({
      proxyPort: port,
      targetUrl: 'http://127.0.0.1:9222/json',
    });
    expect(ssrfLocal.statusCode).toBe(403);

    const b64Secret = Buffer.from(protectedHostSecret).toString('base64');
    const gzipBody = zlib.gzipSync(Buffer.from(JSON.stringify({ data: b64Secret })));
    const dlpBlockRes = await httpsMitmViaProxy({
      proxyPort: port,
      caCertPem,
      hostname: 'api.github.com',
      path: '/repos/org/repo/issues',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-encoding': 'gzip',
        'content-length': String(gzipBody.length),
      },
      body: gzipBody,
    });
    expect(dlpBlockRes.statusCode).toBe(403);

    const crossHostRes = await httpViaProxy({
      proxyPort: port,
      targetUrl: 'http://registry.npmjs.org/who',
      headers: { authorization: `Bearer ${phantomGhToken}` },
    });
    expect(crossHostRes.statusCode).toBe(403);
    expect(lastUpstreamAuthHeader ?? '').not.toContain(realGhToken);

    const okBody = JSON.stringify({ title: 'Safe PR' });
    const authorizedRes = await httpsMitmViaProxy({
      proxyPort: port,
      caCertPem,
      hostname: 'api.github.com',
      path: '/repos/org/repo/issues',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': String(Buffer.byteLength(okBody)),
        authorization: `Bearer ${phantomGhToken}`,
      },
      body: okBody,
    });
    expect(authorizedRes.statusCode).toBe(200);
    expect(lastUpstreamAuthHeader).toBe(`Bearer ${realGhToken}`);
    const parsedResp = JSON.parse(authorizedRes.body) as {
      echoedAuth: string;
      smuggled: string;
    };
    expect(parsedResp.echoedAuth).toBe(`Bearer ${phantomGhToken}`);
    expect(parsedResp.smuggled).toBe('cleantext');

    const canaryRes = await httpViaProxy({
      proxyPort: port,
      targetUrl: 'http://registry.npmjs.org/search?q=feedfa',
    });
    expect(canaryRes.statusCode).toBe(403);
    expect(canaryEvents).toHaveLength(1);
    expect(canaryEvents[0]?.reason).toBe('CANARY_TRIPWIRE_TRIGGERED');

    const reasons = firewall.getViolationEvents().map((e) => e.reason);
    expect(reasons).toContain('DOMAIN_NOT_ALLOWED');
    expect(reasons).toContain('METHOD_NOT_ALLOWED');
    expect(reasons).toContain('PRIVATE_IP_SSRF_BLOCKED');
    expect(reasons).toContain('SECRET_FINGERPRINT_MATCH');
    expect(reasons).toContain('CANARY_TRIPWIRE_TRIGGERED');
  });

  it('pins validated DNS resolution to prevent DNS-rebinding TOCTOU and fails closed on DNS errors', async () => {
    const policy: SandboxPolicy = {
      sessionId: 'fw-dns-pin-01',
      repoRootPath: tempRoot,
      tier: 'tier1-kernel-mac',
      cowDirectories: [],
      readOnlyToolchainPaths: [],
      egressRules: [
        { domain: 'rebind.allowed.test', allowedMethods: ['GET'] },
        { domain: 'broken.allowed.test', allowedMethods: ['GET'] },
        { domain: 'pinned.allowed.test', allowedMethods: ['GET'] },
      ],
      phantomCredentials: [],
      protectedSecrets: [],
      timeoutMs: 5000,
    };

    let pinnedLookupCalls = 0;
    firewall = new EgressFirewall({
      policy,
      sessionTmpDir: tempRoot,
      allowTestLoopbackUpstreamPorts: [mockPort],
      dnsLookup: async (hostname) => {
        if (hostname === 'rebind.allowed.test') {
          return [{ address: '169.254.169.254', family: 4 }];
        }
        if (hostname === 'broken.allowed.test') {
          throw Object.assign(new Error('getaddrinfo ENOTFOUND broken.allowed.test'), { code: 'ENOTFOUND' });
        }
        if (hostname === 'pinned.allowed.test') {
          pinnedLookupCalls += 1;
          if (pinnedLookupCalls === 1) {
            return [{ address: '127.0.0.1', family: 4 }];
          }
          return [{ address: '169.254.169.254', family: 4 }];
        }
        throw new Error(`Unexpected DNS lookup for ${hostname}`);
      },
    });

    const { port } = await firewall.start();

    const rebindRes = await httpViaProxy({
      proxyPort: port,
      targetUrl: 'http://rebind.allowed.test/meta',
    });
    expect(rebindRes.statusCode).toBe(403);
    expect(rebindRes.body).toContain('PRIVATE_IP_SSRF_BLOCKED');

    const brokenRes = await httpViaProxy({
      proxyPort: port,
      targetUrl: 'http://broken.allowed.test/meta',
    });
    expect(brokenRes.statusCode).toBe(403);
    expect(brokenRes.body).toContain('DNS_RESOLUTION_FAILED');

    const pinnedRes = await httpViaProxy({
      proxyPort: port,
      targetUrl: `http://pinned.allowed.test:${mockPort}/ok`,
    });
    expect(pinnedRes.statusCode).toBe(200);
    expect(pinnedLookupCalls).toBe(1);

    const reasons = firewall.getViolationEvents().map((e) => e.reason);
    expect(reasons).toContain('PRIVATE_IP_SSRF_BLOCKED');
    expect(reasons).toContain('DNS_RESOLUTION_FAILED');
  });
});
