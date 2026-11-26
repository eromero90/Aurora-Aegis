import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { afterEach, describe, expect, it } from 'vitest';
import {
  AEGIS_POLICY_FILENAME,
  EgressFirewall,
  PackageRegistryGuard,
  type SandboxPolicy,
  canonicalizePath,
  detectProtectedPackageTyposquat,
  discoverRepoLockedPackagesWithDiagnostics,
  extractRegistryPackageRequest,
  levenshteinDistance,
  loadRepositoryPolicyFile,
  mergePolicyWithRepoConfig,
} from '../../src/index.js';

const tempDirs: string[] = [];

function createTempDir(prefix: string): string {
  const dir = canonicalizePath(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  tempDirs.push(dir);
  return dir;
}

function httpsMitmViaProxy(options: {
  proxyPort: number;
  caCertPem: string;
  hostname: string;
  path: string;
  method?: string;
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
      (agent as unknown as { createConnection: () => tls.TLSSocket }).createConnection = () => tlsSocket;

      const tlsReq = http.request(
        {
          host: options.hostname,
          path: options.path,
          method: options.method ?? 'GET',
          agent,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (chunk: Buffer) => chunks.push(chunk));
          res.on('end', () => {
            resolve({
              statusCode: res.statusCode ?? 0,
              body: Buffer.concat(chunks).toString('utf8'),
            });
          });
        },
      );
      tlsReq.on('error', reject);
      tlsReq.end();
    });

    connectReq.on('error', reject);
    connectReq.end();
  });
}

function buildPolicy(repoRootPath: string, overrides: Partial<SandboxPolicy> = {}): SandboxPolicy {
  return {
    sessionId: 'm10-supply-chain-test',
    repoRootPath,
    tier: 'tier1-kernel-mac',
    cowDirectories: [],
    readOnlyToolchainPaths: [],
    egressRules: [
      { domain: 'registry.npmjs.org', allowedMethods: ['GET'] },
      { domain: 'pypi.org', allowedMethods: ['GET'] },
      { domain: 'files.pythonhosted.org', allowedMethods: ['GET'] },
    ],
    phantomCredentials: [],
    protectedSecrets: [],
    timeoutMs: 30_000,
    ...overrides,
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

describe('PackageRegistryGuard & Supply-Chain Egress Firewall', () => {
  it('parses npm and PyPI package identifiers and detects distance-1 typosquats', () => {
    expect(extractRegistryPackageRequest('registry.npmjs.org', '/lodash')).toEqual({
      ecosystem: 'npm',
      packageName: 'lodash',
    });
    expect(extractRegistryPackageRequest('registry.npmjs.org', '/@babel%2fcore/-/core-7.24.0.tgz')).toEqual({
      ecosystem: 'npm',
      packageName: '@babel/core',
    });
    expect(extractRegistryPackageRequest('registry.yarnpkg.com', '/@scope/pkg')).toEqual({
      ecosystem: 'npm',
      packageName: '@scope/pkg',
    });
    expect(extractRegistryPackageRequest('registry.npmjs.org', '/-/ping')).toBeNull();

    expect(extractRegistryPackageRequest('pypi.org', '/simple/Requests/')).toEqual({
      ecosystem: 'pypi',
      packageName: 'requests',
    });
    expect(
      extractRegistryPackageRequest(
        'files.pythonhosted.org',
        '/packages/source/p/pydantic_core/pydantic_core-2.18.0.tar.gz',
      ),
    ).toEqual({
      ecosystem: 'pypi',
      packageName: 'pydantic-core',
    });

    expect(levenshteinDistance('express', 'expresss')).toBe(1);
    expect(detectProtectedPackageTyposquat('lodahs')).toBe('lodash');
    expect(detectProtectedPackageTyposquat('reqeusts')).toBe('requests');
    expect(detectProtectedPackageTyposquat('axois')).toBe('axios');
    expect(detectProtectedPackageTyposquat('fastpai')).toBe('fastapi');
    expect(detectProtectedPackageTyposquat('expresss')).toBe('express');
    expect(detectProtectedPackageTyposquat('@evil/reakt')).toBe('react');
    expect(detectProtectedPackageTyposquat('lodash')).toBeNull();
    expect(detectProtectedPackageTyposquat('requests')).toBeNull();
  });

  it('parses and merges packagePolicy from aegis.policy.json with restrictive defaults', () => {
    const repoDir = createTempDir('aegis-m10-policy-');
    fs.writeFileSync(
      path.join(repoDir, AEGIS_POLICY_FILENAME),
      JSON.stringify({
        version: 1,
        packagePolicy: {
          allowedPackages: ['lodash', 'zod', 'requests'],
          deniedPackages: ['@evil/*'],
          enforceLockfile: true,
        },
      }),
      'utf8',
    );

    const parsed = loadRepositoryPolicyFile(repoDir);
    expect(parsed?.packagePolicy).toEqual({
      allowedPackages: ['lodash', 'zod', 'requests'],
      deniedPackages: ['@evil/*'],
      enforceLockfile: true,
    });

    const base = buildPolicy(repoDir, {
      packagePolicy: {
        allowedPackages: ['lodash', 'express', 'zod'],
        deniedPackages: ['crossenv'],
        enforceLockfile: false,
      },
    });
    const merged = mergePolicyWithRepoConfig(base, parsed);
    expect(merged.packagePolicy?.allowedPackages).toEqual(['lodash', 'zod']);
    expect(merged.packagePolicy?.deniedPackages).toEqual(['crossenv', '@evil/*']);
    expect(merged.packagePolicy?.enforceLockfile).toBe(true);

    const badRepo = createTempDir('aegis-m10-bad-policy-');
    fs.writeFileSync(
      path.join(badRepo, AEGIS_POLICY_FILENAME),
      JSON.stringify({ version: 1, packagePolicy: { enforceLockfile: 'yes' } }),
      'utf8',
    );
    expect(() => loadRepositoryPolicyFile(badRepo)).toThrow(/enforceLockfile/);
  });

  it('enforces lockfile pinning, denylists, and typosquat blocking inside EgressFirewall HTTPS MITM', async () => {
    const repoDir = createTempDir('aegis-m10-fw-repo-');
    const tmpDir = createTempDir('aegis-m10-fw-tmp-');

    fs.writeFileSync(
      path.join(repoDir, 'package.json'),
      JSON.stringify({
        name: 'demo',
        dependencies: { lodash: '^4.17.21' },
      }),
      'utf8',
    );
    fs.writeFileSync(
      path.join(repoDir, 'pnpm-lock.yaml'),
      "lockfileVersion: '9.0'\npackages:\n  '@types/node@22.0.0':\n    resolution: {}\n",
      'utf8',
    );
    fs.writeFileSync(path.join(repoDir, 'requirements.txt'), '# prod deps\nrequests==2.31.0\n', 'utf8');

    const mockUpstream = http.createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, path: req.url }));
    });
    await new Promise<void>((resolve) => mockUpstream.listen(0, '127.0.0.1', resolve));
    const addr = mockUpstream.address();
    if (!addr || typeof addr === 'string') {
      throw new Error('Failed to start mock upstream server.');
    }

    const strictFirewall = new EgressFirewall({
      policy: buildPolicy(repoDir, {
        packagePolicy: {
          deniedPackages: ['@evil/trojan', '@bad-scope/*'],
          enforceLockfile: true,
        },
      }),
      sessionTmpDir: tmpDir,
      allowTestLoopbackUpstreamPorts: [addr.port],
      upstreamOverrides: {
        'registry.npmjs.org': { protocol: 'http:', host: '127.0.0.1', port: addr.port },
        'pypi.org': { protocol: 'http:', host: '127.0.0.1', port: addr.port },
        'files.pythonhosted.org': { protocol: 'http:', host: '127.0.0.1', port: addr.port },
      },
    });

    try {
      const { port: proxyPort, caCertPath } = await strictFirewall.start();
      const caCertPem = fs.readFileSync(caCertPath, 'utf8');

      const allowedNpm = await httpsMitmViaProxy({
        proxyPort,
        caCertPem,
        hostname: 'registry.npmjs.org',
        path: '/lodash',
      });
      expect(allowedNpm.statusCode).toBe(200);

      const allowedScoped = await httpsMitmViaProxy({
        proxyPort,
        caCertPem,
        hostname: 'registry.npmjs.org',
        path: '/@types/node',
      });
      expect(allowedScoped.statusCode).toBe(200);

      const allowedPypi = await httpsMitmViaProxy({
        proxyPort,
        caCertPem,
        hostname: 'pypi.org',
        path: '/simple/requests/',
      });
      expect(allowedPypi.statusCode).toBe(200);

      const deniedExact = await httpsMitmViaProxy({
        proxyPort,
        caCertPem,
        hostname: 'registry.npmjs.org',
        path: '/@evil/trojan',
      });
      expect(deniedExact.statusCode).toBe(403);
      expect(deniedExact.body).toContain('DENIED_PACKAGE:@evil/trojan');

      const deniedWildcard = await httpsMitmViaProxy({
        proxyPort,
        caCertPem,
        hostname: 'registry.npmjs.org',
        path: '/@bad-scope/backdoor',
      });
      expect(deniedWildcard.statusCode).toBe(403);
      expect(deniedWildcard.body).toContain('DENIED_PACKAGE:@bad-scope/backdoor');

      const unpinnedNpm = await httpsMitmViaProxy({
        proxyPort,
        caCertPem,
        hostname: 'registry.npmjs.org',
        path: '/left-pad',
      });
      expect(unpinnedNpm.statusCode).toBe(403);
      expect(unpinnedNpm.body).toContain('LOCKFILE_UNPINNED_PACKAGE:left-pad');

      const violations = strictFirewall.getViolationEvents();
      expect(violations.filter((v) => v.reason === 'SUPPLY_CHAIN_PACKAGE_BLOCKED')).toHaveLength(3);
    } finally {
      await strictFirewall.stop();
    }

    const permissiveFirewall = new EgressFirewall({
      policy: buildPolicy(repoDir),
      sessionTmpDir: tmpDir,
      allowTestLoopbackUpstreamPorts: [addr.port],
      upstreamOverrides: {
        'registry.npmjs.org': { protocol: 'http:', host: '127.0.0.1', port: addr.port },
        'files.pythonhosted.org': { protocol: 'http:', host: '127.0.0.1', port: addr.port },
      },
    });

    try {
      const { port: proxyPort, caCertPath } = await permissiveFirewall.start();
      const caCertPem = fs.readFileSync(caCertPath, 'utf8');

      const typosquatNpm = await httpsMitmViaProxy({
        proxyPort,
        caCertPem,
        hostname: 'registry.npmjs.org',
        path: '/lodahs',
      });
      expect(typosquatNpm.statusCode).toBe(403);
      expect(typosquatNpm.body).toContain('TYPOSQUAT_SUSPECT:lodahs->lodash');

      const typosquatWheel = await httpsMitmViaProxy({
        proxyPort,
        caCertPem,
        hostname: 'files.pythonhosted.org',
        path: '/packages/py3/r/reqeusts/reqeusts-2.31.0-py3-none-any.whl',
      });
      expect(typosquatWheel.statusCode).toBe(403);
      expect(typosquatWheel.body).toContain('TYPOSQUAT_SUSPECT:reqeusts->requests');

      const benignNewPkg = await httpsMitmViaProxy({
        proxyPort,
        caCertPem,
        hostname: 'registry.npmjs.org',
        path: '/left-pad',
      });
      expect(benignNewPkg.statusCode).toBe(200);

      const directGuard = new PackageRegistryGuard(repoDir, { allowedPackages: ['lodash'] });
      expect(directGuard.evaluateRequest('registry.npmjs.org', '/zod').matchedRule).toBe('UNLISTED_PACKAGE:zod');
      expect(directGuard.evaluateRequest('registry.npmjs.org', '/lodash').allowed).toBe(true);
    } finally {
      await permissiveFirewall.stop();
      await new Promise<void>((resolve) => mockUpstream.close(() => resolve()));
    }
  });

  it('surfaces lockfile parse diagnostics and fails closed under enforceLockfile when manifests are malformed', () => {
    const malformedRepo = createTempDir('aegis-m10-malformed-');
    fs.writeFileSync(path.join(malformedRepo, 'package.json'), '{ malformed json', 'utf8');

    const discovery = discoverRepoLockedPackagesWithDiagnostics(malformedRepo);
    expect(discovery.packages.size).toBe(0);
    expect(discovery.diagnostics).toHaveLength(1);
    expect(discovery.diagnostics[0]?.filePath).toBe(path.join(malformedRepo, 'package.json'));

    const strictGuard = new PackageRegistryGuard(malformedRepo, { enforceLockfile: true });
    expect(strictGuard.getLockfileDiagnostics()).toHaveLength(1);
    const decision = strictGuard.evaluateRequest('registry.npmjs.org', '/lodash');
    expect(decision.allowed).toBe(false);
    expect(decision.matchedRule).toBe('LOCKFILE_PARSE_ERROR:package.json');
  });
});
