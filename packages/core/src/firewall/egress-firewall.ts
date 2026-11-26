import dns from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import path from 'node:path';
import tls from 'node:tls';
import type {
  DlpViolationEvent,
  DlpViolationReason,
  EgressFirewallServer,
  HttpMethod,
  SandboxPolicy,
} from '../types/contracts.js';
import {
  type DiagnosticReporter,
  formatErrorMessage,
  getErrnoCode,
  isExpectedErrno,
} from '../utils/error-codes.js';
import { canonicalizePath } from '../utils/paths.js';
import { DlpScanner } from './dlp-scanner.js';
import { EphemeralCA } from './ephemeral-ca.js';
import { type LockfileDiagnostic, PackageRegistryGuard } from './package-registry-guard.js';
import { PhantomVault } from './phantom-vault.js';
import { SecretFingerprinter } from './secret-fingerprinter.js';

const EXPECTED_SOCKET_TEARDOWN_ERRNOS = new Set([
  'ERR_SOCKET_CLOSED',
  'ERR_STREAM_DESTROYED',
  'EPIPE',
  'ENOTCONN',
  'ECONNRESET',
]);

const VALID_METHODS = new Set<HttpMethod>([
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'HEAD',
  'OPTIONS',
]);

export interface ResolvedHostAddress {
  readonly address: string;
  readonly family: number;
}

export type DnsLookupFn = (hostname: string) => Promise<readonly ResolvedHostAddress[]>;

export interface UpstreamOverrideTarget {
  readonly protocol: 'http:' | 'https:';
  readonly host: string;
  readonly port: number;
}

export interface EgressFirewallOptions {
  readonly policy: SandboxPolicy;
  readonly sessionTmpDir: string;
  readonly enableUdsServer?: boolean | undefined;
  readonly allowTestLoopbackUpstreamPorts?: readonly number[] | undefined;
  readonly upstreamOverrides?: Readonly<Record<string, UpstreamOverrideTarget>> | undefined;
  readonly dnsLookup?: DnsLookupFn | undefined;
  readonly onDiagnostic?: DiagnosticReporter | undefined;
}

export function isPrivateOrLoopbackIp(rawIp: string): boolean {
  let ip = rawIp.trim().replace(/^\[|\]$/g, '').toLowerCase();
  const zoneIdx = ip.indexOf('%');
  if (zoneIdx !== -1) {
    ip = ip.slice(0, zoneIdx);
  }

  if (ip.startsWith('::ffff:')) {
    ip = ip.slice('::ffff:'.length);
  }

  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map((p) => Number.parseInt(p, 10));
    const a = parts[0] ?? -1;
    const b = parts[1] ?? -1;
    if (a === 0 || a === 127 || a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    return false;
  }

  if (net.isIPv6(ip)) {
    if (ip === '::' || ip === '::1') return true;
    if (ip.startsWith('fc') || ip.startsWith('fd')) return true;
    if (/^fe[89ab][0-9a-f]:/.test(ip) || ip.startsWith('fe80')) return true;
    return false;
  }

  return false;
}

export class EgressFirewall implements EgressFirewallServer {
  private readonly ca: EphemeralCA;
  private readonly dlpScanner: DlpScanner;
  private readonly packageGuard: PackageRegistryGuard;
  private readonly phantomVault: PhantomVault;
  private readonly violations: DlpViolationEvent[] = [];
  private readonly canaryListeners = new Set<(event: DlpViolationEvent) => void>();
  private readonly mitmTargets = new WeakMap<
    object,
    { readonly host: string; readonly port: number; readonly resolved?: ResolvedHostAddress | undefined }
  >();
  private readonly activeSockets = new Set<import('node:stream').Duplex>();

  private proxyServer: http.Server | undefined;
  private mitmServer: http.Server | undefined;
  private udsProxyServer: http.Server | undefined;
  private udsSocketPath: string | undefined;

  constructor(private readonly options: EgressFirewallOptions) {
    const canonicalTmp = canonicalizePath(options.sessionTmpDir);
    this.ca = new EphemeralCA(canonicalTmp);

    const fingerprinter = new SecretFingerprinter();
    const fingerprints = fingerprinter.createFingerprints(
      options.policy.protectedSecrets,
      options.policy.phantomCredentials,
    );

    this.dlpScanner = new DlpScanner({
      fingerprints,
      canaries: options.policy.canaries,
      outboundByteBudget: options.policy.outboundByteBudget,
    });
    this.packageGuard = new PackageRegistryGuard(options.policy.repoRootPath, options.policy.packagePolicy);
    this.phantomVault = new PhantomVault(options.policy.phantomCredentials);
  }

  async start(): Promise<{
    readonly port: number;
    readonly caCertPath: string;
    readonly udsSocketPath?: string | undefined;
  }> {
    const caCertPath = this.ca.init();

    const mitmServer = http.createServer((req, res) => {
      const target = this.mitmTargets.get(req.socket);
      const hostHeader = req.headers.host ?? target?.host ?? 'unknown';
      const defaultPort = target?.port ?? 443;
      const protocol = 'https:';
      const fullUrl = req.url?.startsWith('http')
        ? req.url
        : `${protocol}//${hostHeader}${req.url ?? '/'}`;

      void this.handleHttpRequest(req, res, fullUrl, defaultPort);
    });
    this.mitmServer = mitmServer;

    const createForwardProxy = () => {
      const server = http.createServer((req, res) => {
        const rawUrl = req.url ?? '/';
        const hostHeader = req.headers.host ?? '';
        const fullUrl = rawUrl.startsWith('http://') || rawUrl.startsWith('https://')
          ? rawUrl
          : `http://${hostHeader}${rawUrl}`;
        void this.handleHttpRequest(req, res, fullUrl, 80);
      });

      server.on('connect', (req, clientSocket, head) => {
        void this.handleConnect(req, clientSocket, head, mitmServer);
      });

      return server;
    };

    const proxyServer = createForwardProxy();
    this.proxyServer = proxyServer;

    await new Promise<void>((resolve, reject) => {
      proxyServer.once('error', reject);
      proxyServer.listen(0, '127.0.0.1', () => {
        proxyServer.off('error', reject);
        resolve();
      });
    });

    const address = proxyServer.address();
    if (!address || typeof address === 'string') {
      throw new Error('Failed to bind EgressFirewall loopback port.');
    }

    if (this.options.enableUdsServer) {
      const sockPath = path.join(canonicalizePath(this.options.sessionTmpDir), 'egress.sock');
      const udsServer = createForwardProxy();
      this.udsProxyServer = udsServer;
      await new Promise<void>((resolve, reject) => {
        udsServer.once('error', reject);
        udsServer.listen(sockPath, () => {
          udsServer.off('error', reject);
          resolve();
        });
      });
      this.udsSocketPath = sockPath;
    }

    return {
      port: address.port,
      caCertPath,
      udsSocketPath: this.udsSocketPath,
    };
  }

  onCanaryTriggered(listener: (event: DlpViolationEvent) => void): void {
    this.canaryListeners.add(listener);
  }

  getViolationEvents(): readonly DlpViolationEvent[] {
    return [...this.violations];
  }

  getLockfileDiagnostics(): readonly LockfileDiagnostic[] {
    return this.packageGuard.getLockfileDiagnostics();
  }

  async stop(): Promise<void> {
    for (const sock of this.activeSockets) {
      try {
        sock.destroy();
      } catch (err) {
        if (!isExpectedErrno(err, EXPECTED_SOCKET_TEARDOWN_ERRNOS)) {
          this.options.onDiagnostic?.({
            source: 'EgressFirewall.stop',
            code: getErrnoCode(err),
            message: formatErrorMessage(err),
          });
        }
      }
    }
    this.activeSockets.clear();
    this.mitmServer?.closeAllConnections?.();

    const closeServer = (srv: http.Server | undefined) =>
      srv && srv.listening
        ? new Promise<void>((resolve) => {
            srv.closeAllConnections?.();
            srv.close(() => resolve());
          })
        : Promise.resolve();

    await Promise.all([
      closeServer(this.proxyServer),
      closeServer(this.udsProxyServer),
    ]);

    this.proxyServer = undefined;
    this.udsProxyServer = undefined;
    this.mitmServer = undefined;
    this.udsSocketPath = undefined;
    this.ca.destroy();
  }

  private async handleConnect(
    req: http.IncomingMessage,
    clientSocket: net.Socket | import('node:stream').Duplex,
    head: Buffer,
    mitmServer: http.Server,
  ): Promise<void> {
    this.activeSockets.add(clientSocket);
    clientSocket.once('close', () => this.activeSockets.delete(clientSocket));
    clientSocket.on('error', () => {});

    const authority = req.url ?? '';
    const { hostname, port } = this.parseConnectAuthority(authority);

    if (!hostname) {
      clientSocket.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
      clientSocket.destroy();
      return;
    }

    const staticSsrfReason = this.checkStaticSsrf(hostname, port);
    if (staticSsrfReason) {
      this.recordViolation('CONNECT' as HttpMethod, `https://${hostname}:${port}`, 'PRIVATE_IP_SSRF_BLOCKED', staticSsrfReason);
      clientSocket.write(
        'HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\nAurora-Aegis SSRF Blocked',
      );
      clientSocket.destroy();
      return;
    }

    if (!this.findDomainRule(hostname)) {
      this.recordViolation('GET', `https://${hostname}:${port}`, 'DOMAIN_NOT_ALLOWED', hostname);
      clientSocket.write(
        'HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\nAurora-Aegis Domain Not Allowed',
      );
      clientSocket.destroy();
      return;
    }

    const resolution = await this.resolveAndValidateTarget(hostname, port);
    if (!resolution.ok) {
      this.recordViolation('CONNECT' as HttpMethod, `https://${hostname}:${port}`, resolution.reason, resolution.detail);
      clientSocket.write(
        `HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\nAurora-Aegis ${resolution.reason}`,
      );
      clientSocket.destroy();
      return;
    }

    const leaf = this.ca.getLeafCertificate(hostname);
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

    const tlsSocket = new tls.TLSSocket(clientSocket, {
      isServer: true,
      key: leaf.key,
      cert: leaf.cert,
    });
    this.activeSockets.add(tlsSocket);
    tlsSocket.once('close', () => this.activeSockets.delete(tlsSocket));
    tlsSocket.on('error', () => {});
    this.mitmTargets.set(tlsSocket, { host: hostname, port, resolved: resolution.resolved });

    if (head.length > 0) {
      tlsSocket.unshift(head);
    }

    mitmServer.emit('connection', tlsSocket);
  }

  private async handleHttpRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    fullUrl: string,
    defaultPort: number,
  ): Promise<void> {
    const method = this.normalizeMethod(req.method);
    const rawBody = await this.readBody(req);

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(fullUrl);
    } catch {
      res.writeHead(400, { 'content-type': 'text/plain' });
      res.end('Invalid proxy target URL');
      return;
    }

    const hostname = parsedUrl.hostname.toLowerCase();
    const targetPort = parsedUrl.port ? Number.parseInt(parsedUrl.port, 10) : defaultPort;

    const staticSsrfMatch = this.checkStaticSsrf(hostname, targetPort);
    if (staticSsrfMatch) {
      this.recordViolation(method, fullUrl, 'PRIVATE_IP_SSRF_BLOCKED', staticSsrfMatch);
      res.writeHead(403, { 'content-type': 'text/plain' });
      res.end(`Aurora-Aegis Firewall Blocked (PRIVATE_IP_SSRF_BLOCKED): ${staticSsrfMatch}`);
      return;
    }

    const domainRule = this.findDomainRule(hostname);
    if (!domainRule) {
      this.recordViolation(method, fullUrl, 'DOMAIN_NOT_ALLOWED', hostname);
      res.writeHead(403, { 'content-type': 'text/plain' });
      res.end(`Aurora-Aegis Firewall Blocked (DOMAIN_NOT_ALLOWED): ${hostname}`);
      return;
    }

    if (!domainRule.allowedMethods.includes(method)) {
      this.recordViolation(
        method,
        fullUrl,
        'METHOD_NOT_ALLOWED',
        `${method}:${domainRule.domain}`,
      );
      res.writeHead(403, { 'content-type': 'text/plain' });
      res.end(`Aurora-Aegis Firewall Blocked (METHOD_NOT_ALLOWED): ${method} ${hostname}`);
      return;
    }

    const mitmTarget = this.mitmTargets.get(req.socket);
    let resolvedTarget: ResolvedHostAddress | undefined;
    if (mitmTarget && mitmTarget.host.toLowerCase() === hostname && mitmTarget.resolved) {
      resolvedTarget = mitmTarget.resolved;
    } else {
      const resolution = await this.resolveAndValidateTarget(hostname, targetPort);
      if (!resolution.ok) {
        this.recordViolation(method, fullUrl, resolution.reason, resolution.detail);
        res.writeHead(403, { 'content-type': 'text/plain' });
        res.end(`Aurora-Aegis Firewall Blocked (${resolution.reason}): ${resolution.detail}`);
        return;
      }
      resolvedTarget = resolution.resolved;
    }

    const packageDecision = this.packageGuard.evaluateRequest(hostname, parsedUrl.pathname);
    if (!packageDecision.allowed) {
      this.recordViolation(
        method,
        fullUrl,
        'SUPPLY_CHAIN_PACKAGE_BLOCKED',
        packageDecision.matchedRule ?? 'SUPPLY_CHAIN_POLICY',
      );
      res.writeHead(403, { 'content-type': 'text/plain' });
      res.end(
        `Aurora-Aegis Supply-Chain Firewall Blocked (SUPPLY_CHAIN_PACKAGE_BLOCKED): ${packageDecision.matchedRule ?? ''}`,
      );
      return;
    }

    const contentEncodingHeader = req.headers['content-encoding'];
    const contentEncoding = Array.isArray(contentEncodingHeader)
      ? contentEncodingHeader.join(', ')
      : contentEncodingHeader;

    const dlpResult = this.dlpScanner.scanRequest({
      method,
      url: fullUrl,
      headers: req.headers,
      rawBody,
      contentEncoding,
    });

    if (!dlpResult.allowed) {
      const reason = dlpResult.reason ?? 'SECRET_FINGERPRINT_MATCH';
      const event = this.recordViolation(
        method,
        fullUrl,
        reason,
        dlpResult.matchedRule ?? 'DLP_RULE',
      );
      if (dlpResult.canaryTriggered) {
        for (const listener of this.canaryListeners) {
          listener(event);
        }
      }
      res.writeHead(403, { 'content-type': 'text/plain' });
      res.end(`Aurora-Aegis DLP Blocked (${reason}): ${dlpResult.matchedRule ?? ''}`);
      return;
    }

    const phantomResult = this.phantomVault.processOutbound(
      hostname,
      req.headers,
      dlpResult.decompressedBodyText,
    );
    if (!phantomResult.allowed) {
      this.recordViolation(
        method,
        fullUrl,
        'SECRET_FINGERPRINT_MATCH',
        phantomResult.matchedRule ?? 'PHANTOM_CROSS_HOST',
      );
      res.writeHead(403, { 'content-type': 'text/plain' });
      res.end(`Aurora-Aegis DLP Blocked: ${phantomResult.matchedRule ?? 'Unauthorized Phantom Credential host'}`);
      return;
    }

    const bodyWasSwapped = phantomResult.bodyText !== dlpResult.decompressedBodyText;
    const outboundHeaders: Record<string, string | string[]> = {};
    for (const [k, v] of Object.entries(phantomResult.headers)) {
      const lower = k.toLowerCase();
      if (lower === 'proxy-connection' || lower === 'connection') {
        continue;
      }
      if (bodyWasSwapped && (lower === 'content-length' || lower === 'content-encoding')) {
        continue;
      }
      outboundHeaders[k] = typeof v === 'string' ? v : [...v];
    }
    const outboundBody = bodyWasSwapped
      ? Buffer.from(phantomResult.bodyText, 'utf8')
      : rawBody;
    if (bodyWasSwapped) {
      outboundHeaders['content-length'] = String(outboundBody.length);
    }

    await this.forwardUpstream(parsedUrl, method, outboundHeaders, outboundBody, res, resolvedTarget);
  }

  private async forwardUpstream(
    parsedUrl: URL,
    method: HttpMethod,
    headers: Record<string, string | string[]>,
    body: Buffer,
    res: http.ServerResponse,
    resolvedTarget?: ResolvedHostAddress,
  ): Promise<void> {
    const override = this.options.upstreamOverrides?.[parsedUrl.hostname.toLowerCase()];
    const protocol = override?.protocol ?? (parsedUrl.protocol === 'https:' ? 'https:' : 'http:');
    const targetHost = override?.host ?? parsedUrl.hostname;
    const targetPort =
      override?.port ??
      (parsedUrl.port
        ? Number.parseInt(parsedUrl.port, 10)
        : protocol === 'https:'
          ? 443
          : 80);

    const requestFn = protocol === 'https:' ? https.request : http.request;
    const pinnedLookup: http.RequestOptions['lookup'] =
      !override && resolvedTarget
        ? (_host, lookupOpts, callback) => {
            if (lookupOpts && typeof lookupOpts === 'object' && 'all' in lookupOpts && lookupOpts.all) {
              (
                callback as (
                  err: NodeJS.ErrnoException | null,
                  addresses: readonly ResolvedHostAddress[],
                ) => void
              )(null, [{ address: resolvedTarget.address, family: resolvedTarget.family }]);
              return;
            }
            callback(null, resolvedTarget.address, resolvedTarget.family);
          }
        : undefined;

    await new Promise<void>((resolve) => {
      const upstreamReq = requestFn(
        {
          host: targetHost,
          port: targetPort,
          method,
          path: `${parsedUrl.pathname}${parsedUrl.search}`,
          headers,
          ...(pinnedLookup ? { lookup: pinnedLookup } : {}),
        },
        (upstreamRes) => {
          const chunks: Buffer[] = [];
          upstreamRes.on('data', (c: Buffer) => chunks.push(c));
          upstreamRes.on('end', () => {
            const respBuf = Buffer.concat(chunks);
            const contentType = String(upstreamRes.headers['content-type'] ?? '');
            const isTextLike =
              contentType === '' ||
              contentType.includes('text/') ||
              contentType.includes('json') ||
              contentType.includes('xml') ||
              contentType.includes('javascript');

            let finalBody: Buffer = respBuf;
            const outHeaders: Record<string, string | string[]> = {};
            for (const [k, v] of Object.entries(upstreamRes.headers)) {
              if (v !== undefined && k.toLowerCase() !== 'transfer-encoding') {
                outHeaders[k] = v;
              }
            }

            if (isTextLike && !upstreamRes.headers['content-encoding']) {
              const scrubbed = this.dlpScanner.sanitizeInboundText(
                this.phantomVault.scrubInbound(respBuf.toString('utf8')),
              );
              finalBody = Buffer.from(scrubbed, 'utf8');
              outHeaders['content-length'] = String(finalBody.length);
            }

            res.writeHead(upstreamRes.statusCode ?? 502, outHeaders);
            res.end(finalBody);
            resolve();
          });
        },
      );

      upstreamReq.on('error', (err) => {
        if (!res.headersSent) {
          res.writeHead(502, { 'content-type': 'text/plain' });
          res.end(`Upstream proxy error: ${err.message}`);
        }
        resolve();
      });

      if (body.length > 0) {
        upstreamReq.write(body);
      }
      upstreamReq.end();
    });
  }

  private checkStaticSsrf(hostname: string, port: number): string | undefined {
    const cleanHost = hostname.toLowerCase().replace(/^\[|\]$/g, '');

    if (this.options.upstreamOverrides?.[cleanHost]) {
      return undefined;
    }

    const isAllowedTestPort =
      this.options.allowTestLoopbackUpstreamPorts?.includes(port) ?? false;

    if (cleanHost === 'localhost' || cleanHost.endsWith('.localhost')) {
      return isAllowedTestPort ? undefined : `localhost:${port}`;
    }

    if (net.isIP(cleanHost)) {
      if (isPrivateOrLoopbackIp(cleanHost)) {
        const isLoopback = cleanHost === '127.0.0.1' || cleanHost === '::1';
        if (isLoopback && isAllowedTestPort) {
          return undefined;
        }
        return cleanHost;
      }
      return undefined;
    }

    return undefined;
  }

  private async resolveAndValidateTarget(
    hostname: string,
    port: number,
  ): Promise<
    | { readonly ok: true; readonly resolved?: ResolvedHostAddress | undefined }
    | { readonly ok: false; readonly reason: 'PRIVATE_IP_SSRF_BLOCKED' | 'DNS_RESOLUTION_FAILED'; readonly detail: string }
  > {
    const cleanHost = hostname.toLowerCase().replace(/^\[|\]$/g, '');

    if (this.options.upstreamOverrides?.[cleanHost]) {
      return { ok: true };
    }

    const staticReason = this.checkStaticSsrf(cleanHost, port);
    if (staticReason) {
      return { ok: false, reason: 'PRIVATE_IP_SSRF_BLOCKED', detail: staticReason };
    }

    const ipVersion = net.isIP(cleanHost);
    if (ipVersion) {
      return { ok: true, resolved: { address: cleanHost, family: ipVersion } };
    }

    const isAllowedTestPort =
      this.options.allowTestLoopbackUpstreamPorts?.includes(port) ?? false;

    let resolvedEntries: readonly ResolvedHostAddress[];
    try {
      const lookupFn =
        this.options.dnsLookup ??
        ((host: string) => dns.lookup(host, { all: true }));
      resolvedEntries = await lookupFn(cleanHost);
    } catch (err) {
      return {
        ok: false,
        reason: 'DNS_RESOLUTION_FAILED',
        detail: `${cleanHost}: ${formatErrorMessage(err)}`,
      };
    }

    if (resolvedEntries.length === 0) {
      return {
        ok: false,
        reason: 'DNS_RESOLUTION_FAILED',
        detail: `${cleanHost}: DNS lookup returned no addresses`,
      };
    }

    for (const entry of resolvedEntries) {
      if (isPrivateOrLoopbackIp(entry.address)) {
        const isLoopback = entry.address === '127.0.0.1' || entry.address === '::1';
        if (isLoopback && isAllowedTestPort) {
          continue;
        }
        return {
          ok: false,
          reason: 'PRIVATE_IP_SSRF_BLOCKED',
          detail: `${cleanHost}->${entry.address}`,
        };
      }
    }

    return { ok: true, resolved: resolvedEntries[0] };
  }

  private findDomainRule(hostname: string) {
    const clean = hostname.toLowerCase();
    return this.options.policy.egressRules.find((rule) => {
      const pattern = rule.domain.toLowerCase();
      if (pattern.startsWith('*.')) {
        const suffix = pattern.slice(1);
        return clean.endsWith(suffix) && clean.length > suffix.length;
      }
      return pattern === clean;
    });
  }

  private parseConnectAuthority(authority: string): { hostname: string; port: number } {
    const lastColon = authority.lastIndexOf(':');
    if (lastColon === -1) {
      return { hostname: authority, port: 443 };
    }
    const hostPart = authority.slice(0, lastColon);
    const portPart = Number.parseInt(authority.slice(lastColon + 1), 10);
    return {
      hostname: hostPart.replace(/^\[|\]$/g, ''),
      port: Number.isFinite(portPart) ? portPart : 443,
    };
  }

  private normalizeMethod(rawMethod?: string): HttpMethod {
    const upper = (rawMethod ?? 'GET').toUpperCase() as HttpMethod;
    return VALID_METHODS.has(upper) ? upper : 'GET';
  }

  private async readBody(req: http.IncomingMessage): Promise<Buffer> {
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    return Buffer.concat(chunks);
  }

  private recordViolation(
    method: HttpMethod,
    url: string,
    reason: DlpViolationReason,
    matchedRule: string,
  ): DlpViolationEvent {
    const event: DlpViolationEvent = {
      timestamp: new Date().toISOString(),
      method,
      url,
      reason,
      matchedRule,
    };
    this.violations.push(event);
    return event;
  }
}
