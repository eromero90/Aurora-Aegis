import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import type {
  CommandResult,
  EgressDomainRule,
  HarvestResult,
  SandboxDriver,
  SandboxPolicy,
  SessionLifecycleState,
  WorkspaceDescriptor,
} from '../types/contracts.js';
import {
  type DiagnosticReporter,
  formatErrorMessage,
  getErrnoCode,
  isExpectedErrno,
} from '../utils/error-codes.js';
import { canonicalizePath } from '../utils/paths.js';
import { SandboxSessionOrchestrator } from './session-orchestrator.js';

const EXPECTED_UNLINK_ERRNOS = new Set(['ENOENT']);

export interface DaemonSessionStatus {
  readonly sessionId: string;
  readonly repoRootPath: string;
  readonly worktreePath: string;
  readonly state: SessionLifecycleState;
  readonly canaryTriggered: boolean;
  readonly violationCount: number;
}

export interface DaemonExecParams {
  readonly repoRootPath: string;
  readonly command: string;
  readonly cwd?: string | undefined;
  readonly timeoutMs?: number | undefined;
  readonly allowedHosts?: readonly string[] | undefined;
  readonly cowDirectories?: readonly string[] | undefined;
  readonly harvestOnSuccess?: boolean | undefined;
}

export interface DaemonHarvestParams {
  readonly repoRootPath: string;
  readonly applyToHost: boolean;
  readonly closeSession?: boolean | undefined;
}

export type DaemonRpcRequest =
  | { readonly action: 'ping' }
  | ({ readonly action: 'exec' } & DaemonExecParams)
  | { readonly action: 'status'; readonly repoRootPath?: string | undefined }
  | ({ readonly action: 'harvest' } & DaemonHarvestParams)
  | { readonly action: 'close_session'; readonly repoRootPath: string }
  | { readonly action: 'shutdown' };

export type DaemonErrorResponse = {
  readonly ok: false;
  readonly error: string;
};

export type DaemonPingResponse = {
  readonly ok: true;
  readonly pid: number;
  readonly activeWorkspaces: readonly string[];
};

export type DaemonExecResponse = {
  readonly ok: true;
  readonly commandResult: CommandResult;
  readonly workspace: WorkspaceDescriptor;
  readonly harvestResult?: HarvestResult | undefined;
};

export type DaemonStatusResponse = {
  readonly ok: true;
  readonly sessions: readonly DaemonSessionStatus[];
};

export type DaemonHarvestResponse = {
  readonly ok: true;
  readonly harvestResult: HarvestResult;
};

export type DaemonCloseSessionResponse = {
  readonly ok: true;
  readonly closed: boolean;
};

export type DaemonShutdownResponse = {
  readonly ok: true;
};

export type DaemonRpcResponse =
  | DaemonErrorResponse
  | DaemonPingResponse
  | DaemonExecResponse
  | DaemonStatusResponse
  | DaemonHarvestResponse
  | DaemonCloseSessionResponse
  | DaemonShutdownResponse;

export interface AegisControlDaemonOptions {
  readonly socketPath: string;
  readonly hostEnv?: NodeJS.ProcessEnv | undefined;
  readonly driverFactory?: (() => SandboxDriver) | undefined;
  readonly onDiagnostic?: DiagnosticReporter | undefined;
}

export class AegisControlDaemon {
  private readonly socketPath: string;
  private readonly sessions = new Map<string, SandboxSessionOrchestrator>();
  private readonly workspaceQueues = new Map<string, Promise<unknown>>();
  private readonly activeSockets = new Set<net.Socket>();
  private server: net.Server | null = null;
  private stopPromise: Promise<void> | null = null;
  private stoppedResolvers: Array<() => void> = [];

  constructor(private readonly options: AegisControlDaemonOptions) {
    this.socketPath = path.resolve(options.socketPath);
  }

  public getSocketPath(): string {
    return this.socketPath;
  }

  public async start(): Promise<string> {
    if (this.server) {
      return this.socketPath;
    }

    fs.mkdirSync(path.dirname(this.socketPath), { recursive: true, mode: 0o700 });
    if (fs.existsSync(this.socketPath)) {
      const stat = fs.lstatSync(this.socketPath);
      if (!stat.isSocket()) {
        throw new Error(`Refusing to overwrite non-socket file at "${this.socketPath}".`);
      }
      fs.unlinkSync(this.socketPath);
    }

    const server = net.createServer((socket) => {
      this.attachClientSocket(socket);
    });
    this.server = server;

    await new Promise<void>((resolve, reject) => {
      const onError = (err: Error) => {
        server.off('listening', onListening);
        reject(err);
      };
      const onListening = () => {
        server.off('error', onError);
        try {
          fs.chmodSync(this.socketPath, 0o600);
          resolve();
        } catch (chmodErr) {
          reject(chmodErr);
        }
      };
      server.once('error', onError);
      server.once('listening', onListening);
      server.listen(this.socketPath);
    });

    return this.socketPath;
  }

  public async stop(): Promise<void> {
    if (this.stopPromise) {
      return this.stopPromise;
    }
    this.stopPromise = this.performStop();
    return this.stopPromise;
  }

  public waitForStop(): Promise<void> {
    if (this.stopPromise) {
      return this.stopPromise;
    }
    if (!this.server) {
      return Promise.resolve();
    }
    return new Promise<void>((resolve) => {
      this.stoppedResolvers.push(resolve);
    });
  }

  private async performStop(): Promise<void> {
    try {
      const openSessions = [...this.sessions.values()];
      this.sessions.clear();
      await Promise.allSettled(openSessions.map((session) => session.close()));

      for (const socket of this.activeSockets) {
        socket.destroy();
      }
      this.activeSockets.clear();

      if (this.server) {
        const srv = this.server;
        this.server = null;
        await new Promise<void>((resolve) => {
          srv.close(() => resolve());
        });
      }
    } finally {
      if (fs.existsSync(this.socketPath)) {
        try {
          fs.unlinkSync(this.socketPath);
        } catch (err) {
          if (!isExpectedErrno(err, EXPECTED_UNLINK_ERRNOS)) {
            this.options.onDiagnostic?.({
              source: 'AegisControlDaemon.performStop.unlink',
              code: getErrnoCode(err),
              message: formatErrorMessage(err),
            });
          }
        }
      }
      const resolvers = this.stoppedResolvers.splice(0, this.stoppedResolvers.length);
      for (const resolve of resolvers) {
        resolve();
      }
    }
  }

  private attachClientSocket(socket: net.Socket): void {
    this.activeSockets.add(socket);
    socket.on('close', () => {
      this.activeSockets.delete(socket);
    });

    let buffer = '';
    let requestChain = Promise.resolve();

    socket.on('data', (chunk: Buffer | string) => {
      buffer += chunk.toString('utf8');
      let newlineIdx = buffer.indexOf('\n');
      while (newlineIdx !== -1) {
        const line = buffer.slice(0, newlineIdx).trim();
        buffer = buffer.slice(newlineIdx + 1);
        if (line.length > 0) {
          requestChain = requestChain.then(() => this.handleLine(socket, line));
        }
        newlineIdx = buffer.indexOf('\n');
      }
    });
  }

  private async handleLine(socket: net.Socket, rawLine: string): Promise<void> {
    let parsed: DaemonRpcRequest;
    try {
      parsed = JSON.parse(rawLine) as DaemonRpcRequest;
    } catch {
      this.writeResponse(socket, { ok: false, error: 'Invalid JSON RPC payload.' });
      return;
    }

    let response: DaemonRpcResponse;
    let shouldShutdown = false;
    try {
      if (parsed.action === 'shutdown') {
        shouldShutdown = true;
        response = { ok: true };
      } else {
        response = await this.dispatchRequest(parsed);
      }
    } catch (error) {
      response = {
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }

    await this.writeResponse(socket, response);
    if (shouldShutdown) {
      setImmediate(() => {
        void this.stop();
      });
    }
  }

  private writeResponse(socket: net.Socket, response: DaemonRpcResponse): Promise<void> {
    if (socket.destroyed || !socket.writable) {
      return Promise.resolve();
    }
    return new Promise<void>((resolve) => {
      socket.write(`${JSON.stringify(response)}\n`, () => resolve());
    });
  }

  private runSerialized<T>(canonicalRepo: string, fn: () => Promise<T>): Promise<T> {
    const previous = this.workspaceQueues.get(canonicalRepo) ?? Promise.resolve();
    const current = previous.catch(() => undefined).then(fn);
    const tail = current.then(
      () => undefined,
      () => undefined,
    );
    this.workspaceQueues.set(canonicalRepo, tail);
    void tail.finally(() => {
      if (this.workspaceQueues.get(canonicalRepo) === tail) {
        this.workspaceQueues.delete(canonicalRepo);
      }
    });
    return current;
  }

  private async dispatchRequest(req: Exclude<DaemonRpcRequest, { action: 'shutdown' }>): Promise<DaemonRpcResponse> {
    switch (req.action) {
      case 'ping':
        return {
          ok: true,
          pid: process.pid,
          activeWorkspaces: [...this.sessions.keys()],
        };

      case 'status': {
        const filterRepo = req.repoRootPath ? canonicalizePath(req.repoRootPath) : undefined;
        const sessions: DaemonSessionStatus[] = [];
        for (const [repoRootPath, session] of this.sessions.entries()) {
          if (filterRepo && repoRootPath !== filterRepo) {
            continue;
          }
          sessions.push({
            sessionId: session.getEffectivePolicy().sessionId,
            repoRootPath,
            worktreePath: session.getWorkspace()?.worktreePath ?? '',
            state: session.getState(),
            canaryTriggered: session.isCanaryTriggered(),
            violationCount: session.getViolations().length,
          });
        }
        return { ok: true, sessions };
      }

      case 'exec': {
        const canonicalRepo = canonicalizePath(req.repoRootPath);
        return this.runSerialized(canonicalRepo, async () => {
          let orchestrator = this.sessions.get(canonicalRepo);
          if (!orchestrator || orchestrator.getState() === 'cleaned-up') {
            orchestrator = new SandboxSessionOrchestrator({
              policy: this.buildPolicy(canonicalRepo, req),
              hostEnv: this.options.hostEnv,
              driver: this.options.driverFactory?.(),
            });
            await orchestrator.start();
            this.sessions.set(canonicalRepo, orchestrator);
          }

          const commandResult = await orchestrator.exec(req.command, {
            cwd: req.cwd,
            timeoutMs: req.timeoutMs,
          });
          const workspace = orchestrator.getWorkspace();
          if (!workspace) {
            throw new Error('Daemon session workspace is not initialized.');
          }

          let harvestResult: HarvestResult | undefined;
          if (req.harvestOnSuccess && commandResult.exitCode === 0 && !commandResult.canaryTriggered) {
            harvestResult = await orchestrator.harvest(true);
          }

          return {
            ok: true,
            commandResult,
            workspace,
            ...(harvestResult !== undefined ? { harvestResult } : {}),
          };
        });
      }

      case 'harvest': {
        const canonicalRepo = canonicalizePath(req.repoRootPath);
        return this.runSerialized(canonicalRepo, async () => {
          const orchestrator = this.sessions.get(canonicalRepo);
          if (!orchestrator) {
            throw new Error(`No active daemon session for workspace "${canonicalRepo}".`);
          }
          const harvestResult = await orchestrator.harvest(req.applyToHost);
          if (req.closeSession) {
            this.sessions.delete(canonicalRepo);
            await orchestrator.close();
          }
          return { ok: true, harvestResult };
        });
      }

      case 'close_session': {
        const canonicalRepo = canonicalizePath(req.repoRootPath);
        return this.runSerialized(canonicalRepo, async () => {
          const orchestrator = this.sessions.get(canonicalRepo);
          if (!orchestrator) {
            return { ok: true, closed: false };
          }
          this.sessions.delete(canonicalRepo);
          await orchestrator.close();
          return { ok: true, closed: true };
        });
      }
    }
  }

  private buildPolicy(canonicalRepo: string, req: DaemonExecParams): SandboxPolicy {
    const egressRules: EgressDomainRule[] = (
      req.allowedHosts ?? ['registry.npmjs.org', 'api.github.com']
    ).map((domain) => ({
      domain,
      allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'],
    }));

    return {
      sessionId: `daemon-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
      repoRootPath: canonicalRepo,
      tier: 'tier1-kernel-mac',
      cowDirectories: req.cowDirectories ?? [],
      readOnlyToolchainPaths: [path.dirname(process.execPath)],
      egressRules,
      phantomCredentials: [],
      protectedSecrets: [],
      timeoutMs: req.timeoutMs ?? 60_000,
    };
  }
}

export class AegisDaemonClient {
  private readonly socketPath: string;

  constructor(socketPath: string) {
    this.socketPath = path.resolve(socketPath);
  }

  public ping(): Promise<DaemonPingResponse> {
    return this.send<DaemonPingResponse>({ action: 'ping' });
  }

  public exec(params: DaemonExecParams): Promise<DaemonExecResponse> {
    return this.send<DaemonExecResponse>({ action: 'exec', ...params });
  }

  public status(repoRootPath?: string): Promise<DaemonStatusResponse> {
    return this.send<DaemonStatusResponse>({
      action: 'status',
      ...(repoRootPath !== undefined ? { repoRootPath } : {}),
    });
  }

  public harvest(params: DaemonHarvestParams): Promise<DaemonHarvestResponse> {
    return this.send<DaemonHarvestResponse>({ action: 'harvest', ...params });
  }

  public closeSession(repoRootPath: string): Promise<DaemonCloseSessionResponse> {
    return this.send<DaemonCloseSessionResponse>({ action: 'close_session', repoRootPath });
  }

  public shutdown(): Promise<DaemonShutdownResponse> {
    return this.send<DaemonShutdownResponse>({ action: 'shutdown' });
  }

  private send<T extends Extract<DaemonRpcResponse, { ok: true }>>(request: DaemonRpcRequest): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const client = net.createConnection(this.socketPath, () => {
        client.write(`${JSON.stringify(request)}\n`);
      });

      let buffer = '';
      let settled = false;

      const finishReject = (err: Error) => {
        if (settled) return;
        settled = true;
        client.destroy();
        reject(err);
      };

      client.on('data', (chunk: Buffer | string) => {
        buffer += chunk.toString('utf8');
        const newlineIdx = buffer.indexOf('\n');
        if (newlineIdx === -1) {
          return;
        }
        const line = buffer.slice(0, newlineIdx).trim();
        settled = true;
        client.end();

        try {
          const parsed = JSON.parse(line) as DaemonRpcResponse;
          if (!parsed.ok) {
            reject(new Error(parsed.error));
            return;
          }
          resolve(parsed as T);
        } catch (parseErr) {
          reject(parseErr instanceof Error ? parseErr : new Error(String(parseErr)));
        }
      });

      client.on('error', (err) => {
        finishReject(err);
      });

      client.on('end', () => {
        if (!settled) {
          finishReject(new Error('Daemon closed connection before sending RPC response.'));
        }
      });
    });
  }
}
