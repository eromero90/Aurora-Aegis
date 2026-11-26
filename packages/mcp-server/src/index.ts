#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { pathToFileURL } from 'node:url';
import {
  type EgressDomainRule,
  type IsolationTier,
  type SandboxDriver,
  SandboxSessionOrchestrator,
  type SandboxPolicy,
} from '@aegis/core';

export interface McpToolDefinition {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: {
    readonly type: 'object';
    readonly properties: Readonly<Record<string, unknown>>;
    readonly required?: readonly string[] | undefined;
  };
}

export interface McpToolCallResult {
  readonly content: readonly [{ readonly type: 'text'; readonly text: string }];
  readonly structuredContent?: unknown;
  readonly isError?: boolean | undefined;
}

export interface JsonRpcRequest {
  readonly jsonrpc: '2.0';
  readonly id?: string | number | null | undefined;
  readonly method: string;
  readonly params?: Record<string, unknown> | undefined;
}

export interface JsonRpcResponse {
  readonly jsonrpc: '2.0';
  readonly id: string | number | null;
  readonly result?: unknown;
  readonly error?: { readonly code: number; readonly message: string } | undefined;
}

export interface AegisMcpServerOptions {
  readonly driverFactory?: (() => SandboxDriver) | undefined;
  readonly hostEnv?: NodeJS.ProcessEnv | undefined;
}

function errorToolResult(message: string): McpToolCallResult {
  const payload = { error: message };
  return {
    content: [{ type: 'text', text: JSON.stringify(payload) }],
    structuredContent: payload,
    isError: true,
  };
}

function okToolResult(payload: unknown): McpToolCallResult {
  return {
    content: [{ type: 'text', text: JSON.stringify(payload) }],
    structuredContent: payload,
  };
}

export class AegisMcpServer {
  private readonly sessions = new Map<string, SandboxSessionOrchestrator>();

  constructor(private readonly options: AegisMcpServerOptions = {}) {}

  public listTools(): readonly McpToolDefinition[] {
    return [
      {
        name: 'sandbox_fork',
        description: 'Provision an isolated Ephemeral Worktree sandbox session with CoW dependencies and Egress Firewall.',
        inputSchema: {
          type: 'object',
          properties: {
            repoRootPath: { type: 'string' },
            sessionId: { type: 'string' },
            tier: { type: 'string', enum: ['tier1-kernel-mac', 'tier2-microvm'] },
            cowDirectories: { type: 'array', items: { type: 'string' } },
            allowedHosts: { type: 'array', items: { type: 'string' } },
            timeoutMs: { type: 'number' },
          },
          required: ['repoRootPath'],
        },
      },
      {
        name: 'sandbox_exec',
        description: 'Execute a shell command inside a provisioned Sandbox Session.',
        inputSchema: {
          type: 'object',
          properties: {
            sessionId: { type: 'string' },
            command: { type: 'string' },
            cwd: { type: 'string' },
            timeoutMs: { type: 'number' },
          },
          required: ['sessionId', 'command'],
        },
      },
      {
        name: 'sandbox_diff',
        description: 'Inspect changed files, unified Git patch, hook integrity, and persistence findings without mutating host.',
        inputSchema: {
          type: 'object',
          properties: {
            sessionId: { type: 'string' },
          },
          required: ['sessionId'],
        },
      },
      {
        name: 'sandbox_harvest',
        description: 'Verify integrity and optionally apply sandbox patch diff back to host repository, then close session.',
        inputSchema: {
          type: 'object',
          properties: {
            sessionId: { type: 'string' },
            applyToHost: { type: 'boolean' },
          },
          required: ['sessionId'],
        },
      },
    ];
  }

  public getActiveSessionIds(): readonly string[] {
    return [...this.sessions.keys()];
  }

  public async callTool(name: string, args: Record<string, unknown> = {}): Promise<McpToolCallResult> {
    try {
      switch (name) {
        case 'sandbox_fork':
          return await this.handleFork(args);
        case 'sandbox_exec':
          return await this.handleExec(args);
        case 'sandbox_diff':
          return await this.handleDiff(args);
        case 'sandbox_harvest':
          return await this.handleHarvest(args);
        default:
          return errorToolResult(`Unknown MCP tool: ${name}`);
      }
    } catch (error) {
      return errorToolResult(error instanceof Error ? error.message : String(error));
    }
  }

  public async handleJsonRpc(request: JsonRpcRequest): Promise<JsonRpcResponse | null> {
    if (request.id === undefined && request.method.startsWith('notifications/')) {
      return null;
    }

    const responseId = request.id ?? null;

    if (request.method === 'initialize') {
      return {
        jsonrpc: '2.0',
        id: responseId,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: {
            name: 'aurora-aegis-mcp-server',
            version: '0.1.0',
          },
        },
      };
    }

    if (request.method === 'tools/list') {
      return {
        jsonrpc: '2.0',
        id: responseId,
        result: { tools: this.listTools() },
      };
    }

    if (request.method === 'tools/call') {
      const toolName = typeof request.params?.['name'] === 'string' ? request.params['name'] : '';
      const rawArgs = request.params?.['arguments'];
      const toolArgs =
        rawArgs !== null && typeof rawArgs === 'object' && !Array.isArray(rawArgs)
          ? (rawArgs as Record<string, unknown>)
          : {};
      if (!toolName) {
        return {
          jsonrpc: '2.0',
          id: responseId,
          error: { code: -32602, message: 'Missing tools/call parameter: name' },
        };
      }
      const toolResult = await this.callTool(toolName, toolArgs);
      return {
        jsonrpc: '2.0',
        id: responseId,
        result: toolResult,
      };
    }

    return {
      jsonrpc: '2.0',
      id: responseId,
      error: { code: -32601, message: `Method not found: ${request.method}` },
    };
  }

  public serveStdio(
    input: NodeJS.ReadableStream = process.stdin,
    output: NodeJS.WritableStream = process.stdout,
  ): Promise<void> {
    const rl = readline.createInterface({ input, crlfDelay: Infinity });
    const pendingRequests = new Set<Promise<void>>();

    rl.on('line', (line) => {
      const trimmed = line.trim();
      if (trimmed.length === 0) {
        return;
      }
      let parsed: JsonRpcRequest;
      try {
        parsed = JSON.parse(trimmed) as JsonRpcRequest;
      } catch {
        const errResp: JsonRpcResponse = {
          jsonrpc: '2.0',
          id: null,
          error: { code: -32700, message: 'Parse error' },
        };
        output.write(`${JSON.stringify(errResp)}\n`);
        return;
      }

      const task = this.handleJsonRpc(parsed).then((resp) => {
        if (resp !== null) {
          output.write(`${JSON.stringify(resp)}\n`);
        }
      });
      pendingRequests.add(task);
      void task.finally(() => {
        pendingRequests.delete(task);
      });
    });

    return new Promise<void>((resolve) => {
      rl.once('close', () => {
        void Promise.allSettled([...pendingRequests])
          .then(() => this.closeAll())
          .finally(() => resolve());
      });
    });
  }

  public async closeAll(): Promise<void> {
    const openSessions = [...this.sessions.values()];
    this.sessions.clear();
    for (const session of openSessions) {
      await session.close();
    }
  }

  private async handleFork(args: Record<string, unknown>): Promise<McpToolCallResult> {
    const repoRootPath = typeof args['repoRootPath'] === 'string' ? args['repoRootPath'] : '';
    if (repoRootPath.length === 0) {
      return errorToolResult('sandbox_fork requires non-empty string "repoRootPath".');
    }

    const sessionId =
      typeof args['sessionId'] === 'string' && args['sessionId'].length > 0
        ? args['sessionId']
        : `mcp-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;

    if (this.sessions.has(sessionId)) {
      return errorToolResult(`Session "${sessionId}" already exists.`);
    }

    const tier: IsolationTier = args['tier'] === 'tier2-microvm' ? 'tier2-microvm' : 'tier1-kernel-mac';
    const cowDirectories = Array.isArray(args['cowDirectories'])
      ? args['cowDirectories'].filter((v): v is string => typeof v === 'string')
      : [];
    const allowedHosts = Array.isArray(args['allowedHosts'])
      ? args['allowedHosts'].filter((v): v is string => typeof v === 'string')
      : [];
    const timeoutMs = typeof args['timeoutMs'] === 'number' && args['timeoutMs'] > 0 ? args['timeoutMs'] : 60_000;

    const egressRules: EgressDomainRule[] = allowedHosts.map((domain) => ({
      domain,
      allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'],
    }));

    const policy: SandboxPolicy = {
      sessionId,
      repoRootPath,
      tier,
      cowDirectories,
      readOnlyToolchainPaths: [path.dirname(process.execPath)],
      egressRules,
      phantomCredentials: [],
      protectedSecrets: [],
      timeoutMs,
    };

    const orchestrator = new SandboxSessionOrchestrator({
      policy,
      hostEnv: this.options.hostEnv,
      driver: this.options.driverFactory?.(),
    });

    const workspace = await orchestrator.start();
    this.sessions.set(sessionId, orchestrator);

    return okToolResult({
      sessionId,
      worktreePath: workspace.worktreePath,
      state: orchestrator.getState(),
      clonedCowDirs: workspace.clonedCowDirs,
    });
  }

  private async handleExec(args: Record<string, unknown>): Promise<McpToolCallResult> {
    const sessionId = typeof args['sessionId'] === 'string' ? args['sessionId'] : '';
    const command = typeof args['command'] === 'string' ? args['command'] : '';
    const orchestrator = this.sessions.get(sessionId);
    if (!orchestrator) {
      return errorToolResult(`Unknown session "${sessionId}".`);
    }
    if (command.length === 0) {
      return errorToolResult('sandbox_exec requires non-empty "command".');
    }

    const cwd = typeof args['cwd'] === 'string' ? args['cwd'] : undefined;
    const timeoutMs = typeof args['timeoutMs'] === 'number' ? args['timeoutMs'] : undefined;
    const result = await orchestrator.exec(command, { cwd, timeoutMs });
    return okToolResult(result);
  }

  private async handleDiff(args: Record<string, unknown>): Promise<McpToolCallResult> {
    const sessionId = typeof args['sessionId'] === 'string' ? args['sessionId'] : '';
    const orchestrator = this.sessions.get(sessionId);
    if (!orchestrator) {
      return errorToolResult(`Unknown session "${sessionId}".`);
    }
    const diffResult = await orchestrator.harvest(false);
    return okToolResult(diffResult);
  }

  private async handleHarvest(args: Record<string, unknown>): Promise<McpToolCallResult> {
    const sessionId = typeof args['sessionId'] === 'string' ? args['sessionId'] : '';
    const orchestrator = this.sessions.get(sessionId);
    if (!orchestrator) {
      return errorToolResult(`Unknown session "${sessionId}".`);
    }

    const applyToHost = args['applyToHost'] !== false;
    try {
      const harvestResult = await orchestrator.harvest(applyToHost);
      return okToolResult(harvestResult);
    } finally {
      this.sessions.delete(sessionId);
      await orchestrator.close();
    }
  }
}

function isMainEntrypoint(moduleUrl: string): boolean {
  const entry = process.argv[1];
  if (!entry) {
    return false;
  }
  try {
    return moduleUrl === pathToFileURL(fs.realpathSync(entry)).href;
  } catch {
    return moduleUrl === pathToFileURL(entry).href;
  }
}

if (isMainEntrypoint(import.meta.url)) {
  void new AegisMcpServer().serveStdio();
}
