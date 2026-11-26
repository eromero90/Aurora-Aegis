import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { afterEach, describe, expect, it } from 'vitest';
import type { CommandResult, HarvestResult } from '@aegis/core';
import { AegisMcpServer } from '../src/index.js';

const tempDirs: string[] = [];
const openServers: AegisMcpServer[] = [];

function makeTempDir(prefix: string): string {
  const dir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  tempDirs.push(dir);
  return dir;
}

function initGitRepo(repoDir: string, files: Record<string, string>): void {
  execFileSync('git', ['init', '-b', 'main'], { cwd: repoDir, stdio: 'pipe' });
  execFileSync('git', ['config', 'user.email', 'mcp-test@aurora-aegis.local'], { cwd: repoDir, stdio: 'pipe' });
  execFileSync('git', ['config', 'user.name', 'Aegis MCP Test'], { cwd: repoDir, stdio: 'pipe' });

  for (const [relPath, content] of Object.entries(files)) {
    const absPath = path.join(repoDir, relPath);
    fs.mkdirSync(path.dirname(absPath), { recursive: true });
    fs.writeFileSync(absPath, content, 'utf8');
  }

  execFileSync('git', ['add', '-A'], { cwd: repoDir, stdio: 'pipe' });
  execFileSync('git', ['commit', '-m', 'init'], { cwd: repoDir, stdio: 'pipe' });
}

afterEach(async () => {
  while (openServers.length > 0) {
    const server = openServers.pop();
    if (server) {
      await server.closeAll();
    }
  }
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir && fs.existsSync(dir)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

describe('@aegis/mcp-server', () => {
  it('handles JSON-RPC initialize, tools/list, and sandbox_fork -> exec -> diff -> harvest workflow', async () => {
    const repoDir = makeTempDir('aegis-mcp-repo-');
    initGitRepo(repoDir, {
      'src/math.ts': 'export const add = (a: number, b: number) => a - b;\n',
    });

    const server = new AegisMcpServer();
    openServers.push(server);

    const initResp = await server.handleJsonRpc({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
    });
    expect(initResp?.error).toBeUndefined();
    expect((initResp?.result as { serverInfo: { name: string } }).serverInfo.name).toBe('aurora-aegis-mcp-server');

    const notifResp = await server.handleJsonRpc({
      jsonrpc: '2.0',
      method: 'notifications/initialized',
    });
    expect(notifResp).toBeNull();

    const listResp = await server.handleJsonRpc({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/list',
    });
    const tools = (listResp?.result as { tools: Array<{ name: string }> }).tools;
    expect(tools.map((t) => t.name)).toEqual([
      'sandbox_fork',
      'sandbox_exec',
      'sandbox_diff',
      'sandbox_harvest',
    ]);

    const forkResp = await server.handleJsonRpc({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: {
        name: 'sandbox_fork',
        arguments: {
          repoRootPath: repoDir,
          sessionId: 'mcp-e2e-1',
        },
      },
    });
    const forkPayload = (forkResp?.result as { structuredContent: { sessionId: string; worktreePath: string; state: string } })
      .structuredContent;
    expect(forkPayload.sessionId).toBe('mcp-e2e-1');
    expect(forkPayload.state).toBe('proxy-active');
    expect(fs.existsSync(forkPayload.worktreePath)).toBe(true);

    const execResp = await server.handleJsonRpc({
      jsonrpc: '2.0',
      id: 4,
      method: 'tools/call',
      params: {
        name: 'sandbox_exec',
        arguments: {
          sessionId: 'mcp-e2e-1',
          command: 'printf "export const add = (a: number, b: number) => a + b;\\n" > src/math.ts',
        },
      },
    });
    const execPayload = (execResp?.result as { structuredContent: CommandResult }).structuredContent;
    expect(execPayload.exitCode).toBe(0);
    expect(execPayload.canaryTriggered).toBe(false);

    const diffResp = await server.handleJsonRpc({
      jsonrpc: '2.0',
      id: 5,
      method: 'tools/call',
      params: {
        name: 'sandbox_diff',
        arguments: { sessionId: 'mcp-e2e-1' },
      },
    });
    const diffPayload = (diffResp?.result as { structuredContent: HarvestResult }).structuredContent;
    expect(diffPayload.appliedToHost).toBe(false);
    expect(diffPayload.changedFiles).toContain('src/math.ts');
    expect(diffPayload.patchDiff).toContain('+export const add = (a: number, b: number) => a + b;');
    expect(fs.readFileSync(path.join(repoDir, 'src/math.ts'), 'utf8')).toContain('a - b');

    const harvestResp = await server.handleJsonRpc({
      jsonrpc: '2.0',
      id: 6,
      method: 'tools/call',
      params: {
        name: 'sandbox_harvest',
        arguments: { sessionId: 'mcp-e2e-1', applyToHost: true },
      },
    });
    const harvestPayload = (harvestResp?.result as { structuredContent: HarvestResult }).structuredContent;
    expect(harvestPayload.appliedToHost).toBe(true);
    expect(harvestPayload.hookIntegrityVerified).toBe(true);
    expect(fs.readFileSync(path.join(repoDir, 'src/math.ts'), 'utf8')).toContain('a + b');
    expect(server.getActiveSessionIds()).toHaveLength(0);
    expect(fs.existsSync(forkPayload.worktreePath)).toBe(false);
  });

  it('serves newline-delimited JSON-RPC over stdio streams and reports -32700 on malformed JSON', async () => {
    const server = new AegisMcpServer();
    openServers.push(server);

    const input = new PassThrough();
    const output = new PassThrough();
    let rawOutput = '';
    output.on('data', (chunk: Buffer | string) => {
      rawOutput += chunk.toString('utf8');
    });

    const served = server.serveStdio(input, output);
    input.write('{malformed json\n');
    input.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' })}\n`);
    input.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
    input.write(`${JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' })}\n`);
    input.end();

    await served;

    const lines = rawOutput
      .trim()
      .split('\n')
      .map(
        (line) =>
          JSON.parse(line) as {
            id: number | null;
            error?: { code: number; message: string };
            result?: {
              serverInfo?: { name: string };
              tools?: Array<{ name: string }>;
            };
          },
      );

    expect(lines).toHaveLength(3);
    expect(lines[0]?.id).toBeNull();
    expect(lines[0]?.error?.code).toBe(-32700);
    expect(lines[1]?.id).toBe(1);
    expect(lines[1]?.result?.serverInfo?.name).toBe('aurora-aegis-mcp-server');
    expect(lines[2]?.id).toBe(2);
    expect(lines[2]?.result?.tools?.map((t) => t.name)).toEqual([
      'sandbox_fork',
      'sandbox_exec',
      'sandbox_diff',
      'sandbox_harvest',
    ]);
  });
});
