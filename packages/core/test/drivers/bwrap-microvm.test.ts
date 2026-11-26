import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { compileBwrapArgs } from '../../src/drivers/bwrap-compiler.js';
import { MicroVMDriver } from '../../src/drivers/microvm-driver.js';
import { UdsLoopbackBridge } from '../../src/drivers/uds-bridge.js';
import type { SandboxPolicy } from '../../src/types/contracts.js';
import { EphemeralWorktreeManager } from '../../src/workspace/worktree-manager.js';

describe('BwrapCompiler, UdsLoopbackBridge & MicroVMDriver', () => {
  let tempRoot: string;
  let repoRoot: string;
  const manager = new EphemeralWorktreeManager();

  beforeEach(() => {
    tempRoot = fs.realpathSync.native(
      fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-bwrap-test-')),
    );
    repoRoot = path.join(tempRoot, 'repo');
    fs.mkdirSync(repoRoot, { recursive: true });

    execFileSync('git', ['init'], { cwd: repoRoot, stdio: 'ignore' });
    execFileSync('git', ['config', 'user.email', 'test@aegis.local'], { cwd: repoRoot });
    execFileSync('git', ['config', 'user.name', 'Aegis Test'], { cwd: repoRoot });
    fs.writeFileSync(path.join(repoRoot, 'README.md'), '# Bwrap Test\n');
    execFileSync('git', ['add', 'README.md'], { cwd: repoRoot });
    execFileSync('git', ['commit', '-m', 'init'], { cwd: repoRoot, stdio: 'ignore' });
  });

  afterEach(() => {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  it('compiles bubblewrap args with unshare-all, masked HOME, Git Hook Guard, and UDS mount', async () => {
    const workspace = await manager.create(repoRoot, 'bwrap_01', []);
    const udsPath = path.join(workspace.sessionTmpDir, 'egress.sock');
    fs.writeFileSync(udsPath, '');

    try {
      const policy: SandboxPolicy = {
        sessionId: 'bwrap_01',
        repoRootPath: workspace.repoRootPath,
        tier: 'tier1-kernel-mac',
        cowDirectories: [],
        readOnlyToolchainPaths: [],
        egressRules: [],
        phantomCredentials: [],
        protectedSecrets: [],
        timeoutMs: 5000,
      };

      const args = compileBwrapArgs(policy, workspace, udsPath, 'echo ok');
      const joined = args.join(' ');
      expect(args).toContain('--unshare-all');
      expect(args).toContain('--tmpfs');
      expect(joined).toContain(`--ro-bind ${workspace.repoGitDir}/hooks ${workspace.repoGitDir}/hooks`);
      expect(joined).toContain(`--ro-bind-try ${workspace.repoGitDir}/config ${workspace.repoGitDir}/config`);
      expect(joined).toContain(`--bind ${udsPath} /run/aegis/egress.sock`);
    } finally {
      await manager.destroy(workspace);
    }
  });

  it('forwards TCP loopback traffic bidirectionally to a Unix Domain Socket via UdsLoopbackBridge', async () => {
    const sockPath = path.join(tempRoot, 'echo.sock');
    const udsServer = net.createServer((socket) => {
      socket.on('data', (data) => socket.write(`echo:${data.toString('utf8')}`));
    });
    await new Promise<void>((resolve) => udsServer.listen(sockPath, resolve));

    const bridge = new UdsLoopbackBridge();
    const tcpPort = await bridge.start(sockPath);

    try {
      const response = await new Promise<string>((resolve, reject) => {
        const client = net.createConnection({ host: '127.0.0.1', port: tcpPort }, () => {
          client.write('hello-aegis');
        });
        client.on('data', (chunk) => {
          client.end();
          resolve(chunk.toString('utf8'));
        });
        client.on('error', reject);
      });

      expect(response).toBe('echo:hello-aegis');
    } finally {
      await bridge.stop();
      await new Promise<void>((resolve) => udsServer.close(() => resolve()));
    }
  });

  it('enforces networkless virtio-vsock isolation invariants and unconfigured guest guard on MicroVMDriver', async () => {
    const workspace = await manager.create(repoRoot, 'vm_01', []);
    const driver = new MicroVMDriver({ vcpus: 4, memoryMb: 2048, vsockPort: 6100 });

    try {
      await expect(
        driver.exec({
          command: 'id',
          env: {},
          proxyPort: 8899,
          caCertPath: path.join(workspace.sessionTmpDir, 'ca.pem'),
        }),
      ).rejects.toThrow(/before prepare/);

      const policy: SandboxPolicy = {
        sessionId: 'vm_01',
        repoRootPath: workspace.repoRootPath,
        tier: 'tier2-microvm',
        cowDirectories: [],
        readOnlyToolchainPaths: [],
        egressRules: [],
        phantomCredentials: [],
        protectedSecrets: [],
        timeoutMs: 5000,
      };

      await driver.prepare(policy, workspace, 8899);
      const spec = driver.getLaunchSpec();
      expect(spec).toBeDefined();
      const joinedArgs = spec!.args.join(' ');
      expect(spec?.vsockSocketPath).toBe(path.join(workspace.sessionTmpDir, 'vsock.sock'));
      expect(joinedArgs).not.toContain('virtio-net');

      if (process.platform === 'darwin') {
        expect(joinedArgs).toContain(`sharedDir=${workspace.worktreePath}`);
        expect(joinedArgs).toContain(`socketURL=${workspace.sessionTmpDir}/vsock.sock`);
      }

      await expect(
        driver.exec({
          command: 'id',
          env: {},
          proxyPort: 8899,
          caCertPath: path.join(workspace.sessionTmpDir, 'ca.pem'),
        }),
      ).rejects.toThrow(/requires configured kernel\/rootfs/);
    } finally {
      await driver.cleanup();
      await manager.destroy(workspace);
    }
  });
});
