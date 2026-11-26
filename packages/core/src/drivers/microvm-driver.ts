import path from 'node:path';
import type {
  CommandResult,
  DriverExecOptions,
  IsolationTier,
  SandboxDriver,
  SandboxPolicy,
  WorkspaceDescriptor,
} from '../types/contracts.js';
import { canonicalizePath } from '../utils/paths.js';

export interface MicroVMConfig {
  readonly kernelPath?: string | undefined;
  readonly initrdPath?: string | undefined;
  readonly rootfsPath?: string | undefined;
  readonly vcpus?: number | undefined;
  readonly memoryMb?: number | undefined;
  readonly vsockPort?: number | undefined;
}

export interface MicroVMLaunchSpec {
  readonly hypervisor: 'vfkit' | 'firecracker';
  readonly binary: string;
  readonly args: readonly string[];
  readonly vsockSocketPath: string;
  readonly vsockPort: number;
  readonly guestCid: number;
}

export class MicroVMDriver implements SandboxDriver {
  readonly tier: IsolationTier = 'tier2-microvm';

  private policy: SandboxPolicy | undefined;
  private workspace: WorkspaceDescriptor | undefined;
  private launchSpec: MicroVMLaunchSpec | undefined;

  constructor(private readonly vmConfig: MicroVMConfig = {}) {}

  async prepare(
    policy: SandboxPolicy,
    workspace: WorkspaceDescriptor,
    _proxyPort: number,
  ): Promise<void> {
    this.policy = policy;
    this.workspace = workspace;
    this.launchSpec = this.buildVmLaunchSpec(policy, workspace);
  }

  buildVmLaunchSpec(
    _policy: SandboxPolicy,
    workspace: WorkspaceDescriptor,
  ): MicroVMLaunchSpec {
    const sessionTmp = canonicalizePath(workspace.sessionTmpDir);
    const worktree = canonicalizePath(workspace.worktreePath);
    const vsockSocketPath = path.join(sessionTmp, 'vsock.sock');
    const vsockPort = this.vmConfig.vsockPort ?? 5000;
    const vcpus = this.vmConfig.vcpus ?? 2;
    const memoryMb = this.vmConfig.memoryMb ?? 1024;
    const kernel = this.vmConfig.kernelPath ?? '/opt/aegis/vm/vmlinux';
    const rootfs = this.vmConfig.rootfsPath ?? '/opt/aegis/vm/rootfs.ext4';

    if (process.platform === 'darwin') {
      const args: string[] = [
        '--cpus',
        String(vcpus),
        '--memory',
        String(memoryMb),
        '--bootloader',
        `linux,kernel=${kernel}${this.vmConfig.initrdPath ? `,initrd=${this.vmConfig.initrdPath}` : ''},cmdline=console=hvc0 root=/dev/vda rw`,
        '--device',
        `virtio-blk,path=${rootfs}`,
        '--device',
        `virtio-fs,sharedDir=${worktree},mountTag=aegis-worktree`,
        '--device',
        `virtio-vsock,port=${vsockPort},socketURL=${vsockSocketPath},listen`,
      ];

      return {
        hypervisor: 'vfkit',
        binary: 'vfkit',
        args,
        vsockSocketPath,
        vsockPort,
        guestCid: 3,
      };
    }

    const firecrackerConfigPath = path.join(sessionTmp, 'firecracker.json');
    return {
      hypervisor: 'firecracker',
      binary: 'firecracker',
      args: ['--api-sock', path.join(sessionTmp, 'firecracker.sock'), '--config-file', firecrackerConfigPath],
      vsockSocketPath,
      vsockPort,
      guestCid: 3,
    };
  }

  async exec(
    _options: DriverExecOptions,
  ): Promise<Omit<CommandResult, 'blockedEgressEvents' | 'canaryTriggered'>> {
    if (!this.policy || !this.workspace || !this.launchSpec) {
      throw new Error('MicroVMDriver.exec called before prepare().');
    }
    throw new Error(
      `Tier 2 MicroVM guest runtime (${this.launchSpec.hypervisor}) requires configured kernel/rootfs guest images at "${this.vmConfig.kernelPath ?? '/opt/aegis/vm/vmlinux'}".`,
    );
  }

  getLaunchSpec(): MicroVMLaunchSpec | undefined {
    return this.launchSpec;
  }

  async cleanup(): Promise<void> {
    this.launchSpec = undefined;
  }
}
