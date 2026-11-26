import type { ChildProcess } from 'node:child_process';
import { EventEmitter } from 'node:events';
import path from 'node:path';
import { BwrapDriver } from '../drivers/bwrap-driver.js';
import { MicroVMDriver } from '../drivers/microvm-driver.js';
import { SeatbeltDriver } from '../drivers/seatbelt-driver.js';
import { EgressFirewall, type UpstreamOverrideTarget } from '../firewall/egress-firewall.js';
import { AttestationSigner } from '../harvester/attestation.js';
import { DiffHarvester } from '../harvester/diff-harvester.js';
import { GitHookIntegrityVerifier, type GitIntegritySnapshot } from '../harvester/hook-verifier.js';
import { loadRepositoryPolicyFile, mergePolicyWithRepoConfig } from '../policy/policy-loader.js';
import type {
  AuditLedgerEntry,
  CanaryHoneytoken,
  CommandResult,
  DlpViolationEvent,
  HarvestResult,
  PhantomCredentialRule,
  SandboxDriver,
  SandboxPolicy,
  SessionLifecycleState,
  WorkspaceDescriptor,
} from '../types/contracts.js';
import { CanaryPlanter } from '../workspace/canary-planter.js';
import { EnvScrubber } from '../workspace/env-scrubber.js';
import { EphemeralWorktreeManager } from '../workspace/worktree-manager.js';
import {
  type RuntimeDiagnostic,
  formatErrorMessage,
  getErrnoCode,
  isExpectedErrno,
} from '../utils/error-codes.js';
import { SessionAuditLedger } from './audit-ledger.js';

const EXPECTED_CLOSE_ERRNOS = new Set(['ENOENT', 'ESRCH']);

export interface SandboxSessionOptions {
  readonly policy: SandboxPolicy;
  readonly driver?: SandboxDriver | undefined;
  readonly hostEnv?: NodeJS.ProcessEnv | undefined;
  readonly enableUdsServer?: boolean | undefined;
  readonly allowTestLoopbackUpstreamPorts?: readonly number[] | undefined;
  readonly upstreamOverrides?: Readonly<Record<string, UpstreamOverrideTarget>> | undefined;
  readonly plantCanaries?: boolean | undefined;
  readonly scrubWorktreeEnv?: boolean | undefined;
  readonly defaultAllowedHostsForEnvPhantom?: readonly string[] | undefined;
}

export interface ExecCommandOptions {
  readonly cwd?: string | undefined;
  readonly timeoutMs?: number | undefined;
}

interface KillableDriver extends SandboxDriver {
  killActiveProcesses?: () => void;
}

function deduplicateStrings(values: readonly string[]): string[] {
  return [...new Set(values.filter((v) => v.length > 0))];
}

function deduplicatePhantoms(phantoms: readonly PhantomCredentialRule[]): PhantomCredentialRule[] {
  const seen = new Map<string, PhantomCredentialRule>();
  for (const phantom of phantoms) {
    seen.set(phantom.phantomToken, phantom);
  }
  return [...seen.values()];
}

function deduplicateCanaries(canaries: readonly CanaryHoneytoken[]): CanaryHoneytoken[] {
  const seen = new Map<string, CanaryHoneytoken>();
  for (const canary of canaries) {
    seen.set(canary.tokenValue, canary);
  }
  return [...seen.values()];
}

export class SandboxSessionOrchestrator extends EventEmitter {
  private readonly options: SandboxSessionOptions;
  private state: SessionLifecycleState = 'provisioning';
  private readonly stateHistory: SessionLifecycleState[] = ['provisioning'];
  private workspace: WorkspaceDescriptor | null = null;
  private effectivePolicy: SandboxPolicy;
  private firewall: EgressFirewall | null = null;
  private driver: KillableDriver | null = null;
  private harvester: DiffHarvester | null = null;
  private hookBaseline: GitIntegritySnapshot | null = null;
  private readonly worktreeManager: EphemeralWorktreeManager;
  private readonly attestationSigner = new AttestationSigner();
  private readonly auditLedger: SessionAuditLedger;
  private canaries: CanaryHoneytoken[] = [];
  private executedCommandCount = 0;
  private processEnv: Record<string, string> = {};
  private proxyPort = 0;
  private caCertPath = '';
  private udsSocketPath: string | undefined;
  private canaryTriggered = false;
  private abortedReason: string | null = null;
  private closed = false;
  private cleanupPromise: Promise<void> | null = null;
  private signalHandler: (() => void) | null = null;

  constructor(options: SandboxSessionOptions) {
    super();
    this.options = options;
    this.effectivePolicy = options.policy;
    this.auditLedger = new SessionAuditLedger(options.policy.sessionId, this.attestationSigner);
    this.worktreeManager = new EphemeralWorktreeManager(undefined, (diagnostic) => {
      this.recordDiagnostic(diagnostic);
    });
  }

  public getState(): SessionLifecycleState {
    return this.state;
  }

  public getStateHistory(): readonly SessionLifecycleState[] {
    return [...this.stateHistory];
  }

  public getWorkspace(): WorkspaceDescriptor | null {
    return this.workspace;
  }

  public getEffectivePolicy(): SandboxPolicy {
    return this.effectivePolicy;
  }

  public getCanaries(): readonly CanaryHoneytoken[] {
    return this.canaries;
  }

  public getViolations(): readonly DlpViolationEvent[] {
    return this.firewall?.getViolationEvents() ?? [];
  }

  public getAbortedReason(): string | null {
    return this.abortedReason;
  }

  public isCanaryTriggered(): boolean {
    return this.canaryTriggered;
  }

  public getAuditLedger(): readonly AuditLedgerEntry[] {
    return this.auditLedger.getEntries();
  }

  public exportAuditLedgerJsonl(): string {
    return this.auditLedger.exportJsonl();
  }

  public async start(): Promise<WorkspaceDescriptor> {
    if (this.state !== 'provisioning') {
      throw new Error(`Cannot start session ${this.options.policy.sessionId} from state "${this.state}".`);
    }

    try {
      const repoConfig = loadRepositoryPolicyFile(this.options.policy.repoRootPath);
      const policy = mergePolicyWithRepoConfig(this.options.policy, repoConfig);
      this.effectivePolicy = policy;
      const cowDirectories = policy.cowDirectories;
      const workspace = await this.worktreeManager.create(policy.repoRootPath, policy.sessionId, cowDirectories);
      this.workspace = workspace;
      this.auditLedger.setLedgerFilePath(path.join(workspace.sessionTmpDir, 'audit-ledger.jsonl'));
      this.transitionState('worktree-ready');
      this.transitionState('cow-cloned');

      const hookVerifier = new GitHookIntegrityVerifier();
      this.hookBaseline = hookVerifier.captureSnapshot(workspace.repoGitDir);
      this.harvester = new DiffHarvester(this.hookBaseline, hookVerifier);

      const scrubber = new EnvScrubber();
      const defaultAllowedHosts =
        this.options.defaultAllowedHostsForEnvPhantom ?? policy.egressRules.map((rule) => rule.domain);
      const scrubResult =
        this.options.scrubWorktreeEnv === false
          ? { phantomCredentials: [] as PhantomCredentialRule[], protectedSecrets: [] as string[], scrubbedFiles: [] as string[] }
          : scrubber.scrubWorktreeEnvFiles(workspace.repoRootPath, workspace.worktreePath, defaultAllowedHosts);

      const hostEnv = this.options.hostEnv ?? process.env;
      const hostSecrets = scrubber.extractHostEnvSecrets(hostEnv);

      const plantedCanaries =
        this.options.plantCanaries === false
          ? []
          : new CanaryPlanter().plantCanaries(workspace.sessionHomeDir, policy.sessionId);

      const mergedPhantoms = deduplicatePhantoms([...policy.phantomCredentials, ...scrubResult.phantomCredentials]);
      const mergedSecrets = deduplicateStrings([
        ...policy.protectedSecrets,
        ...scrubResult.protectedSecrets,
        ...hostSecrets,
        ...mergedPhantoms.map((p) => p.realSecret),
      ]);
      const mergedCanaries = deduplicateCanaries([...(policy.canaries ?? []), ...plantedCanaries]);
      this.canaries = mergedCanaries;

      this.effectivePolicy = {
        ...policy,
        repoRootPath: workspace.repoRootPath,
        cowDirectories: workspace.clonedCowDirs,
        protectedSecrets: mergedSecrets,
        phantomCredentials: mergedPhantoms,
        canaries: mergedCanaries,
      };
      this.transitionState('env-scrubbed');

      const firewall = new EgressFirewall({
        policy: this.effectivePolicy,
        sessionTmpDir: workspace.sessionTmpDir,
        enableUdsServer: this.options.enableUdsServer ?? process.platform === 'linux',
        allowTestLoopbackUpstreamPorts: this.options.allowTestLoopbackUpstreamPorts,
        upstreamOverrides: this.options.upstreamOverrides,
        onDiagnostic: (diagnostic) => this.recordDiagnostic(diagnostic),
      });
      this.firewall = firewall;

      for (const lockDiag of firewall.getLockfileDiagnostics()) {
        this.recordDiagnostic({
          source: 'PackageRegistryGuard',
          code: lockDiag.code,
          message: `Failed to parse lockfile "${lockDiag.filePath}": ${lockDiag.message}`,
        });
      }

      firewall.onCanaryTriggered((event) => {
        this.handleCanaryTripwire(
          `Canary tripwire triggered via egress proxy (${event.reason}) for ${event.url}: ${event.matchedRule}`,
        );
      });

      const endpoints = await firewall.start();
      this.proxyPort = endpoints.port;
      this.caCertPath = endpoints.caCertPath;
      this.udsSocketPath = endpoints.udsSocketPath;

      this.processEnv = scrubber.sanitizeProcessEnv({
        hostEnv,
        workspace,
        proxyPort: endpoints.port,
        caCertPath: endpoints.caCertPath,
        phantomCredentials: mergedPhantoms,
        canaries: mergedCanaries,
      });

      const driver = this.selectDriver();
      this.driver = driver;
      await driver.prepare(this.effectivePolicy, workspace, endpoints.port);

      this.registerSignalCleanup();
      this.transitionState('proxy-active');
      return workspace;
    } catch (error) {
      await this.close();
      throw error;
    }
  }

  public spawnInteractive(
    command: string,
    execOptions?: { readonly cwd?: string | undefined },
  ): ChildProcess {
    if (this.state === 'aborted' || this.canaryTriggered) {
      throw new Error(
        `Session "${this.effectivePolicy.sessionId}" is aborted: ${this.abortedReason ?? 'security violation'}`,
      );
    }
    if (this.state !== 'proxy-active') {
      throw new Error(`Cannot spawn interactive command in state "${this.state}".`);
    }
    if (!this.driver || !this.workspace) {
      throw new Error('Session driver or workspace is not initialized.');
    }
    if (!this.driver.spawnInteractive) {
      throw new Error(`Driver "${this.driver.tier}" does not support interactive stdio spawning.`);
    }

    this.executedCommandCount += 1;
    this.transitionState('executing');
    const child = this.driver.spawnInteractive({
      command,
      env: this.processEnv,
      udsSocketPath: this.udsSocketPath,
      cwd: execOptions?.cwd ?? this.workspace.worktreePath,
    });

    const restoreState = () => {
      if (this.state === 'executing') {
        this.transitionState('proxy-active');
      }
    };
    child.once('close', restoreState);
    child.once('error', restoreState);
    return child;
  }

  public triggerCanaryTripwire(reason: string): void {
    this.handleCanaryTripwire(reason);
  }

  public async exec(command: string, execOptions?: ExecCommandOptions): Promise<CommandResult> {
    if (this.state === 'aborted' || this.canaryTriggered) {
      throw new Error(`Session "${this.effectivePolicy.sessionId}" is aborted: ${this.abortedReason ?? 'security violation'}`);
    }
    if (this.state !== 'proxy-active') {
      throw new Error(`Cannot execute command in state "${this.state}".`);
    }
    if (!this.driver || !this.workspace || !this.firewall) {
      throw new Error('Session driver, workspace, or firewall is not initialized.');
    }

    const violationOffset = this.firewall.getViolationEvents().length;
    this.executedCommandCount += 1;
    this.transitionState('executing');
    try {
      const rawResult = await this.driver.exec({
        command,
        env: this.processEnv,
        proxyPort: this.proxyPort,
        udsSocketPath: this.udsSocketPath,
        caCertPath: this.caCertPath,
        cwd: execOptions?.cwd ?? this.workspace.worktreePath,
        timeoutMs: execOptions?.timeoutMs ?? this.effectivePolicy.timeoutMs,
      });

      const combinedOutput = `${rawResult.stdout}\n${rawResult.stderr}`;
      for (const canary of this.canaries) {
        if (
          combinedOutput.includes(canary.tokenValue) ||
          canary.tripwireSubstrings.some((sub) => combinedOutput.includes(sub))
        ) {
          this.handleCanaryTripwire(
            `Canary token ${canary.id} (${canary.filePath ?? canary.envVarName ?? canary.label}) leaked into process output.`,
          );
          break;
        }
      }

      if ((this.state as SessionLifecycleState) !== 'aborted') {
        this.transitionState('proxy-active');
      }

      const blockedEgressEvents = this.firewall.getViolationEvents().slice(violationOffset);
      for (const violation of blockedEgressEvents) {
        this.auditLedger.append('DLP_VIOLATION_BLOCKED', {
          method: violation.method,
          url: violation.url,
          reason: violation.reason,
          matchedRule: violation.matchedRule,
        });
      }
      this.auditLedger.append('COMMAND_EXECUTED', {
        command,
        exitCode: rawResult.exitCode,
        durationMs: rawResult.durationMs,
        blockedEgressCount: blockedEgressEvents.length,
        canaryTriggered: this.canaryTriggered,
      });
      return {
        ...rawResult,
        blockedEgressEvents,
        canaryTriggered: this.canaryTriggered,
      };
    } catch (error) {
      if ((this.state as SessionLifecycleState) !== 'aborted') {
        this.transitionState('proxy-active');
      }
      throw error;
    }
  }

  public async harvest(applyToHost: boolean): Promise<HarvestResult> {
    if (this.closed || this.state === 'cleaned-up') {
      throw new Error(`Cannot harvest closed session "${this.effectivePolicy.sessionId}".`);
    }
    if (!this.workspace || !this.harvester) {
      throw new Error('Session harvester or workspace is not initialized.');
    }

    if (applyToHost && (this.state === 'aborted' || this.canaryTriggered || this.abortedReason !== null)) {
      return this.signHarvestResult({
        sessionId: this.effectivePolicy.sessionId,
        patchDiff: '',
        changedFiles: [],
        hookIntegrityVerified: false,
        persistenceFindings: [
          {
            filePath: this.workspace.sessionHomeDir,
            category: 'PHANTOM_TOKEN_LEAK',
            description: `Refusing to harvest aborted session "${this.effectivePolicy.sessionId}": ${
              this.abortedReason ?? 'canary tripwire triggered'
            }`,
          },
        ],
        appliedToHost: false,
      });
    }

    const previousState = this.state;
    if (applyToHost) {
      this.transitionState('harvesting');
    }

    try {
      const result = await this.harvester.harvest(this.workspace, applyToHost);
      if (this.state === 'harvesting') {
        this.transitionState(previousState === 'aborted' ? 'aborted' : 'proxy-active');
      }
      return this.signHarvestResult(result);
    } catch (error) {
      if (this.state === 'harvesting') {
        this.transitionState(previousState === 'aborted' ? 'aborted' : 'proxy-active');
      }
      throw error;
    }
  }

  public async close(): Promise<void> {
    if (this.cleanupPromise) {
      return this.cleanupPromise;
    }
    this.cleanupPromise = this.performClose();
    return this.cleanupPromise;
  }

  private async performClose(): Promise<void> {
    this.unregisterSignalCleanup();
    try {
      if (this.driver) {
        try {
          this.driver.killActiveProcesses?.();
          await this.driver.cleanup();
        } catch (err) {
          if (!isExpectedErrno(err, EXPECTED_CLOSE_ERRNOS)) {
            this.recordDiagnostic({
              source: 'SandboxSessionOrchestrator.performClose.driver',
              code: getErrnoCode(err),
              message: formatErrorMessage(err),
            });
          }
        }
      }
      if (this.firewall) {
        try {
          await this.firewall.stop();
        } catch (err) {
          if (!isExpectedErrno(err, EXPECTED_CLOSE_ERRNOS)) {
            this.recordDiagnostic({
              source: 'SandboxSessionOrchestrator.performClose.firewall',
              code: getErrnoCode(err),
              message: formatErrorMessage(err),
            });
          }
        }
      }
      if (this.workspace) {
        try {
          await this.worktreeManager.destroy(this.workspace);
        } catch (err) {
          if (!isExpectedErrno(err, EXPECTED_CLOSE_ERRNOS)) {
            this.recordDiagnostic({
              source: 'SandboxSessionOrchestrator.performClose.worktree',
              code: getErrnoCode(err),
              message: formatErrorMessage(err),
            });
          }
        }
      }
    } finally {
      this.closed = true;
      if (this.state !== 'cleaned-up') {
        this.transitionState('cleaned-up');
      }
    }
  }

  private recordDiagnostic(diagnostic: RuntimeDiagnostic): void {
    this.auditLedger.append('SESSION_DIAGNOSTIC', {
      source: diagnostic.source,
      ...(diagnostic.code !== undefined ? { code: diagnostic.code } : {}),
      message: diagnostic.message,
    });
  }

  private signHarvestResult(
    result: Omit<HarvestResult, 'attestation' | 'auditLedgerEntries'>,
  ): HarvestResult {
    const attestation = this.attestationSigner.signHarvest({
      sessionId: result.sessionId,
      repoRootPath: this.effectivePolicy.repoRootPath,
      patchDiff: result.patchDiff,
      changedFiles: result.changedFiles,
      executedCommandCount: this.executedCommandCount,
      hookIntegrityVerified: result.hookIntegrityVerified,
      persistenceFindingCount: result.persistenceFindings.length,
      dlpViolationCount: this.getViolations().length,
      canaryTriggered: this.canaryTriggered,
      appliedToHost: result.appliedToHost,
    });
    this.auditLedger.append('HARVEST_COMPLETED', {
      appliedToHost: result.appliedToHost,
      changedFiles: [...result.changedFiles],
      patchSha256: attestation.patchSha256,
      hookIntegrityVerified: result.hookIntegrityVerified,
      persistenceFindingCount: result.persistenceFindings.length,
    });
    return {
      ...result,
      attestation,
      auditLedgerEntries: this.auditLedger.getEntries(),
    };
  }

  private selectDriver(): KillableDriver {
    if (this.options.driver) {
      return this.options.driver;
    }
    if (this.effectivePolicy.tier === 'tier2-microvm') {
      return new MicroVMDriver();
    }
    if (process.platform === 'linux') {
      return new BwrapDriver();
    }
    return new SeatbeltDriver();
  }

  private transitionState(next: SessionLifecycleState): void {
    const previous = this.state;
    if (previous === next) {
      return;
    }
    this.state = next;
    this.stateHistory.push(next);
    this.auditLedger.append('SESSION_STATE_CHANGED', { from: previous, to: next });
    this.emit('stateChange', { from: previous, to: next });
  }

  private handleCanaryTripwire(reason: string): void {
    this.canaryTriggered = true;
    this.abortedReason ??= reason;
    this.auditLedger.append('CANARY_TRIPWIRE_TRIGGERED', { reason });
    if (this.state !== 'cleaned-up') {
      this.transitionState('aborted');
    }
    this.driver?.killActiveProcesses?.();
    this.emit('aborted', { reason });
  }

  private registerSignalCleanup(): void {
    if (this.signalHandler) {
      return;
    }
    this.signalHandler = () => {
      this.driver?.killActiveProcesses?.();
      void this.close();
    };
    process.once('SIGINT', this.signalHandler);
    process.once('SIGTERM', this.signalHandler);
  }

  private unregisterSignalCleanup(): void {
    if (!this.signalHandler) {
      return;
    }
    process.off('SIGINT', this.signalHandler);
    process.off('SIGTERM', this.signalHandler);
    this.signalHandler = null;
  }
}
