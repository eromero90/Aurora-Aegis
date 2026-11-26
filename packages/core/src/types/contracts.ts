import type { ChildProcess } from 'node:child_process';

export type IsolationTier = 'tier1-kernel-mac' | 'tier2-microvm';

export type SessionLifecycleState =
  | 'provisioning'
  | 'worktree-ready'
  | 'cow-cloned'
  | 'env-scrubbed'
  | 'proxy-active'
  | 'executing'
  | 'harvesting'
  | 'aborted'
  | 'cleaned-up';

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';

export type DlpViolationReason =
  | 'DOMAIN_NOT_ALLOWED'
  | 'METHOD_NOT_ALLOWED'
  | 'PRIVATE_IP_SSRF_BLOCKED'
  | 'DNS_RESOLUTION_FAILED'
  | 'MALFORMED_CONTENT_ENCODING'
  | 'SECRET_FINGERPRINT_MATCH'
  | 'REGEX_SIGNATURE_MATCH'
  | 'CANARY_TRIPWIRE_TRIGGERED'
  | 'ENTROPY_QUOTA_EXCEEDED'
  | 'SUPPLY_CHAIN_PACKAGE_BLOCKED';

export interface PackageRegistryPolicy {
  readonly allowedPackages?: readonly string[] | undefined;
  readonly deniedPackages?: readonly string[] | undefined;
  readonly enforceLockfile?: boolean | undefined;
}

export interface EgressDomainRule {
  readonly domain: string;
  readonly allowedMethods: readonly HttpMethod[];
}

export interface PhantomCredentialRule {
  readonly envVarName: string;
  readonly phantomToken: string;
  readonly realSecret: string;
  readonly allowedHosts: readonly string[];
}

export interface SecretFingerprint {
  readonly id: string;
  readonly envVarName?: string | undefined;
  readonly raw: string;
  readonly base64: string;
  readonly base64NoPad: string;
  readonly base64Url: string;
  readonly hexLower: string;
  readonly hexUpper: string;
  readonly urlEncoded: string;
}

export interface CanaryHoneytoken {
  readonly id: string;
  readonly label: string;
  readonly filePath?: string | undefined;
  readonly envVarName?: string | undefined;
  readonly tokenValue: string;
  readonly tripwireSubstrings: readonly string[];
}

export type PersistenceVectorCategory =
  | 'GIT_ATTRIBUTES_FILTER'
  | 'GIT_SUBMODULE'
  | 'IDE_AUTORUN_TASK'
  | 'PACKAGE_LIFECYCLE_SCRIPT'
  | 'CARGO_BUILD_SCRIPT'
  | 'SHELL_RC_FILE'
  | 'PHANTOM_TOKEN_LEAK'
  | 'POLICY_FILE_TAMPER';

export interface PersistenceVectorFinding {
  readonly filePath: string;
  readonly category: PersistenceVectorCategory;
  readonly description: string;
}

export interface WorkspaceDescriptor {
  readonly sessionId: string;
  readonly repoRootPath: string;
  readonly repoGitDir: string;
  readonly worktreePath: string;
  readonly worktreeGitDir: string;
  readonly sessionTmpDir: string;
  readonly sessionHomeDir: string;
  readonly clonedCowDirs: readonly string[];
}

export interface SandboxPolicy {
  readonly sessionId: string;
  readonly repoRootPath: string;
  readonly tier: IsolationTier;
  readonly cowDirectories: readonly string[];
  readonly readOnlyToolchainPaths: readonly string[];
  readonly egressRules: readonly EgressDomainRule[];
  readonly phantomCredentials: readonly PhantomCredentialRule[];
  readonly protectedSecrets: readonly string[];
  readonly canaries?: readonly CanaryHoneytoken[] | undefined;
  readonly outboundByteBudget?: number | undefined;
  readonly packagePolicy?: PackageRegistryPolicy | undefined;
  readonly timeoutMs: number;
}

export interface DlpViolationEvent {
  readonly timestamp: string;
  readonly method: HttpMethod;
  readonly url: string;
  readonly reason: DlpViolationReason;
  readonly matchedRule: string;
}

export interface CommandResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly durationMs: number;
  readonly blockedEgressEvents: readonly DlpViolationEvent[];
  readonly canaryTriggered: boolean;
}

export interface HarvestAttestation {
  readonly schemaVersion: '1.0';
  readonly sessionId: string;
  readonly timestamp: string;
  readonly repoRootPath: string;
  readonly patchSha256: string;
  readonly changedFiles: readonly string[];
  readonly executedCommandCount: number;
  readonly hookIntegrityVerified: boolean;
  readonly persistenceFindingCount: number;
  readonly dlpViolationCount: number;
  readonly canaryTriggered: boolean;
  readonly appliedToHost: boolean;
  readonly publicKeyPem: string;
  readonly signatureBase64: string;
}

export type AuditLedgerEventType =
  | 'SESSION_STATE_CHANGED'
  | 'COMMAND_EXECUTED'
  | 'DLP_VIOLATION_BLOCKED'
  | 'CANARY_TRIPWIRE_TRIGGERED'
  | 'HARVEST_COMPLETED'
  | 'SESSION_DIAGNOSTIC';

export interface AuditLedgerEntry {
  readonly sequence: number;
  readonly sessionId: string;
  readonly timestamp: string;
  readonly eventType: AuditLedgerEventType;
  readonly details: Readonly<Record<string, unknown>>;
  readonly prevEntrySha256: string;
  readonly entrySha256: string;
  readonly publicKeyPem: string;
  readonly signatureBase64: string;
}

export interface AuditLedgerVerificationResult {
  readonly valid: boolean;
  readonly entryCount: number;
  readonly sessionId?: string | undefined;
  readonly brokenAtSequence?: number | undefined;
  readonly failureReason?: string | undefined;
}

export interface HarvestResult {
  readonly sessionId: string;
  readonly patchDiff: string;
  readonly changedFiles: readonly string[];
  readonly hookIntegrityVerified: boolean;
  readonly persistenceFindings: readonly PersistenceVectorFinding[];
  readonly appliedToHost: boolean;
  readonly attestation?: HarvestAttestation | undefined;
  readonly auditLedgerEntries?: readonly AuditLedgerEntry[] | undefined;
}

export interface DriverExecOptions {
  readonly command: string;
  readonly env: Readonly<Record<string, string>>;
  readonly proxyPort: number;
  readonly udsSocketPath?: string | undefined;
  readonly caCertPath: string;
  readonly timeoutMs?: number | undefined;
  readonly cwd?: string | undefined;
}

export interface SandboxInteractiveSpawnOptions {
  readonly command: string;
  readonly env: Readonly<Record<string, string>>;
  readonly udsSocketPath?: string | undefined;
  readonly cwd?: string | undefined;
}

export interface SandboxDriver {
  readonly tier: IsolationTier;
  prepare(policy: SandboxPolicy, workspace: WorkspaceDescriptor, proxyPort: number): Promise<void>;
  exec(options: DriverExecOptions): Promise<Omit<CommandResult, 'blockedEgressEvents' | 'canaryTriggered'>>;
  spawnInteractive?(options: SandboxInteractiveSpawnOptions): ChildProcess;
  cleanup(): Promise<void>;
}

export interface EgressFirewallServer {
  start(): Promise<{ readonly port: number; readonly caCertPath: string; readonly udsSocketPath?: string | undefined }>;
  onCanaryTriggered(listener: (event: DlpViolationEvent) => void): void;
  getViolationEvents(): readonly DlpViolationEvent[];
  stop(): Promise<void>;
}

export interface WorktreeManager {
  create(repoRootPath: string, sessionId: string, cowDirectories: readonly string[]): Promise<WorkspaceDescriptor>;
  destroy(workspace: WorkspaceDescriptor): Promise<void>;
}

export interface DiffHarvesterContract {
  harvest(workspace: WorkspaceDescriptor, applyToHost: boolean): Promise<HarvestResult>;
}
