#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  AEGIS_POLICY_FILENAME,
  AegisControlDaemon,
  AegisDaemonClient,
  type AegisPolicyFileSchema,
  type AuditLedgerEntry,
  type CommandResult,
  DEFAULT_EGRESS_HOSTS,
  type EgressDomainRule,
  type HarvestAttestation,
  type HarvestResult,
  type PersistenceVectorFinding,
  PersistenceScanner,
  type SandboxDriver,
  SandboxSessionOrchestrator,
  type SandboxPolicy,
  type WorkspaceDescriptor,
  canonicalizePath,
  discoverDefaultCowDirectories,
  discoverHostToolchainPaths,
  formatErrorMessage,
  isExpectedErrno,
  killProcessTree,
  loadRepositoryPolicyFile,
  parseAndVerifyAuditLedgerJsonl,
  verifyAuditLedgerEntries,
  verifyHarvestAttestation,
} from '@aegis/core';

export interface McpServerConfigEntry {
  command: string;
  args?: string[] | undefined;
  env?: Record<string, string> | undefined;
  [key: string]: unknown;
}

export interface McpConfigFileShape {
  mcpServers?: Record<string, McpServerConfigEntry> | undefined;
  [key: string]: unknown;
}

export interface IntegrateMcpOptions {
  readonly wrapBinary?: string | undefined;
  readonly includeAegisServer?: boolean | undefined;
}

export interface IntegrateMcpResult {
  readonly configPath: string;
  readonly backupPath: string;
  readonly wrappedServers: readonly string[];
  readonly alreadyWrappedServers: readonly string[];
  readonly changed: boolean;
}

export interface WrapCommandOptions {
  readonly repoRootPath: string;
  readonly allowedHosts?: readonly string[] | undefined;
  readonly cowDirectories?: readonly string[] | undefined;
  readonly protectedSecrets?: readonly string[] | undefined;
  readonly applyChanges?: boolean | undefined;
  readonly interactive?: boolean | undefined;
  readonly input?: NodeJS.ReadableStream | undefined;
  readonly output?: NodeJS.WritableStream | undefined;
  readonly errorOutput?: NodeJS.WritableStream | undefined;
  readonly timeoutMs?: number | undefined;
  readonly driver?: SandboxDriver | undefined;
  readonly hostEnv?: NodeJS.ProcessEnv | undefined;
}

export interface WrapCommandResult {
  readonly commandResult: CommandResult;
  readonly harvestResult: HarvestResult;
}

export interface McpWrapSupervisorOptions extends WrapCommandOptions {
  readonly input?: NodeJS.ReadableStream | undefined;
  readonly output?: NodeJS.WritableStream | undefined;
  readonly errorOutput?: NodeJS.WritableStream | undefined;
}

export interface McpWrapSupervisorResult {
  readonly exitCode: number;
  readonly canaryTriggered: boolean;
  readonly redactedSecretCount: number;
  readonly harvestResult: HarvestResult;
}

export interface ZshShimOptions extends WrapCommandOptions {
  readonly harvestOnSuccess?: boolean | undefined;
  readonly daemonSocketPath?: string | undefined;
}

export interface ZshShimResult {
  readonly commandResult: CommandResult;
  readonly workspace: WorkspaceDescriptor;
  readonly harvestResult?: HarvestResult | undefined;
}

export interface SecurityAuditReport {
  readonly repoRootPath: string;
  readonly sandboxBackendAvailable: boolean;
  readonly backendName: 'seatbelt' | 'bubblewrap' | 'unsupported';
  readonly exposedEnvFiles: readonly string[];
  readonly findings: readonly PersistenceVectorFinding[];
  readonly passed: boolean;
}

const SECRET_ENV_LINE_PATTERN =
  /(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|PRIVATE|_authToken|sk-|ghp_|github_pat_|AKIA)/i;

const workspaceShimSessions = new Map<string, SandboxSessionOrchestrator>();

function isAlreadyWrapped(entry: McpServerConfigEntry): boolean {
  const args = entry.args ?? [];
  const cmdBase = path.basename(entry.command);
  return (cmdBase === 'aegis' || cmdBase === 'aegis-cli') && args[0] === 'mcp-wrap';
}

function buildDefaultPolicy(options: WrapCommandOptions, sessionPrefix: string): SandboxPolicy {
  const canonicalRepo = canonicalizePath(options.repoRootPath);
  const egressRules: EgressDomainRule[] = (options.allowedHosts ?? DEFAULT_EGRESS_HOSTS).map(
    (domain) => ({
      domain,
      allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'],
    }),
  );

  return {
    sessionId: `${sessionPrefix}-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
    repoRootPath: canonicalRepo,
    tier: 'tier1-kernel-mac',
    cowDirectories: options.cowDirectories ?? discoverDefaultCowDirectories(canonicalRepo),
    readOnlyToolchainPaths: discoverHostToolchainPaths(),
    egressRules,
    phantomCredentials: [],
    protectedSecrets: options.protectedSecrets ?? [],
    timeoutMs: options.timeoutMs ?? 60_000,
  };
}

function extractShellCommand(args: readonly string[]): string {
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if ((arg === '-c' || arg === '-lc' || arg === '--command') && args[i + 1] !== undefined) {
      return args[i + 1]!;
    }
  }
  const normalized = args[0] === '--' ? args.slice(1) : args;
  return normalized.join(' ');
}

function shellEscapeArg(arg: string): string {
  if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(arg)) {
    return arg;
  }
  return `'${arg.replace(/'/g, `'\\''`)}'`;
}

export function integrateMcpConfigFile(configPath: string, options: IntegrateMcpOptions = {}): IntegrateMcpResult {
  const resolvedPath = path.resolve(configPath);
  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`MCP config file does not exist: ${resolvedPath}`);
  }

  const rawText = fs.readFileSync(resolvedPath, 'utf8');
  const parsed = JSON.parse(rawText) as McpConfigFileShape;
  const servers = parsed.mcpServers ?? {};
  const wrapBinary = options.wrapBinary ?? 'aegis';

  const wrappedServers: string[] = [];
  const alreadyWrappedServers: string[] = [];
  const nextServers: Record<string, McpServerConfigEntry> = {};

  for (const [name, entry] of Object.entries(servers)) {
    if (name === 'aurora-aegis' || isAlreadyWrapped(entry)) {
      alreadyWrappedServers.push(name);
      nextServers[name] = entry;
      continue;
    }

    wrappedServers.push(name);
    nextServers[name] = {
      ...entry,
      command: wrapBinary,
      args: ['mcp-wrap', '--', entry.command, ...(entry.args ?? [])],
    };
  }

  if (options.includeAegisServer && !nextServers['aurora-aegis']) {
    nextServers['aurora-aegis'] = {
      command: 'aegis-mcp-server',
      args: [],
    };
    wrappedServers.push('aurora-aegis');
  }

  const backupPath = `${resolvedPath}.bak`;
  const changed = wrappedServers.length > 0;

  if (changed) {
    if (!fs.existsSync(backupPath)) {
      fs.writeFileSync(backupPath, rawText, 'utf8');
    }
    const updated: McpConfigFileShape = {
      ...parsed,
      mcpServers: nextServers,
    };
    fs.writeFileSync(resolvedPath, `${JSON.stringify(updated, null, 2)}\n`, 'utf8');
  }

  return {
    configPath: resolvedPath,
    backupPath,
    wrappedServers,
    alreadyWrappedServers,
    changed,
  };
}

interface InteractiveChildSessionResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly durationMs: number;
  readonly canaryTriggered: boolean;
  readonly redactedSecretCount: number;
}

async function runInteractiveChildSession(
  orchestrator: SandboxSessionOrchestrator,
  commandString: string,
  options: {
    readonly input: NodeJS.ReadableStream;
    readonly output: NodeJS.WritableStream;
    readonly errorOutput: NodeJS.WritableStream;
    readonly redactSecrets: boolean;
  },
): Promise<InteractiveChildSessionResult> {
  const startedAt = Date.now();
  const child = orchestrator.spawnInteractive(commandString);

  const canaries = orchestrator.getCanaries();
  const sortedSecrets = options.redactSecrets
    ? [...orchestrator.getEffectivePolicy().protectedSecrets]
        .filter((s) => s.length >= 4)
        .sort((a, b) => b.length - a.length)
    : [];

  let redactedSecretCount = 0;
  const stdoutParts: string[] = [];
  const stderrParts: string[] = [];

  const sanitizeChunk = (
    chunkText: string,
    rollingTail: { value: string },
  ): { canaryHit: boolean; sanitized: string } => {
    const scanWindow = `${rollingTail.value}${chunkText}`;
    for (const canary of canaries) {
      if (
        scanWindow.includes(canary.tokenValue) ||
        canary.tripwireSubstrings.some((sub) => scanWindow.includes(sub))
      ) {
        orchestrator.triggerCanaryTripwire(
          `Canary token ${canary.id} (${canary.filePath ?? canary.envVarName ?? canary.label}) written to supervised stdio stream.`,
        );
        return { canaryHit: true, sanitized: '' };
      }
    }
    rollingTail.value = scanWindow.slice(-128);

    let sanitized = chunkText;
    for (const secret of sortedSecrets) {
      if (sanitized.includes(secret)) {
        const parts = sanitized.split(secret);
        redactedSecretCount += parts.length - 1;
        sanitized = parts.join('[AEGIS_REDACTED_SECRET]');
      }
    }
    return { canaryHit: false, sanitized };
  };

  const stdoutTail = { value: '' };
  const stderrTail = { value: '' };

  child.stdout?.on('data', (chunk: Buffer | string) => {
    const text = typeof chunk === 'string' ? chunk : chunk.toString('utf8');
    const { canaryHit, sanitized } = sanitizeChunk(text, stdoutTail);
    if (!canaryHit && sanitized.length > 0) {
      stdoutParts.push(sanitized);
      options.output.write(sanitized);
    }
  });

  child.stderr?.on('data', (chunk: Buffer | string) => {
    const text = typeof chunk === 'string' ? chunk : chunk.toString('utf8');
    const { canaryHit, sanitized } = sanitizeChunk(text, stderrTail);
    if (!canaryHit && sanitized.length > 0) {
      stderrParts.push(sanitized);
      options.errorOutput.write(sanitized);
    }
  });

  const EXPECTED_STDIN_ERRNOS = new Set(['EPIPE', 'ERR_STREAM_DESTROYED', 'ECONNRESET']);
  child.stdin?.on('error', (err) => {
    if (!isExpectedErrno(err, EXPECTED_STDIN_ERRNOS)) {
      options.errorOutput.write(`[aegis] unexpected child stdin error: ${formatErrorMessage(err)}\n`);
    }
  });

  const onInputData = (chunk: Buffer | string) => {
    if (!child.killed && child.stdin && !child.stdin.destroyed && child.stdin.writable) {
      child.stdin.write(chunk);
    }
  };
  const onInputEnd = () => {
    if (child.stdin && !child.stdin.destroyed) {
      child.stdin.end();
    }
  };

  options.input.on('data', onInputData);
  options.input.on('end', onInputEnd);
  if ('readableEnded' in options.input && (options.input as { readonly readableEnded?: boolean }).readableEnded === true) {
    onInputEnd();
  }

  let settleAbort: (() => void) | undefined;
  const onAborted = () => {
    killProcessTree(child);
    settleAbort?.();
  };
  orchestrator.on('aborted', onAborted);

  const exitCode = await new Promise<number>((resolve) => {
    let settled = false;
    const finish = (code: number) => {
      if (settled) return;
      settled = true;
      resolve(code);
    };
    settleAbort = () => finish(-1);
    if (orchestrator.isCanaryTriggered()) {
      onAborted();
      return;
    }
    child.once('close', (code) => finish(code ?? -1));
    child.once('error', () => finish(-1));
  }).finally(() => {
    options.input.off('data', onInputData);
    options.input.off('end', onInputEnd);
    if (
      options.input === process.stdin &&
      typeof (options.input as { pause?: () => void }).pause === 'function'
    ) {
      (options.input as { pause: () => void }).pause();
    }
    orchestrator.off('aborted', onAborted);
  });

  return {
    exitCode,
    stdout: stdoutParts.join(''),
    stderr: stderrParts.join(''),
    durationMs: Date.now() - startedAt,
    canaryTriggered: orchestrator.isCanaryTriggered(),
    redactedSecretCount,
  };
}

export async function runWrapCommand(
  commandArgs: readonly string[],
  options: WrapCommandOptions,
): Promise<WrapCommandResult> {
  let interactiveFlag = options.interactive ?? false;
  let idx = 0;
  while (idx < commandArgs.length && (commandArgs[idx] === '--interactive' || commandArgs[idx] === '-i')) {
    interactiveFlag = true;
    idx += 1;
  }
  const sliced = commandArgs.slice(idx);
  const effectiveArgs = sliced[0] === '--' ? sliced.slice(1) : sliced;
  if (effectiveArgs.length === 0) {
    throw new Error('runWrapCommand requires at least one command argument.');
  }

  const commandString = effectiveArgs.length === 1 ? effectiveArgs[0]! : effectiveArgs.map(shellEscapeArg).join(' ');
  const policy = buildDefaultPolicy(options, 'wrap');
  const orchestrator = new SandboxSessionOrchestrator({
    policy,
    hostEnv: options.hostEnv,
    driver: options.driver,
  });

  try {
    await orchestrator.start();

    let commandResult: CommandResult;
    if (interactiveFlag) {
      const live = await runInteractiveChildSession(orchestrator, commandString, {
        input: options.input ?? process.stdin,
        output: options.output ?? process.stdout,
        errorOutput: options.errorOutput ?? process.stderr,
        redactSecrets: true,
      });
      commandResult = {
        exitCode: live.exitCode,
        stdout: live.stdout,
        stderr: live.stderr,
        durationMs: live.durationMs,
        blockedEgressEvents: orchestrator.getViolations(),
        canaryTriggered: live.canaryTriggered,
      };
    } else {
      commandResult = await orchestrator.exec(commandString, { timeoutMs: options.timeoutMs });
    }

    const shouldApply = (options.applyChanges ?? true) && commandResult.exitCode === 0 && !commandResult.canaryTriggered;
    const harvestResult = await orchestrator.harvest(shouldApply);
    return { commandResult, harvestResult };
  } finally {
    await orchestrator.close();
  }
}

export async function runMcpWrapSupervisor(
  commandArgs: readonly string[],
  options: McpWrapSupervisorOptions,
): Promise<McpWrapSupervisorResult> {
  const effectiveArgs = commandArgs[0] === '--' ? commandArgs.slice(1) : commandArgs;
  if (effectiveArgs.length === 0) {
    throw new Error('runMcpWrapSupervisor requires at least one command argument.');
  }

  const commandString = effectiveArgs.length === 1 ? effectiveArgs[0]! : effectiveArgs.map(shellEscapeArg).join(' ');
  const policy = buildDefaultPolicy(options, 'mcp-wrap');
  const orchestrator = new SandboxSessionOrchestrator({
    policy,
    hostEnv: options.hostEnv,
    driver: options.driver,
  });

  try {
    await orchestrator.start();
    const live = await runInteractiveChildSession(orchestrator, commandString, {
      input: options.input ?? process.stdin,
      output: options.output ?? process.stdout,
      errorOutput: options.errorOutput ?? process.stderr,
      redactSecrets: true,
    });

    const shouldApply = (options.applyChanges ?? false) && live.exitCode === 0 && !live.canaryTriggered;
    const harvestResult = await orchestrator.harvest(shouldApply);

    return {
      exitCode: live.exitCode,
      canaryTriggered: live.canaryTriggered,
      redactedSecretCount: live.redactedSecretCount,
      harvestResult,
    };
  } finally {
    await orchestrator.close();
  }
}

export async function runZshShim(args: readonly string[], options: ZshShimOptions): Promise<ZshShimResult> {
  const command = extractShellCommand(args);
  if (command.trim().length === 0) {
    throw new Error('runZshShim requires a non-empty shell command.');
  }

  const socketPath =
    options.daemonSocketPath ?? options.hostEnv?.['AEGIS_DAEMON_SOCKET'] ?? process.env['AEGIS_DAEMON_SOCKET'];
  if (socketPath && socketPath.length > 0) {
    const client = new AegisDaemonClient(socketPath);
    const resp = await client.exec({
      repoRootPath: options.repoRootPath,
      command,
      timeoutMs: options.timeoutMs,
      allowedHosts: options.allowedHosts,
      cowDirectories: options.cowDirectories,
      harvestOnSuccess: options.harvestOnSuccess,
    });
    return resp.harvestResult !== undefined
      ? { commandResult: resp.commandResult, workspace: resp.workspace, harvestResult: resp.harvestResult }
      : { commandResult: resp.commandResult, workspace: resp.workspace };
  }

  const canonicalRepo = canonicalizePath(options.repoRootPath);
  let orchestrator = workspaceShimSessions.get(canonicalRepo);
  if (!orchestrator || orchestrator.getState() === 'aborted' || orchestrator.getState() === 'cleaned-up') {
    if (orchestrator) {
      await orchestrator.close();
    }
    orchestrator = new SandboxSessionOrchestrator({
      policy: buildDefaultPolicy(options, 'zsh'),
      hostEnv: options.hostEnv,
      driver: options.driver,
    });
    await orchestrator.start();
    workspaceShimSessions.set(canonicalRepo, orchestrator);
  }

  const workspace = orchestrator.getWorkspace();
  if (!workspace) {
    throw new Error('Shim orchestrator missing initialized workspace.');
  }

  const commandResult = await orchestrator.exec(command, { timeoutMs: options.timeoutMs });
  let harvestResult: HarvestResult | undefined;
  if (options.harvestOnSuccess && commandResult.exitCode === 0 && !commandResult.canaryTriggered) {
    harvestResult = await orchestrator.harvest(true);
  }

  return harvestResult ? { commandResult, workspace, harvestResult } : { commandResult, workspace };
}

export async function closeWorkspaceShimSession(repoRootPath: string): Promise<void> {
  const canonicalRepo = canonicalizePath(repoRootPath);
  const orchestrator = workspaceShimSessions.get(canonicalRepo);
  if (!orchestrator) {
    return;
  }
  workspaceShimSessions.delete(canonicalRepo);
  await orchestrator.close();
}

export async function closeAllShimSessions(): Promise<void> {
  const entries = [...workspaceShimSessions.values()];
  workspaceShimSessions.clear();
  for (const session of entries) {
    await session.close();
  }
}

export function runSecurityAudit(targetDir: string): SecurityAuditReport {
  const canonicalRepo = canonicalizePath(targetDir);

  let backendName: SecurityAuditReport['backendName'] = 'unsupported';
  let sandboxBackendAvailable = false;

  if (process.platform === 'darwin') {
    backendName = 'seatbelt';
    sandboxBackendAvailable = fs.existsSync('/usr/bin/sandbox-exec');
  } else if (process.platform === 'linux') {
    backendName = 'bubblewrap';
    try {
      execFileSync('which', ['bwrap'], { stdio: 'pipe' });
      sandboxBackendAvailable = true;
    } catch {
      sandboxBackendAvailable = false;
    }
  }

  const exposedEnvFiles: string[] = [];
  for (const envCandidate of ['.env', '.env.local', '.env.development', '.env.production', '.npmrc']) {
    const absPath = path.join(canonicalRepo, envCandidate);
    if (!fs.existsSync(absPath)) {
      continue;
    }
    const content = fs.readFileSync(absPath, 'utf8');
    if (SECRET_ENV_LINE_PATTERN.test(content)) {
      exposedEnvFiles.push(envCandidate);
    }
  }

  const scanner = new PersistenceScanner();
  const candidateFiles = ['.gitattributes', '.gitmodules', '.vscode/tasks.json', '.vscode/settings.json', 'package.json'];
  const presentFiles: string[] = [];
  const combinedPatchChunks: string[] = [];

  for (const relPath of candidateFiles) {
    const absPath = path.join(canonicalRepo, relPath);
    if (!fs.existsSync(absPath)) {
      continue;
    }
    presentFiles.push(relPath);
    const lines = fs.readFileSync(absPath, 'utf8').split(/\r?\n/);
    combinedPatchChunks.push(`diff --git a/${relPath} b/${relPath}\n${lines.map((l) => `+${l}`).join('\n')}`);
  }

  const findings = [...scanner.scanDiff(presentFiles, combinedPatchChunks.join('\n'))];

  try {
    loadRepositoryPolicyFile(canonicalRepo);
  } catch (err) {
    findings.push({
      filePath: path.join(canonicalRepo, AEGIS_POLICY_FILENAME),
      category: 'POLICY_FILE_TAMPER',
      description: `Invalid ${AEGIS_POLICY_FILENAME}: ${err instanceof Error ? err.message : String(err)}`,
    });
  }

  const hooksDir = path.join(canonicalRepo, '.git', 'hooks');
  if (fs.existsSync(hooksDir)) {
    for (const fileName of fs.readdirSync(hooksDir)) {
      if (fileName.endsWith('.sample')) {
        continue;
      }
      const hookPath = path.join(hooksDir, fileName);
      if (fs.statSync(hookPath).isFile()) {
        findings.push({
          filePath: `.git/hooks/${fileName}`,
          category: 'SHELL_RC_FILE',
          description: `Active custom Git hook ".git/hooks/${fileName}" executes automatically outside the sandbox unless protected.`,
        });
      }
    }
  }

  return {
    repoRootPath: canonicalRepo,
    sandboxBackendAvailable,
    backendName,
    exposedEnvFiles,
    findings,
    passed: sandboxBackendAvailable && findings.length === 0,
  };
}

export interface SarifRuleDescriptor {
  readonly id: string;
  readonly name: string;
  readonly shortDescription: {
    readonly text: string;
  };
  readonly defaultConfiguration?: {
    readonly level: 'error' | 'warning' | 'note';
  };
}

export interface SarifResult {
  readonly ruleId: string;
  readonly level: 'error' | 'warning' | 'note';
  readonly message: {
    readonly text: string;
  };
  readonly locations: readonly [
    {
      readonly physicalLocation: {
        readonly artifactLocation: {
          readonly uri: string;
        };
      };
    },
  ];
}

export interface SarifLog {
  readonly $schema: 'https://json.schemastore.org/sarif-2.1.0.json';
  readonly version: '2.1.0';
  readonly runs: readonly [
    {
      readonly tool: {
        readonly driver: {
          readonly name: 'Aurora Aegis';
          readonly informationUri: string;
          readonly rules: readonly SarifRuleDescriptor[];
        };
      };
      readonly results: readonly SarifResult[];
    },
  ];
}

function toSarifArtifactUri(repoRootPath: string, targetPath: string): string {
  const relPath = path.isAbsolute(targetPath) ? path.relative(repoRootPath, targetPath) : targetPath;
  const posixPath = relPath.split(path.sep).join('/');
  return posixPath.length > 0 ? posixPath : '.';
}

export function formatAuditReportAsSarif(report: SecurityAuditReport): SarifLog {
  const rules = new Map<string, SarifRuleDescriptor>();
  const results: SarifResult[] = [];

  const registerRule = (descriptor: SarifRuleDescriptor) => {
    if (!rules.has(descriptor.id)) {
      rules.set(descriptor.id, descriptor);
    }
  };

  if (!report.sandboxBackendAvailable) {
    const ruleId = 'AEGIS_SANDBOX_BACKEND_UNAVAILABLE';
    registerRule({
      id: ruleId,
      name: 'SandboxBackendUnavailable',
      shortDescription: {
        text: 'Kernel sandbox isolation backend is unavailable on this host.',
      },
      defaultConfiguration: { level: 'error' },
    });
    results.push({
      ruleId,
      level: 'error',
      message: {
        text: `Sandbox isolation backend (${report.backendName}) is unavailable on platform ${process.platform}.`,
      },
      locations: [{ physicalLocation: { artifactLocation: { uri: '.' } } }],
    });
  }

  for (const envFile of report.exposedEnvFiles) {
    const ruleId = 'AEGIS_EXPOSED_DOTENV_SECRET';
    registerRule({
      id: ruleId,
      name: 'ExposedDotenvSecret',
      shortDescription: {
        text: 'Secret-bearing configuration file detected in repository workspace.',
      },
      defaultConfiguration: { level: 'warning' },
    });
    results.push({
      ruleId,
      level: 'warning',
      message: {
        text: `Secret-bearing file "${envFile}" detected on disk; Aegis will scrub and replace values with phantom tokens in sandboxed sessions.`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: toSarifArtifactUri(report.repoRootPath, envFile) },
          },
        },
      ],
    });
  }

  for (const finding of report.findings) {
    const ruleId = `AEGIS_${finding.category}`;
    registerRule({
      id: ruleId,
      name: finding.category,
      shortDescription: {
        text: `Security audit persistence or policy finding (${finding.category}).`,
      },
      defaultConfiguration: { level: 'error' },
    });
    results.push({
      ruleId,
      level: 'error',
      message: {
        text: finding.description,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: toSarifArtifactUri(report.repoRootPath, finding.filePath) },
          },
        },
      ],
    });
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Aurora Aegis',
            informationUri: 'https://github.com/aurora-aegis/aurora-aegis',
            rules: [...rules.values()],
          },
        },
        results,
      },
    ],
  };
}

export interface VerifyArtifactReport {
  readonly filePath: string;
  readonly artifactType: 'harvest-attestation' | 'audit-ledger-jsonl' | 'harvest-result' | 'unknown';
  readonly valid: boolean;
  readonly sessionId?: string | undefined;
  readonly entryCount?: number | undefined;
  readonly failureReason?: string | undefined;
}

export function verifySecurityArtifactFile(targetPath: string): VerifyArtifactReport {
  const resolvedPath = path.resolve(targetPath);
  if (!fs.existsSync(resolvedPath)) {
    return {
      filePath: resolvedPath,
      artifactType: 'unknown',
      valid: false,
      failureReason: `Artifact file does not exist: ${resolvedPath}`,
    };
  }

  const raw = fs.readFileSync(resolvedPath, 'utf8');
  const trimmed = raw.trim();
  const nonEmptyLines = trimmed
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  let looksLikeMultiLineLedger = false;
  if (nonEmptyLines.length > 1) {
    try {
      const firstLine = JSON.parse(nonEmptyLines[0]!) as unknown;
      if (
        firstLine !== null &&
        typeof firstLine === 'object' &&
        !Array.isArray(firstLine) &&
        typeof (firstLine as Record<string, unknown>)['entrySha256'] === 'string' &&
        typeof (firstLine as Record<string, unknown>)['prevEntrySha256'] === 'string'
      ) {
        looksLikeMultiLineLedger = true;
      }
    } catch {
      looksLikeMultiLineLedger = resolvedPath.endsWith('.jsonl');
    }
  }

  if (resolvedPath.endsWith('.jsonl') || looksLikeMultiLineLedger) {
    const ledgerRes = parseAndVerifyAuditLedgerJsonl(raw);
    return {
      filePath: resolvedPath,
      artifactType: 'audit-ledger-jsonl',
      valid: ledgerRes.valid,
      ...(ledgerRes.sessionId !== undefined ? { sessionId: ledgerRes.sessionId } : {}),
      entryCount: ledgerRes.entryCount,
      ...(ledgerRes.failureReason !== undefined ? { failureReason: ledgerRes.failureReason } : {}),
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return {
      filePath: resolvedPath,
      artifactType: 'unknown',
      valid: false,
      failureReason: `Invalid JSON artifact: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return {
      filePath: resolvedPath,
      artifactType: 'unknown',
      valid: false,
      failureReason: 'Artifact JSON root must be an object.',
    };
  }

  const record = parsed as Record<string, unknown>;

  if (
    record['schemaVersion'] === '1.0' &&
    typeof record['patchSha256'] === 'string' &&
    typeof record['signatureBase64'] === 'string'
  ) {
    const attestation = parsed as HarvestAttestation;
    const valid = verifyHarvestAttestation(attestation);
    return {
      filePath: resolvedPath,
      artifactType: 'harvest-attestation',
      valid,
      ...(typeof attestation.sessionId === 'string' ? { sessionId: attestation.sessionId } : {}),
      ...(!valid ? { failureReason: 'Harvest attestation Ed25519 signature verification failed.' } : {}),
    };
  }

  if (typeof record['attestation'] === 'object' && record['attestation'] !== null) {
    const attestation = record['attestation'] as HarvestAttestation;
    const attestationValid = verifyHarvestAttestation(attestation);
    const sessionId =
      typeof record['sessionId'] === 'string'
        ? record['sessionId']
        : typeof attestation.sessionId === 'string'
          ? attestation.sessionId
          : undefined;

    if (Array.isArray(record['auditLedgerEntries'])) {
      const ledgerRes = verifyAuditLedgerEntries(record['auditLedgerEntries'] as AuditLedgerEntry[]);
      const valid = attestationValid && ledgerRes.valid;
      const failureReason = !attestationValid
        ? 'Harvest attestation Ed25519 signature verification failed.'
        : ledgerRes.failureReason;
      return {
        filePath: resolvedPath,
        artifactType: 'harvest-result',
        valid,
        ...(sessionId !== undefined ? { sessionId } : {}),
        entryCount: ledgerRes.entryCount,
        ...(failureReason !== undefined ? { failureReason } : {}),
      };
    }

    return {
      filePath: resolvedPath,
      artifactType: 'harvest-result',
      valid: attestationValid,
      ...(sessionId !== undefined ? { sessionId } : {}),
      ...(!attestationValid ? { failureReason: 'Harvest attestation Ed25519 signature verification failed.' } : {}),
    };
  }

  if (typeof record['entrySha256'] === 'string' && typeof record['prevEntrySha256'] === 'string') {
    const ledgerRes = parseAndVerifyAuditLedgerJsonl(raw);
    return {
      filePath: resolvedPath,
      artifactType: 'audit-ledger-jsonl',
      valid: ledgerRes.valid,
      ...(ledgerRes.sessionId !== undefined ? { sessionId: ledgerRes.sessionId } : {}),
      entryCount: ledgerRes.entryCount,
      ...(ledgerRes.failureReason !== undefined ? { failureReason: ledgerRes.failureReason } : {}),
    };
  }

  return {
    filePath: resolvedPath,
    artifactType: 'unknown',
    valid: false,
    failureReason: 'Unrecognized Aegis security artifact format.',
  };
}

export interface InitPolicyOptions {
  readonly overwrite?: boolean | undefined;
  readonly enforceLockfile?: boolean | undefined;
}

export interface InitPolicyResult {
  readonly policyFilePath: string;
  readonly policy: AegisPolicyFileSchema;
}

export function initRepositoryPolicyFile(
  targetDir: string,
  options: InitPolicyOptions = {},
): InitPolicyResult {
  const canonicalRepo = canonicalizePath(targetDir);
  const policyFilePath = path.join(canonicalRepo, AEGIS_POLICY_FILENAME);
  if (fs.existsSync(policyFilePath) && !options.overwrite) {
    throw new Error(`${AEGIS_POLICY_FILENAME} already exists at ${policyFilePath}`);
  }

  const policy: AegisPolicyFileSchema = {
    version: 1,
    tier: 'tier1-kernel-mac',
    cowDirectories: discoverDefaultCowDirectories(canonicalRepo),
    egressRules: [
      { domain: 'registry.npmjs.org', allowedMethods: ['GET', 'POST'] },
      { domain: 'pypi.org', allowedMethods: ['GET', 'POST'] },
      { domain: 'files.pythonhosted.org', allowedMethods: ['GET', 'POST'] },
      { domain: 'api.github.com', allowedMethods: ['GET', 'POST'] },
    ],
    packagePolicy: {
      enforceLockfile: options.enforceLockfile ?? true,
    },
    timeoutMs: 60_000,
  };

  fs.writeFileSync(policyFilePath, `${JSON.stringify(policy, null, 2)}\n`, 'utf8');
  return { policyFilePath, policy };
}

export function getDefaultDaemonSocketPath(uid?: number): string {
  const resolvedUid = uid ?? (typeof process.getuid === 'function' ? process.getuid() : 0);
  return path.join(canonicalizePath(os.tmpdir()), `aegis-daemon-${resolvedUid}.sock`);
}

export async function runDaemonCliCommand(
  args: readonly string[],
  options: { readonly socketPath?: string | undefined } = {},
): Promise<number> {
  let flagSocketPath: string | undefined;
  const positional: string[] = [];
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === '--socket' && args[i + 1]) {
      flagSocketPath = args[i + 1];
      i += 1;
    } else {
      positional.push(args[i]!);
    }
  }

  const socketPath =
    options.socketPath ?? flagSocketPath ?? process.env['AEGIS_DAEMON_SOCKET'] ?? getDefaultDaemonSocketPath();

  const [action, targetRepo] = positional;

  if (action === 'start') {
    const daemon = new AegisControlDaemon({ socketPath });
    const boundSocket = await daemon.start();
    process.stdout.write(`${JSON.stringify({ started: true, socketPath: boundSocket })}\n`);
    await daemon.waitForStop();
    return 0;
  }

  const client = new AegisDaemonClient(socketPath);

  if (action === 'status') {
    const res = await client.status(targetRepo);
    process.stdout.write(`${JSON.stringify(res.sessions, null, 2)}\n`);
    return 0;
  }

  if (action === 'harvest') {
    const repoRootPath = targetRepo ?? process.cwd();
    const res = await client.harvest({ repoRootPath, applyToHost: true, closeSession: true });
    process.stdout.write(`${JSON.stringify(res.harvestResult, null, 2)}\n`);
    return res.harvestResult.appliedToHost ? 0 : 1;
  }

  if (action === 'stop') {
    await client.shutdown();
    process.stdout.write(`${JSON.stringify({ shutdown: true })}\n`);
    return 0;
  }

  process.stderr.write(`Unknown daemon action: ${action ?? '(none)'}\n`);
  return 1;
}

export async function runCli(argv: readonly string[]): Promise<number> {
  const [subcommand, ...rest] = argv;
  if (!subcommand || subcommand === '--help' || subcommand === '-h') {
    process.stdout.write('Usage: aegis <init | wrap | zsh | integrate | audit | verify | mcp-wrap | daemon> [args]\n');
    return 0;
  }

  if (subcommand === 'init') {
    const overwrite = rest.includes('--force');
    const enforceLockfile = !rest.includes('--no-lockfile');
    const targetDir = rest.find((arg) => !arg.startsWith('--')) ?? process.cwd();
    const result = initRepositoryPolicyFile(targetDir, { overwrite, enforceLockfile });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return 0;
  }

  if (subcommand === 'audit') {
    const sarif = rest.includes('--sarif');
    const target = rest.find((arg) => !arg.startsWith('--')) ?? process.cwd();
    const report = runSecurityAudit(target);
    const output = sarif ? formatAuditReportAsSarif(report) : report;
    process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
    return report.passed ? 0 : 1;
  }

  if (subcommand === 'verify') {
    const artifactPath = rest[0];
    if (!artifactPath) {
      process.stderr.write('Missing artifact path to verify.\n');
      return 1;
    }
    const report = verifySecurityArtifactFile(artifactPath);
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    return report.valid ? 0 : 1;
  }

  if (subcommand === 'integrate') {
    const configPath = rest[0];
    if (!configPath) {
      process.stderr.write('Missing MCP config path.\n');
      return 1;
    }
    const result = integrateMcpConfigFile(configPath);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return 0;
  }

  if (subcommand === 'wrap') {
    let interactiveLeading = false;
    for (const arg of rest) {
      if (arg === '--interactive' || arg === '-i') {
        interactiveLeading = true;
      } else {
        break;
      }
    }
    const result = await runWrapCommand(rest, { repoRootPath: process.cwd() });
    if (!interactiveLeading) {
      process.stdout.write(result.commandResult.stdout);
      process.stderr.write(result.commandResult.stderr);
    }
    return result.commandResult.exitCode;
  }

  if (subcommand === 'mcp-wrap') {
    const result = await runMcpWrapSupervisor(rest, { repoRootPath: process.cwd(), applyChanges: false });
    return result.exitCode;
  }

  if (subcommand === 'daemon') {
    return runDaemonCliCommand(rest);
  }

  if (subcommand === 'zsh' || subcommand === 'aegis-zsh') {
    const daemonSocketPath = process.env['AEGIS_DAEMON_SOCKET'];
    try {
      const result = await runZshShim(rest, { repoRootPath: process.cwd(), daemonSocketPath });
      process.stdout.write(result.commandResult.stdout);
      process.stderr.write(result.commandResult.stderr);
      return result.commandResult.exitCode;
    } finally {
      if (!daemonSocketPath) {
        await closeAllShimSessions();
      }
    }
  }

  process.stderr.write(`Unknown aegis command: ${subcommand}\n`);
  return 1;
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
  runCli(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((err: unknown) => {
      process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
      process.exitCode = 1;
    });
}
