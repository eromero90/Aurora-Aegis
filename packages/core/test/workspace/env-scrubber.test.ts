import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { WorkspaceDescriptor } from '../../src/types/contracts.js';
import { CanaryPlanter } from '../../src/workspace/canary-planter.js';
import { EnvScrubber } from '../../src/workspace/env-scrubber.js';

describe('EnvScrubber & CanaryPlanter', () => {
  let tempRoot: string;
  let repoRoot: string;
  let worktreeRoot: string;
  let sessionHome: string;
  let sessionTmp: string;

  const scrubber = new EnvScrubber();
  const planter = new CanaryPlanter();

  beforeEach(() => {
    tempRoot = fs.realpathSync.native(
      fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-env-test-')),
    );
    repoRoot = path.join(tempRoot, 'repo');
    worktreeRoot = path.join(tempRoot, 'worktree');
    sessionHome = path.join(tempRoot, 'home');
    sessionTmp = path.join(tempRoot, 'tmp');

    fs.mkdirSync(repoRoot, { recursive: true });
    fs.mkdirSync(worktreeRoot, { recursive: true });
    fs.mkdirSync(sessionHome, { recursive: true });
    fs.mkdirSync(sessionTmp, { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  it('scrubs .env secrets into Phantom Credentials inside the worktree without writing real secrets', () => {
    fs.writeFileSync(
      path.join(repoRoot, '.env'),
      [
        '# Production keys',
        'OPENAI_API_KEY="sk-live-secret-9988776655"',
        "GITHUB_TOKEN='ghp_1234567890abcdef1234567890abcdef1234'",
        'EMPTY_VAR=',
      ].join('\n'),
    );

    const result = scrubber.scrubWorktreeEnvFiles(repoRoot, worktreeRoot, ['api.openai.com']);
    expect(result.scrubbedFiles).toContain('.env');
    expect(result.protectedSecrets).toContain('sk-live-secret-9988776655');
    expect(result.protectedSecrets).toContain('ghp_1234567890abcdef1234567890abcdef1234');
    expect(result.phantomCredentials).toHaveLength(2);

    const worktreeEnv = fs.readFileSync(path.join(worktreeRoot, '.env'), 'utf8');
    expect(worktreeEnv).not.toContain('sk-live-secret-9988776655');
    expect(worktreeEnv).not.toContain('ghp_1234567890abcdef1234567890abcdef1234');
    expect(worktreeEnv).toContain('aegis_phantom_openai_api_key_');
    expect(worktreeEnv).toContain('aegis_phantom_github_token_');
  });

  it('sanitizes process.env by stripping SSH_AUTH_SOCK, DOCKER_HOST, and inherited API keys', () => {
    const workspace: WorkspaceDescriptor = {
      sessionId: 'sess-1',
      repoRootPath: repoRoot,
      repoGitDir: path.join(repoRoot, '.git'),
      worktreePath: worktreeRoot,
      worktreeGitDir: path.join(repoRoot, '.git', 'worktrees', 'sess-1'),
      sessionTmpDir: sessionTmp,
      sessionHomeDir: sessionHome,
      clonedCowDirs: [],
    };

    const canaries = planter.plantCanaries(sessionHome, 'sess-1');
    const hostEnv: NodeJS.ProcessEnv = {
      PATH: '/usr/local/bin:/usr/bin:/bin',
      TERM: 'xterm-256color',
      SSH_AUTH_SOCK: '/tmp/ssh-agent.sock',
      GPG_AGENT_INFO: '/tmp/gpg-agent',
      DOCKER_HOST: 'unix:///var/run/docker.sock',
      OPENAI_API_KEY: 'sk-real-host-key-000000',
      AWS_SECRET_ACCESS_KEY: 'aws-real-secret-value',
    };

    const extracted = scrubber.extractHostEnvSecrets(hostEnv);
    expect(extracted).toContain('sk-real-host-key-000000');
    expect(extracted).toContain('aws-real-secret-value');

    const childEnv = scrubber.sanitizeProcessEnv({
      hostEnv,
      workspace,
      proxyPort: 54321,
      caCertPath: path.join(sessionTmp, 'aegis-ca.pem'),
      phantomCredentials: [
        {
          envVarName: 'GITHUB_TOKEN',
          phantomToken: 'aegis_phantom_gh_1234',
          realSecret: 'ghp_real',
          allowedHosts: ['api.github.com'],
        },
      ],
      canaries,
    });

    expect(childEnv['SSH_AUTH_SOCK']).toBeUndefined();
    expect(childEnv['GPG_AGENT_INFO']).toBeUndefined();
    expect(childEnv['DOCKER_HOST']).toBeUndefined();
    expect(childEnv['OPENAI_API_KEY']).toBeUndefined();
    expect(childEnv['AWS_SECRET_ACCESS_KEY']).toBeUndefined();

    expect(childEnv['HOME']).toBe(sessionHome);
    expect(childEnv['HTTP_PROXY']).toBe('http://127.0.0.1:54321');
    expect(childEnv['HTTPS_PROXY']).toBe('http://127.0.0.1:54321');
    expect(childEnv['NODE_EXTRA_CA_CERTS']).toBe(path.join(sessionTmp, 'aegis-ca.pem'));
    expect(childEnv['GITHUB_TOKEN']).toBe('aegis_phantom_gh_1234');
    expect(childEnv['AEGIS_INTERNAL_VAULT_TOKEN']).toMatch(/^aegis_canary_env_/);
  });

  it('plants Canary Honeytokens on disk and generates >= 6-char tripwire substrings', () => {
    const canaries = planter.plantCanaries(sessionHome, 'canary-test');
    expect(canaries).toHaveLength(3);

    const awsCanary = canaries.find((c) => c.label === 'aws-decoy-credentials');
    const sshCanary = canaries.find((c) => c.label === 'ssh-decoy-private-key');
    expect(awsCanary?.filePath).toBe(path.join(sessionHome, '.aws', 'credentials'));
    expect(sshCanary?.filePath).toBe(path.join(sessionHome, '.ssh', 'id_ed25519'));
    expect(fs.existsSync(awsCanary!.filePath!)).toBe(true);
    expect(fs.existsSync(sshCanary!.filePath!)).toBe(true);

    for (const canary of canaries) {
      expect(canary.tripwireSubstrings.length).toBeGreaterThan(3);
      expect(canary.tripwireSubstrings.every((s) => s.length >= 6)).toBe(true);
    }
  });
});
