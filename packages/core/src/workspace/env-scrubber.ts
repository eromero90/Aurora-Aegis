import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type {
  CanaryHoneytoken,
  PhantomCredentialRule,
  WorkspaceDescriptor,
} from '../types/contracts.js';
import { canonicalizePath } from '../utils/paths.js';

const ENV_FILE_CANDIDATES = ['.env', '.env.local', '.env.development', '.env.production'] as const;
const STRUCTURAL_ENV_ALLOWLIST = [
  'PATH',
  'LANG',
  'LC_ALL',
  'TERM',
  'USER',
  'LOGNAME',
  'SHELL',
  'SYSTEMROOT',
] as const;

const SENSITIVE_KEY_PATTERN =
  /(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH|PRIVATE|DATABASE_URL|REDIS_URL|WEBHOOK)/i;
const SENSITIVE_PREFIX_PATTERN = /^(?:AWS_|GITHUB_|OPENAI_|ANTHROPIC_)/i;

export interface ScrubWorktreeEnvResult {
  readonly phantomCredentials: readonly PhantomCredentialRule[];
  readonly protectedSecrets: readonly string[];
  readonly scrubbedFiles: readonly string[];
}

export interface SanitizeProcessEnvOptions {
  readonly hostEnv: NodeJS.ProcessEnv;
  readonly workspace: WorkspaceDescriptor;
  readonly proxyPort: number;
  readonly caCertPath: string;
  readonly phantomCredentials: readonly PhantomCredentialRule[];
  readonly canaries?: readonly CanaryHoneytoken[] | undefined;
}

export class EnvScrubber {
  scrubWorktreeEnvFiles(
    repoRootPath: string,
    worktreePath: string,
    defaultAllowedHosts: readonly string[] = [],
  ): ScrubWorktreeEnvResult {
    const canonicalRepo = canonicalizePath(repoRootPath);
    const canonicalWorktree = canonicalizePath(worktreePath);

    const phantomCredentials: PhantomCredentialRule[] = [];
    const protectedSecretsSet = new Set<string>();
    const scrubbedFiles: string[] = [];

    for (const fileName of ENV_FILE_CANDIDATES) {
      const repoFile = path.join(canonicalRepo, fileName);
      const worktreeFile = path.join(canonicalWorktree, fileName);
      const sourcePath = fs.existsSync(repoFile)
        ? repoFile
        : fs.existsSync(worktreeFile)
          ? worktreeFile
          : undefined;

      if (!sourcePath) {
        continue;
      }

      const rawContent = fs.readFileSync(sourcePath, 'utf8');
      const lines = rawContent.split(/\r?\n/);
      const outputLines: string[] = [];

      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.length === 0 || trimmed.startsWith('#')) {
          outputLines.push(line);
          continue;
        }

        const match = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/.exec(line);
        if (!match) {
          outputLines.push(line);
          continue;
        }

        const key = match[1];
        const rawVal = match[2];
        if (key === undefined || rawVal === undefined) {
          outputLines.push(line);
          continue;
        }

        const cleanValue = this.stripMatchingQuotes(rawVal.trim());
        if (cleanValue.length === 0) {
          outputLines.push(`${key}=`);
          continue;
        }

        const normalizedKey = key.toLowerCase().replace(/[^a-z0-9]/g, '_');
        const phantomToken = `aegis_phantom_${normalizedKey}_${crypto.randomBytes(4).toString('hex')}`;

        phantomCredentials.push({
          envVarName: key,
          phantomToken,
          realSecret: cleanValue,
          allowedHosts: [...defaultAllowedHosts],
        });
        protectedSecretsSet.add(cleanValue);
        outputLines.push(`${key}=${phantomToken}`);
      }

      fs.writeFileSync(worktreeFile, `${outputLines.join('\n')}\n`, { mode: 0o600 });
      scrubbedFiles.push(fileName);
    }

    const npmrcRepo = path.join(canonicalRepo, '.npmrc');
    const npmrcWorktree = path.join(canonicalWorktree, '.npmrc');
    const npmrcSource = fs.existsSync(npmrcRepo)
      ? npmrcRepo
      : fs.existsSync(npmrcWorktree)
        ? npmrcWorktree
        : undefined;

    if (npmrcSource) {
      const rawNpmrc = fs.readFileSync(npmrcSource, 'utf8');
      const lines = rawNpmrc.split(/\r?\n/);
      const outLines: string[] = [];

      for (const line of lines) {
        const tokenMatch = /^(\s*.*:_authToken\s*=\s*)(.+)\s*$/.exec(line);
        if (tokenMatch && tokenMatch[1] !== undefined && tokenMatch[2] !== undefined) {
          const cleanToken = this.stripMatchingQuotes(tokenMatch[2].trim());
          if (cleanToken.length > 0) {
            const phantomToken = `aegis_phantom_npm_${crypto.randomBytes(4).toString('hex')}`;
            phantomCredentials.push({
              envVarName: 'NPM_AUTH_TOKEN',
              phantomToken,
              realSecret: cleanToken,
              allowedHosts:
                defaultAllowedHosts.length > 0 ? [...defaultAllowedHosts] : ['registry.npmjs.org'],
            });
            protectedSecretsSet.add(cleanToken);
            outLines.push(`${tokenMatch[1]}${phantomToken}`);
            continue;
          }
        }
        outLines.push(line);
      }

      fs.writeFileSync(npmrcWorktree, `${outLines.join('\n')}\n`, { mode: 0o600 });
      scrubbedFiles.push('.npmrc');
    }

    return {
      phantomCredentials,
      protectedSecrets: [...protectedSecretsSet],
      scrubbedFiles,
    };
  }

  extractHostEnvSecrets(hostEnv: NodeJS.ProcessEnv): readonly string[] {
    const secrets = new Set<string>();

    for (const [key, value] of Object.entries(hostEnv)) {
      if (typeof value !== 'string' || value.length < 6) {
        continue;
      }
      if (SENSITIVE_KEY_PATTERN.test(key) || SENSITIVE_PREFIX_PATTERN.test(key)) {
        secrets.add(value);
      }
    }

    return [...secrets];
  }

  sanitizeProcessEnv(options: SanitizeProcessEnvOptions): Record<string, string> {
    const sanitized: Record<string, string> = {};

    for (const key of STRUCTURAL_ENV_ALLOWLIST) {
      const value = options.hostEnv[key];
      if (typeof value === 'string' && value.length > 0) {
        sanitized[key] = value;
      }
    }

    const proxyUrl = `http://127.0.0.1:${options.proxyPort}`;
    sanitized['HOME'] = options.workspace.sessionHomeDir;
    sanitized['TMPDIR'] = options.workspace.sessionTmpDir;
    sanitized['CI'] = 'true';
    sanitized['HTTP_PROXY'] = proxyUrl;
    sanitized['HTTPS_PROXY'] = proxyUrl;
    sanitized['ALL_PROXY'] = proxyUrl;
    sanitized['NO_PROXY'] = '';
    sanitized['NODE_EXTRA_CA_CERTS'] = options.caCertPath;
    sanitized['SSL_CERT_FILE'] = options.caCertPath;
    sanitized['REQUESTS_CA_BUNDLE'] = options.caCertPath;
    sanitized['GIT_SSL_CAINFO'] = options.caCertPath;
    sanitized['CARGO_HTTP_CAINFO'] = options.caCertPath;

    for (const rule of options.phantomCredentials) {
      sanitized[rule.envVarName] = rule.phantomToken;
    }

    if (options.canaries) {
      for (const canary of options.canaries) {
        if (canary.envVarName) {
          sanitized[canary.envVarName] = canary.tokenValue;
        }
      }
    }

    return sanitized;
  }

  private stripMatchingQuotes(value: string): string {
    if (
      value.length >= 2 &&
      ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'")))
    ) {
      return value.slice(1, -1);
    }
    return value;
  }
}
