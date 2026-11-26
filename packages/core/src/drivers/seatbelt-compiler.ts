import os from 'node:os';
import type { SandboxPolicy, WorkspaceDescriptor } from '../types/contracts.js';
import { canonicalizePath } from '../utils/paths.js';

function escapeSbString(value: string): string {
  return value.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
}

export function compileSeatbeltProfile(
  policy: SandboxPolicy,
  workspace: WorkspaceDescriptor,
  proxyPort: number,
): string {
  if (!Number.isInteger(proxyPort) || proxyPort <= 0 || proxyPort > 65535) {
    throw new Error(`Invalid proxy port for Seatbelt profile: ${proxyPort}`);
  }

  const realHome = canonicalizePath(os.homedir());
  const realWorktree = canonicalizePath(workspace.worktreePath);
  const realSessionTmp = canonicalizePath(workspace.sessionTmpDir);
  const realSessionHome = canonicalizePath(workspace.sessionHomeDir);
  const realRepoGit = canonicalizePath(workspace.repoGitDir);
  const realWorktreeGit = canonicalizePath(workspace.worktreeGitDir);

  const canonicalToolchains = policy.readOnlyToolchainPaths
    .filter((p) => p.length > 0)
    .map((p) => canonicalizePath(p));

  const lines: string[] = [
    '(version 1)',
    '(allow default)',
    '',
    '(deny file-read* file-write*',
    `  (subpath "${escapeSbString(realHome)}"))`,
    '',
  ];

  if (canonicalToolchains.length > 0) {
    lines.push('(allow file-read*');
    for (const tcPath of canonicalToolchains) {
      lines.push(`  (subpath "${escapeSbString(tcPath)}")`);
    }
    lines[lines.length - 1] += ')';
    lines.push('');
  }

  lines.push(
    '(deny file-write*)',
    '',
    '(allow file-read* file-write*',
    `  (subpath "${escapeSbString(realWorktree)}")`,
    `  (subpath "${escapeSbString(realSessionTmp)}")`,
    `  (subpath "${escapeSbString(realSessionHome)}")`,
    '  (literal "/dev/null")',
    '  (literal "/dev/zero")',
    '  (literal "/dev/random")',
    '  (literal "/dev/urandom")',
    '  (literal "/dev/tty"))',
    '',
    ';; Git Hook Guard: deny rules follow allow rules because Seatbelt evaluates last-match precedence',
    '(allow file-read*',
    `  (subpath "${escapeSbString(realRepoGit)}"))`,
    '(allow file-write*',
    `  (subpath "${escapeSbString(realWorktreeGit)}")`,
    `  (subpath "${escapeSbString(`${realRepoGit}/objects`)}"))`,
    '(deny file-write*',
    `  (subpath "${escapeSbString(`${realRepoGit}/hooks`)}")`,
    `  (literal "${escapeSbString(`${realRepoGit}/config`)}")`,
    `  (literal "${escapeSbString(`${realRepoGit}/packed-refs`)}")`,
    `  (subpath "${escapeSbString(`${realRepoGit}/refs/heads`)}")`,
    `  (literal "${escapeSbString(`${realWorktree}/aegis.policy.json`)}"))`,
    '',
    '(deny network*)',
    '(allow network-outbound',
    `  (remote tcp "localhost:${proxyPort}"))`,
    '(allow network-bind',
    '  (local tcp "localhost:*"))',
    '(allow network-inbound',
    '  (local tcp "localhost:*"))',
    '',
    '(deny mach-lookup',
    '  (global-name "com.apple.pasteboard.1")',
    '  (global-name "com.apple.SecurityServer")',
    '  (global-name "com.apple.securityd.xpc")',
    '  (global-name "com.apple.SystemConfiguration.configd"))',
    '(deny file-read* file-write*',
    '  (literal "/var/run/docker.sock")',
    '  (literal "/private/var/run/docker.sock")',
    '  (subpath "/private/tmp/com.apple.launchd"))',
    '',
  );

  return lines.join('\n');
}
