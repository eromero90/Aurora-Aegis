import os from 'node:os';
import type { SandboxPolicy, WorkspaceDescriptor } from '../types/contracts.js';
import { canonicalizePath } from '../utils/paths.js';

export function compileBwrapArgs(
  policy: SandboxPolicy,
  workspace: WorkspaceDescriptor,
  udsSocketPath: string,
  command: string,
): readonly string[] {
  const realHome = canonicalizePath(os.homedir());
  const realWorktree = canonicalizePath(workspace.worktreePath);
  const realSessionTmp = canonicalizePath(workspace.sessionTmpDir);
  const realSessionHome = canonicalizePath(workspace.sessionHomeDir);
  const realRepoGit = canonicalizePath(workspace.repoGitDir);
  const realWorktreeGit = canonicalizePath(workspace.worktreeGitDir);
  const realUdsSocket = canonicalizePath(udsSocketPath);

  const args: string[] = [
    '--unshare-all',
    '--die-with-parent',
    '--ro-bind',
    '/usr',
    '/usr',
    '--ro-bind',
    '/bin',
    '/bin',
    '--ro-bind',
    '/lib',
    '/lib',
    '--ro-bind-try',
    '/lib64',
    '/lib64',
    '--ro-bind-try',
    '/etc/ssl',
    '/etc/ssl',
    '--ro-bind-try',
    '/etc/resolv.conf',
    '/etc/resolv.conf',
    '--dev',
    '/dev',
    '--proc',
    '/proc',
    '--tmpfs',
    realHome,
  ];

  for (const tcPath of policy.readOnlyToolchainPaths) {
    if (tcPath.length === 0) continue;
    const canonicalTc = canonicalizePath(tcPath);
    args.push('--ro-bind-try', canonicalTc, canonicalTc);
  }

  args.push(
    '--bind',
    realSessionHome,
    realSessionHome,
    '--bind',
    realWorktree,
    realWorktree,
    '--ro-bind-try',
    `${realWorktree}/aegis.policy.json`,
    `${realWorktree}/aegis.policy.json`,
    '--bind',
    realSessionTmp,
    realSessionTmp,
    '--ro-bind',
    realRepoGit,
    realRepoGit,
    '--bind',
    realWorktreeGit,
    realWorktreeGit,
    '--bind',
    `${realRepoGit}/objects`,
    `${realRepoGit}/objects`,
    '--ro-bind',
    `${realRepoGit}/hooks`,
    `${realRepoGit}/hooks`,
    '--ro-bind-try',
    `${realRepoGit}/config`,
    `${realRepoGit}/config`,
    '--ro-bind-try',
    `${realRepoGit}/packed-refs`,
    `${realRepoGit}/packed-refs`,
    '--ro-bind-try',
    `${realRepoGit}/refs/heads`,
    `${realRepoGit}/refs/heads`,
    '--dir',
    '/run/aegis',
    '--ro-bind',
    realUdsSocket,
    '/run/aegis/egress.sock',
    '--chdir',
    realWorktree,
    '--',
    '/bin/sh',
    '-c',
    command,
  );

  return args;
}
