#!/usr/bin/env node
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
import { closeAllShimSessions, runZshShim } from './index.js';

async function main(): Promise<number> {
  const daemonSocketPath = process.env['AEGIS_DAEMON_SOCKET'];
  try {
    const result = await runZshShim(process.argv.slice(2), {
      repoRootPath: process.cwd(),
      daemonSocketPath,
    });
    process.stdout.write(result.commandResult.stdout);
    process.stderr.write(result.commandResult.stderr);
    return result.commandResult.exitCode;
  } finally {
    if (!daemonSocketPath) {
      await closeAllShimSessions();
    }
  }
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
  main()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((err: unknown) => {
      process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
      process.exitCode = 1;
    });
}
