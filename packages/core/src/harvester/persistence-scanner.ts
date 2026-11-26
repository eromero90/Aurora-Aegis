import type { PersistenceVectorFinding } from '../types/contracts.js';

const SHELL_RC_FILES = new Set([
  '.bashrc',
  '.bash_profile',
  '.zshrc',
  '.zprofile',
  '.profile',
  '.envrc',
]);

const PACKAGE_LIFECYCLE_HOOK_REGEX =
  /^\+.*"(?:preinstall|install|postinstall|prepare|preprepare|postprepare|prepublish|prepublishOnly)"\s*:/m;
const CARGO_BUILD_REGEX = /^\+\s*build\s*=/m;
const TOKEN_LEAK_LINE_REGEX = /^\+(?!\+\+).*?(aegis_phantom_[a-z0-9_]+|aegis_canary_[a-z0-9_]+)/m;

export class PersistenceScanner {
  scanDiff(
    changedFiles: readonly string[],
    patchDiff: string,
  ): readonly PersistenceVectorFinding[] {
    const findings: PersistenceVectorFinding[] = [];
    const seen = new Set<string>();

    const addFinding = (finding: PersistenceVectorFinding) => {
      const key = `${finding.category}:${finding.filePath}`;
      if (!seen.has(key)) {
        seen.add(key);
        findings.push(finding);
      }
    };

    for (const rawFile of changedFiles) {
      const normalized = rawFile.replaceAll('\\', '/');
      const baseName = normalized.split('/').pop() ?? normalized;

      if (baseName === '.gitattributes') {
        addFinding({
          filePath: normalized,
          category: 'GIT_ATTRIBUTES_FILTER',
          description: 'Modification of .gitattributes can register custom Git clean/smudge filter execution drivers.',
        });
      }

      if (normalized === 'aegis.policy.json' || baseName === 'aegis.policy.json') {
        addFinding({
          filePath: normalized,
          category: 'POLICY_FILE_TAMPER',
          description: 'Modification of aegis.policy.json attempts to weaken security policy controls across harvests.',
        });
      }

      if (baseName === '.gitmodules') {
        addFinding({
          filePath: normalized,
          category: 'GIT_SUBMODULE',
          description: 'Modification of .gitmodules can introduce malicious repository checkout hooks.',
        });
      }

      if (
        normalized === '.vscode/tasks.json' ||
        normalized === '.vscode/settings.json' ||
        normalized === '.vscode/launch.json' ||
        normalized.startsWith('.idea/')
      ) {
        addFinding({
          filePath: normalized,
          category: 'IDE_AUTORUN_TASK',
          description: 'Modification of IDE workspace configuration may execute commands automatically on folder open.',
        });
      }

      if (SHELL_RC_FILES.has(baseName)) {
        addFinding({
          filePath: normalized,
          category: 'SHELL_RC_FILE',
          description: `Modification of shell initialization file "${baseName}" introduces host shell persistence.`,
        });
      }

      if (baseName === 'build.rs') {
        addFinding({
          filePath: normalized,
          category: 'CARGO_BUILD_SCRIPT',
          description: 'Modification of Rust build.rs executes arbitrary host code during cargo builds.',
        });
      }

      if (baseName === 'Cargo.toml' && CARGO_BUILD_REGEX.test(this.extractFilePatch(patchDiff, normalized))) {
        addFinding({
          filePath: normalized,
          category: 'CARGO_BUILD_SCRIPT',
          description: 'Cargo.toml adds or modifies a custom build script directive.',
        });
      }

      if (
        baseName === 'package.json' &&
        PACKAGE_LIFECYCLE_HOOK_REGEX.test(this.extractFilePatch(patchDiff, normalized))
      ) {
        addFinding({
          filePath: normalized,
          category: 'PACKAGE_LIFECYCLE_SCRIPT',
          description: 'package.json adds or modifies a lifecycle install/prepare script.',
        });
      }
    }

    const tokenMatch = TOKEN_LEAK_LINE_REGEX.exec(patchDiff);
    if (tokenMatch) {
      addFinding({
        filePath: '<diff>',
        category: 'PHANTOM_TOKEN_LEAK',
        description: `Diff contains synthetic Aegis token "${tokenMatch[1] ?? 'aegis_token'}" that must not be harvested.`,
      });
    }

    return findings;
  }

  private extractFilePatch(patchDiff: string, normalizedPath: string): string {
    const marker = `diff --git a/${normalizedPath} b/${normalizedPath}`;
    const startIdx = patchDiff.indexOf(marker);
    if (startIdx === -1) {
      return patchDiff;
    }
    const nextIdx = patchDiff.indexOf('\ndiff --git ', startIdx + marker.length);
    return nextIdx === -1 ? patchDiff.slice(startIdx) : patchDiff.slice(startIdx, nextIdx);
  }
}
