import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const PACKAGES_DIR = path.resolve(import.meta.dirname, '..', '..');

function collectTsFiles(dirPath: string): string[] {
  const results: string[] = [];
  if (!fs.existsSync(dirPath)) {
    return results;
  }
  for (const entry of fs.readdirSync(dirPath, { withFileTypes: true })) {
    const fullPath = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === 'dist') {
        continue;
      }
      results.push(...collectTsFiles(fullPath));
    } else if (entry.isFile() && entry.name.endsWith('.ts')) {
      results.push(fullPath);
    }
  }
  return results;
}

function collectMonorepoPackageTsFiles(): { srcFiles: string[]; testFiles: string[] } {
  const srcFiles: string[] = [];
  const testFiles: string[] = [];

  for (const pkgEntry of fs.readdirSync(PACKAGES_DIR, { withFileTypes: true })) {
    if (!pkgEntry.isDirectory()) {
      continue;
    }
    const pkgDir = path.join(PACKAGES_DIR, pkgEntry.name);
    srcFiles.push(...collectTsFiles(path.join(pkgDir, 'src')));
    testFiles.push(...collectTsFiles(path.join(pkgDir, 'test')));
  }

  return { srcFiles, testFiles };
}

describe('Anti-Tautology Gate', () => {
  const NUMBERED_STEP_COMMENT = /^\s*(?:\/\/|;;)\s*\d+\.\s+/;
  const BOILERPLATE_COMMENT =
    /\/\/\s*(?:Configuration options for|Ignore already-exited|Clean up running)\b/;
  const LITERAL_TAUTOLOGY = /expect\(\s*(true|false|\d+|'[^']*'|"[^"]*")\s*\)\.toBe\(\s*\1\s*\)/;
  const IDENTICAL_EXPR_TAUTOLOGY =
    /expect\(\s*([A-Za-z_$][A-Za-z0-9_$.?]*)\s*\)\.(?:toBe|toEqual|toStrictEqual)\(\s*\1\s*\)/;

  it('rejects tautological step/boilerplate comments across all package sources and tests', () => {
    const { srcFiles, testFiles } = collectMonorepoPackageTsFiles();
    const allFiles = [...srcFiles, ...testFiles];
    expect(allFiles.length).toBeGreaterThan(10);

    const violations: string[] = [];
    for (const filePath of allFiles) {
      if (filePath.endsWith('anti-tautology.test.ts')) {
        continue;
      }
      const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/);
      lines.forEach((line, index) => {
        if (NUMBERED_STEP_COMMENT.test(line) || BOILERPLATE_COMMENT.test(line)) {
          violations.push(`${path.relative(PACKAGES_DIR, filePath)}:${index + 1}: ${line.trim()}`);
        }
      });
    }

    expect(violations).toEqual([]);
  });

  it('rejects self-comparison assertions and assertionless test files across all packages', () => {
    const { testFiles } = collectMonorepoPackageTsFiles();
    expect(testFiles.length).toBeGreaterThan(8);

    const violations: string[] = [];
    for (const filePath of testFiles) {
      if (filePath.endsWith('anti-tautology.test.ts')) {
        continue;
      }
      const content = fs.readFileSync(filePath, 'utf8');
      if (!content.includes('expect(')) {
        violations.push(`${path.relative(PACKAGES_DIR, filePath)}: missing any expect() assertion`);
      }

      const lines = content.split(/\r?\n/);
      lines.forEach((line, index) => {
        if (LITERAL_TAUTOLOGY.test(line) || IDENTICAL_EXPR_TAUTOLOGY.test(line)) {
          violations.push(`${path.relative(PACKAGES_DIR, filePath)}:${index + 1}: ${line.trim()}`);
        }
      });
    }

    expect(violations).toEqual([]);
  });
});
