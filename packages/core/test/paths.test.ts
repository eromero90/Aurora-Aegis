import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  assertCanonicalAbsolutePath,
  canonicalizePath,
  isSubpathOf,
} from '../src/utils/paths.js';

describe('paths canonicalization & containment helpers', () => {
  let tempRoot: string;

  beforeEach(() => {
    tempRoot = fs.realpathSync.native(
      fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-paths-test-')),
    );
  });

  afterEach(() => {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  it('canonicalizes existing directories and files identically to fs.realpathSync.native', () => {
    const nestedDir = path.join(tempRoot, 'workspace', 'src');
    const filePath = path.join(nestedDir, 'index.ts');
    fs.mkdirSync(nestedDir, { recursive: true });
    fs.writeFileSync(filePath, 'export {};\n');

    expect(canonicalizePath(nestedDir)).toBe(fs.realpathSync.native(nestedDir));
    expect(canonicalizePath(filePath)).toBe(fs.realpathSync.native(filePath));
  });

  it('canonicalizes non-existent leaf paths under symlinked directories', () => {
    const realTarget = path.join(tempRoot, 'real-dir');
    const symlinkAlias = path.join(tempRoot, 'alias-dir');
    fs.mkdirSync(realTarget, { recursive: true });
    fs.symlinkSync(realTarget, symlinkAlias);

    const nonExistentViaAlias = path.join(symlinkAlias, 'worktree', 'nested', 'file.txt');
    const expected = path.join(realTarget, 'worktree', 'nested', 'file.txt');

    expect(canonicalizePath(nonExistentViaAlias)).toBe(expected);

    if (process.platform === 'darwin') {
      const macTmpNonExistent = `/tmp/aegis-nonexistent-leaf-${process.pid}/child/file.txt`;
      expect(canonicalizePath(macTmpNonExistent)).toBe(
        `/private/tmp/aegis-nonexistent-leaf-${process.pid}/child/file.txt`,
      );
    }
  });

  it('resolves relative paths against cwd and canonicalizes them', () => {
    const relativeResult = canonicalizePath('./package.json');
    expect(path.isAbsolute(relativeResult)).toBe(true);
    expect(relativeResult).toBe(fs.realpathSync.native(path.resolve('./package.json')));
  });

  it('rejects empty strings and paths containing null bytes', () => {
    expect(() => canonicalizePath('')).toThrow(/non-empty/);
    expect(() => canonicalizePath('/tmp/bad\0path')).toThrow(/null bytes/);
  });

  it('detects true containment via isSubpathOf while rejecting traversal and sibling prefixes', () => {
    const realParent = path.join(tempRoot, 'aegis-wt-1');
    const realChild = path.join(realParent, 'packages', 'core');
    const siblingPrefix = path.join(tempRoot, 'aegis-wt-10');
    const dotDotSibling = path.join(realParent, '..foo');
    const aliasParent = path.join(tempRoot, 'alias-wt-1');

    fs.mkdirSync(realChild, { recursive: true });
    fs.mkdirSync(siblingPrefix, { recursive: true });
    fs.mkdirSync(dotDotSibling, { recursive: true });
    fs.symlinkSync(realParent, aliasParent);

    expect(isSubpathOf(realParent, realParent)).toBe(true);
    expect(isSubpathOf(realChild, realParent)).toBe(true);
    expect(isSubpathOf(path.join(aliasParent, 'packages', 'core'), realParent)).toBe(true);
    expect(isSubpathOf(path.join(aliasParent, 'not-created-yet', 'a.ts'), realParent)).toBe(true);

    expect(isSubpathOf(dotDotSibling, realParent)).toBe(true);

    expect(isSubpathOf(siblingPrefix, realParent)).toBe(false);
    expect(isSubpathOf(path.join(realParent, '..', 'aegis-wt-10'), realParent)).toBe(false);
    expect(isSubpathOf(tempRoot, realParent)).toBe(false);
  });

  it('validates canonical absolute paths via assertCanonicalAbsolutePath', () => {
    const realDir = path.join(tempRoot, 'canonical-dir');
    const aliasDir = path.join(tempRoot, 'alias-dir');
    fs.mkdirSync(realDir, { recursive: true });
    fs.symlinkSync(realDir, aliasDir);

    expect(() => assertCanonicalAbsolutePath(realDir)).not.toThrow();
    expect(() => assertCanonicalAbsolutePath(path.join(realDir, 'future-leaf'))).not.toThrow();

    expect(() => assertCanonicalAbsolutePath(aliasDir)).toThrow(/not canonical/);
    expect(() => assertCanonicalAbsolutePath('relative/path')).toThrow(/must be absolute/);
    expect(() => assertCanonicalAbsolutePath('')).toThrow(/non-empty/);
    expect(() => assertCanonicalAbsolutePath('/tmp/null\0byte')).toThrow(/null bytes/);
  });
});
