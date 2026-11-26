import fs from 'node:fs';
import path from 'node:path';

export function canonicalizePath(targetPath: string): string {
  if (typeof targetPath !== 'string' || targetPath.length === 0) {
    throw new Error('Path must be a non-empty string.');
  }
  if (targetPath.includes('\0')) {
    throw new Error('Path must not contain null bytes.');
  }

  const resolved = path.resolve(targetPath);

  try {
    return fs.realpathSync.native(resolved);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== 'ENOENT') {
      throw err;
    }
  }

  const missingSegments: string[] = [];
  let current = resolved;

  while (true) {
    const parent = path.dirname(current);
    const segment = path.basename(current);
    if (segment.length > 0) {
      missingSegments.push(segment);
    }

    if (parent === current) {
      return resolved;
    }

    current = parent;

    try {
      const canonicalAncestor = fs.realpathSync.native(current);
      missingSegments.reverse();
      return path.join(canonicalAncestor, ...missingSegments);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== 'ENOENT') {
        throw err;
      }
    }
  }
}

export function isSubpathOf(childPath: string, parentPath: string): boolean {
  const canonicalChild = canonicalizePath(childPath);
  const canonicalParent = canonicalizePath(parentPath);
  const relative = path.relative(canonicalParent, canonicalChild);

  if (relative === '') {
    return true;
  }

  return (
    relative !== '..' &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
  );
}

export function assertCanonicalAbsolutePath(targetPath: string): void {
  if (typeof targetPath !== 'string' || targetPath.length === 0) {
    throw new Error('Path must be a non-empty string.');
  }
  if (targetPath.includes('\0')) {
    throw new Error('Path must not contain null bytes.');
  }
  if (!path.isAbsolute(targetPath)) {
    throw new Error(`Path must be absolute: "${targetPath}"`);
  }

  const canonical = canonicalizePath(targetPath);
  if (targetPath !== canonical) {
    throw new Error(
      `Path is not canonical: expected "${canonical}", received "${targetPath}"`,
    );
  }
}
