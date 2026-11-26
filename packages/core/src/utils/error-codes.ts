export interface RuntimeDiagnostic {
  readonly source: string;
  readonly code?: string | undefined;
  readonly message: string;
}

export type DiagnosticReporter = (diagnostic: RuntimeDiagnostic) => void;

export function getErrnoCode(error: unknown): string | undefined {
  if (error !== null && typeof error === 'object' && 'code' in error) {
    const code = (error as { readonly code?: unknown }).code;
    if (typeof code === 'string' && code.length > 0) {
      return code;
    }
  }
  return undefined;
}

export function isExpectedErrno(error: unknown, expectedCodes: ReadonlySet<string>): boolean {
  const code = getErrnoCode(error);
  return code !== undefined && expectedCodes.has(code);
}

export function formatErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
