import type { ChildProcess } from 'node:child_process';
import {
  type DiagnosticReporter,
  formatErrorMessage,
  getErrnoCode,
  isExpectedErrno,
} from './error-codes.js';

const EXPECTED_KILL_ERRNOS = new Set(['ESRCH', 'EPERM']);

export function killProcessTree(child: ChildProcess, onDiagnostic?: DiagnosticReporter): void {
  const pid = child.pid;
  if (pid !== undefined && pid > 0) {
    try {
      process.kill(-pid, 'SIGKILL');
    } catch (groupErr) {
      if (!isExpectedErrno(groupErr, EXPECTED_KILL_ERRNOS)) {
        onDiagnostic?.({
          source: 'killProcessTree.group',
          code: getErrnoCode(groupErr),
          message: formatErrorMessage(groupErr),
        });
      }
      try {
        child.kill('SIGKILL');
      } catch (childErr) {
        if (!isExpectedErrno(childErr, EXPECTED_KILL_ERRNOS)) {
          onDiagnostic?.({
            source: 'killProcessTree.child',
            code: getErrnoCode(childErr),
            message: formatErrorMessage(childErr),
          });
        }
      }
    }
  } else {
    try {
      child.kill('SIGKILL');
    } catch (childErr) {
      if (!isExpectedErrno(childErr, EXPECTED_KILL_ERRNOS)) {
        onDiagnostic?.({
          source: 'killProcessTree.child',
          code: getErrnoCode(childErr),
          message: formatErrorMessage(childErr),
        });
      }
    }
  }

  child.stdin?.destroy();
  child.stdout?.destroy();
  child.stderr?.destroy();
}
