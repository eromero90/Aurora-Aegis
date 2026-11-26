import { describe, expect, it } from 'vitest';
import { RedTeamSuite } from '../src/index.js';

describe('@aegis/red-team adversarial security matrix', () => {
  it('blocks 100% of all 15 escape, exfiltration, SSRF, IPC, canary, and persistence vectors', async () => {
    const suite = new RedTeamSuite();
    const results = await suite.runAllProbes();

    expect(results).toHaveLength(15);
    for (const result of results) {
      expect(result.evidence.length, `Probe ${result.id} (${result.name}) returned empty evidence`).toBeGreaterThan(0);
      expect(result.blocked, `Probe ${result.id} (${result.name}) failed to block: ${result.evidence}`).toBe(true);
    }
  }, 30_000);
});
