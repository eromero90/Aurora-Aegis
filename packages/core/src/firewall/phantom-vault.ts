import type { PhantomCredentialRule } from '../types/contracts.js';

export interface PhantomProcessResult {
  readonly allowed: boolean;
  readonly headers: Record<string, string | readonly string[]>;
  readonly bodyText: string;
  readonly matchedRule?: string | undefined;
}

export class PhantomVault {
  constructor(private readonly rules: readonly PhantomCredentialRule[]) {}

  processOutbound(
    targetHost: string,
    headers: Readonly<Record<string, string | readonly string[] | undefined>>,
    bodyText: string,
  ): PhantomProcessResult {
    const normalizedHost = targetHost.toLowerCase().replace(/:\d+$/, '');
    const updatedHeaders: Record<string, string | readonly string[]> = {};

    for (const [key, val] of Object.entries(headers)) {
      if (typeof val === 'string') {
        updatedHeaders[key] = val;
      } else if (Array.isArray(val)) {
        updatedHeaders[key] = [...val];
      }
    }

    let updatedBody = bodyText;

    for (const rule of this.rules) {
      let foundInRequest = updatedBody.includes(rule.phantomToken);

      if (!foundInRequest) {
        for (const val of Object.values(updatedHeaders)) {
          if (typeof val === 'string' && val.includes(rule.phantomToken)) {
            foundInRequest = true;
            break;
          }
          if (Array.isArray(val) && val.some((item) => item.includes(rule.phantomToken))) {
            foundInRequest = true;
            break;
          }
        }
      }

      if (!foundInRequest) {
        continue;
      }

      const hostAuthorized = rule.allowedHosts.some((allowed) =>
        this.matchesHostPattern(allowed, normalizedHost),
      );
      if (!hostAuthorized) {
        return {
          allowed: false,
          headers: {},
          bodyText,
          matchedRule: `PHANTOM_UNAUTHORIZED_HOST:${rule.envVarName}->${normalizedHost}`,
        };
      }

      updatedBody = updatedBody.replaceAll(rule.phantomToken, rule.realSecret);
      for (const [key, val] of Object.entries(updatedHeaders)) {
        if (typeof val === 'string') {
          updatedHeaders[key] = val.replaceAll(rule.phantomToken, rule.realSecret);
        } else {
          updatedHeaders[key] = val.map((item) =>
            item.replaceAll(rule.phantomToken, rule.realSecret),
          );
        }
      }
    }

    return {
      allowed: true,
      headers: updatedHeaders,
      bodyText: updatedBody,
    };
  }

  scrubInbound(text: string): string {
    let sanitized = text;
    for (const rule of this.rules) {
      if (rule.realSecret.length > 0) {
        sanitized = sanitized.replaceAll(rule.realSecret, rule.phantomToken);
      }
    }
    return sanitized;
  }

  private matchesHostPattern(pattern: string, hostname: string): boolean {
    const normalizedPattern = pattern.toLowerCase();
    if (normalizedPattern.startsWith('*.')) {
      const suffix = normalizedPattern.slice(1);
      return hostname.endsWith(suffix) && hostname.length > suffix.length;
    }
    return normalizedPattern === hostname;
  }
}
