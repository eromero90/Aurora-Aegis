import zlib from 'node:zlib';
import type {
  CanaryHoneytoken,
  DlpViolationReason,
  HttpMethod,
  SecretFingerprint,
} from '../types/contracts.js';

const BUILTIN_SECRET_REGEXES: ReadonlyArray<{ readonly name: string; readonly regex: RegExp }> = [
  { name: 'OPENAI_API_KEY', regex: /\bsk-[a-zA-Z0-9_-]{20,}\b/ },
  { name: 'GITHUB_TOKEN', regex: /\bgh[pousr]_[A-Za-z0-9_]{36,}\b/ },
  { name: 'GITHUB_PAT', regex: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/ },
  { name: 'AWS_ACCESS_KEY', regex: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'SLACK_TOKEN', regex: /\bxox[baprs]-[0-9a-zA-Z-]{10,}\b/ },
  { name: 'PEM_PRIVATE_KEY', regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/ },
];

export interface DlpScannerOptions {
  readonly fingerprints: readonly SecretFingerprint[];
  readonly canaries?: readonly CanaryHoneytoken[] | undefined;
  readonly outboundByteBudget?: number | undefined;
}

export interface DlpScanInput {
  readonly method: HttpMethod;
  readonly url: string;
  readonly headers: Readonly<Record<string, string | readonly string[] | undefined>>;
  readonly rawBody: Buffer;
  readonly contentEncoding?: string | undefined;
}

export interface DlpScanResult {
  readonly allowed: boolean;
  readonly reason?: DlpViolationReason | undefined;
  readonly matchedRule?: string | undefined;
  readonly canaryTriggered: boolean;
  readonly decompressedBodyText: string;
}

export class MalformedContentEncodingError extends Error {
  constructor(
    public readonly encoding: string,
    message: string,
  ) {
    super(message);
    this.name = 'MalformedContentEncodingError';
  }
}

export class DlpScanner {
  private totalOutboundBytes = 0;

  constructor(private readonly options: DlpScannerOptions) {}

  decompressBody(rawBody: Buffer, contentEncoding?: string | undefined): Buffer {
    if (rawBody.length === 0 || !contentEncoding) {
      return rawBody;
    }

    const encodings = contentEncoding
      .split(',')
      .map((enc) => enc.trim().toLowerCase())
      .filter((enc) => enc.length > 0 && enc !== 'identity')
      .reverse();

    let current = rawBody;
    for (const enc of encodings) {
      if (enc === 'gzip' || enc === 'x-gzip') {
        try {
          current = zlib.gunzipSync(current);
        } catch (err) {
          throw new MalformedContentEncodingError(
            enc,
            `Failed to decompress ${enc} payload: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
      } else if (enc === 'deflate') {
        try {
          current = zlib.inflateSync(current);
        } catch {
          try {
            current = zlib.inflateRawSync(current);
          } catch (err) {
            throw new MalformedContentEncodingError(
              enc,
              `Failed to decompress deflate payload: ${err instanceof Error ? err.message : String(err)}`,
            );
          }
        }
      } else if (enc === 'br') {
        try {
          current = zlib.brotliDecompressSync(current);
        } catch (err) {
          throw new MalformedContentEncodingError(
            enc,
            `Failed to decompress br payload: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
      } else {
        throw new MalformedContentEncodingError(enc, `Unsupported Content-Encoding "${enc}".`);
      }
    }

    return current;
  }

  scanRequest(input: DlpScanInput): DlpScanResult {
    let decompressed: Buffer;
    try {
      decompressed = this.decompressBody(input.rawBody, input.contentEncoding);
    } catch (err) {
      const encoding =
        err instanceof MalformedContentEncodingError
          ? err.encoding
          : (input.contentEncoding ?? 'unknown');
      return {
        allowed: false,
        reason: 'MALFORMED_CONTENT_ENCODING',
        matchedRule: `CONTENT_ENCODING:${encoding}`,
        canaryTriggered: false,
        decompressedBodyText: '',
      };
    }
    const bodyText = decompressed.toString('utf8');

    const decodedUrl = this.decodeUriSafe(input.url);
    const headersText = this.serializeHeaders(input.headers);
    const decodedQueryParts = this.extractDecodedQueryCandidates(input.url);

    const targets = [
      input.url,
      decodedUrl,
      headersText,
      bodyText,
      ...decodedQueryParts,
    ].filter((s) => s.length > 0);

    if (this.options.canaries) {
      for (const canary of this.options.canaries) {
        const patterns = [canary.tokenValue, ...canary.tripwireSubstrings];
        for (const target of targets) {
          for (const pat of patterns) {
            if (pat.length > 0 && target.includes(pat)) {
              return {
                allowed: false,
                reason: 'CANARY_TRIPWIRE_TRIGGERED',
                matchedRule: canary.id,
                canaryTriggered: true,
                decompressedBodyText: bodyText,
              };
            }
          }
        }
      }
    }

    this.totalOutboundBytes += Math.max(input.rawBody.length, decompressed.length);
    if (
      this.options.outboundByteBudget !== undefined &&
      this.totalOutboundBytes > this.options.outboundByteBudget
    ) {
      return {
        allowed: false,
        reason: 'ENTROPY_QUOTA_EXCEEDED',
        matchedRule: 'OUTBOUND_BYTE_BUDGET',
        canaryTriggered: false,
        decompressedBodyText: bodyText,
      };
    }

    for (const fp of this.options.fingerprints) {
      const variants = [
        fp.raw,
        fp.base64,
        fp.base64NoPad,
        fp.base64Url,
        fp.hexLower,
        fp.hexUpper,
        fp.urlEncoded,
      ];
      for (const target of targets) {
        for (const variant of variants) {
          if (variant.length > 0 && target.includes(variant)) {
            return {
              allowed: false,
              reason: 'SECRET_FINGERPRINT_MATCH',
              matchedRule: fp.id,
              canaryTriggered: false,
              decompressedBodyText: bodyText,
            };
          }
        }
      }
    }

    for (const sig of BUILTIN_SECRET_REGEXES) {
      for (const target of targets) {
        if (sig.regex.test(target)) {
          return {
            allowed: false,
            reason: 'REGEX_SIGNATURE_MATCH',
            matchedRule: sig.name,
            canaryTriggered: false,
            decompressedBodyText: bodyText,
          };
        }
      }
    }

    return {
      allowed: true,
      canaryTriggered: false,
      decompressedBodyText: bodyText,
    };
  }

  sanitizeInboundText(text: string): string {
    return text.replace(/[\u{E0000}-\u{E007F}\u200B-\u200D\uFEFF]/gu, '');
  }

  private decodeUriSafe(value: string): string {
    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  }

  private serializeHeaders(
    headers: Readonly<Record<string, string | readonly string[] | undefined>>,
  ): string {
    const parts: string[] = [];
    for (const [k, v] of Object.entries(headers)) {
      if (typeof v === 'string') {
        parts.push(`${k}: ${v}`);
      } else if (Array.isArray(v)) {
        parts.push(`${k}: ${v.join(', ')}`);
      }
    }
    return parts.join('\n');
  }

  private extractDecodedQueryCandidates(rawUrl: string): string[] {
    const qIdx = rawUrl.indexOf('?');
    if (qIdx === -1) {
      return [];
    }
    const query = rawUrl.slice(qIdx + 1);
    const params = new URLSearchParams(query);
    const decoded: string[] = [];

    for (const [, val] of params.entries()) {
      if (val.length >= 6) {
        decoded.push(val);
      }
    }

    return decoded;
  }
}
