/**
 * RFC 8785 JCS conformance tests.
 *
 * Two corpora:
 *   1. RFC 8785 Appendix B number samples (24 samples).
 *   2. cyberphone json-canonicalization corpus (6 input/output pairs).
 *
 * Plus negative self-tests for inputs JCS must reject.
 *
 * Ground truth lives in docs/reference/. Do not edit the corpora to make
 * a test pass — fix the canonicalizer.
 *
 * Task: TASK-P1-026
 * Build Master: §3.8
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import { jcsCanonicalizeString, JcsError } from './jcs.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, '../../..');

const NUMBER_SAMPLES_PATH = join(REPO_ROOT, 'docs/reference/rfc8785-number-samples.json');
const CORPUS_INPUT_DIR = join(REPO_ROOT, 'docs/reference/jcs-conformance/input');
const CORPUS_OUTPUT_DIR = join(REPO_ROOT, 'docs/reference/jcs-conformance/output');

function ieeeHexToDouble(hex: string): number {
  // 16 hex chars = 8 bytes, big-endian, IEEE 754 double.
  return Buffer.from(hex, 'hex').readDoubleBE(0);
}

describe('RFC 8785 Appendix B number samples', () => {
  const raw = JSON.parse(readFileSync(NUMBER_SAMPLES_PATH, 'utf8')) as {
    samples: Array<{ ieee754_hex: string; expected_serialization: string; comment: string }>;
  };

  for (const sample of raw.samples) {
    const label = sample.comment
      ? `${sample.ieee754_hex} (${sample.comment})`
      : sample.ieee754_hex;
    it(`serializes ${label} as ${JSON.stringify(sample.expected_serialization)}`, () => {
      const d = ieeeHexToDouble(sample.ieee754_hex);
      expect(jcsCanonicalizeString(d)).toBe(sample.expected_serialization);
    });
  }
});

describe('cyberphone JCS conformance corpus', () => {
  const files = readdirSync(CORPUS_INPUT_DIR).sort();
  for (const name of files) {
    it(`canonicalizes ${name} to the expected output byte-for-byte`, () => {
      const inputRaw = readFileSync(join(CORPUS_INPUT_DIR, name), 'utf8');
      const expected = readFileSync(join(CORPUS_OUTPUT_DIR, name), 'utf8');
      const parsed = JSON.parse(inputRaw) as unknown;
      const got = jcsCanonicalizeString(parsed);
      expect(got).toBe(expected);
    });
  }
});

describe('JCS rejects invalid inputs', () => {
  it('rejects NaN', () => {
    expect(() => jcsCanonicalizeString(NaN)).toThrow(JcsError);
  });

  it('rejects Infinity', () => {
    expect(() => jcsCanonicalizeString(Infinity)).toThrow(JcsError);
  });

  it('rejects -Infinity', () => {
    expect(() => jcsCanonicalizeString(-Infinity)).toThrow(JcsError);
  });

  it('rejects undefined', () => {
    expect(() => jcsCanonicalizeString(undefined)).toThrow(JcsError);
  });

  it('rejects BigInt', () => {
    expect(() => jcsCanonicalizeString(BigInt(1))).toThrow(JcsError);
  });

  it('rejects functions', () => {
    expect(() => jcsCanonicalizeString(() => {})).toThrow(JcsError);
  });

  it('rejects symbols', () => {
    expect(() => jcsCanonicalizeString(Symbol('x'))).toThrow(JcsError);
  });

  it('rejects sparse arrays', () => {
    // eslint-disable-next-line no-sparse-arrays
    expect(() => jcsCanonicalizeString([1, , 3])).toThrow(JcsError);
  });

  it('rejects objects with a toJSON method', () => {
    const withToJSON = { toJSON: () => ({}) };
    expect(() => jcsCanonicalizeString(withToJSON)).toThrow(JcsError);
  });

  it('rejects objects that contain a nested undefined value', () => {
    expect(() => jcsCanonicalizeString({ a: undefined })).toThrow(JcsError);
  });
});

describe('JCS behavior spot checks', () => {
  it('sorts object keys by UTF-16 code unit order', () => {
    expect(jcsCanonicalizeString({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });

  it('preserves array order', () => {
    expect(jcsCanonicalizeString([3, 1, 2])).toBe('[3,1,2]');
  });

  it('collapses -0 to 0', () => {
    expect(jcsCanonicalizeString(-0)).toBe('0');
  });

  it('emits 1e21 with a plus sign in the exponent', () => {
    expect(jcsCanonicalizeString(1e21)).toBe('1e+21');
  });

  it('rejects a bare JSON number is not tested here (JCS takes parsed values)', () => {
    // Placeholder for the reader: JCS is defined over parsed values. If
    // you need to reject duplicate keys, do so at the JSON.parse stage
    // (see the note in docs/reference/canonical-matrix-test-vectors.json
    // vector N-001).
    expect(true).toBe(true);
  });
});
