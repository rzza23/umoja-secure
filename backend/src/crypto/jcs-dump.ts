/**
 * Cross-check dump: reads the JCS conformance corpora, canonicalizes each
 * input with the TS reference implementation, and writes
 * {id}\t{base64(canonical)} lines to stdout, sorted by id.
 *
 * The Kotlin side produces the same shape from the same inputs.
 * scripts/jcs-cross-check.sh diffs the two.
 *
 * Rejections emit "REJECT:<message>" in place of the base64 field.
 *
 * Usage:
 *   cd backend && npx tsx src/crypto/jcs-dump.ts
 *
 * Task: TASK-P1-026
 * Closes: KI-012
 */
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { jcsCanonicalize, JcsError } from './jcs.js';

function findRepoRoot(): string {
  let dir = process.cwd();
  for (let i = 0; i < 12; i++) {
    if (existsSync(join(dir, 'UMOJA-SECURE-BUILD-MASTER.md'))) return dir;
    const parent = join(dir, '..');
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error('could not find repo root');
}

const ROOT = findRepoRoot();

interface Entry {
  id: string;
  value: unknown;
}

function loadCyberphone(): Entry[] {
  const dir = join(ROOT, 'docs/reference/jcs-conformance/input');
  const names = readdirSync(dir).filter((n) => n.endsWith('.json')).sort();
  return names.map((name) => ({
    id: `cyberphone:${name.replace(/\.json$/, '')}`,
    value: JSON.parse(readFileSync(join(dir, name), 'utf8')),
  }));
}

function loadUmojaWrappers(): Entry[] {
  const path = join(ROOT, 'docs/reference/canonical-matrix-test-vectors.json');
  const doc = JSON.parse(readFileSync(path, 'utf8')) as {
    vectors: Array<{ id: string; input_wrapper?: unknown }>;
  };
  const out: Entry[] = [];
  for (const v of doc.vectors) {
    if (v.input_wrapper !== undefined) {
      out.push({ id: `umoja:${v.id}`, value: v.input_wrapper });
    }
  }
  return out;
}

function loadRfcNumbers(): Entry[] {
  const path = join(ROOT, 'docs/reference/rfc8785-number-samples.json');
  const doc = JSON.parse(readFileSync(path, 'utf8')) as {
    samples: Array<{ ieee754_hex: string }>;
  };
  return doc.samples.map((s) => {
    const buf = Buffer.from(s.ieee754_hex, 'hex');
    return { id: `rfc:${s.ieee754_hex}`, value: buf.readDoubleBE(0) };
  });
}

const entries: Entry[] = [
  ...loadCyberphone(),
  ...loadUmojaWrappers(),
  ...loadRfcNumbers(),
];

const lines: string[] = [];
for (const e of entries) {
  let result: string;
  try {
    result = jcsCanonicalize(e.value).toString('base64');
  } catch (err) {
    if (err instanceof JcsError) {
      result = `REJECT:${err.message}`;
    } else {
      throw err;
    }
  }
  lines.push(`${e.id}\t${result}`);
}
lines.sort();
process.stdout.write(lines.join('\n') + '\n');
