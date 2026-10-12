import { describe, it, expect } from 'vitest';
import { Writable } from 'node:stream';
import { pino } from 'pino';
import { REDACT_PATHS, REDACT_CENSOR } from '../src/observability/logging.js';

function randomValue(prefix: string): string {
  return prefix + '-' + Math.random().toString(36).slice(2, 12);
}

function captureLog(obj: Record<string, unknown>): string {
  const chunks: string[] = [];
  const stream = new Writable({
    write(chunk, _enc, cb) {
      chunks.push(chunk.toString());
      cb();
    },
  });
  const testLogger = pino(
    { redact: { paths: [...REDACT_PATHS], censor: REDACT_CENSOR } },
    stream,
  );
  testLogger.info(obj);
  return chunks.join('');
}

describe('log redaction', () => {
  it('redacts authorization header', () => {
    const v = randomValue('hdr');
    const out = captureLog({
      req: { headers: { authorization: 'Bearer ' + v } },
    });
    expect(out).not.toContain(v);
    expect(out).toContain(REDACT_CENSOR);
  });

  it('redacts enrollment token in request body', () => {
    const v = randomValue('enroll');
    const out = captureLog({ req: { body: { token: v } } });
    expect(out).not.toContain(v);
  });

  it('redacts challenge signature', () => {
    const v = randomValue('sig');
    const out = captureLog({ req: { body: { signature: v } } });
    expect(out).not.toContain(v);
  });

  it('redacts ciphertext', () => {
    const v = randomValue('ct');
    const out = captureLog({ req: { body: { ciphertext: v } } });
    expect(out).not.toContain(v);
  });

  it('redacts session_token in request and response', () => {
    const vReq = randomValue('sreq');
    const reqOut = captureLog({ req: { body: { session_token: vReq } } });
    expect(reqOut).not.toContain(vReq);

    const vRes = randomValue('sres');
    const resOut = captureLog({ res: { body: { session_token: vRes } } });
    expect(resOut).not.toContain(vRes);
  });

  it('redacts ack_token', () => {
    const v = randomValue('ack');
    const out = captureLog({ req: { body: { ack_token: v } } });
    expect(out).not.toContain(v);
  });

  it('redacts attestation payload', () => {
    const v = randomValue('att');
    const out = captureLog({ req: { body: { attestation: v } } });
    expect(out).not.toContain(v);
  });

  it('redacts private key variants at any depth', () => {
    const v1 = randomValue('pk1');
    const out1 = captureLog({ private_key: v1 });
    expect(out1).not.toContain(v1);

    const v2 = randomValue('pk2');
    const out2 = captureLog({ privateKey: v2 });
    expect(out2).not.toContain(v2);
  });

  it('redacts password and secret fields', () => {
    const vPass = randomValue('pw');
    const vSec = randomValue('sec');
    const out = captureLog({ password: vPass, secret: vSec });
    expect(out).not.toContain(vPass);
    expect(out).not.toContain(vSec);
  });

  it('does not redact non-sensitive fields', () => {
    const vDev = randomValue('dev');
    const vLabel = randomValue('lbl');
    const out = captureLog({
      req: { body: { device_id: vDev, label: vLabel } },
    });
    expect(out).toContain(vDev);
    expect(out).toContain(vLabel);
  });
});