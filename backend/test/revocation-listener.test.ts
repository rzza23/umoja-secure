import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  createRevocationListener,
  type RevocationClient,
  type RevocationListenerDeps,
} from '../src/ws/revocation.js';

const RECONNECT_DELAY_MS = 5000;

/**
 * Fake pg PoolClient. Implements the RevocationClient structural
 * interface. Tests drive `error` and `end` events via `emit()`.
 */
class FakeRevocationClient implements RevocationClient {
  queries: string[] = [];
  handlers = new Map<string, Array<(arg?: unknown) => void>>();
  released = false;

  async query(sql: string): Promise<unknown> {
    this.queries.push(sql);
    return undefined;
  }

  on(event: string, handler: (arg?: unknown) => void): void {
    const arr = this.handlers.get(event) ?? [];
    arr.push(handler);
    this.handlers.set(event, arr);
  }

  release(): void {
    this.released = true;
  }

  emit(event: string, arg?: unknown): void {
    for (const h of this.handlers.get(event) ?? []) h(arg);
  }
}

interface Harness {
  deps: RevocationListenerDeps;
  connectCalls: () => number;
  reconcileCalls: () => number;
  cancelCalls: () => number;
  lastClient: () => FakeRevocationClient | null;
  failNext: (n: number) => void;
}

function makeHarness(): Harness {
  let connectCount = 0;
  let reconcileCount = 0;
  let cancelCount = 0;
  let failRemaining = 0;
  let last: FakeRevocationClient | null = null;
  const silent = {
    info: () => {},
    warn: () => {},
    error: () => {},
  };
  const deps: RevocationListenerDeps = {
    connect: async () => {
      connectCount++;
      if (failRemaining > 0) {
        failRemaining--;
        throw new Error('connect failed (test)');
      }
      const c = new FakeRevocationClient();
      last = c;
      return c;
    },
    reconcile: async () => {
      reconcileCount++;
      return 0;
    },
    scheduleReconnect: (fn, ms) => setTimeout(fn, ms),
    cancelReconnect: (h) => {
      cancelCount++;
      clearTimeout(h as NodeJS.Timeout);
    },
    onNotification: () => {},
    logger: silent,
  };
  return {
    deps,
    connectCalls: () => connectCount,
    reconcileCalls: () => reconcileCount,
    cancelCalls: () => cancelCount,
    lastClient: () => last,
    failNext: (n) => {
      failRemaining = n;
    },
  };
}

describe('createRevocationListener reconnect + re-reconcile (TASK-P1-042)', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('TEST-REVOCATION-RECONNECT-ON-ERROR', async () => {
    const h = makeHarness();
    h.failNext(1); // first connect throws

    const listener = createRevocationListener(h.deps);
    await listener.start();

    // First connect failed → reconnect scheduled, not yet connected.
    expect(h.connectCalls()).toBe(1);
    expect(listener.isConnected()).toBe(false);
    expect(listener.isReconnectPending()).toBe(true);

    // Advance the delay; second connect succeeds.
    await vi.advanceTimersByTimeAsync(RECONNECT_DELAY_MS);
    expect(h.connectCalls()).toBe(2);
    expect(listener.isConnected()).toBe(true);
    expect(listener.isReconnectPending()).toBe(false);

    await listener.stop();
  });

  it('TEST-REVOCATION-RECONCILES-AFTER-RECONNECT', async () => {
    const h = makeHarness();
    const listener = createRevocationListener(h.deps);

    await listener.start();
    expect(h.connectCalls()).toBe(1);
    // Startup is a connect; reconcile runs on startup's successful connect.
    expect(h.reconcileCalls()).toBe(1);
    expect(listener.isConnected()).toBe(true);

    // Simulate connection loss: pg emits 'error' then 'end'.
    const first = h.lastClient();
    expect(first).not.toBeNull();
    first!.emit('error', new Error('socket error'));
    first!.emit('end');

    expect(listener.isConnected()).toBe(false);
    expect(listener.isReconnectPending()).toBe(true);

    // Advance delay; reconnect succeeds; reconcile fires again.
    await vi.advanceTimersByTimeAsync(RECONNECT_DELAY_MS);
    expect(h.connectCalls()).toBe(2);
    expect(h.reconcileCalls()).toBe(2); // 1 startup + 1 reconnect
    expect(listener.isConnected()).toBe(true);
    expect(listener.isReconnectPending()).toBe(false);

    await listener.stop();
  });

  it('TEST-REVOCATION-STOP-CANCELS-RECONNECT', async () => {
    const h = makeHarness();
    h.failNext(1);

    const listener = createRevocationListener(h.deps);
    await listener.start();
    expect(listener.isReconnectPending()).toBe(true);
    expect(h.cancelCalls()).toBe(0);

    await listener.stop();
    expect(h.cancelCalls()).toBe(1);
    expect(listener.isReconnectPending()).toBe(false);

    // Advancing timers must NOT reconnect: the timer was cancelled.
    await vi.advanceTimersByTimeAsync(RECONNECT_DELAY_MS);
    expect(h.connectCalls()).toBe(1); // still just the initial failed attempt
  });
});
