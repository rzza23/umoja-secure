# ADR-HARDENING-001 — Session lifecycle & release-build hardening

Document ID: ADR-HARDENING-001
Version: 0.1
Date: 2026-10-17
Status: Proposed
Tasks: TASK-P1-038, TASK-P1-039, TASK-P1-040, TASK-P1-041
Related: ADR-PROVISIONING-001, ADR-IDENTITY-CHANGE-001, THREAT-MODEL-001

---

## §1 The invariant

A fielded device must never present a state the user cannot recover from
without losing data or access. Every 401, 403, network failure, and
verification rejection must route the user to one of:

- **Transparent recovery** — silent re-auth, retry succeeded, user sees
  nothing.
- **Retryable state** — "connection lost, retry" with a retry
  affordance.
- **Terminal state with a clear next step** — "device revoked, contact
  admin"; "session invalid, re-enroll."

"No error banner because we don't know what to say" is not an acceptable
state. A path that produces no outcome is a bug in the state machine,
not a case for later.

The invariant is load-bearing for this ADR. Every ruling below is a
consequence of it, not a preference.

---

## §2 Session lifecycle — the state machine

### States

`SessionStateManager` (new class; `SessionManager`'s token storage is
unchanged) exposes:

- `Unauthenticated` — no session token; app not yet started
- `Authenticating` — challenge-response in flight
- `Authenticated(token, expiresAt)` — normal operation
- `Reauthenticating` — 401 received, challenge-response in flight
- `Revoked` — server rejected re-auth with `device_revoked`
- `NetworkFailure` — re-auth failed on transport, retryable
- `EnrollmentRequired` — re-auth rejected with `active` device status
  (backend inconsistency; requires re-enrollment)

### Transitions

- `Unauthenticated` → `Authenticating` on app start
- `Authenticating` → `Authenticated` on success
- `Authenticating` → `NetworkFailure` on transport failure
- `Authenticating` → `Revoked` on `device_revoked`
- `Authenticated` → `Reauthenticating` on any 401 from any API
- `Reauthenticating` → `Authenticated` on success (interceptor retries
  original call)
- `Reauthenticating` → `NetworkFailure` on transport failure
- `Reauthenticating` → `Revoked` on `device_revoked`
- `Reauthenticating` → `EnrollmentRequired` on 401 with `active` status
- `NetworkFailure` → `Authenticating` on user retry
- `Revoked` — terminal
- `EnrollmentRequired` — terminal until user clears and re-enrolls

### Rulings

**Single-flight.** A mutex in `SessionStateManager` ensures concurrent
401s produce one re-auth. Other callers block on the same future and
resume on resolution. Without this, five parallel requests return
401s and trigger five challenge-response pairs; the backend's challenge
consumption (`used = true` on first verify) makes four of them fail
with `unauthorized` for no reason the user caused.

**Recursion guard.** The `/auth/challenge` and `/auth/verify` calls
themselves must not trigger 401 handling. Excluded at the interceptor
layer by URL prefix. Without this, a re-auth that itself 401s recurses
indefinitely.

**Retry-the-original-call.** The interceptor buffers the failed
request, runs re-auth, retries the buffered call once. All Phase 1 APIs
(`AdminApi`, `ContactsApi`, `IdentityChangeApi`) have JSON bodies that
buffer cleanly. `HttpClient`'s response body for the failed call is
discarded — the retry re-executes the full request, not a resumed
response. **If any future streaming API lands, revisit**; Phase 1 has
none.

**Revoked-vs-expired disambiguation — backend change.** Today a 401
from `middleware.ts` (via `lookupSession`) is `unauthorized` for both
an expired session and a revoked device. The client cannot tell them
apart. **[VERIFY AT IMPLEMENTATION]** the exact shape of `lookupSession`;
if it already surfaces device status, both the backend change and the
client's terminal-state routing simplify to a single inspection. If it
does not, the backend gains a `device_revoked` code on the 401 path
when the session's device status is not `active`, mirroring
`auth/verify.ts`'s existing status filter. Precedent exists in the
codebase; the precedent is the ruling.

**App-start expiry check.** If `sessionExpiresAt` is in the past at
`AppRoot` composition, route to `Authenticating` immediately. Not to a
button tap, not to `EnrollmentScreen`. The user shouldn't tap a button
because the app has been closed for 16 hours. If re-auth succeeds →
`Authenticated` (no intermediate state visible). If it fails → the
state machine's terminal states route appropriately.

**[VERIFY AT IMPLEMENTATION] AppRoot's current routing.** The Session
C/D read shows `LaunchedEffect(Unit)` routing on `sessionExpiresAt ==
null`, not `sessionExpiresAt < now()`. A session that expired while
closed lands on `Authenticated` and the first API call 401s. This is
the exact failure mode this ADR closes. The read confirms the gap;
TASK-P1-040 closes it.

### State diagram (ASCII)

    Unauthenticated ─→ Authenticating ─→ Authenticated
                              │              │
                              │              │ any 401
                              ↓              ↓
                        NetworkFailure ← Reauthenticating ─→ Authenticated
                              │              │
                              │ user retry   ├─→ Revoked (terminal)
                              ↓              └─→ EnrollmentRequired (terminal)
                        Authenticating

---

## §3 Release-build hardening — the rulings

### FLAG_SECURE scope

Set on:

- `ChatScreen` — message history, peer identity
- `AdminScreen` — device list, enrollment tokens, contacts
- `DiagnosticsScreen` — matrix paste fields, raw values

Not on:

- `EnrollmentScreen` — the enrollment token is user-entered and
  short-lived; the QR payload is public device keys
- `SettingsScreen` — role display, logout

**[VERIFY AT IMPLEMENTATION]** UI audit to confirm the set is correct
and no additional sensitive surface is missed. The list above is the
proposal; the audit is the ruling.

### Backup

`android:allowBackup="false"` **and** `android:fullBackupContent="false"`
in `AndroidManifest.xml`. Both. The former is the primary guard; the
latter is defence in depth against a future Android behaviour change
or a manifest merge that loses one.

Rationale: `SecureStorage` values are AES-GCM encrypted with a Keystore
key. Android auto-backup carries the prefs file but not the Keystore
key. A restored device has undecryptable prefs. The current code
degrades `SecureStorage.get` to `null` on decrypt failure, which
routes the user to `EnrollmentScreen` — technically recoverable, but
a confusing first-run experience for a user whose only action was a
device upgrade. `allowBackup=false` removes the failure mode.

### TransportConfig immutability

`useTor` must be a `val`. Today it is a `var` (per handoff §6), which
means a contributor can flip it during debugging and forget. In an app
whose entire threat model rests on Tor being mandatory, mutable
transport config is a security regression waiting to happen.

**[VERIFY AT IMPLEMENTATION]** the current shape. If already `val`
with a `BuildConfig.DEBUG` initialization, the criterion is
"verified present." If mutable, converted to `val` initialized from
`BuildConfig.DEBUG ? false : true`.

Startup assertion in `UmojaApplication`: fail closed if `BuildConfig`
says release but `useTor` is somehow `false`. This catches future
regressions where a mutable is reintroduced.

### Minification + libsignal

`minifyEnabled=true` in release. `proguard-rules.pro` must include keep
rules for libsignal's JNI-facing classes and native-loading paths.

**The acceptance test is not "build succeeds"** — minification bugs
surface at cold-start, not build time. The test is: release APK
launches, enrolls, sends one message. Any other test is insufficient.

### `debuggable=false`

AGP 8.x defaults this correctly. Verified explicitly, not assumed.

---

## §4 Send-gating — the verification, not the design

The design is settled by P1-026's KDoc: contacts are a projection of
the verified matrix, the matrix is authority. The question TASK-P1-038
answers is whether `MessagingService.sendMessage` implements that.

**[VERIFY AT IMPLEMENTATION]** the current state of
`MessagingService.sendMessage`. Two possible outcomes:

- **The gate exists.** Add the two regression tests, done. Task
  closes on evidence alone.
- **The gate does not exist.** Add a check before envelope queuing:
  `peerDeviceId ∈ MatrixStore.permittedContacts()`. Reject with a
  distinct error type. UI surfaces "not authorized" — the 030e-c
  blocked-send banner pattern is the precedent for how blocked states
  render.

No new design in either case. The task's first deliverable is
evidence, not code.

---

## §5 Deliberately out of scope

Named so a future session does not expand this into a larger rewrite:

- **Session token rotation.** Bearer tokens with TTL are correct for
  Phase 1. Rotation is a Phase 2 concern.
- **Refresh-token architecture.** Same.
- **Certificate pinning.** Tor is the transport. Pinning certs on
  `.onion` adds nothing.
- **APK obfuscation.** Tor and server-blind are the real defences.
  Minification is for build size and ProGuard effect, not obfuscation.
- **Backend session TTL tuning.** 16h is a Phase 1 ruling. Changing it
  is an ops decision, not a hardening one.
- **Penetration testing.** TASK-P1-024, already filed, separate scope.
- **SBOM.** TASK-P1-027, already filed.
- **Streaming API retry semantics.** No streaming APIs in Phase 1;
  revisit if one lands.
- **APK signing key custody.** Operational, out of Phase 1 scope.

---

## §6 Sequencing rationale

**Order:** TASK-P1-038 → TASK-P1-039 → TASK-P1-040 → TASK-P1-041.

**038 first.** The one task that might reveal a hole rather than require
new code. If it does, the hole is a security gap that changes what else
is urgent. If it doesn't, it is the smallest possible task — two tests
and a commit. Either outcome is valuable before doing anything else.

**039 second.** Mechanical, independent of 038 and 040. Closing obvious
gaps before field testing means field testing starts closer to reality.
If 039's minification work reveals libsignal fragility, that is better
discovered before 040's state-machine changes add surface.

**040 last.** Largest; needs the ADR state machine implemented and the
backend dependency resolved. Benefits from 039 having verified the
release path works, so manual on-device testing of 040 is not
compounded with minification debugging.

**041 deferred.** Diagnostic, not blocking. Benefits from being
implemented after 040, since 040 establishes the state manager that
verification failures log into.

---

## §7 What this ADR does not decide

Each item is either a future task, a Phase 2 concern, or a code read
that belongs to the task it is contingent on:

- **Whether the send gate exists** — TASK-P1-038's first deliverable
  is evidence.
- **Whether `lookupSession` distinguishes revoked from expired** —
  TASK-P1-040's backend dependency, read at implementation start.
- **Whether `minifyEnabled` breaks libsignal** — TASK-P1-039's smoke
  test proves it, not pre-emptive ProGuard rules.
- **Whether FLAG_SECURE's proposed scope is complete** — TASK-P1-039's
  UI audit.
- **Whether new instrumentation tests are needed** — all three tasks'
  tests as proposed are JVM unit tests plus manual verification. If
  any manual verification would benefit from instrumentation, that is
  a test-infrastructure decision, not a hardening one.

---

## §8 Approval

Approval on disk (repository commit) is the operative approval for
this design. Amendments require version bump and rationale in §9.

---

## §9 Open questions

None blocking. Any that arise during implementation get resolved in
this ADR rather than in code comments or chat.
