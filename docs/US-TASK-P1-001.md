# US-TASK-P1-001-v0.8 — Phase 1 Task Registry Reconciliation

Document ID: US-TASK-P1-001
Version: 0.8
Date: October 2026
Supersedes: v0.7
Purpose: Reconcile the Phase 1 task registry with UMOJA-SECURE-BUILD-MASTER.md v1.4.2.
Authority: Derived from US-MASTER-001 + US-ADD-001. Cannot override them.

---

## §A — NEW TASKS

### TASK-P1-027a: SBOM + dependency review, per-session execution

**Phase:** 1
**Priority:** Medium
**Dependencies:** TASK-P1-013 (backend stack; SBOM tooling originated there)
**Security classification:** Internal

**Objective and non-goals:**
- Execute the dependency review each time the lockfile changes:
  generate SBOM, run audit, refresh dep-tree snapshot, document
  findings.
- Fix high/critical CVEs or document them as exceptions per Build
  Master §6 (CVE, rationale, mitigation, owner, expiry ≤90 days).
- Maintain `docs/security/DEPENDENCY-REVIEW.md` as the running
  review record: inventory, method, findings log, cadence.
- Produce `artifacts/dep-tree.json` snapshot on each lockfile change
  (Build Master §6 step 3).
- Do NOT add CI (that is TASK-P1-027b). Do NOT silence warnings via
  `// eslint-disable`, `.npmrc` overrides, or `npm audit --omit`
  flags (Build Master §6 explicit prohibition). Do NOT add
  Android-side tooling (also 027b).

**Acceptance criteria:**
- [ ] SBOM generated via `npm run sbom`; parse for prohibited runtime
      packages (Build Master §11 list) shows zero matches.
- [ ] `npm audit --audit-level=high` run; high/critical findings
      fixed or documented in `DEPENDENCY-EXCEPTIONS.md` §1.
- [ ] `artifacts/dep-tree.json` regenerated when `package-lock.json`
      changes; reviewed for prohibited packages, unresolved
      versions, new dependencies.
- [ ] `docs/security/DEPENDENCY-REVIEW.md` maintained (inventory,
      method, findings log, cadence).
- [ ] Every finding classified: fix / exception / observed-not-defect
      / deferred-to-027b.

**Required tests:**
- TEST-DEP-REVIEW-SBOM-PROHIBITED-CLEAN (per-invocation check, not
  a committed test file)
- TEST-DEP-REVIEW-AUDIT-CLEAN (per-invocation check)

**Status:** Executed 2026-10-19 (first pass at `9a1173e`; ws CVE
fixed; artifacts/ created; review doc written; §1 resolved entry
added)

---

### TASK-P1-027b: CI enforcement gate for dependency review

**Phase:** 1
**Priority:** Medium
**Dependencies:** TASK-P1-027a (recommended before this); CI provider decision
**Security classification:** Internal

**Objective and non-goals:**
- Automate Build Master §6's gate in a CI pipeline. Currently the
  gate is enforceable only as manual human review because the repo
  has no CI.
- Per-PR: generate SBOM, run `npm audit --audit-level=high` (block on
  high/critical), check SBOM against prohibited-package list, parse
  `./gradlew :app:dependencies --configuration releaseRuntimeClasspath`
  for the same list on Android, attach SBOM + dep-tree to PR.
- Do NOT bake a specific CI provider into this section's acceptance
  until the provider is chosen. Do NOT attempt the Android build
  workflow before the backend workflow is proven on the same
  pipeline (staged rollout).
- Do NOT weaken Build Master §6's manual requirements (the CI gate
  supplements, does not replace, human triage).

**Acceptance criteria:**
- [ ] CI provider chosen and documented (ADR or this section amendment).
- [ ] Backend workflow: SBOM + audit + dep-tree diff; PR blocked on
      high/critical or prohibited package.
- [ ] Android workflow: gradle dependencies parse + prohibited-package
      check.
- [ ] SBOM and dep-tree attached to PR as build artifacts.
- [ ] End-to-end verified on a throwaway branch (both a clean pass
      and a deliberately-failing case).

**Required tests:**
- TEST-CI-PROHIBITED-BLOCKED
- TEST-CI-HIGH-CVE-BLOCKED
- TEST-CI-CLEAN-PASSES
- TEST-ANDROID-DEP-PARSE

**Status:** Blocked on CI provider decision (project-level)

### TASK-P1-033: Offline provisioning-key signing workflow

**Phase:** 1
**Priority:** Critical
**Dependencies:** TASK-P1-025, TASK-P1-026, TASK-P1-029
**Security classification:** Internal

**Objective and non-goals:**
- Implement the offline signing workflow described in Build Master §3.6.
- Admin app collects the matrix, canonicalizes per RFC 8785 JCS, computes SHA-256 of canonical bytes.
- Admin transfers matrix hash and content to an offline signing device via QR or physical medium.
- Offline signing device re-canonicalizes, confirms hash match, displays matrix for human confirmation, signs the 32-byte SHA-256 digest with Ed25519 (per §3.8), and returns the signature.
- Admin app attaches the signature and pushes the signed matrix.
- Do NOT allow the admin app to hold the provisioning private key or sign the matrix.

**Acceptance criteria:**
- [ ] Admin app never has access to the provisioning private key.
- [ ] Admin app computes the same canonical hash as the signing device.
- [ ] Offline signing device displays matrix content and hash before signing.
- [ ] Human confirms on the signing device before signing occurs.
- [ ] Signature verifies on receiving device against pinned public key.
- [ ] Signing protocol matches §3.8 exactly: Ed25519 over SHA-256 of JCS-canonical bytes.
- [ ] Tampered matrix (any byte changed after signing) rejected.
- [ ] Workflow documents supported offline signing devices.
- [ ] Key rotation procedure (new key + overlap window) documented and tested.
- [ ] Key revocation procedure (authorized by recovery key per §3.6) documented and tested.

**Required tests:**
- TEST-PROVSIGN-001: End-to-end signing workflow completes.
- TEST-PROVSIGN-002: Tampered matrix rejected.
- TEST-PROVSIGN-003: Admin app has no write access to provisioning key.
- TEST-PROVSIGN-004: Rotation produces new key; old key accepted in overlap window.
- TEST-PROVSIGN-005: Revoked key rejected.
- TEST-PROVSIGN-006: Human confirmation required on signing device.
- TEST-PROVSIGN-007: Offline signer and Android verifier produce identical intermediate values (canonical bytes, SHA-256 digest, Ed25519 signature) for all test vectors.

**Status:** Proposed

---

### TASK-P1-034: Hardware-backed Ed25519 Keystore verification

**Phase:** 1
**Priority:** Critical
**Dependencies:** TASK-P1-003
**Security classification:** Internal

**Objective and non-goals:**
- Verify each supported Pixel model and GrapheneOS version provides hardware-backed (TEE-level) Ed25519 keys in Android Keystore.
- Test StrongBox separately; StrongBox is NOT required.
- If TEE-backed Ed25519 unavailable on a supported device, STOP and escalate.

**Acceptance criteria:**
- [ ] Procedure documented in `docs/device/KEYSTORE-CAPABILITIES.md`.
- [ ] On each supported model + GrapheneOS version, Ed25519 key generated without StrongBox; `KeyInfo.getSecurityLevel()` reports TEE or higher.
- [ ] Sign/verify succeeds with TEE backing.
- [ ] Key is non-exportable.
- [ ] Key persists across reboot.
- [ ] StrongBox tested separately; result recorded. Not required.
- [ ] `FEATURE_HARDWARE_KEYSTORE` version ≥ 200 recorded but treated as necessary-not-sufficient.
- [ ] Results recorded per device model + OS version.
- [ ] Failures require removal from supported list or documented exception.

**Required tests:**
- TEST-KEYSTORE-001: TEE-backed Ed25519 generation succeeds.
- TEST-KEYSTORE-002: Sign/verify cycle succeeds with TEE backing.
- TEST-KEYSTORE-003: Key export fails.
- TEST-KEYSTORE-004: Key persists across reboot.
- TEST-KEYSTORE-005: Test matrix covers all supported devices.
- TEST-KEYSTORE-006: `getSecurityLevel()` reports TEE or higher.
- TEST-KEYSTORE-007: StrongBox result recorded separately.

**Status:** Proposed

---

### TASK-P1-035: Organization recovery key generation, custody, and revocation workflow

**Phase:** 1
**Priority:** Critical
**Dependencies:** TASK-P1-025, TASK-P1-026, TASK-P1-029, TASK-P1-033
**Security classification:** Internal

**Objective and non-goals:**
- Generate a distinct Ed25519 organization recovery keypair, independent of the provisioning key.
- Pin recovery public key on every device at provisioning.
- Implement recovery-key-authorized revocation workflow for the provisioning key.
- Implement recovery key rotation with monotonic version enforcement.
- Document recovery key compromise → physical re-provisioning.
- Do NOT use provisioning key to authorize its own revocation.
- Do NOT store recovery private key on admin app or any online device.

**Acceptance criteria:**
- [ ] Recovery keypair generated via documented ceremony.
- [ ] Public key pinned on every device at provisioning.
- [ ] `key_revocation` message includes `recovery_key_version` (monotonic).
- [ ] Revocation workflow implemented and tested.
- [ ] Rotation workflow implemented and tested.
- [ ] Out-of-order recovery notices rejected (`version ≤ highest_recovery_key_version`).
- [ ] Conflicting notices at same version: first accepted, subsequent rejected.
- [ ] Recovery key compromise documented as requiring physical re-provisioning.
- [ ] Audit events written for all recovery operations.

**Required tests:**
- TEST-RECKEY-001: Recovery keypair generates a valid Ed25519 key.
- TEST-RECKEY-002: Provisioning key revocation signed by recovery key accepted.
- TEST-RECKEY-003: Provisioning key self-revocation rejected.
- TEST-RECKEY-004: Provisioning key rotation signed by recovery key accepted.
- TEST-RECKEY-005: Recovery key rotation signed by current recovery key accepted.
- TEST-RECKEY-006: Recovery key rollback rejected.
- TEST-RECKEY-007: Post-revocation matrix signed by revoked provisioning key rejected.
- TEST-RECKEY-008: New matrix signed by new provisioning key accepted.
- TEST-RECKEY-009: Out-of-order recovery notice rejected.
- TEST-RECKEY-010: Conflicting same-version notices: second rejected.

**Status:** Proposed

### TASK-P1-036: Provisioning-key rotation and recovery-key revocation notice handling

**Phase:** 1
**Priority:** Critical
**Dependencies:** TASK-P1-026, TASK-P1-029, TASK-P1-033, TASK-P1-035
**Security classification:** Internal

**Objective and non-goals:**
- Handle two client-side notice types: `key_rotation` and
  `key_revocation`.
- `key_rotation`: signed by the current provisioning key. On receipt,
  store the new key as `previous_provisioning_pubkey` and open the
  overlap window during which both keys are trusted for matrix
  verification.
- `key_revocation`: signed by the recovery key. On receipt, revoke the
  specified provisioning key; reject matrices signed by it after the
  revocation is processed.
- Enforce monotonic `recovery_key_version`: reject notices with
  `version <= highest_recovery_key_version`.
- P1-026 shipped the seams: `previous_provisioning_pubkey` and
  `highest_recovery_key_version` SecureStorage keys exist but are
  never written; `verifyMatrix` takes `Set<PublicKey>`. This task
  implements the handlers.
- Per ADR-PROVISIONING-001 §3.6 (rotation ceremony) and §3.7
  (recovery-key authorization).
- Do NOT implement the key custody ceremony (TASK-P1-029,
  TASK-P1-035 own that). Do NOT implement notice transport.

**Acceptance criteria:**
- [ ] `key_rotation` handler verifies signature against
      `current_provisioning_pubkey`; on success, sets
      `previous_provisioning_pubkey = current_provisioning_pubkey`,
      `current_provisioning_pubkey = new_key`, opens overlap window of
      documented duration.
- [ ] During overlap: matrices signed by either key accepted.
- [ ] After overlap closes: previous key no longer trusted.
- [ ] `key_revocation` handler verifies signature against
      `recovery_pubkey`; on success, records revoked key, rejects
      matrices signed by it after the revocation is processed.
- [ ] Monotonic `recovery_key_version`: `version <=
      highest_recovery_key_version` → reject, no state change.
- [ ] Overlap window duration documented in ADR or KDoc, not a
      hardcoded magic number.
- [ ] Fail-closed: rotation notice arriving before handler exists is
      ignored; `previous_provisioning_pubkey` stays absent — no silent
      acceptance.

**Required tests:**
- TEST-ROTATION-ACCEPT-CURRENT-KEY-MATRIX
- TEST-ROTATION-ACCEPT-PREVIOUS-KEY-DURING-OVERLAP
- TEST-ROTATION-REJECT-PREVIOUS-KEY-AFTER-OVERLAP
- TEST-ROTATION-REJECT-BAD-SIGNATURE
- TEST-REVOCATION-ACCEPT-AFTER-RECOVERY-KEY-SIGNED-NOTICE
- TEST-REVOCATION-REJECT-MATRIX-AFTER-REVOCATION
- TEST-REVOCATION-ROLLBACK-REJECTED

**Status:** Proposed

---

### TASK-P1-037: Matrix transport

**Phase:** 1
**Priority:** High
**Dependencies:** TASK-P1-026, TASK-P1-033
**Security classification:** Internal

**Objective and non-goals:**
- Implement the delivery channel for signed matrices from the offline
  signer to enrolled devices.
- Backend: `GET /me/matrix` returns the current signed matrix for the
  caller's `device_id` (per-device, since each matrix binds to a
  specific device).
- Client: fetch on app start (in `Authenticated` state) and on-demand;
  verify against pinned provisioning key; feed to
  `MatrixStore.accept()`.
- Authority comes from the signature and the pinned key, not the
  transport (THREAT-MODEL-001 §7, ADR-PROVISIONING-001 §2 Q3). HTTP is
  chosen for operational simplicity, not security necessity.
- Blocks TASK-P1-030f (integrated test steps 5 and 7 push a matrix to a
  device).
- Do NOT replace the signature-based trust model. Do NOT add
  push-notification (polling suffices for Phase 1).

**Acceptance criteria:**
- [ ] Backend `GET /me/matrix` returns
      `{canonical_utf8, signature_base64url}` for caller's `device_id`
      only.
- [ ] Route-level tests: returns caller's matrix, rejects cross-device
      requests, 404 when no matrix exists for the device.
- [ ] Client `MatrixApi.fetch(sessionToken)` in `transport/`.
- [ ] On `Authenticated` state entry: fetch and call
      `MatrixStore.accept()`.
- [ ] Verification failure on fetch does NOT crash; logs and continues
      (existing matrix remains valid).
- [ ] Unblocks TASK-P1-030f integration test.

**Required tests:**
- TEST-MATRIX-TRANSPORT-FETCH
- TEST-MATRIX-TRANSPORT-CROSS-DEVICE-REJECTED
- TEST-MATRIX-TRANSPORT-VERIFY-ON-RECEIPT
- TEST-MATRIX-TRANSPORT-STORE-ON-VERIFY-SUCCESS

**Status:** Proposed

---

### TASK-P1-038: Send-path matrix enforcement verification

**Phase:** 1
**Priority:** Critical
**Dependencies:** TASK-P1-026, TASK-P1-007
**Security classification:** Internal

**Objective and non-goals:**
- Verify that `MessagingService.sendMessage` gates outbound sends on the
  client-side accepted matrix's `permitted_contacts`. The P1-026 KDoc
  records the design intent ("contacts are a projection of the verified
  matrix, not a trust source") but the enforcement path has not been
  verified. **[VERIFY AT IMPLEMENTATION]** whether the gate exists.
- If the gate exists: add regression tests proving it holds.
- If the gate is missing: implement it in `MessagingService.sendMessage`,
  with a distinct error type and a UI treatment matching the 030e-c
  blocked-send banner pattern.
- Do NOT redesign the send path. Do NOT touch `ContactsApi`. Do NOT
  re-litigate the matrix-as-authority ruling.

**Acceptance criteria:**
- [ ] Evidence recorded: either "gate exists at [file:line], tests
      confirm" or "gate missing, implementation applied, tests confirm."
- [ ] `TEST-SEND-GATE-EXCLUDED-PEER` — peer not in `permitted_contacts`
      rejected before envelope queuing.
- [ ] `TEST-SEND-GATE-PERMITTED-PEER` — allowed path still works
      end-to-end.
- [ ] No regression in existing send-path behaviour.

**Required tests:**
- TEST-SEND-GATE-EXCLUDED-PEER
- TEST-SEND-GATE-PERMITTED-PEER

**Status:** Proposed

---

### TASK-P1-039: Release-build hardening

**Phase:** 1
**Priority:** Critical
**Dependencies:** TASK-P1-013, TASK-P1-014
**Security classification:** Internal

**Objective and non-goals:**
- Close release-build hygiene gaps that make a fielded APK unsafe or
  unusable when screenshotted, restored from backup, minified, or run
  with a misconfigured transport.
- Each criterion is **verification-first**: read current state, close if
  open, mark complete if already present. Do NOT add what already
  exists.
- Do NOT add obfuscation, certificate pinning, or Play Protect
  compatibility.

**Acceptance criteria:**
- [ ] `FLAG_SECURE` set on `ChatScreen`, `AdminScreen`,
      `DiagnosticsScreen`. **[VERIFY AT IMPLEMENTATION]** — UI audit to
      confirm the screen set is correct and no additional sensitive
      surface is missed.
- [ ] `android:allowBackup="false"` and `android:fullBackupContent="false"`
      in `AndroidManifest.xml`.
- [ ] `minifyEnabled=true` in release `buildTypes`, ProGuard rules
      verified against libsignal cold-start.
- [ ] `debuggable=false` in release (explicit, not AGP-default assumed).
- [ ] `TransportConfig.useTor` cannot be `false` in release. If
      already enforced, verified present. If mutable, converted to
      `val` initialized from `BuildConfig.DEBUG`. **[VERIFY AT
      IMPLEMENTATION]**
- [ ] Release APK built, installed on emulator, completes smoke path:
      launch, enroll, chat, send, receive.

**Required tests:**
- TEST-RELEASE-SCREENSHOT-BLOCKED (manual: `adb shell screencap` on a
  secured screen returns black or fails)
- TEST-RELEASE-BACKUP-DISABLED (manual: `adb backup` returns no app
  data)
- TEST-RELEASE-MINIFIED-SMOKE (manual: install release APK, cold-start,
  enroll, send)
- TEST-RELEASE-TOR-MANDATORY (unit: `TransportConfig` with
  `useTor=false` in release build throws or routes to fatal screen)

**Status:** Proposed

---

### TASK-P1-040: Session lifecycle & revocation UX

**Phase:** 1
**Priority:** Critical
**Dependencies:** TASK-P1-014, TASK-P1-020
**Security classification:** Internal

**Objective and non-goals:**
- Close the two session-failure paths that strand a fielded user:
  expired-session 401s with no recovery, and revoked-device 401s
  indistinguishable from expiry. The two are one state machine, not two
  fixes.
- Do NOT add session token rotation. Do NOT add refresh-token
  architecture. Do NOT change session TTL (16h is a Phase 1 ruling).
- Do NOT re-review `lookupSession`'s filter (covered by
  `TEST-ACK-REVOKED-DEVICE`).

**Backend dependency (in scope for this task).**
- The client cannot distinguish "expired" from "revoked" from a plain
  401 today. **[VERIFY AT IMPLEMENTATION]** the exact shape of
  `lookupSession`'s rejection path. Add a distinct error code
  (`device_revoked`) to 401 responses when `status != 'active'`.
  Backend change precedes the client state machine in the same session.

**Acceptance criteria (per ADR-HARDENING-001 §2):**
- [ ] 401 from any API → one challenge-response re-auth, retried once,
      transparent to the user.
- [ ] Concurrent 401s → exactly one re-auth attempt (single-flight
      mutex).
- [ ] Re-auth rejected with `device_revoked` → `AppScreen.Revoked`,
      terminal, clear messaging, no retry loop.
- [ ] Re-auth fails on transport → "connection lost, retry" state, not
      "auth error."
- [ ] Re-auth 401 with `active` device status (backend inconsistency,
      should be impossible) → `AppScreen.EnrollmentRequired`.
- [ ] App-start: `sessionExpiresAt` in the past → silent re-auth, not a
      button tap.
- [ ] Documented state diagram in the ADR shows every terminal and
      non-terminal state.

**Required tests:**
- TEST-SESSION-EXPIRED-AUTO-REAUTH (JVM: mock 401, assert challenge →
  verify → retry)
- TEST-SESSION-CONCURRENT-401-SINGLE-REAUTH (JVM: 5 parallel 401s,
  assert 1 re-auth)
- TEST-SESSION-REVOKED-TERMINAL (JVM: 401 with `device_revoked`,
  assert Revoked state, no retry)
- TEST-SESSION-NETWORK-DURING-REAUTH (JVM: re-auth network failure,
  assert retryable state)
- TEST-SESSION-APP-START-EXPIRED (manual: force expiry to past, launch
  app, observe silent re-auth)
- TEST-SESSION-REVOKED-ON-DEVICE (manual: revoke via admin, wait for
  next API call, observe terminal screen)

**Status:** Proposed

---

### TASK-P1-041: Failed-verification operator logging

**Phase:** 1
**Priority:** Medium
**Dependencies:** TASK-P1-026, TASK-P1-030
**Security classification:** Internal

**Objective and non-goals:**
- Local, user-diagnostics-visible log of verification failures (matrix
  rejected, notice rejected, ack POST rejected). Operator investigating
  "did my peer receive this" has a client-side signal.
- Do NOT add backend logs. Do NOT add telemetry. Do NOT extend the
  server-side audit.
- Deferred from the initial hardening pass; filed for the
  operator-facing story, not blocking fieldable.

**Acceptance criteria:**
- [ ] On signature verification failure, a local entry is recorded:
      timestamp, artifact type, reason code, truncated canonical bytes.
- [ ] `DiagnosticsScreen` surfaces the last N entries.
- [ ] Entries are cleared by the corresponding store's `clear()`
      (matrix-store wipe clears matrix-failure log; notice-store wipe
      clears notice-failure log).

**Required tests:**
- TEST-DIAG-VERIFICATION-FAILURE-LOGGED
- TEST-DIAG-VERIFICATION-LOG-CLEARED-ON-WIPE

**Status:** Proposed — deferred from initial hardening pass

---

### TASK-P1-042: WS revocation listener reconnect + re-reconcile

**Phase:** 1
**Priority:** Medium
**Dependencies:** TASK-P1-040
**Security classification:** Internal

**Objective and non-goals:**
- Close AUTH-SPEC-001 §9.3 defense (2) gap identified in the
  2026-10-18 conformance sweep. The `ws/revocation.ts` listener is a
  single `LISTEN device_revoked` connection. On connection error, the
  listener logs the error and does not reconnect. The reconciliation
  pass (`reconcileRevokedDevices`) runs only at process startup, not
  on listener reconnect. A revocation that lands during the
  listener-disconnected window closes on the next 5-minute
  revalidation cycle, not within the ≤5s guarantee.
- Do NOT change the notification payload or channel name. Do NOT
  touch the 5-minute revalidation cycle (current backstop; remains
  in place).
- Do NOT introduce a second LISTEN connection or a Pub/Sub
  replacement. The fix is a reconnect + re-reconcile loop on the
  same single connection.

**Acceptance criteria:**
- [ ] On `LISTEN` connection error, the listener schedules a bounded
      reconnect (fixed interval or exponential backoff; implementation
      choice) without restarting the backend process.
- [ ] On successful reconnect, `reconcileRevokedDevices()` runs before
      the listener resumes consuming notifications, so any revocation
      that landed during the gap closes active connections immediately.
- [ ] `stopRevocationListener()` cancels any pending reconnect so the
      process shuts down cleanly.
- [ ] AUTH-SPEC-001 §9.3 is amended (v0.3) to describe the
      reconnect-and-reconcile behavior. The v0.2 amendment
      (2026-10-18) states the current startup-only behavior; this
      task closes that stated gap.

**Required tests:**
- TEST-REVOCATION-RECONNECT-ON-ERROR
- TEST-REVOCATION-RECONCILES-AFTER-RECONNECT
- TEST-REVOCATION-STOP-CANCELS-RECONNECT

**Status:** DONE — fixed at commit 07cc2b4 (2026-10-18). WS revocation listener reconnects on connection loss (5s fixed interval); reconciles on every successful connect; stop() cancels pending reconnect. Three named tests pass (TEST-REVOCATION-RECONNECT-ON-ERROR, -RECONCILES-AFTER-RECONNECT, -STOP-CANCELS-RECONNECT). Three docs (AUTH-SPEC-001 §9.3, THREAT-MODEL-001 §8, US-MASTER-001 §3.5) amended to v0.3 referencing this commit.

---

## §B — UPDATED TASKS

### TASK-P1-004 — Extended

Add to acceptance criteria:
- [ ] Hardware-backed Ed25519 verification (TASK-P1-034) completed for target device model.
- [ ] GrapheneOS duress feature verified (requires both duress PIN and duress password; trigger wipes device on target OS version).

### TASK-P1-005 — libsignal integration

**Objective:**
- Integrate `org.signal:libsignal-android` (native AAR, AGPLv3) and `org.signal:libsignal-client` (Java client).
- Pin exact version (Maven latest: 0.86.5; review upstream 0.99.3 and Signal-Android's 0.94.0 before pinning).
- Document AGPLv3 implications.
- Document JNI/Rust integration path.
- Provide a JVM wrapper hiding libsignal specifics.
- Do NOT use `@signalapp/libsignal-client` (npm package).
- Do NOT substitute a different crypto library without escalation.

**Acceptance criteria:**
- [ ] Both artifacts pinned in `android/app/build.gradle.kts`.
- [ ] AGPLv3 implications documented in `docs/legal/AGPL-NOTICE.md`.
- [ ] JNI/Rust path documented in `docs/crypto/LIBSIGNAL-INTEGRATION.md`.
- [ ] Version review in `docs/crypto/LIBSIGNAL-REVIEW.md`.
- [ ] Wrapper exposes only Umoja-domain types; no file outside wrapper imports `org.signal.*`.
- [ ] Build succeeds on arm64-v8a, armeabi-v7a, x86_64.
- [ ] Human approved all native-code work.

**Status:** **EXECUTED 2026-10-18** — upgrade to 0.105.0 (both
artifacts) landed at `97279b1` (Session Z-8). Gate passed: 71/71 per
emulator, 29/29 libsignal target (the "28" figure was a preliminary
count; verified count is 29 — see `LIBSIGNAL-REVIEW.md` §6).

**Decision artifact:** `docs/architecture/ADR-SIGNAL-UPGRADE-001.md`
**v0.2** (2026-10-18, commit `5fd44aa`, Session Z-7). Supersedes v0.1
(`aa6860e`, Session Z-6). Approval record in §5.4; verified facts in
§5.2; plan revised 4–5 → 2–3 sessions. **Execution:** `97279b1`
(Session Z-8) implemented the plan; four mechanical-fix rounds
(constructor arity, property-to-method accessors, catalog swap,
argument-order asymmetry per `LIBSIGNAL-REVIEW.md` §4.1). The three
TASK-P1-005 doc acceptance criteria are satisfied: `docs/legal/AGPL-
NOTICE.md`, `docs/crypto/LIBSIGNAL-REVIEW.md`, `docs/crypto/
LIBSIGNAL-INTEGRATION.md`.

### TASK-P1-013 — Backend stack

**Objective:**
- Node.js 24.x Active LTS (set in `.nvmrc` and `package.json` `engines`).
- Fastify 5.12.5 (pinned exact).
- TypeScript strict.
- PostgreSQL 16.
- Opaque server-side sessions (NOT JWTs).
- PostgreSQL queue with `FOR UPDATE SKIP LOCKED`.
- No Firebase, no `@google/*`, no FCM.

**Acceptance criteria:**
- [ ] `backend/.nvmrc` contains `24`.
- [ ] `package.json` `engines.node` is `>=24.0.0 <27.0.0`.
- [ ] `package.json` pins `fastify@5.12.5`.
- [ ] CI runs on Node 24.
- [ ] `npm ci` succeeds.
- [ ] `/health` responds.

**Status:** Proposed

### TASK-P1-021b — Duress wipe

Wipe-confirmation notification must include: `event_id` (UUID v4), `device_id`, `wipe_completed_at` (ISO8601 UTC), `nonce` (32 bytes from CSPRNG, base64url).

Backend must:
- Verify signature against registered wipe-confirmation public key.
- Reject duplicate `event_id` (idempotent no-op).
- Reject `wipe_completed_at` older than most recent wipe request.
- Validate `nonce` length (base64url → exactly 32 bytes). Client responsible for CSPRNG.
- Rate-limit per device and per source.
- Record as `device_reported_wipe_complete`.

Test coverage required:
- Crash between key destruction and notification.
- Tor unavailable at wipe time.
- Duplicate notifications.
- Old signed notification arriving after a newer wipe request.

### TASK-P1-026 — Authorization matrix

**Acceptance criteria:**
- [ ] Matrix serialized using RFC 8785 JCS.
- [ ] Signed object is `{"domain":"umoja.authorization-matrix.v1","matrix":{...}}`.
- [ ] Signing per §3.8: Ed25519 over SHA-256 of canonical bytes (standard Ed25519, NOT Ed25519ph).
- [ ] Signature base64url without padding.
- [ ] Each matrix has monotonically increasing `version`.
- [ ] Device stores `highest_seen_version`.
- [ ] **Post-initial-enrollment:** matrix with `version ≤ highest_seen_version` rejected, even if validly signed.
- [ ] **Initial enrollment (replacement device):** inclusive floor applies; a matrix with `version = enrollment_matrix_version_floor` is accepted. See §3.7 and TASK-P1-030. After this first acceptance, all subsequent updates must have strictly greater version.
- [ ] Both offline signer and Android verifier produce identical canonical bytes, SHA-256 digests, and Ed25519 signatures for all test vectors.

**Required tests:**
- TEST-MATRIX-001 through TEST-MATRIX-009 (existing).
- TEST-MATRIX-010: Canonical bytes match test vectors on both implementations.
- TEST-MATRIX-011: Matrix with duplicate keys rejected.
- TEST-MATRIX-012: Numbers formatted differently (1.0 vs 1) canonicalize to identical bytes.
- TEST-MATRIX-013: Initial enrollment accepts matrix at version = floor.
- TEST-MATRIX-014: After first acceptance, subsequent push at same version rejected.
- TEST-MATRIX-015: After first acceptance, subsequent push at lower version rejected.

### TASK-P1-029 — Signing-key custody

Custody procedure must cover BOTH:
- Organization provisioning key (TASK-P1-033).
- Organization recovery key (TASK-P1-035).

For each: generation ceremony, storage location, access control (split control for recovery key), use procedure, rotation schedule, retirement, compromise handling, audit.

### TASK-P1-030 — Replacement-device flow

**Acceptance criteria:**
- [ ] Admin initiates replacement flow from admin UI.
- [ ] Old device revoked; sessions closed; messaging WebSockets closed ≤5s.
- [ ] New device enrolls with fresh token.
- [ ] Enrollment token carries `enrollment_matrix_version_floor` equal to current matrix version at issuance.
- [ ] New device accepts matrix with `version ≥ floor` (inclusive).
- [ ] After initial acceptance, device stores `highest_seen_version = accepted_version` and rejects subsequent pushes with `version ≤ highest_seen_version`.
- [ ] New device appears with different device ID.
- [ ] Peers receive identity-change notification listing old and new keys.
- [ ] Peers must explicitly accept or reject; sending blocked until accepted.
- [ ] Old device cannot re-enroll.
- [ ] Integrated end-to-end test per §3.7 passes.
- [ ] Audit trail records full replacement sequence.

**Required tests:**
- TEST-REPLACE-001 through TEST-REPLACE-006 (existing).
- TEST-REPLACE-007: Stale enrollment token rejected.
- TEST-REPLACE-008: Token with floor > current authorized version rejected.
- TEST-REPLACE-009: After accepting v2 at enrollment, subsequent push of v2 rejected.
- TEST-REPLACE-010: After accepting v2 at enrollment, push of v1 rejected.

**Sub-task breakdown (v0.5, 2026-10-16).**

P1-030 is six sessions of work, not one. Sub-tasks are numbered 030a–030f.
Each lands as its own commit; the integrated test (030f) is the last.
KI-018 (backend has no current matrix version) was a hard prerequisite
for 030b and was closed by 030a.

- **P1-030a — Backend tracks current matrix version per org.** Closes KI-018.
  Migration 013 adds `org_matrix_versions` (one row per org: `current_version`,
  `asserted_at`, `asserted_by_device_id`). New endpoints `GET /admin/matrix-version`
  and `POST /admin/matrix-version` (`requireAdmin`); state-changing assertions
  write `matrix_version.asserted` to the audit chain in the same transaction.
  Idempotent assertions (same version) write no audit event. **DONE: commit
  `6013077` (2026-10-16).**
- **P1-030b — Migration: `enrollment_matrix_version_floor` on
  `enrollment_tokens`.** Issuance records the current version (030a's state)
  at the moment the token is created. Column is nullable; floor semantics
  apply only to tokens issued after this migration.
- **P1-030c — `POST /enrollment` response carries the floor.** Client stores
  it alongside the enrolled device identity; it is read once at matrix
  acceptance time and never re-read.
- **P1-030d — `MatrixStore.accept` gains floor-aware mode.** Accepts
  `version >= floor` during initial enrollment (replacement device),
  strictly-greater thereafter. Current implementation (P1-026) is
  strictly-greater always. `highest_seen_version` initializes to the
  accepted version on first acceptance.
- **P1-030e — Peer identity-change notification + ack state.** New protocol
  message carrying old and new device keys. Peers block sending to the
  replacement device until they acknowledge. Channel decision pending
  (see Transport caveat).
- **P1-030f — Integrated test per Build Master §3.7.** The 11-step
  scenario. Depends on 030a–030e being complete.

**Transport caveat (v0.5).** Steps 5 and 7 of the §3.7 integrated test
push a matrix to a device. No delivery transport exists (TASK-P1-037).
Interim path for 030f: the P1-026 Diagnostics debug paste field, since
floor semantics are orthogonal to transport. Steps 8–9 (identity-change
notification) are peer-to-peer and likely need a real channel; decision
pending.

**Framing (v0.5, load-bearing).** 030a's endpoint records an admin-asserted,
unverified claim. The admin app builds the matrix and chooses the version;
the offline signer signs whatever bytes it's handed. Both the floor and the
current-version come from the same party in Phase 1. The endpoint is not
attack-prevention. Its purpose is cross-session and cross-admin audit —
catching "the new admin doesn't know what the last admin signed." In
single-admin single-session it catches nothing. Anti-rollback enforcement
is client-side (`MatrixStore.highestSeenVersion`, P1-026). The server-side
comparison is admin-error-catching, not adversary-catching.

---

## §C — REGISTRY INDEX (v0.8 FINAL)
| ID | Title | Stage | Status |
|----|-------|-------|--------|
| TASK-P1-001 | Initialize repository structure | 1 | Proposed |
| TASK-P1-002 | Configure development environments | 1 | Proposed |
| TASK-P1-003 | Define supported Pixel device specifications | 2 | Proposed |
| TASK-P1-004 | Validate GrapheneOS + attestation on real hardware | 2 | Extended |
| TASK-P1-005 | Integrate libsignal (Android artifacts) | 3 | Corrected |
| TASK-P1-006 | Device cryptographic identity generation | 3 | Proposed |
| TASK-P1-007 | Contact authorization | 4 | Proposed |
| TASK-P1-008 | QR contact verification | 4 | Proposed |
| TASK-P1-009 | E2EE session establishment | 5 | Proposed |
| TASK-P1-010 | Message encryption/decryption | 5 | Proposed |
| TASK-P1-011 | Tor adapter integration | 6 | Proposed |
| TASK-P1-012 | Offline message queue | 6 | Proposed |
| TASK-P1-013 | Backend stack implementation | 7 | Corrected |
| TASK-P1-014 | Backend enrollment API | 7 | Proposed |
| TASK-P1-015 | Backend key directory API | 7 | Proposed |
| TASK-P1-016 | Backend messaging envelope API | 7 | Proposed |
| TASK-P1-017 | Conversation list UI | 8 | Proposed |
| TASK-P1-018 | Message composition/display UI | 8 | Proposed |
| TASK-P1-019 | Device enrollment flow | 9 | Proposed |
| TASK-P1-020 | Device revocation workflow | 9 | Proposed |
| TASK-P1-021a | Emergency lock (reversible) | 9 | Split |
| TASK-P1-021b | Duress wipe (destructive) | 9 | Updated |
| TASK-P1-022 | Phase 1 security test suite | 10 | Proposed |
| TASK-P1-023 | Threat simulation exercises | 10 | Proposed |
| TASK-P1-024 | Independent security review | 10 | Proposed |
| TASK-P1-025 | Admin provisioning tool | 3.5 | New |
| TASK-P1-026 | Authorization matrix + verification | 3.5 | Updated |
| TASK-P1-027a | SBOM + dependency review, per-session | 1 | Executed 2026-10-19 |
| TASK-P1-027b | CI enforcement gate for dep review | 1 | New |
| TASK-P1-028 | Log redaction audit | 10 | New |
| TASK-P1-029 | Signing-key custody | 3.5 | Updated |
| TASK-P1-030 | Replacement-device flow | 9 | Updated |
| TASK-P1-031 | Audit hash-chain verification | 10 | Restored |
| TASK-P1-032 | Resolved-dependency inspection | 1 | New |
| TASK-P1-033 | Offline provisioning-key signing workflow | 3.5 | New |
| TASK-P1-034 | Hardware-backed Ed25519 Keystore verification | 2 | New |
| TASK-P1-035 | Organization recovery key | 3.5 | New |
| TASK-P1-036 | Provisioning-key rotation & recovery-key revocation notices | 3.5 | Proposed |
| TASK-P1-037 | Matrix transport | 3.5 | Proposed |
| TASK-P1-038 | Send-path matrix enforcement verification | 1 | Proposed |
| TASK-P1-039 | Release-build hardening | 1 | Proposed |
| TASK-P1-040 | Session lifecycle & revocation UX | 1 | Proposed |
| TASK-P1-041 | Failed-verification operator logging | 1 | Proposed |
| TASK-P1-042 | WS revocation listener reconnect + re-reconcile | 1 | DONE |

**Total Phase 1 task identifiers:** 44 (001–020, 021a, 021b, 022–026, 027a, 027b, 028–042).

**Execution order (dependency-respecting):**
TASK-P1-001 → TASK-P1-002 → TASK-P1-027 → TASK-P1-032 → TASK-P1-003 → TASK-P1-034 → TASK-P1-004 → TASK-P1-005 → TASK-P1-006 → TASK-P1-013 → TASK-P1-007 → TASK-P1-008 → TASK-P1-025 → TASK-P1-026 → TASK-P1-029 → TASK-P1-033 → TASK-P1-035 → TASK-P1-014 → TASK-P1-015 → TASK-P1-016 → TASK-P1-009 → TASK-P1-010 → TASK-P1-011 → TASK-P1-012 → TASK-P1-019 → TASK-P1-020 → TASK-P1-021a → TASK-P1-021b → TASK-P1-030 → TASK-P1-017 → TASK-P1-018 → TASK-P1-022 → TASK-P1-023 → TASK-P1-024 → TASK-P1-028 → TASK-P1-031

Independent branches (backend Stage 7 and Android Stage 3–6) may be parallelized if two developers are available.

---

## §D — CROSS-REFERENCE UPDATES

Apply to all documents:

| Old reference | New reference |
|---------------|---------------|
| "TASK-P1-021" | TASK-P1-021a + TASK-P1-021b |
| "TASK-P1-029 (audit hash-chain)" | TASK-P1-031 |
| "Node.js 20" | Node.js 24.x Active LTS |
| "Fastify latest 4.x" | Fastify 5.12.5 (pinned) |
| "EncryptedSharedPreferences" | Android Keystore-backed AES-256-GCM |
| "Tink" as an option | Removed — Google runtime dependency |
| "@signalapp/libsignal-client" as Android dep | org.signal:libsignal-android + org.signal:libsignal-client |
| "libsignal 0.81.1 (current)" | Pin exact after review (Maven 0.86.5; upstream 0.99.3; Signal-Android 0.94.0) |
| "sorted keys, UTF-8, no whitespace" | RFC 8785 JCS + SHA-256 + Ed25519 per §3.8 |
| "call-signaling sessions terminated" (Phase 1) | messaging WebSocket sessions only; call-signaling in Phase 3 |

---

## §E — APPROVAL

Applying this reconciliation to `docs/US-TASK-P1-001.md` produces v0.4. Commit with Build Master v1.4.2.

Human approval: ___________________________ Date: __________