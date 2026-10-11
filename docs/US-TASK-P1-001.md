# US-TASK-P1-001-v0.4 — Phase 1 Task Registry Reconciliation

Document ID: US-TASK-P1-001
Version: 0.4
Date: October 2026
Supersedes: v0.3
Purpose: Reconcile the Phase 1 task registry with UMOJA-SECURE-BUILD-MASTER.md v1.4.2.
Authority: Derived from US-MASTER-001 + US-ADD-001. Cannot override them.

---

## §A — NEW TASKS

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

**Status:** Proposed (blocked until human approves native code path)

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

---

## §C — REGISTRY INDEX (v0.4 FINAL)

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
| TASK-P1-027 | SBOM + dependency review gate | 1 | New |
| TASK-P1-028 | Log redaction audit | 10 | New |
| TASK-P1-029 | Signing-key custody | 3.5 | Updated |
| TASK-P1-030 | Replacement-device flow | 9 | Updated |
| TASK-P1-031 | Audit hash-chain verification | 10 | Restored |
| TASK-P1-032 | Resolved-dependency inspection | 1 | New |
| TASK-P1-033 | Offline provisioning-key signing workflow | 3.5 | New |
| TASK-P1-034 | Hardware-backed Ed25519 Keystore verification | 2 | New |
| TASK-P1-035 | Organization recovery key | 3.5 | New |

**Total Phase 1 task identifiers:** 36 (001–020, 021a, 021b, 022–035).

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