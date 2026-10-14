# US-ADD-001 — Approved Decisions and Parameters

Document ID: US-ADD-001
Version: 0.2 (draft for owner review)
Date: 2026-10-14
Authority: Highest authority for approved decisions and parameters. Per UMOJA-SECURE-BUILD-MASTER.md §0, this document wins over US-MASTER-001 in any conflict.
Status: Draft. Not yet in force. Subject to revision.

---

## §1 Provenance

Authored 2026-10-14. Did not exist on disk prior to this date. Grounded
in UMOJA-SECURE-BUILD-MASTER.md v1.4.2 §3 (Decision Register) and §4
(Phase 1 Scope), plus owner attestation recorded in
`docs/architecture/ADR-PROVISIONING-001.md` §2.

This document is a **register**, not a narrative. Each entry is a frozen
decision or parameter. Where Build Master §3 specifies a value, this
document restates it as authoritative. Where this document and Build
Master disagree, this document wins for parameters; Build Master wins
for workflow and closed decisions (Build Master §0).

---

## §2 Product definition

Umoja Secure is a privacy messenger for government and security
professionals. It satisfies six criteria simultaneously. No existing
product satisfies all six.

1. No phone numbers for discovery (Threema model).
2. Admin-provisioned contacts (the differentiator).
3. Server-blind architecture (SimpleX/Briar model).
4. Tor transport for messaging and signaling (Briar/Session model).
5. No Google runtime dependencies of any kind.
6. GrapheneOS-first device baseline.

Additional fixed requirements:

- Signal-grade E2EE via libsignal (PQXDH, X3DH, Double Ratchet).
- Kotlin + Jetpack Compose Android client.
- Node.js + Fastify + PostgreSQL backend.
- Calls deferred to Phase 3 (WebRTC + TURN on clearnet; Tor for signaling
  only).
- Backend never has plaintext, private keys, or Double Ratchet state.

---

## §3 Phase boundaries

### §3.1 Phase 1 — in scope

- Admin provisioning tool (Android admin mode).
- Device enrollment with locally-generated keys.
- Contact authorization matrix.
- E2EE 1:1 text messaging via libsignal.
- Tor-only transport for messaging and signaling.
- Encrypted local message store.
- Server ciphertext envelope queue.
- Server envelope expiration (30 days).
- Device revocation (messaging only).
- Emergency lock (TASK-P1-021a).
- Duress wipe (TASK-P1-021b).
- Audit log with hash chain.
- Real-device acceptance testing.

### §3.2 Phase 1 — out of scope (prohibited, not deferred-with-intent)

Do not implement, do not plan, do not add:

- Group messaging.
- Calls (audio or video).
- Attachments.
- Employee-controlled recovery.
- MDM.
- Compliance retention.
- Key transparency.
- Cover traffic.
- Padding.
- Localization.
- Admin web UI.
- iOS.
- BYOD.
- Tablets.

### §3.3 Phase 3 — deferred, named for future reference

- Calls: WebRTC + TURN on clearnet; Tor for signaling only.
- Call-signaling WebSocket termination on revocation (Phase 1 covers
  messaging WebSockets only; Build Master §3.1).

---

## §4 Parameter register — backend

| Parameter | Value | Notes |
|---|---|---|
| Node.js | 24.x Active LTS | Not 20.x (EOL 2026-04-30). Migration to Node 26.x when it enters Active LTS (2026-10-28). |
| Fastify | 5.12.5 (exact pin) | Not 4.x (EOL 2025-06-30). Not 6.x (alpha). |
| TypeScript | strict mode | |
| PostgreSQL | 16 | |
| Sessions | Opaque server-side | **NOT JWTs.** Immediate revocation required. |
| Queue | PostgreSQL with `FOR UPDATE SKIP LOCKED` | **NOT Redis.** |
| Logging | pino, redacted | |
| Validation | zod | |
| Fastify plugins | `@fastify/helmet`, `@fastify/cors`, `@fastify/rate-limit`, `@fastify/websocket` | Versions aligned to Fastify 5. |
| Forbidden runtime deps | Firebase, `@google/*`, FCM, Tink, `googleapis`, `gaxios`, `google-auth-library`, `firebase*` | Build Master §6, §11. |
| Runtime version file | `backend/.nvmrc` contains `24` | |
| Engines | `package.json` `engines.node` is `>=24.0.0 <27.0.0` | |

---

## §5 Parameter register — Android client

| Parameter | Value | Notes |
|---|---|---|
| Language | Kotlin | |
| UI | Jetpack Compose | |
| `minSdk` | 30 | |
| `targetSdk` (spec) | 35 | Per Build Master §3. Proposed baseline. |
| `targetSdk` (current build) | 36 | Per handoff §2. Reconciliation pending. |
| Package | `com.umoja.secure` | |
| libsignal (native AAR) | `org.signal:libsignal-android` | AGPLv3. Pin exact after review. |
| libsignal (Java client) | `org.signal:libsignal-client` | |
| libsignal — prohibited | `@signalapp/libsignal-client` (npm) | Not the Android dependency. |
| libsignal version policy | Pin exact after compatibility + security review | Maven latest 0.86.5; upstream 0.99.3; Signal-Android uses 0.94.0. Review in `docs/crypto/LIBSIGNAL-REVIEW.md`. |
| Tor | `tor-android` (embedded) | **Not Orbot.** |
| Local storage | SQLCipher | |
| Session token storage | Android Keystore-backed AES-256-GCM (direct) | DataStore may hold encrypted blob; key in Keystore; token never plaintext. |
| Session token storage — prohibited | `androidx.security:security-crypto` / EncryptedSharedPreferences | Deprecated 1.1.0-alpha07, no drop-in replacement. |
| Session token storage — prohibited | Tink (`com.google.crypto.tink:tink-android`) | Google runtime dependency. |

---

## §6 Parameter register — device baseline

| Parameter | Value | Notes |
|---|---|---|
| Supported hardware | Pixel 6a or newer | |
| OS | GrapheneOS stable | |
| Enrollment attestation | Android Key Attestation | GrapheneOS compatibility verified during TASK-P1-004. Fall back to admin-verified enrollment if attestation fails; document limitation. |
| MDM | None in Phase 1 | See Build Master §3.1. |

### §6.1 GrapheneOS OS-level controls (user-configured, not admin-controlled)

- Duress PIN + duress password (both required by GrapheneOS; trigger
  wipes the device).
- Auto-wipe after N failed unlock attempts.
- USB-C port disabled when locked.
- Screenshot blocking.

These are user responsibilities. The admin plane does not control them.
The app assumes they may or may not be enabled.

---

## §7 Parameter register — cryptographic protocol

| Parameter | Value | Notes |
|---|---|---|
| Matrix canonicalization | RFC 8785 JCS | Build Master §3.8. |
| Signed object | `{"domain":"umoja.authorization-matrix.v1","matrix":{...}}` | Wrapper is the signed unit, not the inner matrix. |
| Digest | SHA-256 over JCS-canonical bytes | 32 bytes. |
| Signature algorithm | Ed25519 (standard, **NOT** Ed25519ph) | Signs the 32-byte digest as the message. |
| Signature encoding | base64url, no padding | |
| Matrix version | Monotonic integer | Post-enrollment: `version ≤ highest_seen_version` rejected. |
| Replacement enrollment | `enrollment_matrix_version_floor`, inclusive minimum | Accepted once at `version = floor`; strictly-greater thereafter. |
| Recovery key version | Monotonic integer | `recovery_key_version ≤ highest_recovery_key_version` rejected. |
| Hardware-backed Ed25519 | TEE-backed Keystore sufficient | **StrongBox is not required.** Tested separately. |

---

## §8 Approved prohibitions (Build Master §11, restated)

Violating any of these requires reverting the entire session:

- Adding Firebase, FCM, Google Play services, Tink, or any `com.google.*`
  runtime dependency (source or transitive).
- Implementing any backend path that decrypts message content.
- Storing private keys, Double Ratchet state, or plaintext server-side.
- Using JWTs for sessions.
- Using passwords, OAuth, or third-party identity providers.
- Enabling clearnet fallback when Tor is unavailable.
- Logging tokens, signatures, private keys, or message content.
- Committing secrets or `.env` files with real values.
- Using unpinned dependencies.
- Weakening revocation (adding caches that preserve revoked access).
- Claiming compliance (FIPS, CUI, SOC 2, FedRAMP) without assessment.
- Proceeding past a failing security-critical test.
- Combining phases in one PR.
- Guessing on security-relevant ambiguity.
- Silencing dependency warnings without documented human approval.
- Using `@signalapp/libsignal-client` (npm) as the Android crypto
  dependency.
- Using `androidx.security:security-crypto` / EncryptedSharedPreferences.
- Using Tink (`com.google.crypto.tink:tink-android`).
- Claiming "forensic unrecoverability" of wiped data.
- Holding the organization provisioning private key in the admin app.
- Treating StrongBox support as required for the wipe-confirmation key.
- Accepting a matrix that has not been canonicalized per RFC 8785 JCS.
- Accepting a provisioning key rotation event not signed by the recovery
  key.
- Accepting a recovery notice with
  `recovery_key_version ≤ highest_recovery_key_version`.
- Accepting a matrix with `version ≤ highest_seen_version` after initial
  enrollment.
- Signing the raw canonical bytes instead of the SHA-256 digest.

### §8.1 Interpretation of the `com.google.*` prohibition

The prohibition on `com.google.*` runtime dependencies in §8 applies to
Google-the-company runtime services and SDKs — Firebase, FCM, Google
Play services, Tink, `googleapis`, `gaxios`, `google-auth-library`, and
their transitive dependencies. It does not apply to Maven artifacts
whose groupId begins with `com.google.` but which are Apache-2.0
community projects with no Google service dependency, no Google runtime
callback, and no network egress to Google-controlled infrastructure.

Currently identified as outside the prohibition:

- `com.google.zxing:core` — community ZXing, Apache 2.0, no Google
  services, no runtime callback. Pulled transitively by
  `com.journeyapps:zxing-android-embedded`.

New artifacts matching the namespace but not the intent must be
individually reviewed against this paragraph and recorded in
`docs/security/DEPENDENCY-EXCEPTIONS.md` with owner, rationale, and
date. The §6 dependency-tree grep continues to flag the namespace
pattern; human review cites this section when clearing.

---

## §9 Authority and precedence

Per Build Master §0:

1. **This document (US-ADD-001)** — highest authority for approved
   decisions and parameters.
2. `docs/US-MASTER-001.md` — governing architecture, threat model, phase
   boundaries.
3. `docs/reference/AUTH-SPEC-001.md`, `docs/reference/THREAT-MODEL-001.md`
   — supporting specifications.
4. `UMOJA-SECURE-BUILD-MASTER.md` — execution layer.
5. `docs/US-TASK-P1-001.md` — task list.

If US-ADD-001 and US-MASTER-001 conflict, **US-ADD-001 wins**.

If this document contradicts Build Master, this document wins for
parameters; Build Master wins for workflow and closed decisions.

If both are silent on a security-relevant question, **STOP and escalate.**
Do not guess.

---

## §10 Revision history

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-10-14 | Initial draft. Authored from Build Master v1.4.2 §3, §4, §6, §11 + owner attestation. |
| 0.2 | 2026-10-14 | §8.1 added: interprets the `com.google.*` prohibition as covering Google-the-company runtime services, not every matching Maven groupId. Named carve-out: `com.google.zxing:core` (community Apache-2.0, no Google services). Future matching artifacts require individual review. |

---

— end of US-ADD-001 v0.1 draft —
