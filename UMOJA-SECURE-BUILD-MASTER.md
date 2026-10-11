# UMOJA-SECURE-BUILD-MASTER.md

Version: 1.4.2 (frozen)
Audience: AI coding agents (Claude Code, Devin) and the human developer driving them
Purpose: Operational build instruction for Umoja Secure.

Change log from v1.3: (1) Hardware-backed Ed25519 verification corrected — StrongBox is not required for Curve25519; ordinary TEE-backed Keystore is verified first, StrongBox tested separately; (2) provisioning-key compromise recovery uses an independent recovery trust anchor, not the possibly-compromised previous key; (3) canonical matrix serialization adopts RFC 8785 JCS; (4) replacement-device enrollment bound to current authorization state, with integrated anti-rollback tests; (5) Phase 1 revocation scoped to messaging WebSocket sessions; call-signaling termination remains a Phase 3 requirement. v1.4.1: §3.7 replacement-version rule made consistent; §3.4 nonce validation scoped to length/format; §3.6 recovery-key version/out-of-order handling explicit; §3.8 signing protocol fully specified. v1.4.2: §3.6 signing step aligned to §3.8 (Ed25519 over SHA-256 digest, not canonical bytes directly); §3.6 verification step aligned to §3.8; task-registry counts corrected; §3.6 clarification that the recovery key authorizes the rotation event and the overlap window governs matrix acceptance.

---

## §0 AUTHORITY AND PRECEDENCE

Two layers. Different questions.

**Requirements layer — what must be true:**
1. `docs/US-ADD-001.md` — highest authority for approved decisions and parameters
2. `docs/US-MASTER-001.md` — governing architecture, threat model, phase boundaries
3. `docs/reference/AUTH-SPEC-001.md`, `docs/reference/THREAT-MODEL-001.md` — supporting specifications

**Execution layer — how to build it:**
4. This document (`UMOJA-SECURE-BUILD-MASTER.md`)
5. `docs/US-TASK-P1-001.md` — the task list this document invokes

**Rules:**
- This document is derived from the requirements layer. It cannot override it.
- If this document contradicts the requirements layer, that is a bug in this document. STOP and escalate.
- If US-ADD-001 and US-MASTER-001 conflict, US-ADD-001 wins.
- If both are silent on a security-relevant question, STOP and escalate. Do not guess.
- If the task registry contradicts this document, this document wins for workflow and closed decisions; US-MASTER-001 wins for security requirements. If they cannot be reconciled, STOP and escalate.
- **An instruction to STOP and ESCALATE takes precedence over every instruction to proceed.**

Historical documents in `docs/archive/` are for traceability only. Do not consult them during implementation.

---

## §1 WHAT WE ARE BUILDING

Umoja Secure is a privacy messenger for government and security professionals. It hits six criteria no existing product hits simultaneously:

1. No phone numbers for discovery (Threema model)
2. Admin-provisioned contacts (our differentiator)
3. Server-blind architecture (SimpleX/Briar model)
4. Tor transport for messaging and signaling (Briar/Session model)
5. No Google runtime dependencies of any kind
6. GrapheneOS-first device baseline

Additional requirements:
- Signal-grade E2EE via libsignal
- Kotlin + Jetpack Compose Android client
- Node.js + Fastify + PostgreSQL backend
- Calls deferred to Phase 3 (WebRTC + TURN on clearnet; Tor for signaling only)
- Backend never has plaintext, private keys, or Double Ratchet state

---

## §2 CANONICAL DOCUMENT SET

Governance and architecture:
- `docs/US-MASTER-001.md`
- `docs/US-ADD-001.md`
- `docs/US-ISSUE-001.md`
- `docs/US-TASK-P1-001.md`

Reference:
- `docs/reference/AUTH-SPEC-001.md`
- `docs/reference/THREAT-MODEL-001.md`
- `docs/reference/canonical-challenge.json`
- `docs/reference/canonical-matrix-test-vectors.json`
- `docs/reference/USER-ONBOARDING.md`

Archived:
- `docs/archive/*`

---

## §3 DECISION REGISTER (ALL CLOSED)

### Backend

- **Node.js 24.x (Active LTS)** — not 20.x, which reached end-of-life on 30 April 2026. Node 24 "Krypton" is Active LTS through 20 October 2026, then Maintenance LTS through 30 April 2028. Migrate to Node 26.x when it enters Active LTS on 28 October 2026; Node 26 has end-of-life 30 April 2029.
  - Runtime version is set in `backend/.nvmrc` and `package.json` `engines`.
- **Fastify 5.12.5** — pinned exact version. Fastify 4 reached end-of-life on 30 June 2025 and is unsupported. Fastify 5 requires Node 20+. Fastify 6 is in alpha; do not use alpha versions in production. Several 5.11 and 5.12 releases were security releases; stay on 5.x patches.
- TypeScript (strict mode)
- PostgreSQL 16
- Opaque server-side sessions (**NOT JWTs** — immediate revocation required)
- PostgreSQL queue with `FOR UPDATE SKIP LOCKED` (**NOT Redis**)
- No Firebase, no `@google/*`, no FCM
- pino (redacted), zod (validation)
- `@fastify/helmet`, `@fastify/cors`, `@fastify/rate-limit`, `@fastify/websocket` (versions aligned to Fastify 5)

### Client

- Kotlin + Jetpack Compose
- `minSdk 30`
- `targetSdk 35` — **PROPOSED BASELINE.** Verify during TASK-P1-003. Update this document if the baseline changes before TASK-P1-017.
- **libsignal Android integration:**
  - Android artifacts: `org.signal:libsignal-android` (native AAR, AGPLv3) and `org.signal:libsignal-client` (Java client)
  - **NOT** `@signalapp/libsignal-client` — that is the npm package; it is not the Android dependency.
  - **Pin a specific published version.** Maven Central lists `org.signal:libsignal-android` **0.86.5** as the latest published. Upstream `signalapp/libsignal` has released up to **0.99.3** as of 2026-08-01. The Signal-Android repository itself uses libsignal **0.94.0**. **Do not use "the latest" without a compatibility and security review.** Pin exact version after review. Document the review in `docs/crypto/LIBSIGNAL-REVIEW.md`.
  - Licensing: **AGPLv3.** Document the implications for Umoja Secure distribution. If AGPLv3 is incompatible with your distribution model, STOP and escalate. Do not substitute a different crypto library without approval.
  - Build procedure and JNI/Rust integration path must be documented in TASK-P1-005 before implementation begins.
  - Native-code work requires human approval per §7.
- `tor-android` (embedded, not Orbot)
- SQLCipher for local encrypted storage
- **Session token storage:** **Android Keystore-backed AES-256-GCM** (direct). DataStore may store the encrypted blob, but the encryption key is held in Android Keystore and the token is never written in plaintext. Authenticated encryption with safe nonce handling is required. **Do NOT use `androidx.security:security-crypto` / EncryptedSharedPreferences** — deprecated as of 1.1.0-alpha07 with no drop-in replacement. **Do NOT use Tink** (`com.google.crypto.tink:tink-android`) — that is a Google runtime dependency and violates §6.

### Device

- Pixel 6a or newer, GrapheneOS stable
- Android Key Attestation for enrollment — verify GrapheneOS compatibility during TASK-P1-004. If it fails on target hardware, fall back to admin-verified enrollment only and document the limitation in `docs/US-ISSUE-001.md`.
- **Hardware-backed Ed25519 Keystore verification** — see §3.5.
- No MDM in Phase 1. See §3.1.

### §3.1 DEVICE MANAGEMENT WITHOUT MDM

**Administrator CAN (Phase 1):**
- Revoke a device (server-side). Effect: next request rejected (≤1s); active **messaging** WebSocket sessions terminated (≤5s via `LISTEN/NOTIFY` plus authoritative status check); no new envelopes delivered.
- Issue a server-side wipe request. Effect: on next connectivity, device wipes app-local keys, message store, and session material. Recorded as `REQUESTED`, `ACKNOWLEDGED`, `FAILED`, or `STATUS_UNKNOWN`. **A request is not proof of erasure.**
- Create or revoke enrollment tokens.
- Authorize or revoke contacts.
- Read the audit log.

**Administrator CANNOT (Phase 1):**
- Wipe an offline device.
- Force-lock an offline device.
- Remotely read app data on any device.
- Prevent physical access to data on a lost device.
- Re-enroll without a fresh enrollment token + physical device access.

**Phase 3 addition:** When calls are implemented, revocation also terminates active call-signaling WebSocket sessions within the same 5-second target. This is not implemented in Phase 1 because calls are out of scope.

**GrapheneOS OS-level controls** (configured by the user, not the admin):
- Duress PIN + duress password. GrapheneOS requires **both** to be configured; triggering it wipes the device.
- Auto-wipe after N failed unlock attempts
- USB-C port disabled when locked
- Screenshot blocking

These are user responsibilities. The admin plane does not control them. The app assumes they may or may not be enabled.

**Testing requirements:** TASK-P1-022 must verify, on real hardware, what the admin plane can and cannot do.

### §3.2 PROVISIONING AND KEY MODEL

**Keys generated on each device, never leaving the device:**
1. **Device authentication key** (Ed25519). Challenge-response. Android Keystore, hardware-backed where available.
2. **Messaging protocol identity key** (libsignal identity key). X3DH and Double Ratchet. Stored via libsignal's store, wrapped by Keystore.
3. **Signed prekey** and **one-time prekeys** (libsignal). Public parts uploaded; private parts local.
4. **Device wipe-confirmation key** (Ed25519). Separate from messaging keys. Used **only** to authenticate a single fire-and-forget wipe notification to the backend. See §3.4.

**Keys generated once per organization:**
5. **Organization provisioning key** (Ed25519). Signs the authorization matrix. Held offline. See §3.6.
6. **Organization recovery key** (Ed25519). Independent of the provisioning key. Used only to authorize provisioning-key rotation or revocation when the provisioning key is compromised. Held offline under stricter custody than the provisioning key itself. See §3.6.

**Provisioning sequence:**
1. Admin generates a fresh, single-use enrollment token per device.
2. Each device displays a QR containing its **public** device-authentication key, **public** messaging identity key, and **public** wipe-confirmation key. Private keys never leave the device.
3. Admin scans and records each device's public keys.
4. Admin assigns clearance and group memberships per device.
5. **Admin requests the authorization matrix to be signed by the offline provisioning key.** See §3.6. The admin app does **not** hold the root provisioning private key.
6. Admin pushes to each device: the signed matrix, plus public identity keys and public prekey bundles of authorized peers.
7. Each device verifies the admin signature against the pinned public provisioning key and the pinned public recovery key.
8. Device stores peer public keys locally; outbound sessions created on first send.

**Not pre-shared:** private device auth keys, private messaging identity keys, private prekeys, Double Ratchet state, private wipe-confirmation key.

**Backend receives:** device public auth keys, device public identity keys, device public prekeys, signed authorization matrix, and public wipe-confirmation key. **Never** any private key, session state, or plaintext.

### §3.3 REVOCATION AND WIPE TIMING MODEL (PHASE 1: MESSAGING ONLY)

**Revocation (server-side):**
- Immediate: on revoke commit, backend writes to `device_revoked` PostgreSQL channel via `NOTIFY`.
- Backend instances `LISTEN` on this channel; on receipt, they find active **messaging WebSocket** connections for that device and close them (code 4403).
- Target: ≤5s from revocation commit to WebSocket closure. This does not depend on the 5-minute revalidation cycle.
- **Defense in depth:** PostgreSQL `LISTEN/NOTIFY` is a prompt-wake mechanism, not a durable queue. PostgreSQL does not store notifications; it drops them immediately for any connection not listening at that exact moment. **A missed notification must never leave an active connection alive.**
- **Authoritative status check:** The backend must also check `devices.status` against the database on every protected request before accepting it. Even if a notification is missed (listener disconnect, failover, restart), the next request will see the device is revoked and reject it.
- **Listener reconnection:** On listener disconnect or restart, the backend must perform a **full reconciliation pass** — query all devices with `status = 'revoked'` and `revoked_at > last_reconciliation_time`, and close any active connections for those devices. This covers notifications missed while the listener was down.

**Wipe request (server-side):**
- Poll interval: 30 seconds while the foreground service is active.
- When Android suspends the app (doze, background restriction): the poll does not run. The wipe request remains pending until the app resumes, the foreground service restarts, or the user opens the app.
- While pending, the admin UI shows `REQUESTED`. When the app acknowledges the request, it shows `ACKNOWLEDGED`. If the app reports failure, `FAILED`. If the device has not been heard from since the request, `STATUS_UNKNOWN`.
- `STATUS_UNKNOWN` is the honest state. The admin UI must not imply success.

### §3.4 WIPE CONFIRMATION AND ANTI-REPLAY

The wipe-confirmation key is used as follows:

1. On wipe trigger, the app **first** destroys messaging keys, Double Ratchet state, message store, and cached peer keys.
2. The app then uses the **wipe-confirmation key** (a separate Ed25519 key, never used for messaging) to sign a single notification payload:
   ```
   {
     event_id: <UUID v4, generated once per wipe>,
     device_id: <device_id>,
     wipe_completed_at: <ISO8601 UTC timestamp>,
     nonce: <32 random bytes, base64url>
   }
   ```
3. The app sends this notification to the backend over Tor, best-effort. It does not require a session token.
4. The backend verifies:
   - The signature against the device's registered public wipe-confirmation key.
   - The `event_id` has not been seen before (stored in a `wipe_events` table; duplicate → reject as idempotent no-op).
   - The `wipe_completed_at` is not older than the most recent known wipe request for this device (stale notification → reject).
   - The `nonce` is well-formed: base64url, decodes to exactly 32 bytes.
   - The backend cannot verify that the nonce was generated with a CSPRNG. **The client is responsible for generating the nonce with a CSPRNG.** The backend verifies length and format only, and rate-limits per device and per source.
5. On success, the backend records the event as **device-reported wipe completion** — not as independently verified erasure.
6. The app then destroys the wipe-confirmation private key.

**What a valid signature proves:** the holder of the wipe-confirmation private key signed a notification claiming wipe completion. It does **not** independently prove that the app's data was successfully erased. The backend records the event as `device_reported_wipe_complete`.

**Anti-replay:**
- `event_id` is unique per wipe; duplicate submissions are idempotent no-ops.
- `wipe_completed_at` must be ≥ the `requested_at` of the most recent wipe request for the device.
- `nonce` must be 32 bytes from a CSPRNG (client responsibility; backend validates length only).
- The endpoint rate-limits per device and per source.

**Limitations (documented honestly):**
- If Tor is unavailable at wipe time, the notification is lost. The backend learns of the wipe only when the next session attempt fails.
- If the wipe-confirmation private key is destroyed before the notification is sent (e.g., abrupt power loss), the notification is lost.
- **Cryptographic erasure guarantee:** the app guarantees that the messaging keys and session material are erased and that no path exists to re-derive them from app storage. It does **not** guarantee that every physical storage remnant is forensically unrecoverable. Documented in `docs/reference/USER-ONBOARDING.md`.

### §3.5 HARDWARE-BACKED ED25519 KEYSTORE VERIFICATION

The wipe-confirmation key design assumes Android Keystore can generate and use an Ed25519 key with hardware backing. **StrongBox is not required for this** — Android explicitly documents that StrongBox is not expected to support Curve25519 at feature version 200. Ordinary TEE-backed Keystore is sufficient.

**Verification requirement (TASK-P1-004):**

On each supported Pixel model and GrapheneOS version, confirm:

1. **Ordinary hardware-backed Keystore (required):**
   - Generate an Ed25519 key using Android Keystore without `setIsStrongBoxBacked(true)`.
   - Confirm the key's `KeyInfo.getSecurityLevel()` reports `SECURITY_LEVEL_TRUSTED_ENVIRONMENT` (TEE) or higher.
   - Confirm signing and verification succeed.
   - Confirm the key is non-exportable.
   - Confirm the key remains usable across device reboot.

2. **StrongBox (optional, tested separately):**
   - Attempt to generate an Ed25519 key with `setIsStrongBoxBacked(true)`.
   - If it succeeds, record that this device model has StrongBox Ed25519 capability.
   - If it fails, record the failure. **Do not treat failure as blocking** unless a future requirement explicitly demands StrongBox.
   - The app must not assume StrongBox is available. The wipe-confirmation key design works with TEE-backed Keystore.

3. **Feature-version check:**
   - `PackageManager.getSystemAvailableFeatures()` for `FEATURE_HARDWARE_KEYSTORE` version ≥ 200 is a **necessary but not sufficient** signal. Always confirm actual key security level by generating a test key.

**Testing procedure:** Generate a test Ed25519 key in a temporary alias, log `KeyInfo.getSecurityLevel()`, sign a known payload, verify with the public key, delete the key. Repeat for StrongBox with `setIsStrongBoxBacked(true)` and record the result. Run on every supported device model.

**If ordinary hardware-backed Keystore cannot produce a TEE-backed Ed25519 key on a supported device, STOP and escalate.** Do not silently substitute software-only storage.

### §3.6 OFFLINE PROVISIONING AND RECOVERY

The organization provisioning key is held offline. The admin app does not hold it.

**Signing workflow:**

1. **Admin app** collects the authorization matrix.
2. **Admin app** serializes the matrix using **RFC 8785 JSON Canonicalization Scheme (JCS)**. See §3.8 for the canonicalization specification. The admin app computes `SHA-256` of the canonical bytes.
3. **Admin app** displays the hash and the matrix content for review.
4. **Admin** transfers the canonical matrix (or its hash) to the **offline signing device** via QR or physical medium.
5. **Offline signing device** re-canonicalizes the matrix and confirms the hash matches. Displays the matrix for human confirmation.
6. **Offline signing device** signs the **SHA-256 digest of the JCS-canonical bytes** with the organization provisioning private key (Ed25519), per the exact protocol in §3.8. This is standard Ed25519 signing of a 32-byte message — **not** Ed25519ph, and **not** signing the canonical bytes directly.
7. **Offline signing device** returns the signature via QR or physical medium.
8. **Admin app** attaches the signature and pushes the signed matrix.
9. **Each device** re-canonicalizes the matrix, recomputes the SHA-256 digest, and verifies the Ed25519 signature against the pinned public provisioning key, per §3.8.

**Offline signing device options:**
- A dedicated Android device with the signing key in Keystore, kept offline except during provisioning.
- A hardware security token (e.g., YubiKey) supporting Ed25519.
- An air-gapped computer with the key in a software HSM.

**Key custody:** `docs/ops/KEY-CUSTODY.md` (TASK-P1-029) documents generation ceremony, storage, access control, use procedure, rotation, retirement, and audit for both the provisioning key and the recovery key.

**Key rotation (routine) — two distinct operations:**

1. **Authorization of the rotation (one-time event, recovery-key-signed).** A new provisioning key is generated offline. The rotation is authorized by a single `key_rotation` notice signed by the currently-trusted recovery key. The notice names the new provisioning key and specifies the overlap window duration (e.g., 30 days). This is the only operation that requires a recovery-key signature.

2. **Acceptance of matrices (ongoing, provisioning-key-signed).** Once the rotation is authorized:
   - During the overlap window, devices accept matrices signed by either the previous provisioning key or the current (new) provisioning key.
   - After the overlap window closes, devices accept matrices signed only by the current (new) provisioning key.
   - Matrices are signed with the provisioning key, not the recovery key. A matrix does not need a fresh recovery-key signature.

**Key compromise recovery (provisioning key):**

If the provisioning key is compromised, a signature from the possibly-compromised key cannot authorize its own revocation. The **independent recovery key** is the trust anchor for this case.

1. **Recovery key:** A separate Ed25519 keypair generated at organization setup. Public key is pinned on every device during initial provisioning, alongside the provisioning public key. Private key held offline under stricter custody (e.g., sealed in a safe with two-person control).

2. **Revocation notice:** The org signs a `key_revocation` message with the recovery key. The message includes:
   - `revoked_provisioning_key_id` (public key fingerprint)
   - `new_provisioning_key` (public key)
   - `effective_at` (timestamp)
   - `nonce` (unique)
   - `event_id` (unique)
   - `recovery_key_version` (integer, monotonically increasing)

3. **Distribution:** The revocation is distributed to all devices over the existing Tor channel, authenticated by the org's transport credentials — but the **authority** of the revocation comes from the recovery key signature, not the transport.

4. **Verification on device:** Device verifies the recovery key signature against the pinned recovery public key. If valid, the device:
   - Stops accepting matrices signed by the revoked provisioning key.
   - Accepts matrices signed by the new provisioning key going forward.
   - Records the event in the audit log.

5. **Recovery key rotation:** The recovery key should be rotated periodically (e.g., annually) or after any suspected compromise. Rotation itself is authorized by the recovery key, with the new recovery key distributed alongside.
   - Each recovery key has a monotonically increasing `version`.
   - Each device stores the highest `recovery_key_version` it has seen.
   - A recovery notice signed by a recovery key with `version ≤ highest_recovery_key_version` is **rejected** (stale notice protection).
   - A recovery notice signed by a recovery key with `version > highest_recovery_key_version` is accepted after signature verification, and the device updates `highest_recovery_key_version`.
   - Out-of-order delivery: if a valid notice for version 3 arrives after a valid notice for version 4, the v3 notice is rejected. The device does not roll back to v3.
   - Conflicting notices at the same version: the first valid one is accepted; subsequent notices at the same version are rejected. An admin needing to re-issue must increment the version.
   - This is the ONLY recovery mechanism. There is no alternate path. Compromise of the currently-trusted recovery key requires physical re-provisioning of all devices.

**Key compromise recovery (recovery key):**

If the recovery key is compromised, the situation requires physical re-provisioning of all devices. There is no cryptographic recovery path because the trust anchor is gone. This is a documented limitation and is why recovery key custody is treated with the strictest controls (offline, split control, regular rotation).

**Devices must never accept:**
- A matrix signed by a provisioning key after that key was revoked via recovery key, or after the overlap window closed following a rotation.
- A matrix signed by a provisioning key that has never been authorized (neither current nor within an open overlap window).
- A **rotation event** (a change to the trusted set of provisioning keys) not signed by the currently-trusted recovery key.
- A revocation of the recovery key signed by the provisioning key.
- A recovery notice with `recovery_key_version ≤ highest_recovery_key_version`.

### §3.7 AUTHORIZATION-MATRIX ANTI-ROLLBACK AND REPLACEMENT-DEVICE ENROLLMENT

**Anti-rollback:**
- Each matrix has a monotonically increasing `version`.
- Each device stores the highest `version` it has seen as `highest_seen_version`.
- A matrix with `version` ≤ `highest_seen_version` is **rejected**, even if validly signed.
- A matrix with `version` > `highest_seen_version` is accepted after signature verification and content validation.

**Replacement-device enrollment:**

A replacement device starts with no stored version. The design must ensure it does not accept a stale but validly-signed matrix.

1. **Enrollment is bound to current authorization state.** When the admin issues a replacement-device enrollment token, the backend records:
   - The current matrix `version` at the time of token issuance.
   - The token's `enrollment_matrix_version_floor` (equal to the recorded version).

2. **The replacement device accepts a matrix with `version` ≥ `enrollment_matrix_version_floor`.** The floor is a **minimum** acceptable version, **inclusive**. A matrix with `version < floor` is rejected. A matrix with `version = floor` is accepted during initial enrollment.

3. **After initial acceptance, the highest-seen rule applies.** Once the replacement device accepts a matrix at version V, it stores V as its `highest_seen_version`. Subsequent updates must have `version > highest_seen_version`. So if the device accepted v2 at enrollment, it will reject v2 on any later push.

4. **Fresh matrix only when needed.** If the current authorized matrix version equals the floor, the admin may push it directly. If the admin wants to reflect additional changes (revocations, additions), a matrix with a higher version is required.

5. **Peer identity-change notification.** When peers see the replacement device's new identity key, they receive an identity-change notification (per TASK-P1-030). Sending to the new device is blocked until the peer acknowledges.

6. **Stale enrollment tokens.** An enrollment token that has passed its TTL, been used, or been revoked is rejected. A token whose `enrollment_matrix_version_floor` is greater than the currently-authorized version is also rejected (indicates the token was issued against a superseded state).

**Integrated test (TASK-P1-030):**

The following scenario must pass end-to-end:
1. Provision 4 devices with matrix v1.
2. Revoke device A; matrix v2 issued.
3. Admin issues replacement-device token for A; token records `enrollment_matrix_version_floor = 2`.
4. Replacement device A' enrolls; receives matrix v2 floor (2).
5. Push matrix v2 to A'. **Accepted** (v2 = floor, inclusive). A' stores `highest_seen_version = 2`.
6. Attempt to push matrix v1 (validly signed, but stale) to A'. **Rejected** (v1 < highest_seen_version).
7. Attempt to push matrix v2 again. **Rejected** (v2 = highest_seen_version).
8. Peers receive identity-change notification for A'.
9. Peers block sending until they acknowledge the new key.
10. Old device A cannot re-enroll.
11. Audit log records the full sequence.

### §3.8 CANONICAL MATRIX SERIALIZATION (RFC 8785 JCS)

"Sorted keys, UTF-8, no whitespace" is insufficient. Two implementations could produce different bytes for the same logical matrix if they disagree on number formatting, Unicode escapes, or duplicate-key handling.

**The matrix is serialized using RFC 8785 JSON Canonicalization Scheme (JCS).**

Key properties of JCS:
- Object keys sorted by UTF-16 code unit order.
- No insignificant whitespace.
- Numbers serialized using ECMAScript `Number.prototype.toString()` rules (this matters for `version` — always serialized as an integer without a decimal point).
- Strings serialized per ECMAScript string rules; control characters escaped; no unnecessary escapes.
- Arrays preserve order (order is significant in JSON arrays).
- No duplicate keys allowed; if duplicate keys are detected, the matrix is invalid.

**The signed object is:**
```
{
  "domain": "umoja.authorization-matrix.v1",
  "matrix": { <the authorization matrix> }
}
```

The `domain` field provides domain separation to prevent a matrix signature from being used as a signature for any other object.

**Signature protocol (exact):**

1. Canonicalize the signed object using RFC 8785 JCS. Result: `canonical_bytes` (UTF-8).
2. Compute `digest = SHA-256(canonical_bytes)`. Result: 32 bytes.
3. Sign the 32-byte digest with the Ed25519 private key, treating the digest as the message. Result: 64-byte signature. (This is standard Ed25519 signing of a 32-byte message — **NOT** Ed25519ph.)
4. Transmit the signature as base64url without padding.

**Verification protocol (exact):**

1. Re-canonicalize the signed object using RFC 8785 JCS. Result: `canonical_bytes'`.
2. Compute `digest' = SHA-256(canonical_bytes')`.
3. Verify the Ed25519 signature against the 32-byte `digest'` using the pinned public key.
4. If verification fails, reject the matrix. If the canonical bytes differ from what the signer intended (e.g., due to number formatting), verification fails and the matrix is rejected.

**Test vectors must include:** the canonical bytes, the SHA-256 digest, the Ed25519 signature, and the pinned public key — for each vector. Both implementations must produce identical intermediate values, not just matching final verification results.

**Test vectors:** `docs/reference/canonical-matrix-test-vectors.json` contains known-input/known-output pairs. Both the offline signer and the Android verifier MUST produce identical canonical bytes for all vectors. This is an acceptance criterion for TASK-P1-026 and TASK-P1-033.

---

## §4 PHASE 1 SCOPE

**In scope:**
- Admin provisioning tool (Android admin mode)
- Device enrollment with locally-generated keys
- Contact authorization matrix
- E2EE 1:1 text messaging via libsignal
- Tor-only transport for messaging and signaling
- Encrypted local message store
- Server ciphertext envelope queue
- Server envelope expiration (30 days)
- Device revocation (messaging only)
- Emergency lock (TASK-P1-021a)
- Duress wipe (TASK-P1-021b)
- Audit log with hash chain
- Real-device acceptance testing

**Out of scope — do not implement, do not plan, do not add:**
Group messaging, calls, video, attachments, employee-controlled recovery, MDM, compliance retention, key transparency, cover traffic, padding, localization, admin web UI, iOS, BYOD, tablets.

---

## §5 THE TASK LIST

Execute tasks from `docs/US-TASK-P1-001.md` in dependency order.

**Task ID reconciliation table (v1.4.2):**

| Task ID | Deliverable | Status |
|---------|-------------|--------|
| TASK-P1-005 | libsignal Android integration (see §3) | Corrected |
| TASK-P1-013 | Backend stack (Node 24 LTS, Fastify 5.12.5, PG, opaque sessions, PG queue) | Corrected |
| TASK-P1-021a | Emergency lock (reversible) | Split from P1-021 |
| TASK-P1-021b | Duress wipe (destructive; see §3.3, §3.4) | Split from P1-021 |
| TASK-P1-025 | Admin provisioning tool (Android admin mode) | New |
| TASK-P1-026 | Organization-signed authorization matrix + client verification (JCS per §3.8) | Updated |
| TASK-P1-027 | SBOM generation and dependency review gate | New |
| TASK-P1-028 | Log redaction audit | New |
| TASK-P1-029 | Signing-key custody (provisioning + recovery keys) | Updated |
| TASK-P1-030 | Replacement-device flow (integrated test per §3.7) | Updated |
| TASK-P1-031 | Audit hash-chain verification and tamper-detection tests | Restored |
| TASK-P1-032 | Dependency-tree inspection | New |
| TASK-P1-033 | Offline provisioning-key signing workflow (JCS per §3.8) | Updated |
| TASK-P1-034 | Hardware-backed Ed25519 Keystore verification (TEE + StrongBox per §3.5) | Updated |
| TASK-P1-035 | Organization recovery key: generation, custody, revocation workflow | New |

**Critically:** the task registry file `docs/US-TASK-P1-001.md` must be updated to match this table **before any agent begins execution**. If the file still shows the old IDs, STOP and escalate.

**Acceptance criteria additions:**

- **TASK-P1-021b (Duress wipe):** wipe completes within 5s; messaging keys and session material unrecoverable; wipe-confirmation notification attempted per §3.4 with `event_id` and anti-replay; wipe-confirmation private key destroyed after notification attempt. Tested on spare hardware only. Tests must cover: crash between key destruction and notification; Tor unavailability at wipe time; duplicate notifications; old signed notification arriving after a newer wipe request.
- **TASK-P1-026 (Authorization matrix):** org signature binds device ID, public messaging identity key, clearance, and permitted contacts; stale matrices rejected; **post-initial-enrollment: version ≤ `highest_seen_version` rejected; initial enrollment (replacement device): inclusive floor applies — a matrix with `version = enrollment_matrix_version_floor` is accepted; after this first acceptance, all subsequent updates must have strictly greater version**; revoked devices excluded; replacement devices produce identity-change notification; peer identity changes detected. Canonical bytes match the RFC 8785 JCS test vectors. A QR code is transport, not authentication. Signing protocol per §3.8 (Ed25519 over SHA-256 of canonical bytes).
- **TASK-P1-030 (Replacement device):** integrated test per §3.7 must pass end-to-end, including the rule that v2 (equal to floor) is accepted at initial enrollment, and any subsequent push of v2 is rejected.
- **TASK-P1-034 (Keystore verification):** ordinary TEE-backed Ed25519 confirmed on every supported device model. StrongBox recorded separately. Feature-version check is necessary but not sufficient.
- **TASK-P1-035 (Recovery key):** recovery key generation ceremony documented; public key pinned on every device at initial provisioning; revocation workflow tested; recovery key rotation tested with monotonic version enforcement and out-of-order rejection; recovery key compromise documented as requiring physical re-provisioning.

---

## §6 DEPENDENCY AND AUDIT RULES

`npm audit` is a signal, not a gate.

**Google-dependency prohibition scope:** The prohibition applies to **runtime dependencies** — any package loaded at runtime in the backend or Android app. Build tooling (Gradle plugins, npm CLI tools) and repository hosts are not runtime dependencies and are not covered unless pulled into the shipped artifact.

**Required on every PR:**
1. `package-lock.json` committed and reviewed.
2. CycloneDX SBOM generated (`npm run sbom`) and attached to the PR.
3. `npm ls --all --json` saved to `artifacts/dep-tree.json` and reviewed for:
   - `@google/*`, `com.google.*`, `googleapis`, `gaxios`, `google-auth-library`, `firebase*`, `tink` (runtime dependencies only)
   - Any package without a resolved version
   - Any package newly added in this PR
4. `npm audit --audit-level=high` run; results triaged by a human.
5. Human approval required for **any** new dependency, including transitive.

**Vulnerability triage:**
- HIGH/CRITICAL: PR blocked until fixed or documented exception in `docs/security/DEPENDENCY-EXCEPTIONS.md` (CVE, rationale, mitigation, owner, expiry ≤90 days).
- MEDIUM/LOW: reported to human; documented acceptance.
- Unknown/ambiguous: STOP and escalate. Do not suppress.

**Agent must not** add `// eslint-disable`, `.npmrc` overrides, or `npm audit --omit` flags to silence warnings.

**Android side:** parse `./gradlew :app:dependencies --configuration releaseRuntimeClasspath` in CI; fail if any prohibited package appears in the resolved runtime tree. Verify libsignal artifacts are pinned to specific versions and that their AGPLv3 license is documented.

---

## §7 HOW TO WORK

For every task:
1. Read the task from `docs/US-TASK-P1-001.md`.
2. Read the referenced sections of `docs/US-MASTER-001.md` and `docs/US-ADD-001.md`.
3. Write a plan of 5–10 lines. Wait for human approval.
4. Write tests first, from the task's acceptance criteria.
5. Implement the minimum code to pass the tests.
6. Run the full suite locally.
7. Run typecheck and lint.
8. Run the dependency checks from §6.
9. Commit with a message referencing the task ID.
10. Update the task checklist.
11. **STOP.** Wait for human approval.

**Never:** proceed past a failing test by disabling it; modify a file outside declared scope; modify an applied migration; add a dependency without approval; touch native code without approval; guess on a security-relevant decision.

---

## §8 ESCALATION TRIGGERS AND FORMAT

**STOP and ask the human when ANY of these is true:**
- Cannot determine correct behavior from the docs.
- Docs contradict each other.
- A test fails and cause is unclear.
- Same fix attempted 3+ times without success.
- Task running >2 hours without a passing test.
- About to modify a file outside declared scope.
- About to add a dependency.
- About to touch native code.
- About to modify an applied migration.
- Uncertain whether a change is security-relevant.
- About to change auth, sessions, crypto, revocation, queue, or admin logic in a way not explicitly specified.
- About to make a design decision not covered by §3.

**Required escalation format:**
```
ESCALATION
Task ID: <task being executed>
Blocked issue: <exact question, contradiction, or failure>
Affected requirements: <requirement / ADR / spec section / test ID>
Evidence: <error output, test results, dependency details, conflicting text>
Security impact: <what could go wrong if the agent proceeds>
Options: <viable alternatives, including defer>
Recommendation: <agent's preferred option and rationale>
Approval required: <precise decision the human must make>
```

**Rule:** Do not implement a proposed solution, modify unrelated files, or continue into dependent tasks while awaiting approval.

---

## §9 DEFINITION OF DONE (EVERY TASK)

- [ ] Acceptance criteria met.
- [ ] Unit tests written and passing.
- [ ] Integration tests written and passing (if applicable).
- [ ] Adversarial tests written and passing (for security-relevant tasks).
- [ ] Full test suite passes.
- [ ] Typecheck passes.
- [ ] Lint passes.
- [ ] Dependency checks from §6 pass.
- [ ] No new dependency added without approval.
- [ ] No file outside task scope modified.
- [ ] Commit message references task ID.
- [ ] Task checklist updated.
- [ ] Human has reviewed the diff.

---

## §10 PHASE 1 DEFINITION OF DONE

Phase 1 is complete when:

- A Pixel running GrapheneOS can be provisioned by the admin tool.
- Two provisioned devices can exchange E2EE messages over Tor.
- The backend stores only ciphertext.
- No backend log contains plaintext, tokens, keys, or signatures.
- Device revocation terminates messaging WebSocket sessions within 5 seconds (`LISTEN/NOTIFY` + authoritative status check + reconciliation on listener reconnect).
- Emergency lock and duress wipe work on spare hardware — verified against the actual GrapheneOS version on the target Pixel model.
- Ordinary hardware-backed (TEE) Ed25519 Keystore is verified on target devices. StrongBox results recorded separately.
- Duress-password behavior (OS-level) is verified or explicitly disabled with documented rationale.
- Wipe notification behaves per §3.4, including anti-replay and the documented failure mode when Tor is unavailable.
- Audit chain verifies (TASK-P1-031).
- All Phase 1 tasks are marked complete.
- SBOM is generated and clean of prohibited runtime packages.
- An independent security reviewer has signed off.

---

## §11 ABSOLUTE PROHIBITIONS

Violating any of these requires reverting the entire session:

- Adding Firebase, FCM, Google Play services, Tink, or any `com.google.*` runtime dependency (source or transitive)
- Implementing any backend path that decrypts message content
- Storing private keys, Double Ratchet state, or plaintext server-side
- Using JWTs for sessions
- Using passwords, OAuth, or third-party identity providers
- Enabling clearnet fallback when Tor is unavailable
- Logging tokens, signatures, private keys, or message content
- Committing secrets or `.env` files with real values
- Using unpinned dependencies
- Weakening revocation (adding caches that preserve revoked access)
- Claiming compliance (FIPS, CUI, SOC 2, FedRAMP) without assessment
- Proceeding past a failing security-critical test
- Combining phases in one PR
- Guessing on security-relevant ambiguity
- Silencing dependency warnings without documented human approval
- Using `@signalapp/libsignal-client` (npm) as the Android crypto dependency
- Using `androidx.security:security-crypto` / EncryptedSharedPreferences
- Using Tink (`com.google.crypto.tink:tink-android`)
- Claiming "forensic unrecoverability" of wiped data
- Holding the organization provisioning private key in the admin app
- Treating StrongBox support as required for the wipe-confirmation key
- Accepting a matrix that has not been canonicalized per RFC 8785 JCS
- Accepting a provisioning key rotation event not signed by the recovery key
- Accepting a recovery notice with `recovery_key_version ≤ highest_recovery_key_version`
- Accepting a matrix with `version ≤ highest_seen_version` after initial enrollment
- Signing the raw canonical bytes instead of the SHA-256 digest (per §3.8)

---

## §12 QUICK START

If you are a new AI agent reading this:
1. Read this document completely.
2. Read `docs/US-MASTER-001.md` §Executive Summary and §Core Architecture.
3. Read `docs/US-TASK-P1-001.md` — confirm the task registry matches §5's reconciliation table. If not, STOP and escalate.
4. Check the task checklist to see what's done.
5. Ask the human: "Which task should I work on?"
6. Do not start any task without human confirmation.