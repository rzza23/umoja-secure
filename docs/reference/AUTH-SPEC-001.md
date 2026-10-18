# AUTH-SPEC-001 — Device Identity, Sessions, and Revocation

Document ID: AUTH-SPEC-001
Version: 0.3 (TASK-P1-042 landed 2026-10-18)
Date: 2026-10-14
Authority: Derived from UMOJA-SECURE-BUILD-MASTER.md v1.4.2, plus project-owner attestation on the same date.
Status: Draft. Not yet in force. Subject to revision.

---

## §1 Provenance

Authored 2026-10-14. Did not exist on disk prior to this date. Grounded in
Build Master v1.4.2 and owner attestation recorded in
`docs/architecture/ADR-PROVISIONING-001.md` §2.

This document is the authoritative source on device identity generation,
session lifecycle, and revocation guarantees. THREAT-MODEL-001 §9
cross-references it; the direction of authority is this document.

---

## §2 Purpose

Define the authentication and authorization model for Umoja Secure Phase 1
so that provisioning (TASK-P1-025, TASK-P1-026) composes with it rather
than duplicating or overriding it.

---

## §3 Scope

**In scope:** device identity keys, challenge/response authentication,
opaque server-side sessions, session revocation, enrollment token
authorization, revocation guarantees.

**Out of scope:** passwords, OAuth, third-party identity providers, JWTs.
All prohibited by Build Master §3 and §11.

---

## §4 Key inventory

Four device-side keys. Each has a distinct purpose and a distinct
lifecycle. They must never be conflated.

| Key | Algorithm | Storage | Purpose |
|---|---|---|---|
| Device authentication key | Ed25519 | Android Keystore, TEE-backed where available | Signs challenge-response during auth. Registered with backend at enrollment. |
| Messaging identity key | Curve25519 (libsignal) | libsignal store, Keystore-wrapped | X3DH and Double Ratchet. Public part goes into the authorization matrix as `pub_messaging_identity_key`. |
| Signed prekey + one-time prekeys | libsignal | Local | Uploaded public parts; private parts local. |
| Wipe-confirmation key | Ed25519 | Android Keystore | Signs one fire-and-forget wipe notification (§3.4 of Build Master). |

Two organization-side keys, held offline:

| Key | Algorithm | Custody | Purpose |
|---|---|---|---|
| Provisioning key | Ed25519 | Offline, standard custody | Signs authorization matrices. |
| Recovery key | Ed25519 | Offline, stricter custody | Authorizes provisioning-key rotation and revocation. |

The device authentication key is **not** the messaging identity key. These
live in separate key systems. A matrix in which they are swapped is
malformed and rejected (see THREAT-MODEL-001 §9).

---

## §5 Device identity generation

### §5.1 Device authentication key

- **Algorithm:** Ed25519.
- **Storage:** Android Keystore. Hardware-backed (TEE) where available.
  StrongBox is **not** required and is not assumed. See Build Master §3.5
  and TASK-P1-034.
- **Non-exportable.** The private key never leaves the Keystore.
- **Persistent** across device reboot.
- **Generated on-device.** Never transmitted, never escrowed, never
  derived from a passphrase.
- **Public key registered** with the backend at enrollment, and bound into
  the authorization matrix as `pub_device_auth_key`.

**Emulator fallback:** BouncyCastle software Ed25519 is used on emulator
instances where TEE-backed Keystore is unavailable. This is a development
convenience and **must not** be shipped to production hardware. A future
TASK-P1-034 acceptance criterion requires TEE-backed generation on every
supported Pixel model.

### §5.2 Messaging identity key

- **Algorithm:** Curve25519 (libsignal).
- **Storage:** libsignal's store, wrapped by Keystore.
- **Public part** is registered with the backend as part of the prekey
  bundle and bound into the authorization matrix as
  `pub_messaging_identity_key`.
- **Never used for authentication** to the backend. It is a messaging
  primitive, not an auth primitive.

### §5.3 Wipe-confirmation key

- **Algorithm:** Ed25519.
- **Storage:** Android Keystore.
- **Separate** from the device authentication key. A key used for
  fire-and-forget notification must not be the key used for interactive
  authentication.
- **Destroyed after use** (per Build Master §3.4). One wipe per key
  lifetime.

### §5.4 Key generation sequence

1. Device generates all four keys locally on first run.
2. Device displays a QR containing the three **public** keys (device auth,
   messaging identity, wipe-confirmation).
3. Admin scans and records the public keys.
4. Private keys never leave the device.

### §5.5 Prohibited

Per Build Master §11:

- No passwords.
- No OAuth.
- No third-party identity providers.
- No JWTs for sessions.
- No pre-shared private keys.
- No private-key escrow.

---

## §6 Session lifecycle

### §6.1 Session tokens

- **Opaque server-side tokens.** Not JWTs. Immediate revocation is
  required, and JWTs cannot be revoked without a server-side blocklist —
  which defeats the point of a JWT.
- **Storage on device:** Android Keystore-backed AES-256-GCM. DataStore
  may hold the ciphertext; the encryption key is held in Keystore and the
  token is never written in plaintext.
- **Prohibited storage:** `androidx.security:security-crypto` /
  EncryptedSharedPreferences (deprecated, no drop-in replacement);
  Tink (Google runtime dependency, violates Build Master §6).

### §6.2 Challenge / response flow

1. **POST /auth/challenge** — device sends `device_id`. Backend issues a
   random nonce, records it with a short TTL, returns it.
2. Device signs the nonce with the **device authentication key**
   (Ed25519, Keystore-held).
3. **POST /auth/verify** — device sends `device_id`, nonce, and signature.
   Backend verifies the signature against the registered
   `pub_device_auth_key`.
4. On success, backend issues an opaque session token, records the
   session, returns the token.
5. Device stores the token encrypted at rest (§6.1).

The nonce is single-use. A replayed nonce is rejected.

**v0.2 implementation notes** on §6.2 step 3:

- **Signature length check.** A signature whose byte length is not
  exactly 64 (Ed25519 signature size) is rejected as `unauthorized`.
  No separate error code; malformed and invalid signatures are
  indistinguishable to the caller.
- **Algorithm check.** A device whose registered `public_key_alg` is
  not `ed25519` is rejected with 501 `unsupported_algorithm`. Phase 1
  enrolls only Ed25519 devices; the check exists so a future
  non-Ed25519 registration fails closed rather than falling through.
- **`session_context` field.** The canonical challenge signed in
  step 2 includes a `session_context: string | null` field. In
  Phase 1 it is always `null` (the verify path hardcodes it). If a
  future use of the challenge for sensitive operations needs to bind
  the challenge to a session, this field is where that binding goes.
  Because the field is in the canonical bytes, changing it changes
  the signature — no protocol-level retrofit is needed.

### §6.3 Revalidation

- Periodic revalidation cycle: **5 minutes** (Build Master §3.3).
- Revalidation checks the session is still valid and the device is not
  revoked.
- Revocation does **not** wait for the next revalidation cycle — it acts
  immediately (§9).

### §6.4 Logout

- **POST /auth/logout** — device presents the session token; backend
  marks the session terminated.
- Session is removed server-side. Device deletes its local copy.

### §6.5 Revocation interaction

When a device is revoked (§9), the session is invalidated immediately:

- Next request from the device is rejected (≤1s).
- Active **messaging** WebSocket sessions are closed within ≤5s.
- No new envelopes are delivered.

Call-signaling WebSocket sessions are **not** covered in Phase 1 — calls
are out of scope. That termination is a Phase 3 requirement (Build Master
§3.1).

---

## §7 Authorization model

### §7.1 Roles

| Role | Description |
|---|---|
| Admin | Server-side actor with a valid admin credential. Authority bounded by Build Master §3.1. |
| Device | An enrolled, authenticated device. Belongs to one organization. |

No self-registration. Every device is enrolled via an admin-issued,
single-use enrollment token (§10).

### §7.2 Contacts

- Contacts are **bidirectional** and **admin-authorized**. A device cannot
  self-authorize a contact.
- The authorization matrix binds `permitted_contacts[]` per device. The
  client trusts the matrix only after verifying the organization
  provisioning key signature (Build Master §3.8).
- Contact revocation is a server-side admin action that propagates via the
  next matrix push.

### §7.3 Clearance

- Each device has a `clearance` value set by the admin at provisioning.
- Clearance is currently informational; Phase 1 does not gate message
  delivery on clearance. It is bound into the matrix for future use and
  for audit.

### §7.4 What the client trusts for authorization

The client trusts:

- The matrix signature against the pinned public provisioning key.
- The matrix version rules (Build Master §3.7).

The client does **not** trust the backend to make authorization decisions.
Authorization is enforced by matrix verification. The backend enforces
revocation (§9) but does not itself determine which devices are
authorized to communicate.

---

## §8 Backend session storage

- PostgreSQL 16.
- Sessions are rows in a `sessions` table with an opaque token ID, a
  device reference, an issued-at timestamp, and a terminated-at timestamp.
- Lookup is by opaque token ID. No cryptographic claims are embedded in
  the token.
- Termination is a single-row update. Immediate.

There is no caching layer that could preserve access after a session is
terminated. Build Master §11 prohibits adding one.

---

## §9 Revocation guarantees

### §9.1 Enforcement is server-authoritative

Revocation is enforced by the backend on every protected request. Client
devices do not enforce revocation in the delivery path. This was
confirmed by project-owner attestation on 2026-10-14 (Q4) and recorded in
ADR-PROVISIONING-001 §2.

### §9.2 Timings

| Guarantee | Mechanism | Target |
|---|---|---|
| Request rejection after revocation commit | Per-request `devices.status` check | ≤1s |
| Messaging WebSocket closure after revocation commit — listener healthy | `LISTEN/NOTIFY` on `device_revoked` channel + authoritative check | ≤5s |
| Messaging WebSocket closure after revocation commit — listener disconnected (v0.3) | Reconnect (≤5s fixed interval) + reconcile on every successful connect; 5-min revalidation is independent backstop if reconnect itself repeatedly fails | ≤5s after reconnect fires |
| No new envelopes delivered | Per-request status check at delivery | Immediate |

Call-signaling WebSocket termination is **not** a Phase 1 guarantee.
Phase 3 only.

### §9.3 LISTEN/NOTIFY is a prompt-wake, not a durable queue

Per Build Master §3.3: PostgreSQL does **not** store notifications. It
drops them for any connection not listening at that exact moment. A
missed notification must never leave an active connection alive.

Defenses, in order:

1. **Authoritative status check** on every protected request. This alone
   is sufficient to reject a revoked device's next request.
2. **Full reconciliation on backend process startup.** At process
   startup, query all devices with `status = 'revoked'` and close
   any active connections for those devices. (v0.2 implementation
   note: the current code runs this pass only at startup, not on
   mid-run listener reconnect. Mid-run listener disconnection is
   covered by defense (3), the 5-minute revalidation cycle.
   TASK-P1-042 (fixed at commit 07cc2b4) closes the gap: the
   listener now reconnects on connection loss (5s fixed interval)
   and re-runs reconciliation on every successful connect, before
   reporting ready. See §9.2 for the updated timing.)
3. **Periodic revalidation** as a backstop (5-minute cycle, §6.3).

### §9.4 What revocation does and does not do

**Does:**

- Reject the revoked device's next authenticated request.
- Close its active messaging WebSocket sessions.
- Stop delivery of new envelopes to it.

**Does not:**

- Wipe the device (that is a separate wipe request; Build Master §3.3).
- Prevent the device from reading locally stored plaintext it already has.
- Prevent the device from attempting to connect (it will be rejected).
- Roll back the device's locally held matrix (the device will accept a new
  matrix when one is pushed; the old matrix remains until then — see
  THREAT-MODEL-001 §8).

---

## §10 Enrollment token authorization

### §10.1 Properties

- **Single-use.**
- **Expiring** (TTL enforced at consumption).
- **Admin-issued**, scoped to one organization.
- **Bound at issuance** to the device's public keys — specifically to a
  `bound_public_key` value recorded in the `enrollment_tokens` row.

### §10.2 Schema addition

`enrollment_tokens` gains:

```
bound_public_key BYTEA NOT NULL
enrollment_matrix_version_floor INTEGER  -- nullable; v0.2 note below
```

`bound_public_key` is the device authentication public key the token is
authorized to enroll.

`enrollment_matrix_version_floor` records the current matrix version at
the moment of token issuance. It is the **minimum inclusive** version the
newly enrolled device will accept at first enrollment (Build Master §3.7).

**v0.2 nullability note.** The floor column is `INTEGER` (nullable)
with a `CHECK (enrollment_matrix_version_floor IS NULL OR
enrollment_matrix_version_floor >= 1)` constraint, not `NOT NULL`.
Nullable by design: the first device in a fresh organization enrolls
before any matrix version has been asserted, so there is no current
version to stamp as a floor. A NULL floor means "no floor constraint
on first accept." The CHECK enforces positivity when a floor is
present. An earlier draft of this section said `NOT NULL`; the
migration (014) correctly uses nullable.

### §10.3 Consumption protocol

Consumption runs inside a single database transaction. The sequence:

1. **SELECT … FOR UPDATE** the token row:

```sql
SELECT token_id, org_id, role, expires_at, used_at, revoked_at,
       enrollment_matrix_version_floor
  FROM enrollment_tokens
 WHERE token_hash = $1 AND bound_public_key = $2
   FOR UPDATE;
```

2. **In application code**, reject if the row is missing, `revoked_at`
   is set, `used_at` is set, or `expires_at <= now()`. Reject as
   `invalid_token` — the spec deliberately does not distinguish
   "unknown token" from "already consumed" from "bound-key mismatch";
   distinguishing would leak whether a token_id exists.

3. **INSERT INTO devices** the new device row, using the
   client-supplied `device_id`. A `23505` unique-violation on
   `devices` (from a device_id or public_key collision) rejects with
   `device_already_enrolled` and rolls back the transaction.

4. **UPDATE enrollment_tokens** `SET used_at = now(),
   used_by_device_id = $2 WHERE token_id = $1`.

5. **Commit.**

Semantics:

- **Row-level lock** (`SELECT … FOR UPDATE`) provides single-consumer
  semantics. A concurrent consumer hashing to the same token sees the
  row locked, re-reads after the first consumer commits, and hits the
  `used_at IS NOT NULL` check — rejected. The property stated in the
  earlier draft — "single atomic UPDATE, row-level lock provides
  single-consumer semantics for free" — is preserved. Only the
  mechanism differs from that draft: the operation is
  transactionally atomic, not a single SQL statement.
- **Row absent** → reject as `invalid_token`.
- **Row present but `revoked_at` set, `used_at` set, or `expires_at
  <= now()`** → reject as `invalid_token`.
- **Row present and clean** → proceed with steps 3–5.

### §10.4 Rejections

A token is rejected if any of:

- `used_at` is not NULL (already consumed).
- `expires_at` is not in the future (expired).
- `bound_public_key` does not match the presented key (substitution
  attempt).
- The row does not exist.
- `enrollment_matrix_version_floor` is greater than the currently
  authorized matrix version (token was issued against a superseded state
  — Build Master §3.7 step 6).

### §10.5 Replay resistance

- **Interception in transit:** transport is Tor-only in Phase 1. Even if
  intercepted, the token cannot be used for a different device — the
  `bound_public_key` check rejects substitution.
- **Concurrent consumption:** the atomic UPDATE ensures exactly one
  consumer succeeds. Acceptance test: two concurrent consumes, exactly
  one winner.
- **Replay after consumption:** `used_at IS NULL` guard rejects.

### §10.6 Token issuance

Issued by an admin via `POST /admin/enrollment-tokens`. At issuance:

- A fresh random `token_id` is generated.
- The current matrix version is read and stored as
  `enrollment_matrix_version_floor`.
- The device's intended public authentication key is stored as
  `bound_public_key`.
- The token is returned to the admin for distribution to the device.
  Distribution is out-of-band; Phase 1 does not specify the channel.

### §10.7 Token revocation

An unconsumed token can be revoked via
`POST /admin/enrollment-tokens/:id/revoke`. Revoked tokens are treated
as consumed for the purposes of §10.3 (the `used_at` column is set, or a
separate `revoked_at` column is checked in the WHERE clause; either is
acceptable as long as the WHERE clause excludes it).

---

## §11 Interaction with provisioning

Provisioning (TASK-P1-025, TASK-P1-026) is an additional layer on top of
this spec, not a parallel identity system.

- The `pub_device_auth_key` bound into the matrix is the same key used
  for challenge/response in §6.2.
- The `pub_messaging_identity_key` bound into the matrix is the same key
  registered via the prekey upload endpoint.
- Enrollment token authorization (§10) is the mechanism by which a device
  transitions from "unauthenticated" to "holding a valid session."
- Matrix issuance and distribution happen after enrollment, over the
  authenticated session.

See THREAT-MODEL-001 §9 for the composition note from the threat-model
side.

---

## §12 Out of scope

- Password-based auth (prohibited).
- OAuth or third-party identity (prohibited).
- JWTs (prohibited).
- Multi-factor beyond the device key itself.
- Account recovery (there is no account; there is a device).
- Employee-controlled recovery of any kind (Phase 1 out of scope,
  Build Master §4).

---

## §13 Revision history

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-10-14 | Initial draft. Authored from Build Master v1.4.2 + owner attestation. |
| 0.2 | 2026-10-18 | Conformance sweep vs. code at HEAD (032bc8b). Four amendments to match implementation, one task filed (TASK-P1-042). See §13.1. |
| 0.3 | 2026-10-18 | TASK-P1-042 fixed at commit 07cc2b4. §9.2 listener-disconnected row updated: reconnect (≤5s fixed interval) + reconcile on every successful connect; 5-min revalidation is now the independent backstop if reconnect itself repeatedly fails. §9.3 defense 2 updated: reconciliation now runs on every successful connect (startup and reconnect alike), before the listener reports ready. Closes the gap this document’s v0.2 amendment named. |

---

### §13.1 v0.2 conformance sweep findings

Session sweep of AUTH-SPEC-001 against code at HEAD. Method: read every
auth-related file, compare each claim against actual behavior, classify
each divergence as doc-drift / real gap / coverage gap / holds.

**Amended to match code (doc-drift, code correct):**

- §10.2: `enrollment_matrix_version_floor` is nullable with CHECK, not
  `NOT NULL`. Migration 014's reasoning: fresh-org first enrollment has
  no version to floor against.
- §10.3: consumption is `SELECT FOR UPDATE` + INSERT + UPDATE in a
  transaction, not a single `UPDATE`. The single-consumer property
  holds; only the mechanism prose was wrong.
- §9.2 / §9.3: reconciliation runs at process startup only, not on
  listener reconnect. The 5-minute revalidation cycle is the
  mid-run-listener-disconnect backstop.

**Precision amendments (spec self-clarifying):**

- §6.2: added v0.2 notes on signature-length check, `public_key_alg`
  check, and the `session_context` field.

**Real gap filed as TASK-P1-042:**

- §9.3 defense (2): "Full reconciliation on listener reconnect." The
  code runs startup-only reconciliation; on mid-run LISTEN connection
  error the handler logs and does not reconnect. The 5-minute
  revalidation cycle covers the failure mode, but the spec's own
  defense is unimplemented. Filed with required tests
  TEST-REVOCATION-RECONNECT-ON-ERROR,
  TEST-REVOCATION-RECONCILES-AFTER-RECONNECT,
  TEST-REVOCATION-STOP-CANCELS-RECONNECT.

**Confirmed correct as written (no amendment):**

- §6.1 (opaque tokens, not JWT), §6.4 (logout via `revokeSession`),
  §6.5 (revocation invalidates sessions), §9.1 (per-request status
  check via `requireSession` → `lookupSession`), §9.2 core
  (`LISTEN/NOTIFY` prompt-wake exists and is wired in
  `ws/revocation.ts` + `admin/devices.ts`), §10.1 / §10.5 / §10.6 /
  §10.7 (single-use, replay-resistant, admin-issued, revocable).

**Out of scope, unchanged:** §6 client-side 401 handling. The spec
scopes itself to server behavior; `SessionStateManager.kt` and the
040-era client wiring are documented in the handoff and
ADR-HARDENING-001 §2, not here.

— end of AUTH-SPEC-001 v0.3 draft —
