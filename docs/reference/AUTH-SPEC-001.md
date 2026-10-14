# AUTH-SPEC-001 — Device Identity, Sessions, and Revocation

Document ID: AUTH-SPEC-001
Version: 0.1 (draft for owner review)
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
| Messaging WebSocket closure after revocation commit | `LISTEN/NOTIFY` on `device_revoked` channel + authoritative check | ≤5s |
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
2. **Full reconciliation on listener reconnect.** On listener disconnect
   or backend restart, query all devices with
   `status = 'revoked' AND revoked_at > last_reconciliation_time` and
   close any active connections for those devices.
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
enrollment_matrix_version_floor INTEGER NOT NULL
```

`bound_public_key` is the device authentication public key the token is
authorized to enroll.

`enrollment_matrix_version_floor` records the current matrix version at
the moment of token issuance. It is the **minimum inclusive** version the
newly enrolled device will accept at first enrollment (Build Master §3.7).

### §10.3 Consumption protocol

Consumption is a single atomic UPDATE:

```sql
UPDATE enrollment_tokens
   SET used_at = now()
 WHERE token_id = $1
   AND bound_public_key = $2
   AND used_at IS NULL
   AND expires_at > now()
RETURNING token_id, enrollment_matrix_version_floor;
```

Semantics:

- **Row-level lock** provides single-consumer semantics for free.
- **Zero rows returned** → reject. The token is already consumed, expired,
  does not exist, or the `bound_public_key` does not match.
- **One row returned** → the token is consumed by this request. Proceed
  with enrollment.

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

---

— end of AUTH-SPEC-001 v0.1 draft —
