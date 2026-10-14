# ADR-PROVISIONING-001: Provisioning Trust Boundaries and Authorization Matrix

Status: Accepted (pending commit)
Date: 2026-10-14
Authority: Derived from UMOJA-SECURE-BUILD-MASTER.md v1.4.2, US-MASTER-001, US-ADD-001, AUTH-SPEC-001, THREAT-MODEL-001
Scope: TASK-P1-025 (Admin provisioning tool), TASK-P1-026 (Authorization matrix + verification)
Session type: Design/plan-only. No production code.

---

## 1. Context

Phase 1's differentiator is admin-provisioned contacts. Provisioning is an
additional layer on top of the device identity defined in AUTH-SPEC-001,
not a parallel identity system. Every device that provisioning touches is
already, or will become, an authenticated device via challenge/verify.

This ADR resolves six threat-model questions and fixes the design
decisions that TASK-P1-025 and TASK-P1-026 implement. It is the boundary
between "design approved" and "implementation authorized."

---

## 2. Threat model resolutions

### Q1 — Rogue admin

**Boundary: accepted.** The admin device is trusted. An authorized admin
can act within their authority; the defense is audit, role separation,
and recovery-key revocation of a compromised provisioning key — not
prevention.

Grounding:
- Build Master §3.1 enumerates what admin can and cannot do. Wipe requests
  are recorded honestly as `REQUESTED` / `ACKNOWLEDGED` / `FAILED` /
  `STATUS_UNKNOWN`, never as proof of erasure.
- Build Master §3.2 removes the provisioning private key from the admin
  app entirely. The admin *cannot* forge a matrix, only request one.
- Build Master §3.6 authorizes recovery-key revocation of a compromised
  provisioning key.

Confirmed by project owner, 2026-10-14: admin device is trusted; defense
is audit + recovery-key revocation, not prevention.

### Q2 — Enrollment token replay

Three sub-cases. All resolved.

**Interception in transit.** Tokens are single-use, expiring, and bound at
issuance to the device's public keys (Build Master §3.2 step 1, §3.7
step 6). A token intercepted and presented by an attacker fails the
key-substitution check below. Transport is Tor-only in Phase 1.

**Concurrent consumption.** Consumption uses:

```sql
UPDATE enrollment_tokens
   SET used_at = now()
 WHERE token_id = $1
   AND used_at IS NULL
RETURNING token_id;
```

Row-level lock gives single-consumer semantics. Zero rows returned → the
token was already consumed; reject. This matches the existing pattern in
`consumeEnrollmentToken`. Acceptance test: two concurrent consumes,
exactly one succeeds.

**Key substitution.** `enrollment_tokens` gains a `bound_public_key BYTEA`
column populated at issuance. Consumption is:

```sql
UPDATE enrollment_tokens
   SET used_at = now()
 WHERE token_id = $1
   AND bound_public_key = $2
   AND used_at IS NULL
RETURNING token_id;
```

Mismatch → reject. Acceptance test: token issued against key K, presented
with key K′ → rejected; token not marked consumed.

Resolved by project owner, 2026-10-14.

### Q3 — Matrix forgery

Fully specified in Build Master; no design gap.

- §3.8 signature verifies against the pinned public provisioning key.
- §3.6 rejects matrices signed by revoked provisioning keys.
- §3.7 rejects version rollback via `highest_seen_version`.

A compromised backend serving a stale or revoked-key matrix fails
verification or version check at the device. Content validation is the
device's, not the backend's.

### Q4 — Offline revocation gap

**Boundary: server-authoritative enforcement only.**

Build Master §3.3 is explicit: the backend checks `devices.status` on
every protected request before accepting it. This check is authoritative.
`LISTEN/NOTIFY` is a prompt-wake mechanism; a missed notification is
covered by the per-request status check and by reconciliation on listener
reconnect.

If Device B is offline with a stale matrix and later messages revoked
Device A, the server rejects the envelope because A is revoked. B's local
matrix is irrelevant to delivery. B's contact list may show stale entries
until the next matrix push — a UX-visibility gap, not a security gap.

No client-side enforcement of revocation exists in the delivery path.
Client-side rules in §3.7 govern *matrix* anti-rollback only.

Confirmed by project owner, 2026-10-14: server-only.

### Q5 — Matrix rollback

Fully specified in Build Master §3.7; no design gap.

- Post-enrollment: device stores `highest_seen_version`; matrix with
  `version ≤ highest_seen_version` rejected.
- Initial enrollment (replacement device): `enrollment_matrix_version_floor`
  is a minimum, inclusive. `version = floor` accepted; `version < floor`
  rejected.
- After first acceptance, strictly-greater rule applies for all subsequent
  updates.
- Token with floor greater than currently-authorized version rejected
  (§3.7 step 6).

### Q6 — Provisioning key compromise

Fully specified in Build Master §3.6; no design gap.

- Recovery key signs a `key_revocation` notice naming the revoked
  provisioning key and the new one.
- Recovery public key is pinned on every device at initial provisioning.
- `recovery_key_version` is monotonic. Device stores
  `highest_recovery_key_version`.
- Notices with `version ≤ highest_recovery_key_version` rejected
  (out-of-order and replay protection).
- Same-version conflict: first valid accepted, subsequent rejected; an
  admin needing to reissue must increment the version.
- Compromise of the currently-trusted recovery key requires physical
  re-provisioning of all devices. No cryptographic recovery path. This
  is a documented limitation.

---

## 3. Signing protocol

The **signed unit is the wrapper**, not the inner matrix:

```json
{
  "domain": "umoja.authorization-matrix.v1",
  "matrix": { ... }
}
```

The `domain` field provides domain separation. It is load-bearing: a
signature over the inner matrix alone must fail verification.

**Signing (Build Master §3.8):**

1. Canonicalize the wrapper with RFC 8785 JCS → `canonical_bytes` (UTF-8).
2. `digest = SHA-256(canonical_bytes)` → 32 bytes.
3. Sign the 32-byte digest with Ed25519 (standard Ed25519 over a 32-byte
   message — **not** Ed25519ph).
4. Transmit signature as base64url, no padding.

**Verification:** re-canonicalize wrapper, SHA-256, verify Ed25519 against
the pinned public key.

Both the offline signer (TASK-P1-033) and the Android verifier
(TASK-P1-026) must produce byte-identical canonical bytes for every vector
in `docs/reference/canonical-matrix-test-vectors.json`.

---

## 4. Authorization matrix schema

Single source of truth: one TypeScript type and one Kotlin data class.

| Field | Type | Notes |
|-------|------|-------|
| `version` | integer | Monotonic. Serialized per JCS number rules. |
| `device_id` | string | |
| `pub_device_auth_key` | bytes | **Ed25519, Android Keystore.** Signs challenges. Not the messaging key. |
| `pub_messaging_identity_key` | bytes | **Curve25519, libsignal.** Goes into X3DH / Double Ratchet. Not the device auth key. |
| `pub_wipe_confirmation_key` | bytes | Ed25519. Used only for the fire-and-forget wipe notification (§3.4). |
| `clearance` | string | |
| `permitted_contacts` | array of device_id | Order significant; JCS preserves array order. |
| `issued_at` | string | ISO8601 UTC. |

`pub_device_auth_key` and `pub_messaging_identity_key` are **separate
columns in separate key systems**. They must never be conflated.

---

## 5. Test plan

Written first, from TASK-P1-025 / TASK-P1-026 acceptance criteria.

**Canonicalization and signing (TASK-P1-026):**

- TEST-MATRIX-010: Canonical bytes of the **wrapper** match test vectors
  on both the offline signer and the Android verifier.
  - **Negative assertion (sharp edge):** a signature computed over the
    inner matrix alone (without the `domain` wrapper) MUST fail
    verification. This proves the wrapper is load-bearing.
- TEST-MATRIX-011: Matrix with duplicate keys rejected.
- TEST-MATRIX-012: Numbers formatted differently (1.0 vs 1) canonicalize
  to identical bytes.
- TEST-MATRIX-013: Initial enrollment accepts matrix at version = floor.
- TEST-MATRIX-014: After first acceptance, push at same version rejected.
- TEST-MATRIX-015: After first acceptance, push at lower version rejected.

**Schema integrity (TASK-P1-025):**

- TEST-PROVSCHEMA-001: `pub_device_auth_key` and
  `pub_messaging_identity_key` are stored in distinct columns. A matrix in
  which they are swapped fails content validation.

**Enrollment token (TASK-P1-025):**

- TEST-TOKEN-CONCURRENT: Two concurrent consumes → exactly one succeeds.
- TEST-TOKEN-SUBSTITUTION: Token bound to key K, presented with K′ →
  rejected, token not consumed.

**Replacement device (TASK-P1-030, dependency):**

- TEST-REPLACE-009: After accepting v2 at enrollment, subsequent push of
  v2 rejected.
- TEST-REPLACE-010: After accepting v2 at enrollment, push of v1 rejected.

---

## 6. Finalized implementation plan

1. Read §8-referenced source files; run the two `find` commands; report
   any missing file against §6's repo layout before proceeding.
2. Land the matrix schema as one TS type and one Kotlin data class
   (§4 above). Separate columns for device auth key and messaging identity
   key.
3. Implement JCS canonicalization once per side (TS + Kotlin), driven by
   `docs/reference/canonical-matrix-test-vectors.json`. Both sides must
   produce byte-identical output for every vector **before** any signing
   code is written.
4. Implement sign/verify per §3.8: JCS(wrapper) → SHA-256 → Ed25519 over
   the 32-byte digest → base64url no-pad.
5. Build the QR ceremony (P1-025): device displays QR with three public
   keys (device auth, messaging identity, wipe-confirmation); admin scans;
   assigns clearance and groups; admin app produces unsigned matrix plus
   canonical hash.
6. Build the offline signing handoff (TASK-P1-033 boundary): admin app
   displays hash and matrix; offline signer re-canonicalizes, confirms
   hash, displays matrix for human confirmation, signs, returns signature
   over QR. The admin app never holds the provisioning private key.
7. Implement client verification and storage (P1-026): re-canonicalize
   wrapper, verify against pinned provisioning and recovery public keys,
   enforce `highest_seen_version` (post-enrollment) or inclusive floor
   (replacement), populate contacts from `permitted_contacts`.
8. Add the `bound_public_key BYTEA` column to `enrollment_tokens` and
   update `consumeEnrollmentToken` per §2 Q2.
9. Tests first, from the acceptance criteria and §5 above.
10. Dependency check per Build Master §6 before commit. No new
    dependencies without approval.
11. **STOP.** Commit the ADR and the plan. Await human review before
    Session A's first production code.

---

## 7. Provenance and open items

**Provenance.** The four referenced files (US-MASTER-001, US-ADD-001,
AUTH-SPEC-001, THREAT-MODEL-001) did not arrive in the working session;
file transmission failed repeatedly. Q1 and Q4 were cleared by explicit
project-owner attestation on 2026-10-14. Q2 was resolved by explicit
project-owner direction on the same date. Q3, Q5, and Q6 are fully
specified in Build Master v1.4.2 and required no attestation.

**Pre-Session-A items — all resolved:**

- Q2 concurrent consumption: resolved (§2 Q2).
- Q2 key substitution: resolved (§2 Q2).
- Q1/Q4 provisional tags: cleared by owner attestation.
- targetSdk: spec value 35 (Build Master §3); current build value 36
  (handoff §2). Reconciliation deferred; not blocking.

**Residual honesty item, not a blocker.** File-level verification of Q1
and Q4 against THREAT-MODEL-001 and AUTH-SPEC-001 has not been performed
in-session. Perform it at Session A kickoff, before the first production
commit. If either contradicts the attestation, STOP and escalate per
Build Master §0.

**Not in scope for this ADR:** the replacement-device flow itself
(TASK-P1-030), the recovery-key ceremony (TASK-P1-035), and the offline
signer implementation (TASK-P1-033) are named here only where this ADR
depends on them.

---

## 8. Stop

This ADR authorizes the *plan*. It does not authorize production code.
Session A begins only after the human commits this document and gives
explicit go-ahead.

— end of ADR —