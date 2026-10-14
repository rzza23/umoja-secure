# THREAT-MODEL-001 — Umoja Secure Phase 1

Document ID: THREAT-MODEL-001
Version: 0.1 (draft for owner review)
Date: 2026-10-14
Authority: Derived from UMOJA-SECURE-BUILD-MASTER.md v1.4.2, plus project-owner attestation on the same date.
Status: Draft. Not yet in force. Subject to revision.

---

## §1 Provenance

This document did not exist prior to 2026-10-14. It is authored, not
discovered. A machine-wide search on that date found `US-TASK-P1-001.md`
and nothing else from the canonical document set listed in Build Master
§2.

The document is grounded in:
- Build Master v1.4.2 (frozen), specifically §1, §3.1–§3.8, §10, §11.
- Project-owner answers to the six provisioning threat-model questions,
  recorded in `docs/architecture/ADR-PROVISIONING-001.md` §2.

Until a superseding revision exists, this document carries the authority
of the requirements layer for the questions it addresses, per Build Master
§0. It is not derived from an external review. It is the project owner's
statement of the threat model, formalized.

---

## §2 Scope

**In scope:** Phase 1 as defined by Build Master §4 — admin-provisioned
1:1 text messaging over Tor, with no Google runtime dependencies, on a
GrapheneOS-first device baseline.

**Out of scope:** Group messaging, calls, attachments, MDM, compliance
retention, key transparency, cover traffic, padding, iOS, BYOD, tablets.
All deferred per Build Master §4.

**Explicitly not claimed:** This document does not claim FIPS, CUI,
SOC 2, FedRAMP, or any other compliance posture. Per Build Master §11,
such claims require independent assessment and are not made here.

---

## §3 Assets

What this system protects, in rough order of severity of compromise:

| Asset | Where it lives | Consequence of compromise |
|---|---|---|
| Message plaintext | Device only | Mission compromise |
| Private messaging keys (libsignal) | Device only, Keystore-wrapped | Impersonation, historical decryption |
| Double Ratchet state | Device only | Session compromise |
| Device authentication key (Ed25519) | Device Keystore | Impersonation at auth layer |
| Wipe-confirmation key (Ed25519) | Device Keystore | Forged wipe confirmation (limited impact — see §6.4) |
| Organization provisioning key | Offline | Matrix forgery — see §7 |
| Organization recovery key | Offline, stricter custody | Loss of trust anchor — see §8 |
| Authorization matrix | Device + backend | Contact-graph disclosure; stale-access window |
| Session tokens | Device (Keystore-encrypted) + backend (opaque) | Session hijack until revoked |
| Ciphertext envelopes | Backend | Traffic analysis only; content opaque |
| Audit log | Backend | Deniability / non-repudiation loss |
| Enrollment tokens | Backend, single-use | Unauthorized device enrollment |

The backend does **not** hold: private keys, plaintext, Double Ratchet
state, or anything from which those can be derived.

---

## §4 Adversary classes

| # | Adversary | Capability assumed |
|---|---|---|
| A1 | Passive network observer | Sees traffic to/from the backend. Defeated by Tor. |
| A2 | Active network adversary | Can inject, drop, delay. Defeated by Tor + E2EE; DoS not prevented. |
| A3 | Compromised backend | Full server control. Cannot decrypt; can lie about revocation status, serve stale matrices, drop envelopes. |
| A4 | Malicious enrolled device | Full control of its own device. Can attempt impersonation, replay, matrix tampering. |
| A5 | Rogue admin (authorized) | Valid admin credentials. Can act within admin authority. See §7. |
| A6 | Compromised provisioning key holder | Has the offline provisioning private key. See §8. |
| A7 | Physical device attacker | Has the device. Defeated by GrapheneOS controls + wipe (§6.3). |
| A8 | Supply-chain attacker | Malicious dependency, malicious build. See Build Master §6. |

A5 and A6 are the adversaries this document exists to bound.

---

## §5 STRIDE — provisioning subsystem

Provisioning = QR ceremony + matrix issuance + matrix distribution +
matrix verification. STRIDE applied to that subsystem.

| Threat | Vector | Mitigation | Residual |
|---|---|---|---|
| **S**poofing | Device presents another device's public keys at QR ceremony | Keys generated on-device, never leave; admin visually verifies QR | Physical coercion of admin during ceremony |
| **S**poofing | Attacker impersonates admin to push matrices | Matrix signed by organization provisioning key; device verifies against pinned pubkey | None if key custody holds |
| **T**ampering | Matrix modified in transit | Signature verification (§3.8) | None |
| **T**ampering | Matrix modified by compromised backend | Same | None |
| **R**epudiation | Admin denies issuing a token | Audit log, hash-chained (TASK-P1-031) | If audit log itself compromised |
| **I**nformation disclosure | Matrix contents reveal contact graph | Matrix is end-to-end between offline signer and device; backend sees it too | Backend sees the matrix by design — documented |
| **I**nformation disclosure | QR code photographed by third party | QR carries public keys only | None — public keys are public |
| **D**enial of service | Attacker floods enrollment endpoint | Rate limiting (§3.7 step 6, token TTL) | DoS not fully prevented — accepted |
| **E**levation of privilege | Enrollment token used for a different device | `bound_public_key` check (§6.2) | None |
| **E**levation of privilege | Revoked provisioning key still signs a matrix | Device rejects per §3.6; overlap window governs acceptance | None if client rules enforced |

---

## §6 Specific threat resolutions

### §6.1 — Rogue admin (Q1)

**Boundary: admin device is trusted.**

An authorized admin can act within their authority. The defense is audit,
role separation, and recovery-key revocation of a compromised
provisioning key — not prevention.

Consequences of this boundary, stated plainly:

- An admin can revoke a device that should not be revoked. The audit log
  records it. Recovery is re-enrollment.
- An admin can request a wipe that the device owner did not authorize.
  The wipe notification is honest about its own uncertainty (§3.4). The
  device executes it.
- An admin **cannot** forge a matrix. Build Master §3.2 removes the
  provisioning private key from the admin app. A matrix without a valid
  signature from the offline signer is rejected by every device.

This boundary is accepted. It is not a gap.

### §6.2 — Enrollment token replay (Q2)

Three sub-cases, all resolved:

**Interception in transit.** Token is single-use, expiring, bound at
issuance to the device's public keys. Transport is Tor-only in Phase 1.

**Concurrent consumption.** Consumption uses
`UPDATE ... WHERE used_at IS NULL RETURNING`. Row lock gives
single-consumer semantics. Two concurrent consumes: exactly one succeeds.

**Key substitution.** `enrollment_tokens.bound_public_key` matched at
consumption. Mismatch → reject, token not consumed.

### §6.3 — Physical device attacker (A7)

The app assumes the device may or may not have GrapheneOS-level controls
enabled. Specifically:

- Duress PIN + duress password (both required by GrapheneOS; triggering
  wipes the device)
- Auto-wipe after N failed unlocks
- USB-C disabled when locked
- Screenshot blocking

These are user responsibilities, not admin-controlled. The app does not
rely on them.

What the app **does** guarantee:
- Private keys live in Android Keystore (TEE-backed where available)
- Local storage is AES-GCM encrypted with a Keystore-held key
- Duress wipe (TASK-P1-021b) destroys keys and session material in ≤5s
- Wipe-confirmation notification is best-effort (see §6.4)

What the app does **not** guarantee:
- Forensic unrecoverability of storage remnants. Per Build Master §3.4,
  the guarantee is *cryptographic erasure* — the keys are gone and no
  path exists to re-derive them from app storage. It is not that no
  physical remnant exists.

### §6.4 — Wipe-confirmation forgery

The wipe-confirmation key signs a fire-and-forget notification that the
device has wiped. A valid signature proves **the holder of the private
key signed a claim**. It does not prove the app's data was erased.

This is honest in the backend: the event is recorded as
`device_reported_wipe_complete`, never as `verified_erasure`. The admin
UI must not imply success. Build Master §3.3 requires the states
`REQUESTED`, `ACKNOWLEDGED`, `FAILED`, `STATUS_UNKNOWN`.

A forged notification (by a compromised device that has not actually
wiped) causes the backend to mark the wipe as reported. It does not
grant any privilege. The compromised device still cannot read messages,
because the messaging keys are still wrapped by Keystore — which
theoretically the attacker controls if they've compromised the device,
in which case they've already won. The forging scenario is low-severity.

### §6.5 — Compromised backend (A3)

The backend cannot decrypt anything. What it can do:

- Lie about revocation status → mitigated by client-side matrix
  anti-rollback (§3.7). A device that has seen v5 refuses to accept v4
  even if the backend serves it.
- Serve a stale matrix → same mitigation.
- Drop or delay envelopes → DoS, not a confidentiality breach.
- Serve a matrix signed by a revoked provisioning key → device rejects
  per §3.6.

A compromised backend cannot forge a matrix. It does not hold the
provisioning private key.

### §6.6 — Matrix rollback (Q5)

Fully specified in Build Master §3.7. Client stores
`highest_seen_version`. Post-enrollment, `version ≤ highest_seen_version`
is rejected. Replacement-device enrollment uses an inclusive floor:
`version = enrollment_matrix_version_floor` accepted once at initial
enrollment, strictly-greater thereafter.

### §6.7 — Provisioning key compromise (Q6)

Fully specified in Build Master §3.6. Recovery key signs a
`key_revocation` notice; devices verify against the pinned recovery
public key. `recovery_key_version` is monotonic; out-of-order notices
rejected; conflicting same-version notices rejected (first wins,
subsequent requires version increment).

Compromise of the currently-trusted recovery key requires physical
re-provisioning of every device. No cryptographic recovery path. This is
a documented limitation, not an oversight.

---

## §7 Trust boundaries

**What the admin plane can and cannot do** (Build Master §3.1):

| Can | Cannot |
|---|---|
| Revoke a device (server-side, ≤1s request rejection, ≤5s WS closure) | Wipe an offline device |
| Request a wipe (executed on next connectivity) | Force-lock an offline device |
| Create/revoke enrollment tokens | Read app data on any device |
| Authorize/revoke contacts | Prevent physical access to a lost device |
| Read the audit log | Re-enroll without fresh token + physical access |

**What the client trusts:**

- The pinned public provisioning key(s) and pinned recovery public key(s)
- The matrix signature and version rules in §3.8 and §3.7
- The backend for delivery, not for authorization

**What the client does not trust:**

- Any matrix it cannot verify against a pinned public key
- Any matrix with `version ≤ highest_seen_version` (post-enrollment)
- Any recovery notice with `recovery_key_version ≤ highest_recovery_key_version`
- Any rotation event not signed by the currently-trusted recovery key

**Boundary between "trusted" and "authoritative":** The backend is
trusted to *deliver* messages but not to *authorize* who can receive
them. Authorization is enforced by the client verifying the matrix
signature. This means a device with a stale matrix retains authorization
for its stale contact list until a new matrix is pushed. See §8.

---

## §8 Revocation enforcement (Q4)

**Enforcement is server-authoritative.**

Build Master §3.3 requires the backend to check `devices.status` on
every protected request. `LISTEN/NOTIFY` is a prompt-wake mechanism only.
Missed notifications are covered by:

1. The per-request status check (authoritative)
2. Full reconciliation on listener reconnect, querying
   `status = 'revoked' AND revoked_at > last_reconciliation_time`

**Consequences for the offline gap:** If Device B is offline and holds a
stale matrix showing revoked Device A as a contact, then when B returns
online and messages A:

- The server rejects the envelope because A is revoked.
- B's contact list may still show A until the next matrix push.
- B's UI does not know the message failed until the send attempt.

This is a **UX-visibility gap**, not a security gap. B cannot deliver a
message to A. B cannot establish a session with A. B's stale matrix does
not grant A any access B would not already have.

**What the client does not do:** There is no client-side revocation
enforcement in the delivery path. The client trusts the server to reject
envelopes to revoked devices. If the server is compromised (A3), it can
lie about delivery to a revoked device — but it cannot decrypt the
envelope, so the message content remains protected. The revoked device
receives an envelope it cannot decrypt.

**What could change this:** If Phase 3 introduces client-side enforcement
(e.g., for calls), this section must be revised. It is not in Phase 1.

---

## §9 Composition with AUTH-SPEC-001

Provisioning is an additional layer on top of the device identity
established by AUTH-SPEC-001, not a parallel identity system. Every
device that provisioning touches is already, or will become, an
authenticated device via challenge/verify.

Specifically:

- `pub_device_auth_key` (Ed25519) is the key used in AUTH-SPEC-001's
  challenge/verify flow. Provisioning binds it into the matrix but does
  not replace or re-generate it.
- `pub_messaging_identity_key` (Curve25519) is the libsignal identity
  key. Provisioning binds it into the matrix. It is not used for
  authentication to the backend.
- These are separate keys in separate systems. A matrix that conflates
  them is malformed and rejected (TEST-PROVSCHEMA-001).

---

## §10 Out of scope

Explicitly not covered by this threat model:

- Nation-state adversaries with physical access to the offline signing
  device or the offline recovery key
- Quantum adversaries (no post-quantum commitment in Phase 1; libsignal's
  PQXDH provides some hybrid protection, but formal PQ migration is not
  in Phase 1)
- Traffic-analysis resistance beyond what Tor provides
- Coercion of individual users (duress features exist but their
  effectiveness depends on user configuration)
- Supply-chain attacks beyond the dependency rules in Build Master §6
- Anything in Phase 2 or Phase 3

---

## §11 Revision history

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-10-14 | Initial draft. Authored from Build Master v1.4.2 + owner attestation. |

---

— end of THREAT-MODEL-001 v0.1 draft —
