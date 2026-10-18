# US-MASTER-001 — Umoja Secure Governing Architecture

Document ID: US-MASTER-001
Version: 0.2 (conformance-swept 2026-10-18)
Date: 2026-10-14
Authority: Governing architecture, threat model, phase boundaries. Per UMOJA-SECURE-BUILD-MASTER.md §0, US-ADD-001 wins over this document in any conflict.
Status: Draft. Not yet in force. Subject to revision.

---

## §1 Provenance

Authored 2026-10-14. Did not exist on disk prior to this date. Grounded
in UMOJA-SECURE-BUILD-MASTER.md v1.4.2 and owner attestation recorded in
`docs/architecture/ADR-PROVISIONING-001.md` §2.

This document sits below `docs/US-ADD-001.md` in the precedence chain.
Where the two conflict, US-ADD-001 wins.

---

## §2 Executive summary

Umoja Secure is a privacy messenger for government and security
professionals. Its defining property is that no existing product hits all
six of the following criteria simultaneously:

1. **No phone numbers for discovery.** Threema model — identity is not
   tied to a phone number.
2. **Admin-provisioned contacts.** Our differentiator. An organization
   administrator authorizes who can talk to whom. No self-service
   discovery.
3. **Server-blind architecture.** SimpleX/Briar model — the backend routes
   ciphertext and holds no plaintext, no private keys, and no Double
   Ratchet state.
4. **Tor transport for messaging and signaling.** Briar/Session model.
   No clearnet fallback.
5. **No Google runtime dependencies of any kind.** Not Play Services, not
   Firebase, not FCM, not Tink.
6. **GrapheneOS-first device baseline.** Pixel 6a or newer, GrapheneOS
   stable.

Additional fixed requirements are in `docs/US-ADD-001.md` §2.

---

## §3 Core architecture

### §3.1 Three tiers

**Device.** Android client. Holds all private keys, all plaintext, and
all Double Ratchet state. Generated locally; never transmitted.

**Backend.** Node.js 24 / Fastify 5.12.5 / PostgreSQL 16. Routes
ciphertext envelopes. Enforces revocation, session validity, and
enrollment-token authorization. Holds no plaintext, no private keys, no
session state.

**Transport.** Tor v3 onion service. Messaging and signaling both route
through it. No clearnet fallback. Emulator development uses a local
HTTP→SOCKS5 bridge to work around Java's local-DNS-for-SOCKS behavior
(see handoff §3).

### §3.2 Identity

Four device-side keys with distinct purposes:

- **Device authentication key (Ed25519).** Android Keystore.
  Challenge/response to the backend. Public part registered at enrollment
  and bound into the authorization matrix as `pub_device_auth_key`.
- **Messaging identity key (Curve25519).** libsignal. X3DH and Double
  Ratchet. Public part bound into the authorization matrix as
  `pub_messaging_identity_key`.
- **Signed prekey + one-time prekeys.** libsignal. Public parts uploaded;
  private parts local.
- **Wipe-confirmation key (Ed25519).** Android Keystore. Signs one
  fire-and-forget wipe notification. Destroyed after use.

Two organization-side keys, held offline:

- **Provisioning key (Ed25519).** Signs the authorization matrix.
- **Recovery key (Ed25519).** Independent of the provisioning key.
  Authorizes provisioning-key rotation and revocation.

Detail: `docs/reference/AUTH-SPEC-001.md` §4.

### §3.3 Authorization matrix

The matrix is the org's statement of who may communicate with whom. It is
signed by the offline provisioning key, verified on-device against the
pinned public provisioning key, and enforced by the client — not by the
backend.

Canonicalization: RFC 8785 JCS over the wrapper
`{"domain":"umoja.authorization-matrix.v1","matrix":{...}}`.
Digest: SHA-256. Signature: Ed25519 over the digest. Detail: Build Master
§3.8.

Anti-rollback: monotonic `version`. Post-enrollment, the device stores
`highest_seen_version` and rejects `version ≤ highest_seen_version`.
Replacement-device enrollment uses an inclusive `enrollment_matrix_version_floor`.
Detail: Build Master §3.7.

### §3.4 Messaging

libsignal provides X3DH (or PQXDH) session establishment and Double
Ratchet for forward secrecy. Envelopes traverse the backend as opaque
ciphertext. The backend queues them, expires them after 30 days, and
delivers them on next connectivity.

Tor-only. No clearnet fallback. Build Master §11 forbids enabling one.

### §3.5 Revocation

Server-authoritative. The backend checks `devices.status` on every
protected request. `LISTEN/NOTIFY` on a `device_revoked` channel prompts
WebSocket closure within ≤5s; the per-request check is authoritative and
covers missed notifications.

> *v0.2 correction (2026-10-18):* The v0.1 text claimed "on listener
> reconnect, a full reconciliation pass closes any connections for
> devices revoked while the listener was down." Actual
> `backend/src/ws/revocation.ts` runs reconciliation on listener
> **startup**, not reconnect; the `on('error')` handler logs but does
> not reconnect or re-reconcile. The reconnect gap is real — filed as
> TASK-P1-042 (same gap AUTH-SPEC-001 §9.3 defense 2 and
> THREAT-MODEL-001 §8 v0.2 name). Until P1-042 lands: WS-close timing
> is ≤5s when the listener is healthy, ≤5min when disconnected (via
> per-connection revalidation timer).

Client does **not** enforce revocation in the delivery path. Detail:
Build Master §3.3, `docs/reference/AUTH-SPEC-001.md` §9, and
`docs/reference/THREAT-MODEL-001.md` §8.

### §3.6 Provisioning ceremony

1. Device generates all four keys locally; displays a QR with the three
   public keys.
2. Admin scans; assigns clearance and permitted contacts.
3. Admin app canonicalizes the matrix (JCS), computes the SHA-256 digest,
   and hands hash + content to the offline signer.
4. Offline signer re-canonicalizes, confirms hash match, displays matrix
   for human confirmation, signs the digest with the provisioning key,
   returns the signature.
5. Admin app attaches the signature and pushes the signed matrix.
6. Device re-canonicalizes, verifies the signature against the pinned
   public provisioning key, applies version rules, and stores the matrix.

The admin app never holds the provisioning private key. Detail: Build
Master §3.6, `docs/architecture/ADR-PROVISIONING-001.md`.

---

## §4 Threat model summary

Full model: `docs/reference/THREAT-MODEL-001.md`.

Adversaries in scope:

| # | Adversary | Primary defense |
|---|---|---|
| A1 | Passive network observer | Tor |
| A2 | Active network adversary | Tor + E2EE (DoS not prevented) |
| A3 | Compromised backend | Cannot decrypt; anti-rollback defeats stale matrices |
| A4 | Malicious enrolled device | Signature verification defeats matrix tampering |
| A5 | Rogue admin (authorized) | Audit + role separation + recovery-key revocation |
| A6 | Compromised provisioning key holder | Recovery-key revocation |
| A7 | Physical device attacker | Keystore + GrapheneOS controls + wipe |
| A8 | Supply-chain attacker | Dependency rules (Build Master §6) |

Trust boundary: the backend is trusted to *deliver* but not to
*authorize*. Authorization comes from the client verifying the matrix
signature.

Explicitly out of scope: nation-state physical capture of offline keys,
quantum adversaries, traffic-analysis beyond Tor's guarantees, coercion
of individual users, and compliance claims of any kind.

---

## §5 Phase boundaries

### §5.1 Phase 1 (current)

Admin provisioning, enrollment, E2EE 1:1 text messaging over Tor,
revocation, emergency lock, duress wipe, audit log with hash chain,
real-device acceptance testing. Full list: `docs/US-ADD-001.md` §3.1.

### §5.2 Phase 1 — prohibited

Group messaging, calls, attachments, employee-controlled recovery, MDM,
compliance retention, key transparency, cover traffic, padding,
localization, admin web UI, iOS, BYOD, tablets. Full list:
`docs/US-ADD-001.md` §3.2.

### §5.3 Phase 3

WebRTC + TURN calls on clearnet, with Tor for signaling only. When calls
land, revocation extends to call-signaling WebSocket sessions within the
same ≤5s target that Phase 1 applies to messaging WebSockets. Detail:
Build Master §3.1.

---

## §6 Precedence

Per Build Master §0:

1. `docs/US-ADD-001.md` — highest authority for approved decisions and
   parameters.
2. **This document (US-MASTER-001)** — governing architecture, threat
   model, phase boundaries.
3. `docs/reference/AUTH-SPEC-001.md`, `docs/reference/THREAT-MODEL-001.md`
   — supporting specifications.
4. `UMOJA-SECURE-BUILD-MASTER.md` — execution layer.
5. `docs/US-TASK-P1-001.md` — task list.

If US-ADD-001 and this document conflict, US-ADD-001 wins.

If both are silent on a security-relevant question, **STOP and escalate.**
Do not guess.

---

## §7 Canonical document set

| Document | Path | Authority |
|---|---|---|
| US-ADD-001 | `docs/US-ADD-001.md` | Highest for parameters |
| US-MASTER-001 | `docs/US-MASTER-001.md` | Architecture, threat model, phases |
| AUTH-SPEC-001 | `docs/reference/AUTH-SPEC-001.md` | Device identity, sessions, revocation |
| THREAT-MODEL-001 | `docs/reference/THREAT-MODEL-001.md` | Adversary model, STRIDE |
| USER-ONBOARDING | `docs/reference/USER-ONBOARDING.md` | User-facing: onboarding, recovery, erasure |
| US-TASK-P1-001 | `docs/US-TASK-P1-001.md` | Task registry |
| UMOJA-SECURE-BUILD-MASTER | `UMOJA-SECURE-BUILD-MASTER.md` | Build instructions |

---

## §8 Revision history

| Version | Date | Change |
|---------|------|--------|
| 0.1 | 2026-10-14 | Initial draft. Authored from Build Master v1.4.2 + owner attestation. |
| 0.2 | 2026-10-18 | Conformance sweep (KI-005, Session W-1). §3.5 corrected: v0.1 claimed reconciliation-on-listener-reconnect; actual code runs reconciliation on startup only. Cross-references TASK-P1-042 (same gap AUTH-SPEC-001 §9.3 defense 2 / THREAT-MODEL-001 §8 v0.2). §7 canonical document set adds `USER-ONBOARDING.md` (written Session U-2, referenced by Build Master §2). Ten other architecture claims verified holding (§3.1 tiers, §3.2 four device keys + two org keys, §3.3 matrix, §3.4 messaging, §3.6 ceremony, §4 threat summary, §5 phases, §6 precedence). |

---

— end of US-MASTER-001 v0.2 draft —
