# ADR-IDENTITY-CHANGE-001 — Peer identity-change notification and ack

Document ID: ADR-IDENTITY-CHANGE-001
Version: 0.2
Date: 2026-10-17
Status: Proposed
Task: TASK-P1-030 sub-task 030e-b
Supersedes: none
Related: ADR-PROVISIONING-001, THREAT-MODEL-001 §7, Build Master §3.7

---

## §1 Context

The replacement-device flow (Build Master §3.7) requires that when a
device is replaced, peers who previously communicated with the old
device learn that the same person is now at a new device. Without this,
a peer would be communicating with a departed device while believing
they were still in contact — silently severed from the actual human.

This is distinct from authorization. The matrix says "device P may send
to device D." Continuity says "the person at D_old is now at D_new."
Two claims, two trust flows:

- Authorization is machine-verified: signature + permitted_contacts.
- Continuity requires human confirmation: "do you recognize this
  replacement?" The peer is the only party who can answer.

030e-a landed the signed replacement-notice artifact (§3.8 protocol,
domain-separated from the matrix, both languages byte-identical on
R-series vectors). 030e-b is the backend side: storing notices and
acks, and returning them to peers.

---

## §2 Threat-model answers

### What ack-required continuity prevents

The attack: attacker gains physical access to an admin's phone. They
issue a fresh matrix adding the attacker's device as a "replacement"
for a departed peer. Without continuity, the peer's client would
silently start sending to the attacker.

With continuity: the peer's client sees a replacement notice, blocks
sending to `to_device_id`, and asks the human. If the human does not
recognize the replacement, they reject. The attacker has gained nothing.

### What it does not prevent

- **Compromised admin who issues notice + matrix consistently.** If
  the attacker controls the provisioning key or the admin's device at
  the time of the replacement ceremony, both artifacts are legitimately
  signed. Continuity does not detect this — the peer sees a valid
  notice and a valid matrix. Recovery requires recovery-key-assisted
  revocation (TASK-P1-035, not this task).
- **Out-of-band social engineering.** The peer may be persuaded by
  channels outside the app to accept a replacement they do not
  recognize.
- **Legitimate replacement where the peer does not act.** Peer who
  never opens the app never acks. Sender cannot deliver. This is a
  feature (fail-closed), not a bug — the alternative would be silent
  delivery to a device the peer has not confirmed.

### Non-goals

- Not a replacement for matrix verification. The matrix is still the
  authority on "who may send to whom."
- Not peer-to-peer signed by the old device. The old device is gone
  (that's why there's a replacement). The provisioning key signs the
  notice.
- Not an audit log. Notices and acks are operational state, not
  append-only history. The audit chain (migration 008) records state
  changes.

---

## §3 The ack artifact

**Domain:** `umoja.identity-change-ack.v1`

**Signed unit:**

    {"domain":"umoja.identity-change-ack.v1","ack":{
      "notice_hash":"<base64url-32>",
      "acking_device_id":"<uuid>",
      "decision":"accept" | "reject",
      "issued_at":"<ISO 8601 UTC>"}}

**Signing:** Ed25519 over SHA-256 of JCS-canonical bytes. Signed by
the acking device's device auth key (the same key used for session
authentication). This is deliberate — the backend already has that
public key in `devices.public_key`, so acks can be verified server-side
with zero new configuration.

**Domain separation reasoning.** Distinct domain from
`umoja.replacement-notice.v1` even though both are Ed25519-signed with
different keys. A notice is signed by the provisioning key (offline);
an ack is signed by the device auth key (online). Different key, same
protocol, different claim — domain separation makes it impossible to
cross-validate a notice as an ack or vice versa. Cost: zero. Benefit:
one fewer class of "we forgot to check which domain this was."

**`notice_hash` binding.** SHA-256 of the canonical bytes of the
replacement-notice wrapper. Binds the ack to exactly one notice —
preventing an attacker from moving an ack between notices.

---

## §4 Trust boundaries — the deliberate asymmetry

**Notices are a relay.** The backend stores the signed notice
verbatim. It does NOT verify the provisioning signature, because it
does not have the provisioning public key — that key is pinned
client-side only (`ProvisioningKeys.CURRENT_PROVISIONING_PUBKEY_B64U`
in the APK). This preserves the server-blind property established in
ADR-PROVISIONING-001 §2 Q3: the backend cannot be the trust anchor
for artifact authority. Peers verify notices against the pinned
provisioning key on receipt.

**Acks are verified.** The backend DOES verify the ack signature
before storing it. It has the device auth public key in
`devices.public_key` from enrollment. Verification reuses
`@noble/ed25519.verifyAsync` — the same primitive `verifyChallenge`
already uses for session authentication. Acks that fail verification
are not stored; a distinct 400 code is returned.

**Why the asymmetry is correct.** The backend must not become the
trust anchor for provisioning-key-signed artifacts (server-blind). It
must not accept device-signed state without verifying it (else a
revoked or hostile device could stuff the table). The asymmetry
follows from which keys the backend holds, not from any design
preference.

**Consequence.** A hostile device cannot forge acks (backend rejects).
A hostile admin cannot forge notices (backend accepts them, but the
peer's client rejects on signature). Both defenses are at the correct
layer.

---

## §5 Peer discovery — three options, one chosen

When peer Q's client runs `GET /identity-change-notices`, which
notices should it receive? Q is authorized to see notices affecting
Q's `permitted_contacts`. But the backend does not store matrices —
matrix verification is client-side (P1-026) — so the backend cannot
filter by `permitted_contacts` without new state.

### Option A — backend stores matrices

Break the "matrix is client-side" invariant. Reject: violates the
P1-026 design ruling that authority derives from the signature and the
pinned key, not from the backend. Backend would become the origin of
authority for contact visibility.

### Option B — client POSTs its contact set to backend

Client tells backend "here are my permitted_contacts, filter by these."
Reject: backend learns the contact graph, which is exactly what
server-blind exists to prevent. The whole architecture is designed so
that backend knows "device P sent an envelope" and nothing about
relationships.

### Option C — backend returns all org notices, client filters

Backend returns every replacement notice in the caller's org
(org_id enforced at middleware). Client filters to those in its own
accepted matrix's `permitted_contacts`. **Chosen.**

**Disclosure tradeoff, named.** Under Option C, every device in the
org learns of every replacement in the org, not just replacements
affecting its own contacts. Is this a leak?

- The org boundary is already the trust perimeter. All devices in an
  org are enrolled under one provisioning key, one admin policy.
  Knowing "device X was replaced by device Y" inside that perimeter
  reveals nothing about relationships, which remain hidden.
- The sensitive fact is *who P is talking to*, not *that device X
  exists*. Option C does not reveal the former.
- Same choice already exists for `/envelopes`: any authenticated
  device in an org can see envelope metadata (from/to IDs, ciphertext
  length, timestamps). Option C's disclosure is weaker — it's
  device-existence metadata only.

Volume is bounded by org size × replacement frequency. Phase 1
government/security deployments: tens to low hundreds of devices per
org, replacements on the order of device lifecycle (months). The
`GET /identity-change-notices` query is a single index scan on
`(org_id, created_at DESC) LIMIT 500`. Fine.

### Client-side filtering contract

Client receives the org notice list, filters by
`to_device_id ∈ accepted_matrix.permitted_contacts`. Notices for
`to_device_id` not in the matrix are ignored (not an error, not logged
as suspicious — routine noise from other admins' replacements).

---

## §6 Storage schema (migration 015 sketch)

Storage preserves both the parsed shape for query and the exact
signed bytes for trust. Canonical bytes and signature are the trust
artifacts; `from_device_id` / `to_device_id` are extracted at insert
time for indexing and are not the trust anchor.

    CREATE TABLE identity_change_notices (
      notice_hash         BYTEA PRIMARY KEY
                          CHECK (octet_length(notice_hash) = 32),
      org_id              UUID NOT NULL,
      from_device_id      UUID NOT NULL REFERENCES devices(device_id),
      to_device_id        UUID NOT NULL REFERENCES devices(device_id),
      canonical_bytes     BYTEA NOT NULL,
      signature_base64url TEXT NOT NULL,
      created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX idx_notices_org  ON identity_change_notices(org_id, created_at DESC);
    CREATE INDEX idx_notices_from ON identity_change_notices(from_device_id);
    CREATE INDEX idx_notices_to   ON identity_change_notices(to_device_id);

    CREATE TABLE identity_change_acks (
      notice_hash         BYTEA NOT NULL
                          REFERENCES identity_change_notices(notice_hash),
      acking_device_id    UUID NOT NULL REFERENCES devices(device_id),
      org_id              UUID NOT NULL,
      decision            TEXT NOT NULL CHECK (decision IN ('accept', 'reject')),
      canonical_bytes     BYTEA NOT NULL,
      signature_base64url TEXT NOT NULL,
      created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (notice_hash, acking_device_id)
    );
    CREATE INDEX idx_acks_notice ON identity_change_acks(notice_hash);

**`PRIMARY KEY (notice_hash, acking_device_id)`** gives replay
idempotence for free: a repeated ack is a no-op, not a duplicate row,
not an error. The client can safely retry on network failure.

**`BYTEA` for `canonical_bytes`**, not JSONB. The trust artifact is
byte-identity with what was signed. JSONB round-trip could reorder
keys or normalize numbers; that would invalidate the signature check
on read-back. Verified once at insert, re-verified on the client from
exact bytes; JSONB breaks that property.

---

## §7 API shape

### POST /identity-change-notices

**Auth:** `requireAdmin` (owner or admin). Rationale: notices are
created during the admin-driven replacement flow. The signature is the
true authorization; the role check only prevents non-admin org
members from stuffing the notice table.

**Body:**

    { "canonical_utf8": "<JCS-canonical bytes as UTF-8 string>",
      "signature_base64url": "<base64url>" }

**Validation before insert:**

1. `canonical_utf8` parses as JSON and validates as
   `umoja.replacement-notice.v1` (schema check, no signature check —
   see §4).
2. `from_device_id` exists in `devices` and is in `req.device.org_id`.
3. `to_device_id` exists in `devices` and is in `req.device.org_id`.
4. Compute `notice_hash = SHA-256(canonical_utf8 bytes)`.
5. INSERT ... ON CONFLICT (notice_hash) DO NOTHING.
6. Respond 201 with `notice_hash` whether inserted or already present
   (idempotent).

**Error codes:** `invalid_request` (400, malformed shape),
`device_not_found` (400, from/to device not in org), `forbidden` (403,
not admin).

### GET /identity-change-notices

**Auth:** `requireSession` (any active device).

**Response:**

    { "notices": [
        { "notice_hash": "<base64url>",
          "canonical_utf8": "<string>",
          "signature_base64url": "<string>",
          "from_device_id": "<uuid>",
          "to_device_id": "<uuid>",
          "created_at": "<ISO 8601 UTC>" }, ... ] }

Returns up to 500 most recent notices in the caller's org. No
filtering by permitted_contacts (see §5). Client filters locally.

### POST /identity-change-acks

**Auth:** `requireSession` (any active device that received the
notice).

**Body:** same shape as POST /identity-change-notices but validating
as `umoja.identity-change-ack.v1`.

**Verification before store — THE TRUST MOMENT:**

1. `canonical_utf8` parses and validates as
   `umoja.identity-change-ack.v1`.
2. `ack.acking_device_id === req.device.device_id` — cannot ack as
   someone else.
3. `ack.notice_hash` is a valid base64url-32 value (enforced by the
   schema validator in step 1). Notice existence is step 4. (In v0.1
   this step read "compare notice_hash against SHA-256 of the ack's
   own bytes", which is unsatisfiable — see §10 v0.2.)
4. A notice with `notice_hash = ack.notice_hash` exists in
   `identity_change_notices`.
5. `notice.org_id === req.device.org_id` — cross-org rejection.
6. Look up `acking_device` row in `devices` — status must be `active`.
   (Revoked or suspended device cannot ack.)
7. `acking_device.public_key_alg === 'ed25519'` — reject 501
   `unsupported_algorithm` if not.
8. `ed.verifyAsync(signature, canonical_bytes, acking_device.public_key)`
   — verify. Reject 400 `invalid_signature` on false.
9. INSERT ... ON CONFLICT (notice_hash, acking_device_id) DO NOTHING.
10. Respond 201 with `ack_hash = SHA-256(canonical_bytes)` whether
    inserted or present.

**Error codes:** `invalid_request` (400, malformed shape),
`invalid_signature` (400), `unknown_notice` (400), `cross_org_rejected`
(403), `device_revoked` (403), `unsupported_algorithm` (501).

### GET /identity-change-acks/:notice_hash

**Auth:** `requireSession`.

**Validation:** caller's org must match notice's org.

**Response:** `{ "acks": [{ "acking_device_id": "<uuid>", "decision": "accept"|"reject", "created_at": "<ISO>" }, ...] }`

Content of ack canonical bytes is not returned — the decision and
acking_device_id are sufficient for the sender's state machine, and
the signature has already been verified server-side (per §4). A peer
that wants cryptographic proof of another peer's decision re-fetches
the notice list and re-verifies individually; this is out of scope for
030e-b.

---

## §8 Failure modes — required tests

Failure modes first; happy path last. Every test named for the failure
it pins, not the code path it exercises.

    TEST-NOTICE-REJECT-MALFORMED          canonical does not parse as v1 wrapper
    TEST-NOTICE-REJECT-UNKNOWN-FROM       from_device_id not in org
    TEST-NOTICE-REJECT-UNKNOWN-TO         to_device_id not in org
    TEST-NOTICE-IDEMPOTENT                same notice twice → one row, 201 both times
    TEST-NOTICE-NON-ADMIN-FORBIDDEN       user role POST → 403
    TEST-NOTICE-STORED-VERBATIM           canonical_bytes and signature byte-identical to input
    TEST-ACK-INVALID-SIGNATURE            bad signature → 400 invalid_signature, no row
    TEST-ACK-WRONG-DEVICE                 ack claims different acking_device_id → 400
    TEST-ACK-INVALID-DECISION             decision not in {accept,reject} → 400 invalid_request, no row
    TEST-ACK-UNKNOWN-NOTICE               notice_hash not in table → 400 unknown_notice
    TEST-ACK-CROSS-ORG-REJECTED           acking device org ≠ notice org → 403
    TEST-ACK-REVOKED-DEVICE               revoked device cannot ack → 403 device_revoked
    TEST-ACK-REPLAY-IDEMPOTENT            same ack twice → one row, 201 both times
    TEST-DISCOVERY-RETURNS-ORG-NOTICES    notices from caller's org, none from other orgs
    TEST-DISCOVERY-CROSS-ORG-ISOLATED     org A notices invisible to org B
    TEST-ACK-LIST-BY-NOTICE               acks returned for a notice, scoped to notice org
    TEST-ACK-LIST-CROSS-ORG-FORBIDDEN     caller org ≠ notice org → 403

17 tests. All in `backend/test/identity-change.test.ts`.

Note on TEST-ACK-INVALID-DECISION: the route-level validator is the
first line of defense; the DB CHECK (decision IN ('accept','reject'),
migration 015) is the last. This test asserts the route rejects an
out-of-vocabulary decision *before* any DB write — confirming the
pre-write validation discipline, not merely that the DB constraint
exists. Route-level
(`app.inject`) matching admin.test.ts style. Each test uses
`TEST_ORG_ID = '00000000-0000-0000-0000-0000000000b1'` (distinct from
existing test orgs per §7 convention).

---

## §9 Deferred to implementation session

- Migration 015 SQL — sketch in §6, details at write time.
- Exact error message strings for each error code.
- Whether `POST /identity-change-notices` records an audit-chain event
  (`identity_change.notice_recorded`). Leaning yes — the audit chain
  is the trust ledger, and this is a state change. But audit-chain
  events are for provisioning/authorization actions; notices are
  operational. Deferred to implementation with a note: if we add it,
  do so in a separate commit after the base endpoint works, so the
  audit-chain interaction is a distinct decision.
- Rate limiting on POST endpoints. Phase 1: `requireAdmin` is
  sufficient (no user can spam). Revisit if a user-level notice POST
  ever exists.

---

## §10 Open questions

### v0.2 (2026-10-17) — §7 step 3 fix, §8 test rename

**§7 step 3 was unsatisfiable in v0.1.** Original: `ack.notice_hash
=== SHA-256(canonical_utf8 bytes)` — but `ack.notice_hash` is a field
*inside* `canonical_utf8`, so this compares a hash against the hash
of the bytes containing it. No fixed point exists. §3's independent
description ("SHA-256 of the canonical bytes of the replacement-
notice wrapper") confirms the intent: `ack.notice_hash` is the
*notice's* hash, a pointer, not a self-hash. Fixed: step 3 is schema
validation only; step 4 does the notice-existence check.

**§8 test rename.** `TEST-ACK-HASH-MISMATCH` described the
unsatisfiable comparison. Replaced with `TEST-ACK-INVALID-DECISION`
(decision not in {accept, reject} → 400 invalid_request before any
DB write). `decision` is the load-bearing value for the sender's
state machine; route-level rejection before DB CHECK is the
discipline being tested. Same count (17).

**Signing protocol: prehash, not direct.** ADR §3 states Ed25519
over SHA-256 of JCS-canonical bytes — the **prehash** path. This is
distinct from `verifyChallenge` (auth/verify.ts), which signs the
message directly with no prehash. The ack verifier must compute the
SHA-256 digest and pass *that* to `ed.verifyAsync`, not the
canonical bytes. Caught by the implementation session before writing
any code; the divergence from auth/verify.ts would have produced a
100%-failure ack test suite that looked like a cryptography bug.
Recorded here so the code comment in identityChange/acks.ts can cite
it.

**Process working as intended.** Both the §7 bug and the §8 test
rename surfaced before any code, via the read-the-ADR-before-writing-
tests gate established in Session G. Third consecutive session where
pre-code design review caught a real defect.

### Non-blocking

None blocking. Any that arise during implementation get resolved in
this ADR (§10 gains entries, version bumps) rather than in code
comments or chat.

---

## §11 Approval

Approval on disk (repository commit) is the operative approval for
this design. Amendments require version bump and rationale in §10.
