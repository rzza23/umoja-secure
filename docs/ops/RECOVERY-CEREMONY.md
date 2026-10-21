# Recovery ceremony — operational runbook

**Task:** TASK-P1-035c
**Status:** Specification of procedure. No production ceremony has been
executed.
**Last updated:** 2026-10-21

---

## Purpose

This is the operational runbook for the two ceremonies that operate
the recovery key:

- **Part A — Generation ceremony** (one-time per organization): the
  recovery keypair is generated on an air-gapped offline device
  distinct from the provisioning device, with split passcode and
  three-person control.
- **Part B — Use ceremony** (per rotation or revocation): the
  recovery key signs a `key_rotation`, `key_revocation`, or
  `recovery_key_rotation` notice, and the signed notice is returned
  for distribution.

**Three operators are present throughout both ceremonies**: the
ceremony lead, the witness, and the recovery-key custodian. All
three initial the paper log at every checkpoint. A partial ceremony
is never resumed.

**This document composes `PROVISIONING-CEREMONY.md`.** The shared
mechanical steps — network isolation check, APK hash verification,
StrongBox assertion, signing-device unlock, QR transfer — are
identical to the provisioning ceremonies and are referenced, not
re-described. Only where the recovery ceremony diverges from the
provisioning ceremony (three operators instead of two, split device
passcode, separate Safe #2 in a different physical location,
recovery-key-version tracking, full notice-payload review) is this
document authoritative. The rationale: re-describing the shared
procedure would create two byte-similar procedural texts that drift
independently, the same hazard `docs/ops/KEY-CUSTODY.md` §3.1
addresses with its "Same as §2.1 with these additions" phrasing.

**This document does not stand alone.** It operationalizes
`docs/ops/KEY-CUSTODY.md` §3 (recovery key custody), which
operationalizes Build Master §3.6 (rotation/revocation authority)
and §3.8 (signing protocol). Where this runbook and the design
documents disagree, the design documents win — this runbook is
procedure, not policy.

**This document does not cover** cryptographic protocol (that's
Build Master §3.8), threat modeling (KEY-CUSTODY §7), or routine
provisioning-key operations (that's `PROVISIONING-CEREMONY.md`). It
covers only recovery-key operations: generation, use (three notice
types), annual rotation, and compromise handling.

---

## Execution status

**No production ceremony has been executed as of 2026-10-21.**
TASK-P1-035d will execute the first end-to-end drill using this
runbook. Until that drill completes, this document is a
*specification of procedure*, not a *record of a proven procedure*.

When P1-035d completes, its record is appended here as the first
verified execution:

```
Drill 001 — <date> — outcome: <PASS|FAIL> — deviations: <none|list>
```

If the drill reveals a gap in this runbook, the gap is corrected
before the first production ceremony.

**This drill is hardware-blocked.** P1-035d requires two air-gapped
Pixel 7+ devices (one for the provisioning ceremony's Safe #1, one
for the recovery ceremony's Safe #2) with StrongBox. Same hardware
constraint as P1-033e's provisioning drill; see Session Z-18's
session entry for the reasoning about why the emulator drill doesn't
substitute.

---

## Part A — Recovery key generation (one-time per organization)

The recovery keypair is generated **once** and **never leaves the
device**. Regeneration is a documented recovery procedure (KEY-CUSTODY
§3.6 "Emergency rotation of the recovery key"), not an app action.
Loss of the recovery key requires physical re-provisioning of all
devices — the recovery key IS the trust anchor; there is no
cryptographic path around its loss.

**The recovery device is distinct from the provisioning device.** Never
the same hardware. Safe #2 is a different safe from Safe #1,
physically separate if possible (KEY-CUSTODY §3.1, §3.2).

### A.1 Prerequisites

Before any of the three operators enters the room:

- [ ] **Recovery device** (Pixel 7+ with StrongBox/Titan M2,
      GrapheneOS) is in Safe #2 and has never been connected to any
      network. **Distinct from the provisioning device** — do not
      use the Safe #1 device.
- [ ] **Signing APK** (the same `signing` flavor build used for the
      provisioning ceremony) is built and its SHA-256 recorded in
      the build manifest. Verified by the ceremony lead against a
      known-good build.
- [ ] **Signing APK is installed** on the recovery device via ADB
      from a clean workstation, while the device is physically
      offline (KEY-CUSTODY §4.2).
- [ ] **Ceremony workstation** is a machine the org controls, ADB
      available, USB cable present, no other devices attached.
- [ ] **Paper log** printed (template at A.3), pen, sealed envelope
      for the completed log, tamper-evident bag for the recovery
      device.
- [ ] **Split passcode shares** prepared. The recovery device's
      passcode is split between the ceremony lead and the
      recovery-key custodian (KEY-CUSTODY §3.1 step 1). Neither
      can unlock the device alone. Both shares are physically
      present for the ceremony.
- [ ] **Safe #2 has been provisioned and locked since before the
      ceremony** — its existence is not new, only its contents (the
      recovery device's paper record) will change.
- [ ] **Backend config credentials** (`RECOVERY_PUBKEY_B64U` will
      need to be set post-generation; see A.2.7 — the same shape as
      the provisioning ceremony's A.2.7 for `PROVISIONING_PUBKEY_B64U`).
- [ ] **Three operators present**: ceremony lead, witness, and
      recovery-key custodian. All three must be present for the
      full procedure; any absence is an abort condition.

### A.2 Procedure

Execute `PROVISIONING-CEREMONY.md` Part A.2 (steps A.2.1 through
A.2.8) against the recovery device, with the following three
additions. Where this section adds a step, the added step is
numbered `A.2.N.1` and executes after the referenced A.2.N.

**Step A.2.2.1 — Split passcode verification (added).**

After `PROVISIONING-CEREMONY.md` step A.2.2 launches ceremony mode
and displays the recovery public key, but **before** any paper-log
transcription:

- Ceremony lead enters the first half of the split passcode.
- Recovery-key custodian enters the second half.
- Device unlocks; app shows the recovery public key.

If either half is missing or wrong, the device does not unlock; the
ceremony **aborts**. This verification exists to prove the split
works BEFORE the ceremony commits to generating a key. A split
that has silently been given to one person (say, custodian gave
their half to lead for convenience) would be discovered here.

Record on the paper log: both operators' initials confirming their
own half was entered.

**Step A.2.5.1 — Recovery key version recorded (added).**

After `PROVISIONING-CEREMONY.md` step A.2.5 (attestation recording),
record the **recovery key version** on the paper log. For a fresh
generation, the version is `1`. For a re-generation after emergency
rotation (see Part D), the version is the previous version + 1.

Record on the paper log:
- `recovery_key_version = ____` (integer, ≥ 1)
- All three operators initial.

**Step A.2.6.1 — Three-person seal (modifies A.2.6).**

`PROVISIONING-CEREMONY.md` step A.2.6 says "both operators sign
across the seal." For the recovery ceremony, **all three** operators
sign across the seal. The envelope is not sealed until all three
signatures are present.

If any of the three is absent for the sealing step, the ceremony
**aborts** at seal time even if all prior steps succeeded. A recovery
key whose custody ceremony was attended by only two of the three
required operators is not a valid recovery key per KEY-CUSTODY §3.1.

### A.3 Paper log template (Part A)

Print this template and transcribe as the ceremony proceeds. Do not
prefill fields before the ceremony starts. This template is the
recovery ceremony's counterpart to `PROVISIONING-CEREMONY.md`
Appendix A.3; fields are identical where the procedures are shared,
with three additions specific to recovery custody.

```
UMOJA SECURE — RECOVERY KEY GENERATION CEREMONY
==================================================

Ceremony ID:      ____________________
Date:             ____________________  Time (UTC): __________
Org:              ____________________
Ceremony lead:    ____________________
Witness:          ____________________
Custodian:        ____________________  (recovery-key custodian)

DEVICE & APP
  Recovery device model:  ____________________
  Serial number:          ____________________
  Distinct from Safe #1 provisioning device:  [ ] VERIFIED
  GrapheneOS version:     ____________________
  Signing APK SHA-256:    ____________________
  Expected hash (from build manifest): ____________________
  APK hash matches:       [ ] YES  [ ] NO — ABORT if NO

A.2.1 — NETWORK ISOLATION (per PROVISIONING-CEREMONY.md A.2.1)
  dumpsys connectivity output (attach or transcribe):
  _______________________________________________________________
  _______________________________________________________________
  No active networks:     [ ] VERIFIED
  Lead:      [____]  Witness: [____]  Custodian: [____]

A.2.2 — LAUNCH CEREMONY MODE (per PROVISIONING-CEREMONY.md A.2.2)
  adb command issued:     [ ] YES
  App shows pubkey:       [ ] YES  [ ] NO — ABORT if NO
  Lead:      [____]  Witness: [____]  Custodian: [____]

A.2.2.1 — SPLIT PASSCODE VERIFICATION (added; recovery-only)
  Ceremony lead entered first half:      [ ] YES
  Custodian entered second half:         [ ] YES
  Device unlocked with both halves:      [ ] YES  [ ] NO — ABORT
  Lead:      [____]  Custodian: [____]

A.2.3 — STRONGBOX BACKING (per PROVISIONING-CEREMONY.md A.2.3)
  Key generation reported success:  [ ] YES
  StrongBox assertion passed:       [ ] YES  [ ] NO — ABORT
  Lead:      [____]  Witness: [____]  Custodian: [____]

A.2.4 — PUBLIC KEY TRANSCRIPTION (per PROVISIONING-CEREMONY.md A.2.4)
  Recovery public key (base64url, 32 raw bytes, 43 chars):
  _______________________________________________________
  Transcribed by lead:      [____]
  Transcribed by witness:   [____]
  Transcribed by custodian: [____]
  All three transcriptions match: [ ] YES  [ ] NO — ABORT if NO

A.2.5 — ATTESTATION (per PROVISIONING-CEREMONY.md A.2.5)
  Attestation chain hash:   ____________________________________
  Verified against Google root:  [ ] YES
  If not available in current build:
    [ ] NOT AVAILABLE (pending TASK-P1-034)
  Lead:      [____]  Witness: [____]  Custodian: [____]

A.2.5.1 — RECOVERY KEY VERSION (added; recovery-only)
  recovery_key_version = ________ (integer, ≥ 1)
  For fresh generation: 1. For re-generation: previous + 1.
  Lead:      [____]  Witness: [____]  Custodian: [____]

A.2.6 — SEAL (three-person modification of PROVISIONING-CEREMONY.md A.2.6)
  Envelope number:          __________
  Signed across seal:       lead [____]  witness [____]  custodian [____]
  All three signatures present before sealing: [ ] YES  [ ] NO — ABORT
  Stored in Safe #2 (different physical location from Safe #1): [ ] YES
  Lead:      [____]  Witness: [____]  Custodian: [____]

A.2.7 — BACKEND CONFIG (per PROVISIONING-CEREMONY.md A.2.7)
  RECOVERY_PUBKEY_B64U set:  [ ] YES
  Backend restarted:         [ ] YES
  Health returns 200:        [ ] YES
  Lead:      [____]  Witness: [____]  Custodian: [____]

A.2.8 — RETURN TO SAFE #2 (per PROVISIONING-CEREMONY.md A.2.8)
  adb kill-server issued:   [ ] YES
  USB disconnected:         [ ] YES
  Device locked:            [ ] YES
  Time locked (UTC):        __________
  Lead:      [____]  Witness: [____]  Custodian: [____]

CONCLUSION
  Ceremony complete without deviation: [ ] YES  [ ] NO
  If NO, describe: _____________________________________________

  Ceremony lead signature:  ___________________________
  Witness signature:        ___________________________
  Custodian signature:      ___________________________
```

### A.4 Completion

After the paper log is sealed:

- [ ] File the sealed log in Safe #2 (KEY-CUSTODY §3.2). **NOT**
      Safe #1 — the recovery record lives with the recovery device.
- [ ] Add a custody-log entry naming the ceremony ID, date, the
      recovery public key fingerprint (SHA-256 of the 32-byte
      pubkey, hex), and the recovery key version.
- [ ] **Do NOT store the recovery public key anywhere other than the
      sealed log and the backend env var.** Public keys are not
      secret but keep the process simple.
- [ ] The `android/app/src/main/java/com/umoja/secure/crypto/ProvisioningKeys.kt`
      `RECOVERY_PUBKEY_B64U` const still holds the 32-zero-bytes
      placeholder as of 2026-10-21. Replacing it with the ceremony's
      pubkey is part of the next production build; same replacement
      discipline as `PRODUCTION_PROVISIONING_PUBKEY_B64U` per
      `docs/ops/PROVISIONING-CEREMONY.md` A.4.
- [ ] A second copy of the split passcode halves remains with the
      lead and custodian; the ceremony does not change the split
      holdings, only records the version. If rotation is why the
      ceremony ran, the old device's passcode is destroyed during
      old-key destruction (see Part C).

---

## Part B — Recovery key use ceremony (per notice)

The recovery key signs exactly three kinds of notices (KEY-CUSTODY
§3.4):

- `key_rotation` — routine rotation of the provisioning key.
- `key_revocation` — emergency rotation after provisioning-key
  compromise.
- `recovery_key_rotation` — rotation of the recovery key itself.

Three operators present throughout. The notice is constructed on the
admin workstation first; the offline device signs a pre-canonicalized
notice payload, not raw user input.

### B.1 Prerequisites

- [ ] **Part A completed.** Recovery key exists on the recovery device
      (in Safe #2) and its public key is set as `RECOVERY_PUBKEY_B64U`
      on the backend.
- [ ] **Recovery device removed from Safe #2** and tamper bag opened,
      in the presence of all three operators.
- [ ] **Split passcode shares present** (lead has half, custodian has
      half).
- [ ] **Notice payload prepared** on the admin workstation. The
      payload is one of:
        - `key_rotation`: `{new_provisioning_key, overlap_window_seconds,
          effective_at, nonce, event_id, recovery_key_version}`.
        - `key_revocation`: `{revoked_provisioning_key_id,
          new_provisioning_key, effective_at, nonce, event_id,
          recovery_key_version}`.
        - `recovery_key_rotation`: `{new_recovery_key,
          new_recovery_key_version, effective_at, nonce, event_id,
          recovery_key_version}`.
      The admin workstation displays all fields in full; the notice is
      NOT yet signed.
- [ ] **Backend live** with the pre-notice state (e.g., for
      `key_rotation`, the old `PROVISIONING_PUBKEY_B64U` is set; for
      `recovery_key_rotation`, the old `RECOVERY_PUBKEY_B64U` is set).
- [ ] **Paper log** printed (template at B.3), pen, sealed envelope.
- [ ] **Three operators present**: ceremony lead, witness, and
      recovery-key custodian.

### B.2 Procedure

Execute `PROVISIONING-CEREMONY.md` Part B.2 (steps B.2.1 through
B.2.8) against the recovery device, with the following three
additions.

**Step B.2.1.1 — Full payload review (added).**

After `PROVISIONING-CEREMONY.md` step B.2.1 (admin displays matrix),
and adapted for the recovery ceremony's notice payload rather than a
matrix: all three operators review the **full** notice payload on
the admin workstation. Every field is displayed in full:

- `key_rotation`: `new_provisioning_key`, `overlap_window_seconds`,
  `effective_at`, `nonce`, `event_id`, `recovery_key_version`.
- `key_revocation`: `revoked_provisioning_key_id`,
  `new_provisioning_key`, `effective_at`, `nonce`, `event_id`,
  `recovery_key_version`.
- `recovery_key_rotation`: `new_recovery_key`,
  `new_recovery_key_version`, `effective_at`, `nonce`, `event_id`,
  `recovery_key_version`.

Each operator initials a separate line on the paper log confirming
the fields shown match what they expect. Any operator disagreeing
with any field **aborts** the ceremony. This is the recovery
ceremony's version of the matrix review — but stricter, because the
recovery key's signature is the trust anchor for the entire system's
rotation authority.

**Step B.2.2.1 — Split passcode verification (added).**

Same as A.2.2.1: after the device is unlocked via `adb shell am
start --es mode operating`, but before the notice is loaded:

- Ceremony lead enters first half of the split passcode.
- Recovery-key custodian enters second half.
- Device unlocks; app shows "Ready to sign".

If either half is missing or wrong, the ceremony **aborts**.

**Step B.2.5.1 — Notice signature via RecoveryNoticeSigner (added).**

The offline device calls
`RecoveryNoticeSigner.signKeyRotationWithDeviceKey(...)` (or the
`signKeyRevocationWithDeviceKey` / `signRecoveryKeyRotationWithDeviceKey`
variant), with `signingFn = { digest -> deviceKeyManager.sign(digest) }`.
The Keystore-backed recovery private key never leaves the device.

The signature is 64 bytes, base64url no padding. All three operators
verify the signature length matches `86 chars` and the app displays
"Signature ready".

**Step B.2.6.1 — All three confirm the signature prefix (added).**

The app displays "Signature imported: <first 12 chars>...". All
three operators confirm the same prefix matches between the offline
device's display and the admin workstation's import. Only after
unanimous confirmation is "Push signed notice" pressed.

### B.3 Paper log template (Part B)

```
UMOJA SECURE — RECOVERY KEY USE CEREMONY
==========================================

Ceremony ID:      ____________________
Date:             ____________________  Time (UTC): __________
Ceremony lead:    ____________________
Witness:          ____________________
Custodian:        ____________________

NOTICE TYPE
  [ ] key_rotation        [ ] key_revocation      [ ] recovery_key_rotation

NOTICE PAYLOAD (all fields reviewed)
  (Fields per notice type; transcribe from the admin workstation.)
  _______________________________________________________________
  _______________________________________________________________
  _______________________________________________________________
  _______________________________________________________________
  _______________________________________________________________
  _______________________________________________________________

B.2.1.1 — FULL PAYLOAD REVIEW (added; recovery-only)
  Lead agrees with all fields:       [ ] YES  [ ] NO — ABORT
  Witness agrees with all fields:    [ ] YES  [ ] NO — ABORT
  Custodian agrees with all fields:  [ ] YES  [ ] NO — ABORT
  Lead:      [____]  Witness: [____]  Custodian: [____]

B.2.2 — TRANSFER TO OFFLINE DEVICE (per PROVISIONING-CEREMONY.md B.2.2)
  Device isolated (dumpsys verified):  [ ] YES
  Mode "operating" launched:            [ ] YES
  Notice payload loaded:                [ ] YES
  Lead:      [____]  Witness: [____]  Custodian: [____]

B.2.2.1 — SPLIT PASSCODE VERIFICATION (added; recovery-only)
  Ceremony lead entered first half:      [ ] YES
  Custodian entered second half:         [ ] YES
  Device unlocked with both halves:      [ ] YES  [ ] NO — ABORT
  Lead:      [____]  Custodian: [____]

B.2.3 — HASH COMPARISON (per PROVISIONING-CEREMONY.md B.2.3)
  Device-displayed hash:  ____________________
  Admin-displayed hash:   ____________________
  Match:  [ ] YES (proceed)  [ ] NO — ABORT
  Lead:      [____]  Witness: [____]  Custodian: [____]

B.2.5 — SIGNING (per PROVISIONING-CEREMONY.md B.2.5)
  RecoveryNoticeSigner invoked:      [ ] YES
  "Signature ready" displayed:       [ ] YES
  Signature is 86 chars (64 bytes):  [ ] YES
  Lead:      [____]  Witness: [____]  Custodian: [____]

B.2.6 — TRANSFER BACK (per PROVISIONING-CEREMONY.md B.2.6)
  Signature scanned by admin:        [ ] YES
  "Signature imported" displayed:    [ ] YES

B.2.6.1 — UNANIMOUS SIGNATURE CONFIRMATION (added; recovery-only)
  All three operators confirm prefix:  [ ] YES  [ ] NO — ABORT
  Lead:      [____]  Witness: [____]  Custodian: [____]

B.2.7 — PUSH TO BACKEND (per PROVISIONING-CEREMONY.md B.2.7)
  Notice pushed:                     [ ] YES
  HTTP response code:                __________
  If non-2xx, error code:            __________
  Lead:      [____]  Witness: [____]  Custodian: [____]

B.2.8 — RETURN TO SAFE #2 (per PROVISIONING-CEREMONY.md B.2.8)
  adb kill-server issued:            [ ] YES
  USB disconnected:                  [ ] YES
  Device locked:                     [ ] YES
  Time locked (UTC):                 __________
  Lead:      [____]  Witness: [____]  Custodian: [____]

CONCLUSION
  Ceremony complete without deviation:  [ ] YES  [ ] NO
  If NO, describe: _____________________________________________

  Ceremony lead signature:  ___________________________
  Witness signature:        ___________________________
  Custodian signature:      ___________________________
```

### B.4 Completion

- [ ] File the sealed log in Safe #2.
- [ ] Append a custody-log entry with ceremony ID, date, notice
      type, and the notice's `nonce` / `event_id` (the two
      identifiers a client handler will use to dedupe against
      replay).
- [ ] **After the notice is live:** verify a target device's
      behavior has changed to match the notice's intent (e.g., after
      `key_revocation`, a matrix signed by the revoked key is
      rejected; after `key_rotation`, matrices signed by either the
      previous or current key are accepted during the overlap window).
- [ ] If the notice type was `recovery_key_rotation`: the OLD
      recovery device is destroyed during Part C (this ceremony
      does not itself destroy the old key; a separate Part C
      ceremony does).

---

## Part C — Routine recovery-key rotation (annual)

Per KEY-CUSTODY §3.5, the recovery key is rotated **annually** (or
after any suspected compromise — but see Part D for compromise,
which is terminal and requires physical re-provisioning).

**Procedure:**

1. Generate a **new** recovery keypair per Part A on a **new**
   offline device (or the same device after the old key is
   destroyed, but see step 5). The new key's `recovery_key_version`
   is the old version + 1.
2. The **old** recovery key signs a `recovery_key_rotation` notice
   containing the new recovery public key and the incremented
   version. This is a Part B ceremony using the old device.
3. The notice is distributed to all devices via the normal channel
   (`GET /identity-change-notices` or the notice-specific endpoint
   as P1-036 defines it).
4. Verify all devices have accepted the notice (client-side
   `highest_recovery_key_version` has advanced to the new version).
5. The old recovery device's **passcode is destroyed** and the key
   is destroyed via `deleteKey` during a short three-person
   ceremony against the old device (see C.1).
6. Return the new device to Safe #2.

The old device's passcode destruction (step 5) is what makes the
rotation meaningful — a still-unlockable old device, even with the
key deleted from the app, still holds its unlock credential.

**Part C is a full ceremony**: it requires a Part A ceremony (for the
new key) and a Part B ceremony (for the notice signed by the old
key) and a destruction ceremony (step 5). Three ceremonies, three
paper logs, one recovery-key rotation.

---

## Part D — Emergency recovery-key rotation (compromise)

If the recovery key is compromised, per KEY-CUSTODY §3.6:

- There is **no cryptographic recovery path.** The trust anchor is
  gone. Every device that trusts the current recovery key trusts a
  key now (or possibly) in an adversary's possession.
- **Physical re-provisioning of all devices is required.** Each
  device must be factory-reset, re-enrolled via the provisioning
  ceremony, and given a fresh matrix signed under a fresh
  provisioning key authorized by a fresh recovery key.
- This is a documented limitation of the trust model. It is why
  recovery-key custody is the strictest control in the system.

**There is no Part D ceremony to run.** Emergency recovery-key
rotation is an organizational action, not a procedural one. The
recovery runbook's job here is to name the terminal state honestly,
not to pretend a procedural fix exists.

If compromise is *suspected* but not confirmed: run Part C
(rotation) with the strictest custody precautions. If compromise is
*confirmed*: physical re-provisioning.

---

## Part E — Failure handling

The general rule (same as `PROVISIONING-CEREMONY.md` Part C): **a
partial ceremony is never resumed.** If any step fails, the three
operators abort the ceremony and restart from the first step of the
same Part.

**For Part A specifically:** if the recovery key was generated but a
later step failed (seal absent, second copy of split passcode
missing, backend config step failed), the key is destroyed via
`deleteKey` and the ceremony restarts from A.2.1. A partial Part A
is never resumed. Because two-person control of the safe combination
is established at Safe #2 provisioning, and the device passcode is
split at A.2.2.1, a failed Part A may need an out-of-cycle update to
Safe #2's combination if either the lead or custodian is the reason
for failure.

**For Part B specifically:** a failed notice-signing can be retried
without destroying the key — the key is the same, only the notice
being signed changes. Rerun Part B from the beginning (new paper
log; the failed log is retained as a finding). Critically, if the
notice was partially signed (signature returned but not pushed),
the old signature cannot be reused for a re-run; the recovery
device must sign the notice again with the same key and the same
payload, producing the same signature (Ed25519 is deterministic).
A different payload requires a fresh Part B.

Every abort is recorded on the paper log with the abort reason, the
step reached, and all three operators' initials at the abort.

---

## Part F — Audit trail and retention

Every ceremony — Part A, each Part B instance, each Part C rotation
cycle — produces a sealed paper log filed in Safe #2.

Retention (KEY-CUSTODY §2.8 extended by §3.7): life of the key plus
the organization's retention period, minimum 7 years. The recovery
key's records are retained under the same retention rule as the
provisioning key's, with the addition of the recovery-key
custodian's signature on every record (KEY-CUSTODY §3.7).

Retrieval for external audit follows the same three-person access
control as the key itself (lead + custodian for Safe #2 access, plus
witness for retrieval). Retrieve under witness.

The audit trail does NOT live on the recovery device's storage —
the device is a signing tool, not a log store. The device's `adb
shell` output during the ceremony is captured on the paper log;
the paper log is the durable record.

---

## Part G — What this runbook does NOT cover

- **Routine provisioning-key operations** — `PROVISIONING-CEREMONY.md`.
  This runbook is exclusively about the recovery key; provisioning
  key generation and routine matrix signing live in the other
  runbook.
- **The `RECOVERY_PUBKEY_B64U` env config step in full** — see
  `PROVISIONING-CEREMONY.md` A.2.7 for the analogous
  `PROVISIONING_PUBKEY_B64U`; the shape is identical.
- **Cryptographic protocol** — Build Master §3.8.
- **Threat modeling** — KEY-CUSTODY §7.
- **StrongBox attestation verification** — deferred to TASK-P1-034
  (same gap as `PROVISIONING-CEREMONY.md` A.2.5).
- **Test-signing / test-notice drill** — a rehearsal with a throwaway
  recovery key is recommended annually (similar to KEY-CUSTODY
  §6.1's provisioning test-signing ceremony) but is not this
  runbook's scope.
- **Client-side notice handling** — the code that consumes these
  notices on each device is P1-036 (still `Proposed` in the registry
  as of 2026-10-21; the notice schemas and signer are complete but
  no client handler parses them yet).

---

## Cross-references

Authoritative (design):
- `docs/ops/KEY-CUSTODY.md` §3.1 (generation), §3.2 (storage), §3.3
  (access control), §3.4 (use), §3.5 (routine rotation), §3.6
  (emergency rotation), §3.7 (audit)
- `UMOJA-SECURE-BUILD-MASTER.md` §3.6 (rotation/revocation authority),
  §3.8 (signing protocol)
- `docs/architecture/ADR-PROVISIONING-001.md` §2 Q6 (provisioning
  key compromise)
- `docs/reference/THREAT-MODEL-001.md` §5–§9

Companion runbook (composition):
- `docs/ops/PROVISIONING-CEREMONY.md` — the shared procedural steps
  this runbook references

Implementation:
- `backend/src/crypto/recovery-notice.ts` — TS schema for the three
  notice types (TASK-P1-035a)
- `android/app/src/main/java/com/umoja/secure/crypto/RecoveryNotice.kt`
  — Kotlin schema (TASK-P1-035b)
- `android/app/src/main/java/com/umoja/secure/crypto/RecoveryNoticeSigner.kt`
  — Kotlin signer (TASK-P1-035b)
- `docs/reference/canonical-recovery-notice-test-vectors.json` — 5
  test vectors, cross-language (TASK-P1-035a, verified by
  TASK-P1-035b's Kotlin tests)
- `backend/src/config/env.ts` — `RECOVERY_PUBKEY_B64U` config

---

## Revision history

| Version | Date | Change |
|---|---|---|
| 0.1 | 2026-10-21 | Initial draft. TASK-P1-035c. No ceremony executed yet; runbook is specification-of-procedure until P1-035d. |