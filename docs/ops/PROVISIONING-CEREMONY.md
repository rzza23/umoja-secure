# Provisioning ceremony — operational runbook

**Task:** TASK-P1-033d
**Status:** Specification of procedure. No production ceremony has been
executed.
**Last updated:** 2026-10-20

---

## Purpose

This is the operational runbook for the two ceremonies that move a
matrix from the admin app to signed authorization:

- **Part A — Generation ceremony** (one-time per organization): the
  provisioning keypair is generated on an air-gapped offline device.
- **Part B — Signing ceremony** (per matrix): a canonical matrix from
  the admin app is signed by the offline device, and the signature is
  returned for push to the backend.

Two operators are present throughout both ceremonies. Both initial the
paper log at every checkpoint. A partial ceremony is never resumed.

**This document does not stand alone.** It operationalizes the design
in `docs/ops/KEY-CUSTODY.md` §2 (generation) and §2.4 (signing), and
the protocol in `UMOJA-SECURE-BUILD-MASTER.md` §3.6 and §3.8. Where
this runbook and the design documents disagree, the design documents
win — this runbook is procedure, not policy.

**This document does not cover** cryptographic protocol (that's §3.8),
threat modeling (KEY-CUSTODY §7), or recovery-key custody (TASK-P1-035,
KEY-CUSTODY §3). It covers only routine provisioning-key operations.

---

## Execution status

**No production ceremony has been executed as of 2026-10-20.**
TASK-P1-033e will execute the first end-to-end drill using this
runbook. Until that drill completes, this document is a
*specification of procedure*, not a *record of a proven procedure*.

When P1-033e completes, its record is appended here as the first
verified execution:

```
Drill 001 — <date> — outcome: <PASS|FAIL> — deviations: <none|list>
```

If the drill reveals a gap in this runbook, the gap is corrected
before the first production ceremony.

---

## Part A — Generation ceremony (one-time per organization)

The provisioning keypair is generated **once** and **never leaves the
device**. Regeneration is a documented recovery procedure (KEY-CUSTODY
§2.1 "Failure handling"), not an app action. If `am start --es mode
ceremony` is run on a device that already has a key, the app **refuses**
and displays "already present; ceremony refused" — this is expected
behavior, not a failure of the app.

### A.1 Prerequisites

Before either operator enters the room:

- [ ] **Offline device** (Pixel 7+ with StrongBox/Titan M2, GrapheneOS)
      is in its safe and has never been connected to any network.
- [ ] **Signing APK** is built (`./gradlew :app:assembleSigningDebug`)
      and its SHA-256 recorded in the build manifest. Verified by
      the ceremony lead against a known-good build.
- [ ] **Signing APK is installed** on the offline device via ADB from
      a clean workstation (KEY-CUSTODY §4.2). Installation happened
      while the device was physically offline; if installation is
      being done as part of the ceremony, it must precede step A.2.
- [ ] **Ceremony workstation** is a machine the org controls, ADB
      available, USB cable present, no other devices attached.
- [ ] **Paper log** printed (template at A.3), pen, sealed envelope
      for the completed log, tamper-evident bag for the device.
- [ ] **Backend config credentials** (`PROVISIONING_PUBKEY_B64U` will
      need to be set post-generation; see A.2.7).
- [ ] **Two operators present**: ceremony lead and witness. Both must
      be present for the full procedure; either absence is an abort
      condition.

### A.2 Procedure

Execute KEY-CUSTODY §2.1's 8 steps. Each step has a verification the
paper log records.

**Step A.2.1 — Verify network isolation.**

```
adb shell dumpsys connectivity | grep -iE "active|wifi|mobile|bluetooth|ethernet"
```

Expected: no active networks of any kind. Transcribe or attach the
output to the paper log.

**Step A.2.2 — Launch ceremony mode.**

```
adb shell am start \
  -n com.umoja.secure.signing/com.umoja.secure.signing.SigningActivity \
  --es mode ceremony
```

The app displays the provisioning public key (base64url, 43 chars).
The keypair is generated in StrongBox with `setIsStrongBoxBacked(true)`.

If the app displays "Provisioning key already present; ceremony refused":
**abort**. This device already has a provisioning key. Either the
device was not properly prepared, or an earlier ceremony was not
completed. Investigate before proceeding — do not attempt to force
regeneration; that's a documented recovery procedure (KEY-CUSTODY §2.1).

If the app displays "Ceremony failed: <reason>": **abort**. Record the
reason on the paper log and restart from step A.2.1.

**Step A.2.3 — Verify StrongBox backing.**

The app's key-generation flow asserts StrongBox at generation time; a
TEE-only fallback is not acceptable for this custody model (KEY-CUSTODY
§2.1 step 2). If the app does not display the pubkey (i.e., the
generation failed silently), the StrongBox assertion failed — abort.

**Step A.2.4 — Transcribe the public key.**

The app displays the pubkey as a QR and as copyable text. Both
operators independently transcribe the base64url text onto the paper
log (step A.3, "PROVISIONING PUBLIC KEY" field), then compare
transcriptions. Match required; mismatch aborts.

**Step A.2.5 — Record attestation.**

If the app displays attestation certificate information, record the
certificate chain hash on the paper log. Verify against Google's
published root offline. If the app does not display attestation
information (current implementation as of 2026-10-20 does not), record
"not available in current build — pending TASK-P1-034" on the paper
log. The design intent (KEY-CUSTODY §2.1 step 5) is deferred to P1-034's
StrongBox attestation verification.

**Step A.2.6 — Seal the paper log.**

Place the completed paper log (from this ceremony so far) in a sealed
envelope. Both operators sign across the seal. Initial the paper log
at the seal step.

**Step A.2.7 — Update backend config (post-generation, pre-signing).**

This step is NOT in Build Master §3.6's 9-step list — it is a
prerequisite discovered during implementation (TASK-P1-033a). The
backend verifies signatures at push time against `PROVISIONING_PUBKEY_B64U`;
until that env var is set to the ceremony's public key, every push in
Part B will 400 `invalid_signature`.

```
# On the backend host (NOT the offline device):
export PROVISIONING_PUBKEY_B64U='<the 43-char value from the paper log>'
docker compose up -d --build backend
curl -fsS http://127.0.0.1:8080/health
```

Record on the paper log:
- [ ] `PROVISIONING_PUBKEY_B64U` set on backend: YES / NO
- [ ] Backend restarted: YES / NO
- [ ] Health endpoint returns 200: YES / NO

If any check fails: the ceremony produced a key that nothing can
validate against yet — this is an abort condition, not a deferred
problem. Do not proceed to Part B. The key remains valid; the ceremony
can complete Part A step A.2.8 after the backend issue is resolved.

**Step A.2.8 — Return device to safe.**

```
adb kill-server
```

Disconnect USB. Lock the offline device. Return it to Safe #1 along
with the sealed paper log. Record device lock time on the paper log.

Initial the paper log at completion.

### A.3 Paper log template (Part A)

Print this template and transcribe as the ceremony proceeds. Do not
prefill fields before the ceremony starts.

```
UMOJA SECURE — PROVISIONING KEY GENERATION CEREMONY
====================================================

Ceremony ID:      ____________________
Date:             ____________________  Time (UTC): __________
Org:              ____________________
Ceremony lead:    ____________________
Witness:          ____________________

DEVICE & APP
  Device model:         ____________________
  Serial number:        ____________________
  GrapheneOS version:   ____________________
  Signing APK SHA-256:  ____________________
  Expected hash (from build manifest): ____________________
  APK hash matches:     [ ] YES  [ ] NO — ABORT if NO

A.2.1 — NETWORK ISOLATION
  dumpsys connectivity output (attach or transcribe):
  _______________________________________________________________
  _______________________________________________________________
  No active networks:   [ ] VERIFIED
  Lead initial:   [____]  Witness initial: [____]

A.2.2 — LAUNCH CEREMONY MODE
  adb command issued:   [ ] YES
  App shows pubkey:     [ ] YES  [ ] NO — ABORT if NO
  If NO, reason shown:  ______________________________________
  Lead initial:   [____]  Witness initial: [____]

A.2.3 — STRONGBOX BACKING
  Key generation reported success:  [ ] YES
  StrongBox assertion passed:       [ ] YES  [ ] NO — ABORT
  Lead initial:   [____]  Witness initial: [____]

A.2.4 — PUBLIC KEY TRANSCRIPTION
  Provisioning public key (base64url, 32 raw bytes, 43 chars):
  _______________________________________________________
  Transcribed by lead:      [____]
  Transcribed by witness:   [____]
  Transcriptions match:     [ ] YES  [ ] NO — ABORT if NO

A.2.5 — ATTESTATION
  Attestation chain hash:   ____________________________________
  Verified against Google root:  [ ] YES
  If not available in current build:
    [ ] NOT AVAILABLE (pending TASK-P1-034)
  Lead initial:   [____]  Witness initial: [____]

A.2.6 — SEAL
  Envelope number:          __________
  Signed across seal:       lead [____]  witness [____]
  Stored in Safe #1:        [ ] YES
  Witness initial:   [____]

A.2.7 — BACKEND CONFIG
  PROVISIONING_PUBKEY_B64U set:  [ ] YES
  Backend restarted:             [ ] YES
  Health returns 200:            [ ] YES
  Lead initial:   [____]  Witness initial: [____]

A.2.8 — RETURN TO SAFE
  adb kill-server issued:   [ ] YES
  USB disconnected:         [ ] YES
  Device locked:            [ ] YES
  Time locked (UTC):        __________
  Lead initial:   [____]  Witness initial: [____]

CONCLUSION
  Ceremony complete without deviation: [ ] YES  [ ] NO
  If NO, describe: _____________________________________________

  Ceremony lead signature:  ___________________________
  Witness signature:        ___________________________
```

### A.4 Completion

After the paper log is sealed:

- [ ] File the sealed log in Safe #1 (KEY-CUSTODY §2.2).
- [ ] Add a custody-log entry naming the ceremony ID, date, and the
      public key fingerprint (SHA-256 of the 32-byte pubkey, hex).
- [ ] Do NOT store the public key anywhere other than the sealed
      log and the backend env var — public keys are not secret but
      keep the process simple.
- [ ] The `android/app/src/main/java/com/umoja/secure/crypto/ProvisioningKeys.kt`
      `PRODUCTION_PROVISIONING_PUBKEY_B64U` const still holds the
      43-underscore placeholder as of 2026-10-20. Replacing it with
      the ceremony's pubkey is part of the next production build —
      see TASK-P1-029b's KDoc and TASK-P1-033e's drill for the
      replacement procedure.

---

## Part B — Signing ceremony (routine, per matrix)

Performed every time the admin app produces a new authorization matrix
for a device. Same two-person control as Part A.

### B.1 Prerequisites

- [ ] Part A completed; provisioning key exists on the offline device
      and its public key is set as `PROVISIONING_PUBKEY_B64U` on the
      backend.
- [ ] Admin app has produced `{unsigned_matrix, canonical_hash}` for
      the target device, via the "Build matrix" button (TASK-P1-025,
      TASK-P1-033b).
- [ ] Both operators present, paper log printed (template at B.3).
- [ ] Offline device removed from Safe #1, tamper bag opened, in the
      presence of both operators.
- [ ] Ceremony workstation ready with USB connection to the offline
      device.

### B.2 Procedure

Execute KEY-CUSTODY §2.4's 8 steps. Each step has a verification the
paper log records.

**Step B.2.1 — Admin app displays matrix.**

Ceremony lead: on the admin app, press "Build matrix" in the
provisioning section. The admin app displays the canonical wrapper and
its SHA-256 digest. Witness confirms the values on the admin screen
match the admin's request (device_id, version, permitted contacts).

Record on the paper log: target device_id, matrix version, matrix
hash. Both operators initial.

**Step B.2.2 — Transfer to offline device.**

```
adb shell dumpsys connectivity | grep -iE "active|wifi|mobile|bluetooth|ethernet"
```

Verify no active networks (same check as Part A). Then:

```
adb shell am start \
  -n com.umoja.secure.signing/com.umoja.secure.signing.SigningActivity \
  --es mode operating
```

The app shows "Ready to sign — scan or paste a canonical matrix."
Scan the admin app's matrix QR with the offline device's camera (or
paste the canonical text; QR is preferred).

**Step B.2.3 — Hash comparison.**

The offline device recomputes the SHA-256 of the re-canonicalized
matrix and displays it. Both operators compare this hash to the hash
displayed on the admin app.

**Match required. If mismatch: abort.** A mismatch means either the
transfer corrupted the bytes or the admin app and offline device are
using different canonicalizers. Investigate before proceeding.

Record both hashes on the paper log.

**Step B.2.4 — Matrix content review.**

The offline device displays `device_id`, `version`,
`permitted_contacts`, and `clearance`. Both operators compare each
field to the admin app's request. Mismatch in any field aborts.

Record on the paper log: each field, matched YES/NO. Both initial.

**Step B.2.5 — Signing.**

Ceremony lead presses "Sign" on the offline device. The app computes
the SHA-256 digest of the canonical bytes and signs the 32-byte digest
with the provisioning private key (Ed25519, StrongBox-backed). The
app displays "Signature ready."

Confirm: the signature is 86-char base64url (64 bytes, no padding).

**Step B.2.6 — Transfer back.**

The offline device displays the signature as a QR. On the admin app,
press "Scan signature" and scan the QR (or paste the signature text
into the signature field and press "Import signature").

The admin app displays "Signature imported: <first 12 chars>…". Both
operators confirm this matches the offline device's signature prefix.

**Step B.2.7 — Push to backend.**

On the admin app, press "Push signed matrix." The app calls
`POST /admin/matrices/:device_id`.

Expected response: 201, and the admin app displays
"Pushed: <id8>… at v<version>". The version displayed must match
the version the admin app built in B.2.1.

If response is not 201: **abort**. Common failures:
- 400 `invalid_signature` — the backend's `PROVISIONING_PUBKEY_B64U`
  does not match the offline device's signing key. Re-verify Part A
  step A.2.7.
- 400 `device_id_mismatch` — the URL device_id and the matrix's
  `matrix.device_id` disagree. Re-check the admin app's QR was
  scanned correctly.
- 409 `matrix_version_not_monotonic` — the target device already has
  a matrix at this or a higher version. This is fail-closed
  behavior; investigate why a push is being attempted at this
  version.

Record on the paper log: response code, returned version, and whether
it matches the built version.

**Step B.2.8 — Return device to safe.**

```
adb kill-server
```

Disconnect USB. Lock the offline device. Return it to Safe #1 with the
sealed paper log. Record device lock time.

Record on the paper log. Both initial.

### B.3 Paper log template (Part B)

```
UMOJA SECURE — MATRIX SIGNING CEREMONY
========================================

Ceremony ID:      ____________________
Date:             ____________________  Time (UTC): __________
Ceremony lead:    ____________________
Witness:          ____________________

MATRIX SUBJECT
  Target device_id:     ____________________
  Matrix version:       ____________________
  Matrix hash (admin):  ____________________
  Admin build ID:       ____________________

B.2.1 — ADMIN DISPLAYS MATRIX
  Admin shows unsigned matrix QR + hash: [ ] YES
  Lead initial:   [____]  Witness initial: [____]

B.2.2 — TRANSFER TO OFFLINE DEVICE
  Device isolated (dumpsys verified):  [ ] YES
  Mode "operating" launched:            [ ] YES
  QR scanned successfully:              [ ] YES
  Lead initial:   [____]  Witness initial: [____]

B.2.3 — HASH COMPARISON
  Device-displayed hash:  ____________________
  Admin-displayed hash:   ____________________
  Match:  [ ] YES (proceed)  [ ] NO — ABORT
  Lead initial:   [____]  Witness initial: [____]

B.2.4 — MATRIX CONTENT REVIEW
  device_id matches admin record:    [ ] YES  [ ] NO
  version matches admin record:      [ ] YES  [ ] NO
  permitted_contacts matches:        [ ] YES  [ ] NO
  clearance matches:                 [ ] YES  [ ] NO
  Lead initial:   [____]  Witness initial: [____]

B.2.5 — SIGNING
  "Sign" pressed by lead:            [ ] YES
  "Signature ready" displayed:       [ ] YES
  Signature is 86 chars (64 bytes):  [ ] YES
  Lead initial:   [____]  Witness initial: [____]

B.2.6 — TRANSFER BACK
  Signature scanned by admin app:    [ ] YES
  "Signature imported" displayed:    [ ] YES
  Prefix matches device display:     [ ] YES
  Lead initial:   [____]  Witness initial: [____]

B.2.7 — PUSH TO BACKEND
  "Push signed matrix" pressed:      [ ] YES
  HTTP response code:                __________
  Version returned by server:        __________
  Matches matrix version:            [ ] YES  [ ] NO
  If non-201, error code:            __________
  Lead initial:   [____]  Witness initial: [____]

B.2.8 — RETURN TO SAFE
  adb kill-server issued:            [ ] YES
  USB disconnected:                  [ ] YES
  Device locked:                     [ ] YES
  Time locked (UTC):                 __________
  Lead initial:   [____]  Witness initial: [____]

CONCLUSION
  Ceremony complete without deviation:  [ ] YES  [ ] NO
  If NO, describe: _____________________________________________

  Ceremony lead signature:  ___________________________
  Witness signature:        ___________________________
```

### B.4 Completion

- [ ] File the sealed log in Safe #1.
- [ ] Append a custody-log entry with ceremony ID, date, target
      device_id, matrix version, and the `PushResult` returned by the
      backend.
- [ ] Verify downstream: the target device, on next launch, fetches
      `GET /me/matrix` (P1-037) and calls `MatrixStore.accept`
      (P1-026). The device's diagnostics screen shows
      `highestSeenVersion` matching the version pushed in B.2.7. If
      the target device is available, confirm. If not, note on the
      paper log that downstream verification is deferred.

---

## Part C — Failure handling

The general rule: **a partial ceremony is never resumed.** If any
step fails, the operators abort the ceremony and restart from the
first step of the same Part.

For Part A specifically (KEY-CUSTODY §2.1 "Failure handling"): if
the key was generated but a later step failed, the key is destroyed
(`deleteKey` is invoked via a documented recovery action — not
exposed in the app; contact the ceremony lead's escalation contact)
and the ceremony restarts from A.2.1. A partial Part A is never
resumed.

For Part B specifically: a failed signing can be retried without
destroying the key — the key is the same, only the matrix being
signed changes. Rerun Part B from the beginning (new paper log entry;
the failed log is retained as a finding).

Every abort is recorded on the paper log with the abort reason, the
step reached, and the operators' initials at the abort.

---

## Part D — Audit trail and retention

Every ceremony — Part A and each Part B instance — produces a sealed
paper log filed in Safe #1.

Retention (KEY-CUSTODY §2.8): life of the key plus organization's
retention period, minimum 7 years.

Retrieval for external audit follows the same two-person access
control as the key itself (KEY-CUSTODY §2.3). Retrieve under witness.

The audit trail does NOT live on the offline device's storage — the
device is a signing tool, not a log store. The device's `adb shell`
output during the ceremony is captured on the paper log; the paper
log is the durable record.

---

## Part E — What this runbook does NOT cover

- **Recovery-key generation, custody, and revocation** — TASK-P1-035,
  `docs/ops/KEY-CUSTODY.md` §3.
- **Provisioning-key rotation** — `docs/ops/KEY-CUSTODY.md` §2.5,
  TASK-P1-036. This runbook covers routine signing only.
- **Provisioning-key compromise recovery** — `docs/ops/KEY-CUSTODY.md`
  §2.6. Requires the recovery key; out of scope here.
- **StrongBox attestation verification** — deferred to TASK-P1-034.
  Current signing app does not export an attestation chain; step
  A.2.5 records this as a known gap.
- **Test-signing drill** — `docs/ops/KEY-CUSTODY.md` §6.1.
- **Backend operational procedures** — `docs/ops/RELEASE-ACCEPTANCE.md`
  and `docs/ops/TOR-ONION.md`.

---

## Cross-references

Authoritative (design):
- `docs/ops/KEY-CUSTODY.md` §2.1 (generation), §2.4 (signing), §2.8 (audit)
- `UMOJA-SECURE-BUILD-MASTER.md` §3.6 (workflow), §3.8 (signing protocol)
- `docs/architecture/ADR-PROVISIONING-001.md` §2 Q6, §3
- `docs/reference/THREAT-MODEL-001.md` §5–§8

Implementation:
- `android/app/src/signing/kotlin/com/umoja/secure/signing/SigningActivity.kt`
- `android/app/src/signing/kotlin/com/umoja/secure/signing/SigningScreen.kt`
- `android/app/src/signing/kotlin/com/umoja/secure/signing/SigningState.kt`
- `android/app/src/main/java/com/umoja/secure/crypto/DeviceKeyManager.kt`
- `backend/src/routes/admin.ts` (POST /admin/matrices/:device_id)
- `backend/src/config/env.ts` (PROVISIONING_PUBKEY_B64U)

Related runbook:
- `docs/ops/RELEASE-ACCEPTANCE.md` (build acceptance)

---

## Revision history

| Version | Date | Change |
|---|---|---|
| 0.1 | 2026-10-20 | Initial draft. TASK-P1-033d. No ceremony executed yet; runbook is specification-of-procedure until P1-033e. |