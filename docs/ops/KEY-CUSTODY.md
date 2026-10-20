# KEY-CUSTODY — Provisioning and Recovery Key Custody

Document ID: KEY-CUSTODY
Date: 2026-10-19
Authority: UMOJA-SECURE-BUILD-MASTER.md §3.6 (Offline Provisioning and Recovery); TASK-P1-029
Scope: Generation ceremony, storage, access control, use procedure, rotation, retirement, and audit for both the organization provisioning key and the organization recovery key.

---

## §1 Decision and scope

The organization provisioning key and the organization recovery key are **held offline on dedicated Android devices using StrongBox-backed Keystore**. This document defines the operational procedures that satisfy Build Master §3.6.

The three options offered by §3.6 were evaluated:

| Option | Key-at-rest protection | Attack surface | Implementation cost | Ruling |
|---|---|---|---|---|
| **Dedicated Android device (StrongBox)** | Dedicated secure element; key never in OS memory | Android OS, app code; StrongBox isolates key from both | Low — reuses `MatrixSigner` | **CHOSEN** |
| YubiKey (Ed25519) | Hardware token, non-extractable | USB host machine; token used as signing oracle if host compromised | Medium — PC-side signing tool required | Rejected |
| Air-gapped computer + software HSM | Depends on software; key exists in memory during signing | Entire OS + software stack | High — new tooling, still extractable during signing | Rejected |

**Why StrongBox wins.** StrongBox (Titan M2) is a dedicated secure element — a separate chip with its own processor and memory, not a mode of the main CPU. Key material generated in StrongBox never enters the Android OS address space, not even the TEE's. This is the highest key-at-rest assurance available on commodity mobile hardware in 2026. The project already targets GrapheneOS on Pixel; StrongBox is available on Pixel 7 and later. `MatrixSigner` already uses BouncyCastle Ed25519 on Android and is unchanged. Option 2 requires a separate PC-side signing tool; Option 3 still keeps the key in extractable form during the signing operation.

**What this document does not cover:** the signing protocol itself (Build Master §3.8) and the runtime rotation/recovery protocol (Build Master §3.6). This document is operational: how to generate, store, use, rotate, and audit the keys.

---

## §2 Provisioning key

### §2.1 Generation ceremony

**Where:** A dedicated Android device (Pixel 7 or later, GrapheneOS) that has never been connected to a network, held in a locked safe when not in use.

**Who:** Ceremony lead (runs the device), witness (observes and signs the paper record). Both must be present for the entire ceremony.

**Procedure:**

1. **Verify device state.** `dumpsys connectivity` must show no active SIM, no Wi-Fi association, no Bluetooth pairing, no USB tethering. Record the output on the paper record.
2. **Verify StrongBox availability.** The offline signing app reports `hasStrongBox()` and `isStrongBoxBacked()` for the generated key. If StrongBox is unavailable, the ceremony **aborts** — a TEE-only key is not acceptable for this custody model.
3. **Verify app integrity.** The offline signing APK's SHA-256 hash is compared to the hash recorded in the build manifest. Record the match on the paper record.
4. **Generate the keypair.** The app generates an Ed25519 keypair in StrongBox with `setIsStrongBoxBacked(true)` and `setAttestationChallenge()` set to a ceremony nonce.
5. **Record the attestation.** The app exports the attestation certificate chain. The ceremony lead verifies the chain offline against Google's root and records the certificate hash on the paper record.
6. **Record the public key.** The app displays the public key (base64url, 32 bytes). Both operators transcribe it onto the paper record and initial.
7. **Seal the record.** The paper record is sealed in an envelope, signed across the seal by both operators, and stored in the safe alongside the device.
8. **Destroy ceremony nonce.** The nonce used for attestation is destroyed (overwritten) after the record is sealed.

**Failure handling:** If any step fails, the keypair is destroyed (`deleteKey`) and the ceremony restarts from §2.1 step 1. A partial ceremony is never resumed.

### §2.2 Storage

- **Device:** Stored in a locked safe (Safe #1) when not in active use.
- **Paper record:** Stored in the same safe, in a sealed envelope signed across the seal by both operators.
- **Backup:** No cryptographic backup exists. StrongBox keys are non-exportable by design. If the device is lost or destroyed, the provisioning key is lost and the recovery key must authorize a new provisioning key (§3.4).

### §2.3 Access control

- **Physical access:** Safe #1 combination is held by two named individuals (the ceremony lead and the witness). Opening the safe requires both to be present.
- **Device unlock:** The device has a strong passcode (minimum 8 digits, no biometric unlock for the signing device). The passcode is held by the ceremony lead and stored in a sealed envelope in Safe #1.
- **Signing sessions:** Every signing session requires both the ceremony lead and the witness to be physically present.

### §2.4 Use procedure (signing ceremony)

This operationalizes Build Master §3.6's 9-step workflow.

1. **Admin app** produces `{unsigned_matrix, canonical_hash}` and displays them.
2. **Transfer to offline zone:** The admin transfers the canonical matrix (or its hash) to the offline device via QR. The offline device's camera reads the QR; no network is involved.
3. **Offline device re-canonicalizes** and computes the hash. Both operators compare it to the hash displayed by the admin app. **Match required; mismatch aborts.**
4. **Offline device displays** the matrix content: `device_id`, `version`, `permitted_contacts`, `clearance`. Both operators review and initial the paper record.
5. **Signing:** The offline device signs the SHA-256 digest of the JCS-canonical bytes with the provisioning private key (Ed25519, StrongBox-backed). The signature is 64 bytes, base64url no-padding.
6. **Transfer back:** The offline device displays the signature as a QR. The admin app scans it and attaches the signature to the matrix.
7. **Record the event:** The offline device writes a signed log entry (same key) containing the matrix hash, timestamp, and operator identifiers. The log entry is written to a second offline medium (a second QR or a printed page) and both operators sign the paper log.
8. **Return device to safe.** The device is locked and returned to Safe #1.

### §2.5 Routine rotation

The provisioning key is rotated only when the organization restructures or when a routine security review mandates it. There is no scheduled cadence — routine rotation requires re-authorizing every device's matrix acceptance and is a significant operational event.

**Rotation procedure:** See Build Master §3.6 "Key rotation (routine)." The rotation is authorized by a single `key_rotation` notice signed by the recovery key. The new provisioning key is generated per §2.1 on a new offline device (or the same device after the old key is destroyed). The overlap window duration is recorded in the rotation notice (default 30 days).

### §2.6 Emergency rotation (compromise)

If the provisioning key is compromised:

1. The recovery key signs a `key_revocation` notice per Build Master §3.6.
2. The revoked key is destroyed on the offline device (`deleteKey`).
3. A new provisioning key is generated per §2.1.
4. The new public key is distributed to devices via the `key_revocation` notice.

### §2.7 Retirement

When a provisioning key is retired (routine rotation or compromise):

1. The key is destroyed on the offline device (`deleteKey`).
2. The paper record is annotated with the retirement date and reason.
3. The device is retained for audit purposes (or destroyed per organizational policy).
4. A retirement entry is added to the custody log.

### §2.8 Audit trail

Every ceremony (generation, signing, rotation, retirement) produces:

- A paper record signed by both operators.
- A signed digital log entry written to offline media.
- A hash of the signed log entry recorded in the paper record.

The audit log is retained for the life of the key plus the organization's retention period (minimum 7 years). Retrieval for external audit follows the same two-person access control as the key itself.

---

## §3 Recovery key

The recovery key is the trust anchor for provisioning-key rotation and revocation. Its custody is **stricter** than the provisioning key's, as required by Build Master §3.6.

### §3.1 Generation ceremony

**Where:** A separate dedicated Android device (Pixel 7 or later, GrapheneOS), used only for the recovery key. Never the same device that holds the provisioning key.

**Who:** Ceremony lead, witness, and a third named individual (the recovery-key custodian) who will hold one part of the two-person control. All three must be present.

**Procedure:** Same as §2.1 (StrongBox verification, attestation, public-key recording), with these additions:

1. **Two-person control at generation.** The device passcode is split (e.g., two halves held by the ceremony lead and the recovery-key custodian). Neither can unlock the device alone.
2. **Recovery key version** is recorded (integer, starts at 1; incremented on every rotation).
3. **Public key** is recorded on the paper record and in the signed digital log.

### §3.2 Storage

- **Device:** Stored in a **different** locked safe (Safe #2) from the provisioning key, in a different physical location if possible.
- **Paper record:** Stored in Safe #2.
- **Access:** Safe #2 requires two named individuals (the ceremony lead and the recovery-key custodian). Both must be present.

### §3.3 Access control

- **Safe #2 combination** is held by the ceremony lead and the recovery-key custodian.
- **Device passcode** is split between the same two individuals.
- **Signing sessions** require the ceremony lead, the witness, and the recovery-key custodian.

### §3.4 Use procedure (rotation/revocation signing)

The recovery key signs only:

- `key_rotation` notices (routine rotation of the provisioning key).
- `key_revocation` notices (emergency rotation after compromise).
- Recovery-key rotation notices (rotation of the recovery key itself).

The procedure is the same as §2.4, with these additions:

1. **Three-person ceremony:** Ceremony lead, witness, and recovery-key custodian must all be present.
2. **Recovery key version check:** The offline device displays the current `recovery_key_version`. The ceremony lead confirms it matches the expected value.
3. **Notice content review:** The notice payload (new provisioning key, `effective_at`, `nonce`, `event_id`, `recovery_key_version`) is displayed in full. All three operators review and initial the paper record.

### §3.5 Routine rotation

The recovery key is rotated **annually** (Build Master §3.6: "e.g., annually") or after any suspected compromise. Rotation is authorized by the recovery key itself.

**Procedure:**

1. Generate a new recovery key per §3.1 on a new offline device (or the same device after the old key is destroyed).
2. The old recovery key signs a recovery-key rotation notice containing the new public key and the incremented `recovery_key_version`.
3. The notice is distributed to devices via the normal channel.
4. The old recovery key is destroyed (`deleteKey`).

### §3.6 Emergency rotation of the recovery key

If the recovery key is compromised:

- There is **no cryptographic recovery path**. The trust anchor is gone.
- Physical re-provisioning of all devices is required.
- This is a documented limitation and is why recovery-key custody is the strictest control in the system.

### §3.7 Audit trail

Same as §2.8, with the addition of the recovery-key custodian's signature on every record.

---

## §4 Offline signing device specification

### §4.1 Hardware

- **Model:** Pixel 7 or later (Titan M2 / StrongBox). Specific validated models are recorded in the custody log. Pixel 6 and earlier are **not acceptable** — they lack StrongBox.
- **Minimum storage:** 128 GB (holds the OS, the offline signing app, and log data).
- **No SIM card installed.** No eSIM profile activated.

### §4.2 OS and app

- **OS:** GrapheneOS, verified build, installed from a signed OTA carried on physical media.
- **App:** The offline signing APK is built from the project's source, signed with the organization's release key, and installed via ADB from a clean workstation. The APK's SHA-256 hash is recorded in the custody log and re-verified before every signing session.
- **No network access:** The device is never connected to Wi-Fi, cellular, Bluetooth, or USB networking. `dumpsys connectivity` is checked before every ceremony.

### §4.3 Network isolation verification

Before every ceremony, the ceremony lead runs:

```bash
adb shell dumpsys connectivity | grep -iE "active|wifi|mobile|bluetooth|ethernet"
```

The output must show **no active networks**. The output is recorded in the paper log.

### §4.4 Physical controls

- **Safe storage:** Device is stored in a locked safe when not in active use.
- **Chain of custody:** Every removal from the safe is logged with date, time, purpose, and the individuals present.
- **Tamper evidence:** The device is stored in a tamper-evident bag when transported between the safe and the signing location.

---

## §5 Client implementation notes

### §5.1 ProvisioningKeys.kt DEBUG/PROD split

`ProvisioningKeys.kt` gains:

- `TEST_PROVISIONING_PUBKEY_B64U` — the current test key, pinned to the vector file.
- `PRODUCTION_PROVISIONING_PUBKEY_B64U` — the production key, injected at build time from the custody ceremony's output.
- `CURRENT_PROVISIONING_PUBKEY_B64U` — sourced from `BuildConfig.DEBUG ? TEST_* : PRODUCTION_*`.

`ProvisioningKeysTest` gains:

- `production provisioning pubkey differs from test key` — fails if the production constant accidentally points at the test seed.
- `production provisioning pubkey decodes to 32 bytes` — sanity check.

### §5.2 Rotation seam usage

`STORAGE_KEY_PREVIOUS_PROVISIONING_PUBKEY` is written by the rotation-notice handler when a `key_rotation` notice is accepted. This is TASK-P1-036's territory; this document records that the seam exists and is used exactly as ADR-PROVISIONING-001 §2 Q6 specifies.

---

## §6 Test and drill schedule

### §6.1 Annual test-signing ceremony

Once per year, the team performs a **test signing ceremony** with a throwaway test key (not the production key). The goal is to verify that:

- The offline device is still functional.
- The app's APK hash still matches the recorded value.
- The QR transfer works.
- The paper log procedure works.

### §6.2 Annual recovery-retrieval drill

Once per year, the recovery-key custodian retrieves the recovery device from Safe #2, unlocks it (with the ceremony lead), and verifies that the device is functional and the key is present. The device is returned to the safe. No signing occurs.

### §6.3 Acceptance criteria

- Test-signing ceremony completes without deviation from the documented procedure.
- Recovery-retrieval drill completes without unlocking the recovery key's signing capability (i.e., the device is verified but no signature is produced).
- Any deviation is logged as a finding and corrected before the next scheduled drill.

---

## §7 Threats and countermeasures

| Threat | Countermeasure |
|---|---|
| Theft of offline device | StrongBox non-exportability; strong passcode; safe storage |
| Compromised Android OS on offline device | StrongBox isolates key from OS; ceremony verifies `dumpsys connectivity` |
| Malicious admin app displays wrong matrix | Offline device re-canonicalizes and compares hash; mismatch aborts |
| Operator collusion (single operator) | Two-person control for provisioning; three-person for recovery |
| Lost device | No cryptographic backup; recovery key authorizes a new provisioning key |
| Recovery key compromise | Physical re-provisioning of all devices (documented terminal state) |
| Firmware CVE accumulation | Documented firmware update procedure via signed OTA on physical media |

---

## §8 Related documents

- `UMOJA-SECURE-BUILD-MASTER.md` §3.6, §3.8
- `docs/architecture/ADR-PROVISIONING-001.md` §2 Q6, §3
- `docs/architecture/ADR-HARDENING-001.md` (does not defer custody)
- `docs/reference/AUTH-SPEC-001.md` §5, §9
- `android/app/src/main/java/com/umoja/secure/crypto/ProvisioningKeys.kt`
- `android/app/src/main/java/com/umoja/secure/crypto/MatrixSigner.kt`

---

## §9 Approval

**Status:** Draft for project-owner review.

**Approver:** ______________________  **Date:** __________

**Revision history:**

| Version | Date | Change |
|---|---|---|
| 0.1 | 2026-10-19 | Initial draft. StrongBox-based custody model per Build Master §3.6. |