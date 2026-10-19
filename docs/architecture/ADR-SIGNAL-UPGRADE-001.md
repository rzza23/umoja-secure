# ADR-SIGNAL-UPGRADE-001 — libsignal version upgrade planning

Document ID: ADR-SIGNAL-UPGRADE-001
Version: 0.2 (approved)
Date: 2026-10-18
Authority: Derived from TASK-P1-005 (libsignal integration) and Build Master §0 (escalate, do not guess).
Status: **APPROVED 2026-10-18 — target 0.105.0 from Signal's Maven repository, 28-test absolute gate. See §5.4.**

---

## §1 Context

`TASK-P1-005` pinned `org.signal:libsignal-android:0.81.1` and
`org.signal:libsignal-client:0.86.5` in `android/app/build.gradle.kts`.
Both pins are `implementation` scope, both are outside the version
catalog (`android/gradle/libs.versions.toml` has no `libsignal` entry).

Registry line 703 names the version-review target: "Pin exact after
review (Maven 0.86.5; upstream 0.99.3; Signal-Android 0.94.0)."

`TASK-P1-005`'s current status is **"Proposed (blocked until human
approves native code path)"**, with acceptance criterion "Human
approved all native-code work." This ADR is the decision artifact for
that approval, not the execution of the upgrade.

The pins are functional today: 28 androidTests across 3 files exercise
the protocol layer, and PQXDH works end-to-end (per handoff §2). The
question this ADR answers is whether, when, and to what target that
state should change.

---

## §2 Current state (what the code touches)

### §2.1 Files with libsignal imports

- `android/app/src/main/java/com/umoja/secure/crypto/PersistentSignalProtocolStore.kt` (410 lines)
- `android/app/src/main/java/com/umoja/secure/crypto/SignalIdentityStore.kt` (172 lines)
- `android/app/src/main/java/com/umoja/secure/messaging/MessagingService.kt` (396 lines)

### §2.2 Complete import surface (31 distinct imports)

Enumerated from a `grep -rh 'import org.signal' | sort -u` at HEAD
`80dc9e3`. This is the checklist that a version-changelog comparison
must cover.

Protocol primitives:
`IdentityKey`, `IdentityKeyPair`, `SessionBuilder`, `SessionCipher`,
`SignalProtocolAddress`, `InvalidKeyIdException`,
`ReusedBaseKeyException`.

Key material:
`ecc.ECKeyPair`, `ecc.ECPublicKey`, `ecc.ECPrivateKey`,
`kem.KEMKeyPair`, `kem.KEMKeyType`, `kem.KEMPublicKey`.

Stores:
`state.IdentityKeyStore`, `state.SignalProtocolStore`,
`state.PreKeyStore`, `state.PreKeyRecord`, `state.PreKeyBundle`,
`state.SignedPreKeyStore`, `state.SignedPreKeyRecord`,
`state.KyberPreKeyStore`, `state.KyberPreKeyRecord`,
`state.SessionStore`, `state.SessionRecord`.

Messages:
`message.CiphertextMessage`, `message.PreKeySignalMessage`,
`message.SignalMessage`.

Groups (Phase 1 non-goal; keep throwing):
`groups.state.SenderKeyStore`, `groups.state.SenderKeyRecord`.

### §2.3 Specific fragility points

These are places where the current code depends on a *shape*, not just
a type. Each deserves explicit changelog attention at upgrade time.

**FP-1 — 33-byte `IdentityKey.serialize()` with `0x05` type prefix.**
`SignalIdentityStore.messagingIdentityKeyBase64Url()` asserts the
serialized form is 33 bytes with `[0]==0x05` and strips the prefix to
produce the 32-byte raw key the authorization matrix and QR payload
expect. If the serialization format changed, this accessor breaks — and
it feeds P1-025 / P1-026 (matrix signing and QR payloads).

**FP-2 — split pub/priv persistence workaround.**
`SignalIdentityStore` persists `IdentityKey.serialize()` (33B) and
`ECPrivateKey.serialize()` (32B) *separately*, reconstructing via
`IdentityKeyPair(IdentityKey, ECPrivateKey)`. KDoc records why: the
`IdentityKeyPair.serialize()` / `IdentityKeyPair(byte[])` path
"crashes libsignal's JNI layer on some emulator images." If the newer
version fixed that crash, the workaround could be simplified — but it
*must not* be removed without a real-device + emulator verification
of the alternative path, which is out of scope for the upgrade itself.

**FP-3 — `markKyberPreKeyUsed(kyberPreKeyId, deviceId, baseKey)`.**
The three-argument form is PQXDH-specific. If the signature changed,
both `PersistentSignalProtocolStore` and
`PersistentSignalProtocolStoreTest` (`kyberPreKeyMarkedUsedCannotBeReused`)
break together — that test is not just regression coverage, it is the
check that the PQXDH non-reuse contract holds.

**FP-4 — `CiphertextMessage.PREKEY_TYPE` / `CiphertextMessage.WHISPER_TYPE`.**
Used by `MessagingService.sendMessage` (routing logic) and
`X3DHInMemoryTest` (protocol invariants). These are stable in the Signal
Protocol spec, but if the constants moved packages or changed types
(int vs byte), both files break.

**FP-5 — `InMemorySignalProtocolStore(IdentityKeyPair, Int)` constructor.**
Used only in `X3DHInMemoryTest`. libsignal-provided. If the constructor
changed, the test breaks even though production code is unaffected —
that would be a test-only fix, distinct from a real API break.

**FP-6 — `IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED` / `.REPLACED_EXISTING`.**
Enum values used by `PersistentSignalProtocolStore.saveIdentity`'s
return type and `PersistentSignalProtocolStoreTest.identityChangeIsReported`.
If the enum value names changed, both files break.

### §2.4 Test coverage (28 tests, 635 lines)

| File | Lines | Tests | What it guarantees |
|---|---|---|---|
| `X3DHInMemoryTest.kt` | 274 | 7 | Full Signal Protocol handshake using libsignal's `InMemorySignalProtocolStore`. SessionBuilder.process, first-message type, round-trip, ratchet advancement, ciphertext-must-not-contain-plaintext, tamper rejection, both-sides-persistence. |
| `PersistentSignalProtocolStoreTest.kt` | 283 | 13 | Registration ID stability, identity persistence, signed/kyber/EC prekey persistence across store recreation, peer identity save+change, kyber reuse rejection, signed prekey signature verification, tampered signature rejection, monotonic ID sequences, old batches remain loadable. |
| `LibsignalSmokeTest.kt` | 78 | 8 | API primitives: key generation, `publicKey.serialize()` 33 bytes, `publicKeyBytes` 32 bytes, `privateKey.serialize()` 32 bytes, sign+verify round trip, verify rejection, raw-bytes round-trip, key pair distinctness. |

---

## §3 Version decision

Three candidates, as named in the registry:

### Candidate A — stay at 0.81.1 / 0.86.5

**What changes:** nothing. Current state stays.
**Pros:** zero risk, zero churn, no supply-chain change, no test edits.
**Cons:** no new security fixes since those versions shipped. The two pins are at mismatched versions (0.81.1 AAR vs 0.86.5 client) — this may be intentional (AAR and client have different release cadences) or a stale-pin drift. Worth resolving either way.

### Candidate B — 0.94.0 (Signal-Android's vendored version)

**What changes:** upgrade to the version Signal ships in the Signal Android app.
**Pros:** latest stable Android-context version; includes security fixes that 0.86.5 predates; Signal-Android's release cadence is well-tracked; the API surface a messenger needs is what Signal already exercises.
**Cons:** Signal-Android's artifacts are not on Maven Central; consuming them requires a stable access path (Signal's Maven repo, if available, or a fork). Adds a supply-chain dependency on Signal's release infrastructure.

### Candidate C — 0.99.3 (upstream libsignal)

**What changes:** upgrade to upstream libsignal's current version.
**Pros:** latest protocol work; strongest security posture.
**Cons:** upstream libsignal is the Signal-Protocol reference library, not an Android-specific distribution. Higher chance of refactors unrelated to what a messenger needs. Upstream may not publish to Maven at all — self-hosting would be required for most of the surface.

### Recommendation: Candidate B — **0.105.0, verified at approval time**

**Verified 2026-10-18.** Both external verifications passed. The target is
**0.105.0**, not 0.94.0 as the registry note (2026-10-17) had projected:

- **Maven Central is at 0.86.5** (both artifacts), `<lastUpdated>20251117214318</lastUpdated>`.
  It has not moved. Candidate A would mean staying at 0.86.5 permanently.
- **Signal-Android ships 0.105.0** from
  `https://build-artifacts.signal.org/libraries/maven/`, per Signal-Android's
  `gradle/libs.versions.toml` (`libsignal-client = "0.105.0"` for both
  artifacts) and `settings.gradle.kts` (repo declared, no credentials block).
- **Upstream libsignal is at 0.105.1** (published 2026-10-15). One patch
  ahead of Signal-Android's production pin. Signal-Android has not consumed
  0.105.1 yet.

**Candidate A rejected**: 11 months of no security updates, and the current
mismatched pairing (0.86.5 client / 0.81.1 AAR) stays unvalidated end-to-end.

**Candidate C deferred**: 0.105.1 is one patch ahead of Signal's production
pin but is not Android-targeted and requires self-hosted builds — the right
answer for a Phase 2/3 hardening task if a specific threat model demands it,
not for Phase 1.

**Recommendation: Candidate B at 0.105.0, both artifacts aligned, from
Signal's Maven repository. Approved 2026-10-18 (§5.4).**

**The ADR does not settle which of A/B/C is correct for the project.** It names the candidates, the trade-offs, and the two external facts that will collapse the options at execution time. The human approves the target version after those two facts are confirmed.

---

## §4 Breaking-change checklist

The 31 imports tiered by how likely they are to be *unchanged* between 0.86.5 and 0.94.0. This is not a prediction — it's a checklist, with the tiers naming where to look first.

### Tier 1 — likely stable (compare, but expect unchanged)

`SignalProtocolAddress`, `CiphertextMessage.PREKEY_TYPE`,
`CiphertextMessage.WHISPER_TYPE`, `SignalMessage`,
`PreKeySignalMessage`, `IdentityKey`, `IdentityKeyPair`,
`ecc.ECKeyPair`, `ecc.ECPublicKey`, `ecc.ECPrivateKey`,
`InvalidKeyIdException`, `IdentityKeyStore.IdentityChange`.

### Tier 2 — needs changelog verification

`state.SignalProtocolStore`, `state.PreKeyStore`, `state.PreKeyRecord`,
`state.SignedPreKeyStore`, `state.SignedPreKeyRecord`,
`state.KyberPreKeyStore`, `state.KyberPreKeyRecord`,
`state.SessionStore`, `state.SessionRecord`, `state.PreKeyBundle`,
`state.IdentityKeyStore`, `SessionBuilder.process`,
`SessionCipher.encrypt`, `SessionCipher.decrypt`.

### Tier 3 — known-fragile (FP-1 through FP-6 in §2.3)

- 33-byte identity serialization shape (FP-1)
- `IdentityKeyPair` split pub/priv reconstruction (FP-2)
- `markKyberPreKeyUsed` 3-arg signature (FP-3)
- `InMemorySignalProtocolStore` constructor (FP-5)
- `SenderKeyStore` interface — Phase 1 throws, but a signature change breaks compile (groups not needed for Phase 1, but the throwing methods must still match the new interface to compile)
- `ReusedBaseKeyException` — thrown in `markKyberPreKeyUsed`, caught by nothing but must remain in the exception hierarchy

**Comparison method (execution session):** pull the `CHANGELOG.md` or
release notes for 0.86.5 → 0.94.0 (or the chosen target). Walk each
import. Where the changelog is silent, read the target source. Where
the source is silent, compile against the target and let the compiler
speak. **Do not guess at API stability — verify it.**

---

## §5 Human approval gate

`TASK-P1-005` registry status: **"Proposed (blocked until human approves native code path)."** Acceptance criterion: **"Human approved all native-code work."**

This gate is not bypassable by the ADR. It is a decision reserved for the project owner. The ADR's job is to make the approval question concrete.

### §5.1 The approval questions

The human is being asked to approve:

1. **The target version choice.** ✅ **Answered 2026-10-18: 0.105.0** (Candidate B). Two external verifications completed (§5.2), target confirmed. See §5.4 approval record.

2. **The supply-chain change** (if Candidate B or C). Moving off Maven Central to Signal's artifact repository (or self-hosted build) is a dependency-provenance decision. It changes what "trusted source" means for the two most security-critical artifacts in the codebase.

3. **The AGPLv3 handling.** `libsignal-android` is AGPLv3. Shipping an app that links against it triggers AGPLv3's source-disclosure obligations for any network-accessible functionality. `TASK-P1-005` names this explicitly (acceptance criterion: "AGPLv3 implications documented in `docs/legal/AGPL-NOTICE.md`"). The approval question is whether the current AGPL posture holds for the newer artifact, or whether the newer artifact imposes additional obligations.

4. **The regression-discipline commitment.** The 28 existing androidTests must pass at HEAD-after-upgrade. No test edits allowed except where a test *must* change because it names a breaking point (FP-3 or FP-5 test edits would be legitimate; test edits to make a broken behavior pass would not be). This is the discipline gate, not a technical one.

### §5.2 Facts verified 2026-10-18

Three facts were verified before approval. Evidence is cited so a future
reader can re-check.

**F-1 — Maven Central's current latest: 0.86.5 for both artifacts.**
`maven-metadata.xml` from `repo1.maven.org` shows 0.86.5 as the last
published version, `<lastUpdated>20251117214318</lastUpdated>`. Nothing
newer exists on Maven Central. This is what makes Candidate A (stay) the
current state and not a regression — Maven Central has not moved.

**F-2 — Signal-Android's current version: 0.105.0, from
`https://build-artifacts.signal.org/libraries/maven/`, anonymously.**
Signal-Android's `gradle/libs.versions.toml` declares
`libsignal-client = "0.105.0"` with `libsignal-android` referencing the
same version. Their `settings.gradle.kts` declares the repo with
`content { includeGroupByRegex("org\\.signal.*") }` and **no
`credentials { }` block** — auth is not required (the build-cache repo
declared above it does have credentials, so the contrast is meaningful).

**F-3 — Upstream libsignal's current version: 0.105.1** (published
2026-10-15, GitHub releases). One patch ahead of Signal-Android's
production pin. Upstream release notes exist per-version on GitHub; there
is no consolidated `CHANGELOG.md` (its path returns 404).

**Fact still pending at execution:** the exact `0.86.5 → 0.105.0`
breaking-change inventory (§4's checklist). This must be established by
reading the per-version release notes on GitHub (0.86.6 through 0.105.1)
plus compiling against the target — in that order, per §4's "do not
guess at API stability" rule.

### §5.3 What happens if approval is denied

The current state is functional. Denying approval for the upgrade means:

- 0.81.1 / 0.86.5 stays pinned
- The version-mismatch between the two artifacts stays as-is (worth documenting as a deliberate decision, not a drift)
- A new note in the handoff §4 records the denial and its reasoning

The project continues. An unapproved upgrade is a documented state, not a failure.
### §5.4 Approval record

**Date:** 2026-10-18
**Decision:** Approved. Candidate B at 0.105.0.
**Approver:** Project owner.

**Answers to §5.1's four questions:**

1. **Target version:** 0.105.0 (Signal-Android's current production version).
   See §5.2 for verified evidence. Rejects A (11 months of missing security
   fixes, keeps mismatched pins). Defers C (0.105.1 is one patch ahead but
   not Android-targeted and requires self-hosting).

2. **Supply-chain:** Approved. `https://build-artifacts.signal.org/libraries/maven/`
   — Signal's official distribution channel, anonymously accessible per
   their `settings.gradle.kts`. No new trust relationship beyond what
   `libsignal` already implies.

3. **AGPLv3:** Confirm only, not a new decision. Execution reads the
   `LICENSE` file bundled in the 0.105.0 artifact and confirms it is still
   AGPLv3 with no additional clauses. If the license has changed materially,
   stop and escalate — that's a new decision session.

4. **Regression rule:** Approved as absolute. 28 androidTests must pass.
   Only allowed edits are mechanical API renames at test call sites (a
   function was renamed while its behavior is unchanged); no test deletions,
   no weakened assertions, no "we'll fix it later." If a test fails for a
   behavioral reason, the upgrade does not ship.

**Scope of approval:** Covers the *upgrade to 0.105.0 from Signal's Maven
repo* per §6's execution path (P2-3, P2-4 in v0.2's revised plan). Does
not pre-approve any future version bump (0.105.1, 0.106, etc.) — those
require their own ADR update.

**Plan revision recorded:** v0.1's §6.1 estimated 4–5 sessions because
P2-2 was scoped as "read external changelog + confirm artifact availability
+ write AGPL-NOTICE." Those external verifications happened in-conversation
during the approval round, so P2-2 collapsed into the approval itself.

---


## §6 Execution path (contingent on §5 approval)

**Not executed in this ADR.** Named here so the plan is complete when the human approves.

### §6.1 Scope estimate (v0.2 — revised from v0.1)

**Plan revision recorded.** v0.1 estimated 4–5 sessions because P2-2 was
scoped as "read external changelog + confirm artifact availability + write
AGPL-NOTICE." Those verifications happened in the approval round (§5.2),
not in a separate session. The revised plan collapses P2-2 into the
approval itself.

| Phase | What | Sessions |
|---|---|---|
| P2-3 | `libs.versions.toml` migration (move libsignal artifacts out of `build.gradle.kts`) + version bump 0.86.5/0.81.1 → 0.105.0/0.105.0 + AGPL LICENSE verification + `docs/legal/AGPL-NOTICE.md` write + `docs/crypto/LIBSIGNAL-REVIEW.md` write + `docs/crypto/LIBSIGNAL-INTEGRATION.md` write + API adaptation | 1–2 |
| P2-4 | Regression verification (28 androidTests on both emulators) + manual smoke test (send/receive one message between two emulators, verify no plaintext in envelope) | 1 |

**Total: 2–3 sessions** for the upgrade. A single execution session may
suffice if the 0.86.5→0.105.0 API diff is mechanical (renames only); two
sessions if the diff is behavioral. The 28-test gate is the ship/no-ship
criterion either way.

**Version-verification lessons for future sessions:** the registry note
(US-TASK-P1-001 line 703, dated 2026-10-17) named "Maven 0.86.5; upstream
0.99.3; Signal-Android 0.94.0." The upstream and Signal-Android figures
were already stale when written — actual at approval time was 0.105.1 and
0.105.0, about 6 and 11 releases ahead respectively. **Version notes in
static documents go stale fast; verify at execution time, not from the
document.** Same class as KI-013 (do not propagate test counts from prior
handoffs) and §7's "counts from runner output" rule.

### §6.2 Recommended execution order

1. P2-2's external verification is the gate for everything that follows. If Candidate B's artifact availability fails verification, the ADR's recommendation is invalidated and a new decision session is required.
2. P2-3's catalog migration is safe and reversible — do it before the version bump so a rollback of the bump doesn't also need to roll back the migration.
3. P2-4's API adaptation should be atomic (one commit) — partial compiles leave the tree broken.
4. P2-5's regression verification is the acceptance gate; the upgrade does not land until 28/28 pass.

---

## §7 Regression gate

**The 28 androidTests must pass at HEAD-after-upgrade, with the exceptions named in §5.1.4.** Additional requirements:

- `X3DHInMemoryTest` must pass — it exercises the full protocol handshake end-to-end.
- `PersistentSignalProtocolStoreTest` must pass — it exercises the six interfaces.
- `LibsignalSmokeTest` must pass — it verifies the primitives the store relies on.
- Manual smoke test on emulator: send/receive one message between two emulators, verify no plaintext in the envelope body (already part of the acceptance pattern).

**Do not edit tests to pass a broken upgrade.** If a test fails because the API changed, the *production code* is what changes to absorb the new API, not the test. If a test fails because the test itself uses the changed API, the test's usage adapts. The distinction is: the test asserts protocol invariants (never changes); the test constructs fixtures via libsignal API (may change with the API).

---

## §8 Pin migration to `libs.versions.toml`

Current state: `android/app/build.gradle.kts` lines 44–45 hardcode `libsignal-android:0.81.1` and `libsignal-client:0.86.5`. The version catalog has no libsignal entries.

The migration is small — add to `[versions]` and `[libraries]` in `android/gradle/libs.versions.toml`, then replace the two hardcoded `implementation(...)` lines with catalog references. Behavior-neutral; separate commit from the version bump so a failed bump doesn't also require rolling back the migration.

---

## §9 Rollback plan

If a step in §6 fails:

- **P2-2 (external verification fails):** no code was changed. Revert ADR's recommendation; escalate to human with the specific fact that failed verification.
- **P2-3 (catalog migration fails):** `git revert` the migration commit. Zero behavior impact, one-commit rollback.
- **P2-4 (bump + adaptation fails to compile):** `git revert` the bump commit. The catalog still points at old versions; everything works.
- **P2-4 (bump compiles but tests fail):** rolling back means the upgrade doesn't ship; the failing test names what needs a follow-up ADR or a narrower upgrade. Reverting is one commit.

**Never** partial-revert (some files bumped, some not). One-commit-or-none at each phase.

---

## §10 Out of scope

This ADR does NOT cover:

1. **Signal Protocol version changes.** This ADR is about libsignal *library* version, not Signal Protocol evolution. If upstream changed wire-format invariants, that's a separate ADR.
2. **`SenderKeyStore` (group messaging) implementation.** Phase 1 non-goal. The upgrade must keep the throwing methods compatible with the new interface, but the group-messaging feature is a distinct effort.
3. **Crypto audit of the upgrade.** The regression suite verifies behavior; it does not audit upstream for introduced vulnerabilities. Independent security review is TASK-P1-024 (Phase 3, unscheduled).
4. **The suspend refactor.** Distinct sub-effort (§Phase-2) that touches `HttpClient.executeWithRetry`. Ordered after the upgrade arc per the Phase-2 sequencing decision.
5. **`libsignal-client`-vs-`libsignal-android` version-mismatch resolution.** Current pins are 0.86.5 and 0.81.1. Whether these *should* match is a question this ADR does not settle; the upgrade session must resolve it (either align both to the chosen target, or document why they intentionally diverge).

---

## §11 Revision history

| Version | Date | Change |
|---|---|---|
| 0.1 | 2026-10-18 | Initial draft for human review. Current-state inventory, version decision matrix, breaking-change checklist, human approval gate, execution path, regression gate, pin migration plan, rollback plan, out-of-scope list. |
| 0.2 | 2026-10-18 | Approval session. Verified Maven Central (0.86.5), Signal-Android version (0.105.0 at `build-artifacts.signal.org`, anonymously), and upstream (0.105.1). Recommendation updated 0.94.0 → 0.105.0. §5.2 reframed from "cannot answer" to "verified facts with evidence." §5.4 approval record added. §6.1 scope revised 4–5 → 2–3 sessions (P2-2 collapsed into the approval round). License/regression/pin-migration/rollback/out-of-scope unchanged in substance. |