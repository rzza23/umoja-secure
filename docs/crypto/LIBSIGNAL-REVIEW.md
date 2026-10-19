# libsignal Version Review

Document ID: LIBSIGNAL-REVIEW
Date: 2026-10-18
Authority: TASK-P1-005 acceptance criterion ("Version review in docs/crypto/LIBSIGNAL-REVIEW.md")

---

## §1 Decision

**Both libsignal artifacts pinned at 0.105.0:**

- `org.signal:libsignal-android:0.105.0`
- `org.signal:libsignal-client:0.105.0`

Source: `https://build-artifacts.signal.org/libraries/maven/` (Signal's official Maven repository, declared in `settings.gradle.kts`, anonymously accessible — no credentials required).

Approved by project owner 2026-10-18. Full approval record in `ADR-SIGNAL-UPGRADE-001.md` §5.4.

---

## §2 Verified facts (2026-10-18)

**F-1 — Maven Central is at 0.86.5 for both artifacts**, last updated 2025-11-17. Nothing newer. Maven Central has not moved since our previous pins.

**F-2 — Signal-Android ships 0.105.0** from `build-artifacts.signal.org`, anonymously. Verified from Signal-Android's `gradle/libs.versions.toml` (`libsignal-client = "0.105.0"` for both artifacts) and `settings.gradle.kts` (repo declared, no credentials block).

**F-3 — Upstream libsignal is at 0.105.1** (2026-10-15, GitHub releases). One patch ahead of Signal-Android's production pin.

**F-4 — Release notes for 0.86.6 through 0.105.1 are all empty.** 0 of 68 versions have bodies. The GitHub releases exist as tags but carry no change descriptions.

**F-5 — The AGPLv3 license is unchanged.** Verified from both the `LICENSE` file at tag `v0.105.0` and the published POM's `<licenses>` block.

---

## §3 Why 0.105.0 (not 0.86.5, not 0.105.1)

**Not 0.86.5 (the previous pin):**
- Mismatched pins — 0.86.5 client + 0.81.1 native AAR from different years. Untested pairing.
- 11 months of missing security updates. Maven Central has not moved past 0.86.5, so staying means staying at that exact version indefinitely.
- Candidate A in ADR-SIGNAL-UPGRADE-001 §3 was rejected on these grounds.

**Not 0.105.1 (upstream's latest):**
- One patch ahead of Signal-Android's production version. Signal-Android has not consumed 0.105.1 yet.
- Upstream libsignal is not Android-targeted. Adopting it means owning the self-hosted build pipeline.
- Candidate C in ADR-SIGNAL-UPGRADE-001 §3 was deferred (correct for Phase 2/3 hardening tasks; not for Phase 1).

**0.105.0 is the right choice because:**
- It's the version Signal ships to production Android users.
- It's anonymously accessible from Signal's own repo — no auth, no self-hosting.
- Both artifacts are aligned (same version).
- It's Android-targeted by Signal's own build.

---

## §4 Known API quirks (do not "fix")

### §4.1 SessionBuilder vs SessionCipher argument order

**These two sibling classes take their address arguments in OPPOSITE order.** Verified from libsignal v0.105.0 source (`java/shared/java/.../SessionBuilder.java` and `SessionCipher.java`):

- `SessionBuilder(SignalProtocolStore, SignalProtocolAddress remoteAddress, SignalProtocolAddress localAddress)` — **remote first, local second**
- `SessionCipher(SignalProtocolStore, SignalProtocolAddress localAddress, SignalProtocolAddress remoteAddress)` — **local first, remote second**

**Our code depends on this asymmetry.** In `MessagingService.kt` and `X3DHInMemoryTest.kt`:

```kotlin
SessionBuilder(store, peerAddress, localAddress)   // remote first
SessionCipher(store, localAddress, peerAddress)    // local first
```

**Do not "consistify" these calls.** A future maintainer who notices the asymmetry and swaps one to match the other will get `NoSessionException: session with <peer> not found` at runtime, not at compile. The failure manifests only when the tests run — this was the exact bug that required a runtime debug round during the 0.86.5 → 0.105.0 upgrade. This is a libsignal API design choice, not a bug in our code.

### §4.2 PreKeySignalMessage property accessors

**`PreKeySignalMessage.preKeyId` and `.signedPreKeyId` are methods, not Kotlin properties** in 0.105.0:

- `getPreKeyId()` returns `Optional<Integer>`
- `getSignedPreKeyId()` returns `int`

Kotlin cannot auto-synthesize property access from `Optional`-returning getters. Both must be called as methods: `pkm.getPreKeyId().isPresent`, `pkm.getSignedPreKeyId()`. The 0.86.5 → 0.105.0 upgrade required the same change at both `MessagingService.kt` and `X3DHInMemoryTest.kt`.

---

## §5 Future upgrade cadence

**Bump only after an ADR update.** Because release notes are empty (§2 F-4), the breaking-change inventory is only discoverable through:

1. Compile against target — surfaces constructor arity, accessor renames, method signature changes
2. Run the 29-test gate — surfaces runtime API-shape quirks (argument order, semantic changes)

Neither mechanism substitutes for the other. A compile-clean upgrade can still fail at runtime (§4.1 proved this). An empty release-notes page is not a signal that nothing changed — it's a signal that the changelog must be reconstructed from compile+test evidence.

**Recommended cadence:** on each new version review, open an ADR update session (v0.x → v0.x+1). Section §5.2 of the ADR verifies the same three facts (Maven Central status, Signal-Android version, upstream version). Section §5.4 records the approval. Then P2-3 execution follows this document's §5 mechanism. Do not upgrade a version without the ADR being updated first.

---

## §6 Test count correction

The ADR-SIGNAL-UPGRADE-001 §7 and this document refer to "28 tests." The actual count in the three libsignal-touching test classes at HEAD `1cc21d3`:

- `X3DHInMemoryTest`: 7 tests
- `PersistentSignalProtocolStoreTest`: 14 tests
- `LibsignalSmokeTest`: 8 tests

**Total: 29 tests.**

The "28" figure came from a preliminary count during ADR v0.1 drafting. The 29 count is the verified one. Both the ADR's §7 gate and this review's §5 gate are satisfied by "29/29 pass", which was verified 2026-10-18 during the P2-3 execution session.

---

## §7 Related documents

- `docs/legal/AGPL-NOTICE.md` — license factual record
- `docs/crypto/LIBSIGNAL-INTEGRATION.md` — technical integration
- `docs/architecture/ADR-SIGNAL-UPGRADE-001.md` — version-decision approval record
- `docs/US-TASK-P1-001.md` §A TASK-P1-005 — the task whose acceptance criteria these three docs satisfy

---

— end of LIBSIGNAL-REVIEW —