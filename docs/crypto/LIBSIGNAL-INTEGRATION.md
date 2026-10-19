# libsignal Integration

Document ID: LIBSIGNAL-INTEGRATION
Date: 2026-10-18
Authority: TASK-P1-005 acceptance criterion ("JNI/Rust path documented in docs/crypto/LIBSIGNAL-INTEGRATION.md")

---

## §1 Two artifacts, two roles

Umoja Secure depends on two libsignal artifacts, both pinned at 0.105.0:

**`org.signal:libsignal-client:0.105.0`** — Java client library. Provides the public API surface our Kotlin code calls (classes in `org.signal.libsignal.protocol.*`). Pure Java/JVM, no native code in this artifact.

**`org.signal:libsignal-android:0.105.0`** — Android AAR bundling the native JNI bridge plus prebuilt `.so` files for the app's supported ABIs. The `.so` is the Rust implementation of the Signal Protocol, exposed via `org.signal.libsignal.internal.Native.*` method bindings.

**Transitivity note:** `libsignal-android` transitively pulls `libsignal-client` (confirmed by Gradle dependency resolution, 2026-10-18: `libsignal-android:0.105.0` → `libsignal-client:0.105.0`). Our `build.gradle.kts` declares both explicitly anyway — clarity over minimalism, and it pins the version at the catalog level so a future Android AAR bump cannot silently change the client version.

---

## §2 Where our code touches libsignal

**Three files** import `org.signal.*` (verified `grep -rln 'import org.signal'` at HEAD `1cc21d3`):

- `android/app/src/main/java/com/umoja/secure/crypto/PersistentSignalProtocolStore.kt` (410 lines) — implements `SignalProtocolStore` composite interface (delegating to `IdentityKeyStore`, `PreKeyStore`, `SignedPreKeyStore`, `KyberPreKeyStore`, `SessionStore`, `SenderKeyStore`). The store handles serialization, namespacing, and persistence but delegates the actual Ed25519 signing and Curve25519 key agreement to the native layer.
- `android/app/src/main/java/com/umoja/secure/crypto/SignalIdentityStore.kt` (172 lines) — holds the local IdentityKeyPair in Android Keystore-backed encrypted storage; reconstructs on read from split pub/priv components.
- `android/app/src/main/java/com/umoja/secure/messaging/MessagingService.kt` (396 lines) — the session-establish / encrypt / decrypt flow. This is where `SessionBuilder` and `SessionCipher` are invoked.

**31 distinct libsignal imports** across these three files. The full list is in ADR-SIGNAL-UPGRADE-001 §2.2.

---

## §3 JNI quirks already in code (do not remove)

### §3.1 Split pub/priv persistence workaround

`SignalIdentityStore` persists `IdentityKey.serialize()` (33 bytes) and `ECPrivateKey.serialize()` (32 bytes) as **separate** encrypted storage entries, and reconstructs the keypair via `IdentityKeyPair(IdentityKey, ECPrivateKey)`.

The KDoc in the class records why: the `IdentityKeyPair.serialize()` / `IdentityKeyPair(byte[])` reconstruction path **crashes libsignal's JNI layer on some emulator images**. This was hit during early development and the split-component form (using simpler constructors) was adopted as the workaround.

**Do not remove this workaround** even if a future libsignal version appears to have fixed the underlying emulator issue. The alternative path must be tested on both emulators AND on a real device with TEE-backed Keystore before the workaround can be retired. That verification has not been performed as of 2026-10-18.

### §3.2 Argument-order asymmetry (cross-reference)

`SessionBuilder` and `SessionCipher` take their address arguments in opposite order. This is documented in `LIBSIGNAL-REVIEW.md` §4.1 because it is a load-bearing fact about our integration — the upgrade session initially had these inverted and only discovered it at runtime when X3DHInMemoryTest failed with `NoSessionException`.

Refer to `LIBSIGNAL-REVIEW.md` §4.1 for the full record. Do not duplicate the warning here — one authoritative location, cross-referenced.

---

## §4 Upgrade implication: AAR bump = .so change

**A `libsignal-android` version bump changes the native `.so` files bundled in the APK.** The `.so` files are ABI-specific (arm64-v8a, armeabi-v7a, x86, x86_64 per the Gradle resolution tree). The implications of a bump that the JVM tests alone cannot fully verify:

1. **APK size delta.** Newer libsignal often grows the `.so` — mostly from additional protocol primitives (e.g., post-quantum additions grew the .so across 0.87-0.99). Check the release AAR's `.so` sizes before/after. If the APK grows beyond acceptable limits, ABI splits may need to be introduced (currently not used).

2. **ABI coverage.** Signal's published AAR must include all four ABIs we target. Verify `unzip -l libsignal-android-<version>.aar | grep libsignal_jni` after download. A missing ABI would crash on the affected devices at first native call.

3. **JNI signature drift.** Native methods declared `external fun` in the Java client are bound by exact method-name matching to symbols in the `.so`. If the two artifacts are at different versions (which our current pins avoid), a binding mismatch can produce `UnsatisfiedLinkError` at first call, not at compile.

**Why both artifacts share one version.** Our `libs.versions.toml` declares a single `libsignal = "0.105.0"` version ref used by both `libsignal-android` and `libsignal-client`. This matches Signal-Android's own pattern. Keeping them aligned is what prevents the JNI signature drift class.

---

## §5 The `.so` on emulator vs. real device

Emulator testing has one specific limitation worth recording: emulators run x86_64 `.so` inside QEMU virtualization. Real devices run arm64-v8a `.so` natively. **Emulator passes are necessary but not sufficient** — a `.so` that runs correctly under QEMU can behave differently on a physical ARM device if there's any JNI calling convention mismatch.

**The libsignal 0.105.0 upgrade was verified on emulators only** (both `emulator-5554` and `emulator-5556`, x86_64). Real-device verification is outstanding (per ADR-SIGNAL-UPGRADE-001 §10 out-of-scope item "crypto audit of the upgrade"; TASK-P1-034 for hardware-backed Ed25519 requires physical hardware).

For a Phase 1 dev cycle this is acceptable. For production deployment to government/security users, real-device verification should precede any Release build.

---

## §6 Related documents

- `docs/legal/AGPL-NOTICE.md` — license factual record
- `docs/crypto/LIBSIGNAL-REVIEW.md` — version-decision rationale + argument-order quirk record
- `docs/architecture/ADR-SIGNAL-UPGRADE-001.md` — the approval record
- `docs/US-TASK-P1-001.md` §A TASK-P1-005 — the task whose acceptance criteria these three docs satisfy

---

— end of LIBSIGNAL-INTEGRATION —