# AGPLv3 Notice — libsignal dependency

Document ID: AGPL-NOTICE
Date: 2026-10-18
Authority: TASK-P1-005 acceptance criterion ("AGPLv3 implications documented in docs/legal/AGPL-NOTICE.md")

---

## §1 What we depend on

Umoja Secure consumes two libsignal artifacts from Signal Messenger LLC:

- `org.signal:libsignal-android:0.105.0` — native Android AAR (JNI bridge to libsignal's Rust implementation)
- `org.signal:libsignal-client:0.105.0` — Java client library

Both are licensed under the **GNU Affero General Public License v3** (AGPLv3). Verified 2026-10-18:

- The `LICENSE` file at tag `v0.105.0` of `github.com/signalapp/libsignal` is the standard 661-line AGPLv3 text.
- The published POM (`libsignal-android-0.105.0.pom`) declares `<name>AGPLv3</name>` in its `<licenses>` block.

---

## §2 What AGPLv3 requires

AGPLv3 extends GPLv3 with a **network-use clause** (Section 13): if a modified version of the software is made available over a network, the operator must offer the Corresponding Source to those users.

For Umoja Secure:

1. **We do not modify libsignal.** We consume the published artifacts as-is. The AGPLv3 network-use clause applies to modifications of the covered work — since we don't modify it, the modification-triggered obligations do not apply.

2. **We distribute the compiled artifacts inside our APK.** Distribution of AGPLv3-covered code requires that the complete Corresponding Source be made available to recipients. The Corresponding Source for libsignal is publicly available at `github.com/signalapp/libsignal` at tag `v0.105.0`. We rely on that public source as the source-offer mechanism.

3. **Our own source.** Linking against AGPLv3 code may, under some interpretations, extend copyleft obligations to the linked application. The Umoja Secure project's licensing posture is the project owner's decision, recorded separately; this notice records the factual dependency chain and the technical basis for compliance.

**Compliance posture summary:** consume unmodified artifacts, distribute only compiled forms, rely on Signal's public source tree as the corresponding-source offer. If either of those facts changes (e.g., we patch libsignal locally), this notice must be revisited and the obligations re-evaluated.

---

## §3 What this notice does not cover

- **No independent legal review.** This is a factual and technical statement of the dependency. A legal opinion on AGPLv3's interaction with the Umoja Secure codebase is outside this document's scope.
- **No assertion about downstream distribution.** If Umoja Secure is distributed to third parties who then redistribute, those parties have their own AGPLv3 obligations.
- **Signal's `libsignal-service-java`-style higher-level artifacts** are not used by Umoja Secure and are outside this notice.

---

## §4 Related documents

- `docs/crypto/LIBSIGNAL-REVIEW.md` — version-selection rationale
- `docs/crypto/LIBSIGNAL-INTEGRATION.md` — technical integration and known API quirks
- `docs/architecture/ADR-SIGNAL-UPGRADE-001.md` — the approval record for the 0.105.0 pin

---

— end of AGPL-NOTICE —
