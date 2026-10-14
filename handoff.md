# Umoja Secure — Handoff

Last updated: 2026-10-14 (Session A — JCS done both sides, cross-check harness next)
Purpose: Enable a new AI agent or developer session to pick up the project
without re-reading the entire chat history.

---

## 1. What the project is

Umoja Secure is a privacy messenger for government and security
professionals. Six criteria no existing product hits simultaneously:

1. No phone numbers for discovery (Threema model)
2. Admin-provisioned contacts (our differentiator)
3. Server-blind architecture (SimpleX/Briar model)
4. Tor transport for messaging and signaling (Briar/Session model)
5. No Google runtime dependencies of any kind
6. GrapheneOS-first device baseline

Additional requirements:
- Signal-grade E2EE via libsignal (PQXDH, X3DH, Double Ratchet)
- Kotlin + Jetpack Compose Android client
- Node.js + Fastify + PostgreSQL backend
- Calls deferred to Phase 3 (WebRTC + TURN on clearnet)
- Backend never has plaintext, private keys, or Double Ratchet state

Authoritative documents (all exist on disk):
- UMOJA-SECURE-BUILD-MASTER.md (v1.4.2, frozen)
- docs/US-ADD-001.md, docs/US-MASTER-001.md
- docs/reference/AUTH-SPEC-001.md, docs/reference/THREAT-MODEL-001.md
- docs/US-TASK-P1-001.md (task registry, v0.4)
- docs/architecture/ADR-PROVISIONING-001.md
- docs/ops/TOR-ONION.md

---

## 2. Where the project stands

### Backend (complete for Phase 1 messaging)

- Node.js 24.x, Fastify 5.12.5, PostgreSQL 16
- Docker-deployable (docker compose up -d --build from repo root)
- **130 tests passing** (85 pre-existing + 45 JCS conformance)
- Server-blind: routes ciphertext envelopes, never decrypts
- Exposed as a v3 onion service via the umoja-tor container

Endpoints:
- GET /health, GET /ready
- POST /enrollment
- POST /auth/challenge, POST /auth/verify, POST /auth/logout
- GET /me, GET /me/contacts
- POST /prekeys, GET /prekeys/status, GET /prekeys/:device_id
- POST /envelopes, GET /envelopes/pending, GET /envelopes/:id,
  POST /envelopes/:id/ack
- POST /admin/enrollment-tokens, GET /admin/enrollment-tokens,
  POST /admin/enrollment-tokens/:id/revoke
- GET /admin/devices, POST /admin/devices/:id/revoke,
  POST /admin/devices/:id/suspend, POST /admin/devices/:id/resume
- POST /admin/contacts, POST /admin/contacts/:id/revoke,
  GET /admin/contacts
- GET /admin/audit/verify
- WS /ws

### Android client (working E2EE messenger on emulators, over Tor)

- Kotlin + Jetpack Compose
- minSdk 30
- targetSdk: **35 is the spec value** (US-ADD-001 §5). Build uses 36.
  Reconciliation pending — do not "fix" the build until then.
- Package: com.umoja.secure
- Ed25519 device identity in Android Keystore (TEE-backed on real devices,
  BouncyCastle software fallback on emulator)
- libsignal 0.86.5 (client) + 0.81.1 (native AAR) integrated; PQXDH works
- Persistent SignalProtocolStore (all 6 libsignal interfaces)
- Encrypted local storage (AES-GCM key in Keystore)
- Tor transport working end to end
- Real-time 1:1 encrypted messaging between two emulators
- Contacts screen wired to GET /me/contacts
- Admin screen (device list, enrollment tokens, contact pairs)
- **63 tests passing** (48 pre-existing + 4 number formatter + 11 JCS)

### Tor (dev)

- umoja-tor container publishes <onion>.onion → backend:8080
- Mac Homebrew tor on 127.0.0.1:9050, emulator reaches it via
  `adb reverse tcp:9050 tcp:9050`
- transport/Socks5Bridge.kt — HTTP→SOCKS5 bridge inside the app. Solves
  Java's local-DNS-for-SOCKS bug that broke .onion.
- Onion: `vsf2kj6uapla74qea4wp4vwbahyqzftq3aywsjd3hknlcvgbtzn6xjad.onion`
  (fresh: `docker compose exec tor cat /var/lib/tor/umoja-backend/hostname`)

---

## 3. What was just done

### Session 0 — canonical docs authored

Four requirements-layer documents were authored because they did not
exist on disk (commits `91b5c47`, `692c672`, `059fa5e`, `e505394`,
`43dbe83`, `55ebd13`; tags `v0.30-adr-provisioning`, `v0.31-session-0`).

### Session A — JCS canonicalization, both sides (current)

**Conformance sweep — clean.** Four greps against `backend/src` and
`android/.../secure`. No blocking drift. Findings recorded in the previous
handoff; two still open:

- `@noble/ed25519` not on Build Master §3 approved list (**KI-010**).
- Three canonicalizers coexist; do not unify (**KI-008**).

**Corpus vendored** (commit `fcf6bbd`): RFC 8785 App. B number samples
(24) + cyberphone JCS corpus (6 pairs, Apache 2.0).

**TypeScript canonicalizer — done** (commit `c06aaa8`).

- `backend/src/crypto/jcs.ts` — exports `jcsCanonicalize` and
  `jcsCanonicalizeString`.
- `backend/src/crypto/jcs.test.ts` — 45 passing:
  24 RFC samples + 6 cyberphone pairs + 10 negative + 5 spot checks.

**Kotlin number formatter — done** (commit `ff15357`).

- `android/.../crypto/JcsNumberFormatter.kt` — ES6
  `Number.prototype.toString()` in `internal object`.
- `android/.../crypto/JcsNumberFormatterTest.kt` — 4 passing:
  all 24 RFC samples as hex literals + NaN/Infinity rejection.
- Resolved **KI-007**.

**Kotlin canonicalizer — done** (commit landed just before this handoff).

- `android/.../crypto/JcsCanonicalizer.kt` — `fun jcsCanonicalize(Any?):
  ByteArray` and `fun jcsCanonicalizeString(Any?): String`. Input model
  is pure Kotlin (`null`, `Boolean`, `Number`, `String`, `List<*>`,
  `Map<String, *>`). Callers with `org.json` types convert first.
- `android/.../crypto/JcsCanonicalizerTest.kt` — 11 passing:
  6/6 cyberphone pairs byte-exact + behavior spot checks
  (key sort, array order, `-0` collapse, `1e+21` formatting, string
  escaping, rejections).
- `android/app/build.gradle.kts` — adds test-scope
  `org.json:json:20240303`. **Not a runtime dependency.** Approved
  under KI-011 option A.

**JCS is now implemented on both sides and independently validated
against the same external corpus.** 45 TS tests + 15 Kotlin tests,
byte-identical across every shared input.

---

## 4. Known issues

### KI-001 (FIXED): OkHttp cannot reach .onion through SOCKS
### KI-002: Backend Docker image goes stale during iteration
`docker compose up -d --build backend` after backend changes, or run
`npm run dev` on the Mac during iteration.

### KI-003: Emulator loses app data on cold boot
Shut down emulator cleanly (menu → Power off). Or accept re-enrollment.

### KI-004: Canonical-matrix test vectors still scaffold
`docs/reference/canonical-matrix-test-vectors.json` has `generated: false`.
Inputs authored; outputs `null`.

**Now fully unblockable.** TS and Kotlin canonicalizers are both proven.
Populate by running either on each `input_wrapper`. The signing fields
require the test-only key derivation per the file's
`test_only_key_derivation` block.

**Consequence:** no matrix signing code may commit until `generated: true`.

### KI-005: Requirements layer was authored after the code
The four canonical documents were written 2026-10-14. Session A's
conformance sweep was four greps, not a full audit.

### KI-006: USER-ONBOARDING.md still missing
Referenced by Build Master §2 and §3.4. Not blocking.

### KI-007 (RESOLVED): Kotlin number serialization
Resolved by `ff15357`.

### KI-008: Three canonicalizers coexist

| Encoder | Serves | Prehash? |
|---|---|---|
| `canonicalizeChallenge` (TS) / `CanonicalChallenge.encode` (KT) | challenge-response | no |
| `canonicalJson` (TS, duplicated) | audit hash chain | no |
| `jcsCanonicalize` (TS) / `jcsCanonicalizeString` (KT) | matrix signing | **yes** (SHA-256) |

Do not unify. Different protocols, different signing rules.

Optional cleanup, not Session A: `canonicalJson` is duplicated between
`backend/src/audit/log.ts` and `audit/verify.ts`.

### KI-009: Backend test suite requires Postgres
Every `vitest run` triggers `test/global-setup.ts` → Postgres connection.
Fix: Docker up, or a conditional in `global-setup.ts`.

### KI-010: `@noble/ed25519` not on Build Master §3 approved list
Used in `backend/src/auth/verify.ts`. **Resolve approval before writing
matrix verification.**

### KI-011 (RESOLVED): Kotlin canonicalizer corpus test parser
Resolved by adding test-scope `org.json:json:20240303`. Option A chosen
over hand-transcription because the number-parsing boundary (BigDecimal
on the org.json side) is part of the protocol and a hand-transcribed
corpus would have silently skipped it.

### KI-012: JCS implementations must be cross-checked, not just
  individually validated

Both sides now pass their own corpora. **That is necessary but not
sufficient.** The whole point of the from-scratch decision was
independent implementations converging on the same bytes for the same
inputs.

A cross-check harness does not yet exist. Until it does, a divergence on
an input neither corpus covers would go undetected.

See §5 item 1.

---

## 5. Immediate next steps (recommended order)

**1. Build the cross-check harness.** Feed every input through TS and
   Kotlin; diff the bytes; fail on any divergence.

   Suggested shape:
   - `backend/src/crypto/jcs-dump.ts` — reads JSON from stdin, writes
     canonical string to stdout. Thin wrapper over `jcsCanonicalizeString`.
   - Kotlin side: either a small CLI main in the Android module, or a
     Gradle-invoked JVM test that shells out to the TS side. Simpler:
     a standalone Kotlin test that feeds a fixed input list through
     `jcsCanonicalizeString`, writes each result to a file, and a shell
     script that runs the TS side on the same list and diffs.
   - Input list: the 24 RFC samples, the 6 cyberphone pairs, and the 9
     Umoja wrapper `input_wrapper` objects from
     `canonical-matrix-test-vectors.json`.

   Gate: the diff must be empty. Any divergence is a bug in one of the
   two canonicalizers; the vendored corpus is ground truth for
   adjudicating which.

**2. Populate `canonical-matrix-test-vectors.json`.** Run the (now
   cross-checked) canonicalizer on each `input_wrapper`. Fill
   `expected_canonical_bytes_utf8`. Derive the test-only Ed25519 key per
   the file's `test_only_key_derivation` block. Sign the SHA-256 digest.
   Fill the remaining three fields. Flip `generated: true`.

**3. Matrix schema.** Single TS type + single Kotlin data class. Fields
   per `docs/architecture/ADR-PROVISIONING-001.md` §4. Separate
   `pub_device_auth_key` and `pub_messaging_identity_key`.

**4. Sign/verify per §3.8.** JCS(wrapper) → SHA-256 → Ed25519 over
   digest → base64url no-pad. Both sides.

**5. QR ceremony, offline signing handoff, client verification,
   storage, `bound_public_key` schema addition, tests.**

**After Session A:**

6. Emergency lock (TASK-P1-021a).
7. Duress wipe (TASK-P1-021b).
8. Signing-key custody (TASK-P1-029), offline signer (TASK-P1-033),
   recovery key (TASK-P1-035).
9. Hardware-backed Ed25519 verification (TASK-P1-034). Requires
   physical hardware.
10. Hardening: SBOM, Android redaction audit, penetration test,
    independent review.

---

## 6. Development environment

### Repo layout

    umoja-secure/
      backend/
        src/
          crypto/           jcs.ts, jcs.test.ts             ← new
          auth/             canonical.ts, verify.ts
          audit/            log.ts, verify.ts
          admin/, enrollment/, authorization/, routes/, ws/ ...
      android/
        app/
          build.gradle.kts  (org.json test-scope dep)        ← new
          src/
            main/java/com/umoja/secure/
              crypto/       DeviceKeyManager.kt, DeviceIdentity.kt,
                            SignalIdentityStore.kt,
                            JcsNumberFormatter.kt,           ← new
                            JcsCanonicalizer.kt              ← new
              auth/         CanonicalChallenge.kt, SessionManager.kt
              transport/    AdminApi.kt, ContactsApi.kt, Socks5Bridge.kt
              ui/           admin/, contacts/
            test/java/com/umoja/secure/
              ExampleUnitTest.kt
              crypto/       JcsNumberFormatterTest.kt,       ← new
                            JcsCanonicalizerTest.kt          ← new
      docs/
        architecture/       ADR-PROVISIONING-001.md
        ops/                TOR-ONION.md
        reference/
          AUTH-SPEC-001.md
          THREAT-MODEL-001.md
          canonical-matrix-test-vectors.json  (scaffold, generated:false)
          rfc8785-number-samples.json         (24 samples)
          jcs-conformance/                    (6 pairs, Apache 2.0)
      infra/
      UMOJA-SECURE-BUILD-MASTER.md
      docker-compose.yml
      handoff.md

### Start of session

    # Docker Desktop must be running.
    cd ~/umoja-secure
    docker compose up -d

    # Emulators (one or two).
    $HOME/Library/Android/sdk/emulator/emulator -avd Pixel_9 &
    $HOME/Library/Android/sdk/emulator/emulator -avd Pixel_9_API35_B -memory 1535 &

    # Reverse ports.
    $HOME/Library/Android/sdk/platform-tools/adb -s emulator-5554 reverse tcp:8080 tcp:8080
    $HOME/Library/Android/sdk/platform-tools/adb -s emulator-5554 reverse tcp:9050 tcp:9050

### Backend iteration

    cd ~/umoja-secure/backend
    npm run dev              # dev mode, auto-reloads
    npm test                 # requires Docker Postgres up (KI-009)
    npm test -- <path>       # scoped to one file
    npm run typecheck
    npm run lint
    npm run migrate

    cd ~/umoja-secure
    docker compose up -d --build backend    # after backend changes

### Android unit tests (JVM — no device required)

    cd ~/umoja-secure/android
    ./gradlew :app:testDebugUnitTest
    ./gradlew :app:testDebugUnitTest --tests "com.umoja.secure.crypto.JcsCanonicalizerTest"
    ./gradlew :app:testDebugUnitTest --tests "com.umoja.secure.crypto.JcsCanonicalizerTest" --rerun-tasks

    # Verify a test actually ran (Gradle can succeed with 0 matched):
    cat app/build/test-results/testDebugUnitTest/TEST-com.umoja.secure.crypto.JcsCanonicalizerTest.xml

### Android app build / device install

    cd ~/umoja-secure/android
    ./gradlew installDebug
    ./gradlew connectedAndroidTest

### Tor mode toggle

`android/.../transport/TransportConfig.kt`:

    var useTor: Boolean = false    # clearnet dev via adb reverse
    var useTor: Boolean = true     # .onion over SOCKS via Socks5Bridge

Rebuild after flipping — read at HttpClient construction time.

### Logcat

    $HOME/Library/Android/sdk/platform-tools/adb -s emulator-5554 logcat -c
    # tap in the app
    $HOME/Library/Android/sdk/platform-tools/adb -s emulator-5554 logcat -d | grep -iE "UmojaSocksBridge|UmojaWS|UmojaHttp|UmojaEnroll|okhttp|UmojaAdmin" | tail -40

### Tor verification

    curl --socks5-hostname 127.0.0.1:9050 -sS --max-time 20 \
      http://vsf2kj6uapla74qea4wp4vwbahyqzftq3aywsjd3hknlcvgbtzn6xjad.onion/health

    docker compose logs backend --tail=20 | grep -i onion
    # remoteAddress should be 172.18.0.4 (the tor container)

---

## 7. Conventions

- One task per session. Do not mix unrelated work.
- **Every commit block ends with `git push origin main`.** Tags: follow
  with `git push origin --tags`.
- Update this Handoff at the end of every session.
- For file writes, prefer a text editor (`open -e <path>`, `nano`) over
  terminal heredocs for anything over ~150 lines. Heredocs fragment on
  paste.
- Placeholders like `<paste content here>` are never to be typed
  literally. A suspiciously short file means the placeholder was left in.
- When debugging, log the exception before swallowing it.
- For libsignal, don't hold native handles across scope boundaries in
  tests. Serialize to bytes if state must outlive the store.
- **Corpus files are ground truth.** Do not edit
  `docs/reference/jcs-conformance/` or
  `docs/reference/rfc8785-number-samples.json` to make a failing test
  pass. Fix the canonicalizer.
- **Gradle can succeed with 0 tests matched.** When scoping with
  `--tests`, verify the XML report shows `tests="N" failures="0"`.
- **Two implementations passing their own tests is not interop proof.**
  See KI-012. Cross-check is required.
- Test count is the quickest pulse check. Current:
  **130 backend tests**, **63 Android tests**.

---

## 8. References for the matrix implementation session

### Authoritative design

- `docs/architecture/ADR-PROVISIONING-001.md` — §2 (threat-model
  answers), §3 (signing protocol), §4 (matrix schema), §5 (test plan),
  §6 (11-line plan).
- `docs/reference/THREAT-MODEL-001.md` §5–§8.
- `docs/reference/AUTH-SPEC-001.md` §5, §6, §9, §10.
- `docs/US-ADD-001.md` §7.
- `UMOJA-SECURE-BUILD-MASTER.md` §3.6, §3.7, §3.8.

### Conformance data

- `docs/reference/rfc8785-number-samples.json` — 24 samples.
- `docs/reference/jcs-conformance/` — 6 pairs.
- `docs/reference/canonical-matrix-test-vectors.json` — Umoja wrapper
  vectors, currently scaffold.

### Current code shape

JCS implementations (the new stuff):
- `backend/src/crypto/jcs.ts` — TS reference
- `backend/src/crypto/jcs.test.ts` — 45 tests
- `android/.../crypto/JcsNumberFormatter.kt` — ES6 number formatting
- `android/.../crypto/JcsCanonicalizer.kt` — Kotlin canonicalizer
- `android/app/src/test/java/com/umoja/secure/crypto/JcsNumberFormatterTest.kt`
  — 4 tests
- `android/app/src/test/java/com/umoja/secure/crypto/JcsCanonicalizerTest.kt`
  — 11 tests

Backend — pre-existing, unchanged:
- `backend/src/auth/canonical.ts` — challenge canonicalizer. **Do not
  modify.**
- `backend/src/auth/verify.ts` — challenge verification (`@noble/ed25519`)
- `backend/src/audit/log.ts` + `audit/verify.ts` — audit hash chain
- `backend/src/routes/{admin,enrollment,contacts}.ts`
- `backend/src/admin/{enrollmentTokens,devices}.ts`
- `backend/src/enrollment/consume.ts`
- `backend/src/authorization/contacts.ts`
- `backend/src/auth/sessions.ts`

Android — pre-existing, unchanged:
- `android/.../crypto/DeviceKeyManager.kt` — Ed25519 device auth key
- `android/.../crypto/DeviceIdentity.kt` — SPKI ↔ raw conversion
- `android/.../crypto/SignalIdentityStore.kt` — Curve25519 libsignal key
- `android/.../auth/CanonicalChallenge.kt` — challenge canonicalizer.
  **Do not modify.**
- `android/.../auth/SessionManager.kt`
- `android/.../transport/{AdminApi,ContactsApi,Socks5Bridge}.kt`
- `android/.../ui/admin/AdminScreen.kt`

### Verify paths before reading

    find ~/umoja-secure/backend/src -name "*.ts" | grep -E "crypto|admin|enroll|contact|session|canonical" | sort
    find ~/umoja-secure/android/app/src -name "*.kt" | grep -E "Admin|Contact|Device|Signal|Session|Canonical|Jcs" | sort

### Notes for a new agent

**TASK-P1-027 numbering collision.** Commit `ad89b76` is labeled
"TASK-P1-027: docker deployment". The current registry maps TASK-P1-027
to "SBOM generation and dependency review gate". Registry is
authoritative. Do not "fix" the old commit label.

**Canonical document provenance.** `US-ADD-001`, `US-MASTER-001`,
`AUTH-SPEC-001`, `THREAT-MODEL-001` were authored on 2026-10-14. They did
not exist before. Each carries a §1 Provenance section recording this.

**Ground truth for JCS is the vendored corpus, not either
implementation.** If TS and corpus ever disagree, TS is wrong. Same for
Kotlin.

**`toJSON` rejection is a deliberate deviation.** Both implementations
reject objects with a `toJSON` method, even though RFC 8785's reference
code calls it. Do not "fix" this to match the RFC.

If a security-relevant question arises that none of these answers, do
not guess. STOP and escalate, per Build Master §0.
