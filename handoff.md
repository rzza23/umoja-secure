# Umoja Secure — Handoff

Last updated: 2026-10-14 (Session A — pre-work complete, matrix code not yet started)
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
- 85 tests passing across 10 test files
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
- targetSdk: **35 is the spec value** (per US-ADD-001 §5). Current build
  uses 36. Reconciliation is pending; do not "fix" the build until the
  reconciliation pass lands.
- Package: com.umoja.secure
- Ed25519 device identity in Android Keystore (TEE-backed on real devices,
  BouncyCastle software fallback on emulator)
- libsignal 0.86.5 (client) + 0.81.1 (native AAR) integrated; PQXDH works
- Persistent SignalProtocolStore (all 6 libsignal interfaces)
- Encrypted local storage (AES-GCM key in Keystore)
- Tor transport working end to end — enrollment, auth, prekey upload,
  WebSocket all route over the onion via a local HTTP→SOCKS5 bridge
- WebSocket client: auth handshake, revalidation, heartbeat, auto-reconnect
- Real-time 1:1 encrypted messaging between two emulators
- Contacts screen wired to GET /me/contacts via ContactsApi.kt
- Admin screen (device list, enrollment tokens, contact pairs)
- Transport mode toggle: TransportConfig.useTor (currently false by
  default; set true for Tor mode)

### Tor (dev)

- umoja-tor container publishes <onion>.onion → backend:8080
- Mac Homebrew tor on 127.0.0.1:9050 — client-side Tor, reachable from
  the emulator via `adb reverse tcp:9050 tcp:9050`
- transport/Socks5Bridge.kt — HTTP→SOCKS5 bridge inside the app. Solves
  Java's local-DNS-for-SOCKS bug that broke .onion.
- Onion address: `vsf2kj6uapla74qea4wp4vwbahyqzftq3aywsjd3hknlcvgbtzn6xjad.onion`
  (find fresh value with `docker compose exec tor cat /var/lib/tor/umoja-backend/hostname`)

---

## 3. What was just done

### Session 0 (2026-10-14) — canonical docs authored

Authored four requirements-layer documents that did not exist on disk:

- `docs/architecture/ADR-PROVISIONING-001.md` — commit `91b5c47`, tag
  `v0.30-adr-provisioning`
- `docs/reference/THREAT-MODEL-001.md` — commit `692c672`
- `docs/reference/AUTH-SPEC-001.md` — commit `059fa5e`
- `docs/US-ADD-001.md` — commit `e505394`
- `docs/US-MASTER-001.md` — commit `43dbe83`
- `docs/reference/canonical-matrix-test-vectors.json` — scaffold only,
  `generated: false`

Commit `55ebd13` (handoff) was the tip of Session 0. Tag `v0.31-session-0`.

### Session A pre-work (2026-10-14) — conformance sweep + corpus vendoring

**Conformance sweep — clean.** Four greps ran against `backend/src` and
`android/.../secure`. Drift report verdict: no blocking drift. Findings:

1. **Existing Ed25519 signing is challenge signing only.** `SessionManager.kt:57`
   and `WebSocketClient.kt:231` sign `canonicalBytes` (challenge) via
   `DeviceKeyManager.sign()`. Backend verifies with `@noble/ed25519`. This
   is a distinct protocol from matrix signing and is internally consistent.
   **Rule: do not copy challenge signing into matrix signing.** Build
   Master §3.8 requires SHA-256 prehash for matrices; the challenge
   protocol does not prehash.
2. **Two existing canonicalization systems, neither claiming JCS.**
   `backend/src/auth/canonical.ts` + Kotlin `CanonicalChallenge.kt` (challenge
   protocol, paired); `canonicalJson` in `audit/log.ts` + `audit/verify.ts`
   (audit hash chain, duplicated between two files). Neither collides with
   the forthcoming JCS canonicalizer. **Risk: three encoders will coexist.
   Name the new one distinctly and comment each.**
3. **Key-name conflation: empty.** No hits. Clean.
4. **Client-side revocation: no enforcement.** All hits are reactive UI or
   WebSocket close-code handling. Server-authoritative per AUTH-SPEC-001
   §9. Clean.

**Open item from the sweep:** `@noble/ed25519` is in the backend but is not
on Build Master §3's approved list. Build Master §6 requires human approval
for any new dependency. **Resolve before writing matrix verification on the
backend.** It will almost certainly be the library used to verify matrix
signatures. If approved in an earlier session and just not recorded, say so.

**JCS decision — from-scratch, both sides.** No library. Rationale in ADR
terms: the Kotlin side must be from-scratch regardless (no trusted RFC 8785
lib for Android), so the TS side is too — then both are validated against
the same external ground truth, not one against the other. No dependency
means no Build Master §6 approval cycle.

**Conformance corpus vendored.** Two sources:

- `docs/reference/rfc8785-number-samples.json` — 24 number-serialization
  samples from RFC 8785 Appendix B. IEEE 754 hex preserved; expected
  serialization verbatim. Covers zero/minus-zero, the `1e+21` boundary,
  round-to-even. NaN and Infinity excluded (not valid JSON).
- `docs/reference/jcs-conformance/` — the cyberphone corpus
  (https://github.com/cyberphone/json-canonicalization, Apache 2.0), 6
  input/output pairs covering Unicode, French accents, weird key ordering,
  arrays, structures, and scalar values. Byte-exact as upstream; outputs
  have no trailing newline. `README.md` records provenance and the
  no-edit contract.

**Committed as `docs: vendor JCS conformance corpus — RFC 8785 App. B
samples + cyberphone testdata`** (this commit may be immediately before
the handoff commit you are reading).

---

## 4. Known issues

### KI-001 (FIXED): OkHttp cannot reach .onion through SOCKS

Fixed in `v0.29-tor-transport` with the Socks5Bridge.

### KI-002: Backend Docker image goes stale during iteration

Symptom: new routes return 404 even though source has them. Cause: the
running container is an old build.

Fix: `docker compose up -d --build backend` after backend route or
controller changes. Or run backend in dev mode on the Mac
(`npm run dev` in `backend/`) instead of Docker during active backend
iteration.

### KI-003: Emulator loses app data on cold boot

Symptom: re-enrollment required after killing the emulator process.
Cause: `-no-snapshot-load` or an unclean shutdown.

Fix: shut down emulator cleanly (`...` menu → Power off) so state is
saved; omit `-no-snapshot-load` next start. Or accept re-enrollment as a
dev cost.

### KI-004: Canonical-matrix test vectors are still a scaffold

`docs/reference/canonical-matrix-test-vectors.json` has `generated: false`.
Inputs are authored; outputs (canonical bytes, SHA-256 digest, Ed25519
signature) are `null`. The file's own `stop_condition` field says it is
not authoritative until `generated: true`.

**Consequence:** no matrix signing code may commit until the generator
runs. Session A's next step is to write the TS JCS canonicalizer, validate
it against the vendored corpus, then run it on the wrapper inputs to
populate the output fields.

### KI-005: Requirements layer was authored after the code

The four canonical documents were written 2026-10-14, after most of Phase 1's
messaging code already existed. The code predates its own spec. Session A's
conformance sweep (see §3) checked the highest-risk surfaces and found no
blocking drift, but the sweep was narrow — four greps. A broader conformance
pass is possible later if the codebase churns significantly.

### KI-006: USER-ONBOARDING.md still missing

`docs/reference/USER-ONBOARDING.md` is referenced by Build Master §2 and
§3.4 but does not exist. Not a blocker. Flag for a follow-up.

### KI-007: Kotlin number serialization will need real work

The TypeScript JCS canonicalizer gets ECMAScript number formatting for free
via `JSON.stringify(Number)`. **Kotlin does not.** Java's `Double.toString()`
differs from ECMAScript in boundary cases — most visibly at the `1e21`
threshold and in exponential-notation formatting (`1e+21` vs `1.0E21`).

The Kotlin canonicalizer must implement ES6's number-to-string rules
explicitly. This is a *reformatting* problem (Java already produces shortest
round-tripping doubles via its internal algorithm), not a Ryū/Grisu
implementation problem. Expect 60–100 lines of Kotlin, validated against
`docs/reference/rfc8785-number-samples.json`.

**This is the single most likely line to silently diverge between the two
implementations.** The RFC 8785 Appendix B samples exist specifically to
catch it.

### KI-008: Three canonicalizers will coexist

After Session A, the codebase has three distinct canonical encoders:

| Encoder | Serves | Prehash? |
|---|---|---|
| `canonicalizeChallenge` (TS) / `CanonicalChallenge.encode` (KT) | challenge-response signing | no |
| `canonicalJson` (TS, duplicated) | audit hash chain | no |
| (new) JCS canonicalizer (TS + KT) | matrix signing | **yes** (SHA-256) |

Do not "unify" them. They serve different protocols with different signing
rules. Name the new one distinctly (`jcsCanonicalize` or similar) and add a
one-line comment in each pointing to the protocol it serves.

Optional cleanup, not Session A: `canonicalJson` is duplicated between
`backend/src/audit/log.ts` and `backend/src/audit/verify.ts`. If one drifts,
the audit chain silently breaks. Factor into a shared helper in a later
session.

---

## 5. Immediate next steps (recommended order)

**1. Write the TypeScript JCS canonicalizer (from scratch).** Location
   suggestion: `backend/src/crypto/jcs.ts`. Exports a single
   `jcsCanonicalize(value: unknown): Buffer` or `string`.

   **Then, immediately, before anything else:** run it against
   `docs/reference/rfc8785-number-samples.json` (24 samples) and
   `docs/reference/jcs-conformance/input/` + `output/` (6 pairs). A single
   divergence is a failure — do not "fix" the vector, fix the canonicalizer.

   Design notes for the implementation:
   - `JSON.stringify(number)` on the TS side already produces ES6-compliant
     output. Do not reimplement number formatting; use `JSON.stringify`.
   - Sort object keys by UTF-16 code unit order (`Array.prototype.sort()`
     default) — this is not the same as locale-aware sort.
   - Reject inputs containing `undefined`, `function`, or `Symbol` values.
   - Reject duplicate keys where detectable (JSON.parse with a reviver
     cannot see duplicates; consider a preprocessing check if the input is
     a string, or document the limitation for parsed objects).
   - Output UTF-8. No BOM. No trailing newline.

**2. Write the Kotlin JCS canonicalizer (from scratch).** Location
   suggestion: `android/.../crypto/JcsCanonicalizer.kt`. Same tests, same
   corpus, byte-identical output.

   The tricky part is KI-007 (number serialization). Start by writing the
   number formatter against the 24 RFC samples in isolation, before
   integrating with the rest of the canonicalizer.

**3. Populate the matrix test vectors.** Run the TS canonicalizer on each
   `input_wrapper` in `canonical-matrix-test-vectors.json`. Fill the
   `null` output fields. Sign with the test-only key derived per the file's
   `test_only_key_derivation` block. Flip `generated: true`.

**4. Matrix schema.** Single source of truth — TS type in `backend/src/`,
   Kotlin data class in `android/.../crypto/`. Fields per
   `docs/architecture/ADR-PROVISIONING-001.md` §4.

**5. Sign/verify per §3.8.** JCS(wrapper) → SHA-256 → Ed25519 over digest
   → base64url no-pad. Both sides.

**6. QR ceremony, offline signing handoff, client verification, storage,
   `bound_public_key` schema addition, tests.** See ADR §6.

**After Session A, in order:**

7. Emergency lock (TASK-P1-021a).
8. Duress wipe (TASK-P1-021b).
9. Signing-key custody (TASK-P1-029), offline signer (TASK-P1-033),
   recovery key (TASK-P1-035).
10. Hardware-backed Ed25519 verification (TASK-P1-034). Requires physical
    hardware.
11. Hardening: SBOM, Android redaction audit, penetration test, independent
    review.

---

## 6. Development environment

### Repo layout

    umoja-secure/
      backend/              Fastify + PostgreSQL
      android/              Kotlin + Compose app
      docs/                 ADRs, specs, this Handoff
        architecture/       ADR-PROVISIONING-001.md
        ops/                TOR-ONION.md
        reference/
          AUTH-SPEC-001.md
          THREAT-MODEL-001.md
          canonical-matrix-test-vectors.json   (scaffold, generated:false)
          rfc8785-number-samples.json          (24 samples)
          jcs-conformance/                     (cyberphone corpus, 6 pairs)
            input/
            output/
            README.md
      infra/                docker, tor
      UMOJA-SECURE-BUILD-MASTER.md
      docker-compose.yml
      README.md
      handoff.md

### Start of session

    # Docker Desktop must be running.
    cd ~/umoja-secure
    docker compose up -d

    # Emulator (one or two).
    $HOME/Library/Android/sdk/emulator/emulator -avd Pixel_9 &
    $HOME/Library/Android/sdk/emulator/emulator -avd Pixel_9_API35_B -memory 1535 &

    # Reverse ports so the emulator can reach the Mac.
    $HOME/Library/Android/sdk/platform-tools/adb -s emulator-5554 reverse tcp:8080 tcp:8080
    $HOME/Library/Android/sdk/platform-tools/adb -s emulator-5554 reverse tcp:9050 tcp:9050

### Backend iteration

    cd ~/umoja-secure/backend
    npm run dev              # dev mode, auto-reloads
    npm test
    npm run typecheck
    npm run lint
    npm run migrate

After backend changes that need to ship to Docker:

    cd ~/umoja-secure
    docker compose up -d --build backend

### Android iteration

    cd ~/umoja-secure/android
    ./gradlew installDebug
    ./gradlew connectedAndroidTest

### Tor mode toggle

In `android/app/src/main/java/com/umoja/secure/transport/TransportConfig.kt`:

    var useTor: Boolean = false    # clearnet dev via adb reverse
    var useTor: Boolean = true     # .onion over SOCKS via Socks5Bridge

Rebuild after flipping — the flag is read at HttpClient construction time.

### Logcat

    $HOME/Library/Android/sdk/platform-tools/adb -s emulator-5554 logcat -c
    # tap in the app
    $HOME/Library/Android/sdk/platform-tools/adb -s emulator-5554 logcat -d | grep -iE "UmojaSocksBridge|UmojaWS|UmojaHttp|UmojaEnroll|okhttp|UmojaAdmin" | tail -40

### Tor verification

    # Backend reachable over onion from the Mac?
    curl --socks5-hostname 127.0.0.1:9050 -sS --max-time 20 \
      http://vsf2kj6uapla74qea4wp4vwbahyqzftq3aywsjd3hknlcvgbtzn6xjad.onion/health

    # Look for traffic over Tor in backend logs:
    docker compose logs backend --tail=20 | grep -i onion
    # requests should show "remoteAddress":"172.18.0.4" (the tor container)

---

## 7. Conventions

- One task per session. Do not mix unrelated work.
- **Every commit block ends with `git push origin main`.** If a tag is
  created, follow with `git push origin --tags`.
- Update this Handoff at the end of every session — bump the date, add the
  new tag, rewrite Section 3, re-order Section 5.
- For file writes, prefer a text editor (`open -e <path>` on macOS, or
  `nano`) over a terminal heredoc for anything over ~150 lines. Terminal
  heredocs fragment during paste.
- Placeholder markers like `<paste content here>` are never to be typed
  literally. If a file ends up suspiciously short, that's the tell.
- When debugging, log the exception before swallowing it. Silent catch
  blocks have cost hours on this project.
- For libsignal, don't hold native handles across scope boundaries in
  tests. Serialize to bytes if state must outlive the store that created it.
- Test count and file count are the quickest pulse check. Current:
  85 backend tests, 48 Android tests.

---

## 8. References for the matrix implementation session

### Authoritative design

- `docs/architecture/ADR-PROVISIONING-001.md` — §2 (threat-model answers),
  §3 (signing protocol), §4 (matrix schema), §5 (test plan), §6 (11-line
  plan).
- `docs/reference/THREAT-MODEL-001.md` §5 (STRIDE), §6 (specific
  resolutions), §7 (trust boundaries), §8 (revocation enforcement).
- `docs/reference/AUTH-SPEC-001.md` §5 (identity), §6 (sessions), §9
  (revocation), §10 (enrollment tokens).
- `docs/US-ADD-001.md` §7 (JCS, SHA-256, Ed25519, versioning).
- `UMOJA-SECURE-BUILD-MASTER.md` §3.6, §3.7, §3.8.

### Conformance data

- `docs/reference/rfc8785-number-samples.json` — 24 samples, RFC 8785 App. B.
- `docs/reference/jcs-conformance/` — 6 input/output pairs from cyberphone.
- `docs/reference/canonical-matrix-test-vectors.json` — the Umoja wrapper
  vectors. Currently a scaffold; `generated: false`.

### Current code shape (minimum viable reading set)

Backend:
- `backend/src/routes/admin.ts` — admin route surface
- `backend/src/routes/enrollment.ts` — enrollment token consumption
- `backend/src/admin/enrollmentTokens.ts` — token issue/revoke
- `backend/src/admin/devices.ts` — device list, revoke, suspend, resume
- `backend/src/enrollment/consume.ts` — token-consumption path
  (AUTH-SPEC-001 §10.3)
- `backend/src/authorization/contacts.ts` — bidirectional contact model
- `backend/src/auth/sessions.ts` — opaque session lookup + revocation
- `backend/src/auth/canonical.ts` — **existing** challenge canonicalizer.
  Do not modify; the new JCS canonicalizer is a separate file.
- `backend/src/auth/verify.ts` — challenge signature verification
  (`@noble/ed25519`)

Android:
- `android/app/src/main/java/com/umoja/secure/transport/AdminApi.kt`
- `android/app/src/main/java/com/umoja/secure/transport/ContactsApi.kt`
- `android/app/src/main/java/com/umoja/secure/transport/Socks5Bridge.kt`
- `android/app/src/main/java/com/umoja/secure/crypto/DeviceKeyManager.kt`
  — Ed25519 device auth key. **Not** the libsignal identity key.
- `android/app/src/main/java/com/umoja/secure/crypto/DeviceIdentity.kt`
  — SPKI ↔ raw Ed25519 key conversion
- `android/app/src/main/java/com/umoja/secure/crypto/SignalIdentityStore.kt`
  — Curve25519 libsignal identity key
- `android/app/src/main/java/com/umoja/secure/auth/CanonicalChallenge.kt`
  — **existing** challenge canonicalizer. Do not modify.
- `android/app/src/main/java/com/umoja/secure/auth/SessionManager.kt`
- `android/app/src/main/java/com/umoja/secure/ui/admin/AdminScreen.kt`

### Verify paths before reading

    find ~/umoja-secure/backend/src -name "*.ts" | grep -E "admin|enroll|contact|session|crypto|canonical" | sort
    find ~/umoja-secure/android/app/src/main/java/com/umoja/secure -name "*.kt" | grep -E "Admin|Contact|Device|Signal|Session|Canonical|Jcs" | sort

### Note: TASK-P1-027 numbering collision

Commit `ad89b76` is labeled "TASK-P1-027: docker deployment". The current
registry maps TASK-P1-027 to "SBOM generation and dependency review gate".
The registry is authoritative. Do not "fix" the old commit label.

### Note: provenance of the canonical documents

The four canonical documents (`US-ADD-001`, `US-MASTER-001`,
`AUTH-SPEC-001`, `THREAT-MODEL-001`) were authored on 2026-10-14. They did
not exist before. Each carries its own §1 Provenance section recording this.

If a security-relevant question arises that none of them answers, do not
guess. STOP and escalate, per Build Master §0.
