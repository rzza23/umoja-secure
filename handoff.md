# Umoja Secure — Handoff

Last updated: 2026-10-14 (Session 0 complete)
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

Authoritative documents (all now exist on disk — see §3):
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

## 3. What was just done (Session 0)

Authored the canonical requirements documents. They did not previously
exist on disk.

**Why this happened.** A machine-wide search confirmed that, of the
canonical set listed in Build Master §2, only `docs/US-TASK-P1-001.md`
existed. The other four were referenced everywhere but never written.
Build Master §0 says the requirements layer wins over the execution layer,
but the requirements layer was partly aspirational. Session 0 closed that
gap.

**What was authored (2026-10-14):**

- `docs/architecture/ADR-PROVISIONING-001.md` — provisioning trust
  boundaries and authorization matrix. Answers six threat-model
  questions. Commit `91b5c47`, tag `v0.30-adr-provisioning`.
- `docs/reference/THREAT-MODEL-001.md` — adversary classes, STRIDE table
  for provisioning, specific threat resolutions. Commit `692c672`.
- `docs/reference/AUTH-SPEC-001.md` — device identity, session lifecycle,
  revocation guarantees, enrollment token authorization. Commit
  `059fa5e`.
- `docs/US-ADD-001.md` — approved decisions and parameters. Highest
  authority per Build Master §0. Commit `e505394`.
- `docs/US-MASTER-001.md` — governing architecture, threat model summary,
  phase boundaries. Commit `43dbe83`.
- `docs/reference/canonical-matrix-test-vectors.json` — **scaffold only.**
  Vectors authored, outputs null. `generated: false`. This is deliberate
  and load-bearing: see §4.

**Provenance honesty.** These documents were authored, not discovered.
Each carries a §1 Provenance section saying so. THREAT-MODEL-001 §1 and
AUTH-SPEC-001 §1 record that they are the project owner's statement of
the model, formalized — not the output of an external security review.
The ADR's §7 records that the four files were expected from an earlier
session but did not exist, and that Q1/Q2/Q4 were cleared by explicit
owner attestation.

**What this closes.** The ADR §7 residual item — file-level verification
of Q1/Q4 — is now closed against the newly authored docs:
- Q1 → THREAT-MODEL-001 §6.1
- Q2 → AUTH-SPEC-001 §10
- Q4 → THREAT-MODEL-001 §8

**What this does NOT close.** The authored documents were written *after*
the code they describe was already largely built. Nothing in Session 0
revisited existing backend or client code for conformance. A conformance
sweep against the newly authored specs is a Session A pre-task — see §5.

---

## 4. Known issues

### KI-001 (FIXED): OkHttp cannot reach .onion through SOCKS

Fixed in `v0.29-tor-transport` with the Socks5Bridge. See §3 of the
previous handoff, preserved in git history.

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

### KI-004: Canonical-matrix test vectors are a scaffold, not data

`docs/reference/canonical-matrix-test-vectors.json` has `generated: false`.
The inputs are authored; the outputs (canonical bytes, SHA-256 digest,
Ed25519 signature) are `null`. The file's own `stop_condition` field says
it is not authoritative until `generated: true`.

**Consequence:** no signing code may commit until the generator runs. This
is a Build Master §3.8 precondition, not a preference. Session A's first
task after the conformance sweep is to run the generator.

The file also references RFC 8785's published test data, marked
`TO_BE_IMPORTED_IN_SESSION_A`. Those vectors are external ground truth
for canonicalizer correctness and must be imported verbatim, not
hand-authored.

### KI-005: Requirements layer was authored after the code

The four canonical documents were written on 2026-10-14, after most of
Phase 1's messaging code already existed. The code predates its own spec.
This does not make the code wrong, but it means no systematic conformance
check has been done. Treat Session A's pre-task (§5 item 0) as required,
not optional.

### KI-006: USER-ONBOARDING.md still missing

`docs/reference/USER-ONBOARDING.md` is referenced by Build Master §2 and
§3.4 (cryptographic-erasure disclaimer) but does not exist. Not a Session
A blocker. Flag for a follow-up Session 0b if it starts blocking work.

---

## 5. Immediate next steps (recommended order)

**0. Conformance sweep (Session A pre-task).** Before writing any new
   code, verify that existing backend and client code matches the newly
   authored specs. Specific greps:
   - Any Ed25519 signing path that signs canonical bytes directly
     instead of the SHA-256 digest (Build Master §3.8 — the §3.6
     correction in v1.4.2 makes this the specified protocol).
   - Any place `pub_device_auth_key` and `pub_messaging_identity_key`
     are stored in the same column or conflated.
   - Any client-side revocation enforcement in the delivery path
     (should be none — enforcement is server-authoritative per
     AUTH-SPEC-001 §9).
   - Any JCS-like canonicalization that predates the wrapper convention.
   Report drift; do not silently fix. If drift is found in security-
   relevant code, STOP and escalate.

**1. Session A — TASK-P1-025 + TASK-P1-026.** Admin provisioning tool
   and authorization matrix. Plan is in ADR-PROVISIONING-001 §6, eleven
   lines. The first line is the §8 file-verification step, already done.
   After the conformance sweep, the sequence is:
   - Generate test vectors (flip `generated: true` in
     canonical-matrix-test-vectors.json) — **before any signing code**.
   - Land the matrix schema (TS type + Kotlin data class).
   - Implement JCS canonicalization on both sides; verify byte-identical
     output for every vector.
   - Implement sign/verify per §3.8.
   - QR ceremony, offline signing handoff (TASK-P1-033 boundary), client
     verification and storage, `bound_public_key` schema addition,
     tests.

**2. Emergency lock (TASK-P1-021a).**

**3. Duress wipe (TASK-P1-021b).**

**4. Signing-key custody (TASK-P1-029) and offline signer (TASK-P1-033).**
   Both depend on Session A's matrix schema landing first.

**5. Organization recovery key (TASK-P1-035).**

**6. Hardware-backed Ed25519 verification on real Pixel/GrapheneOS
   (TASK-P1-034).** Depends on physical hardware. Cannot be started in
   emulator.

**7. Hardening.** SBOM, Android redaction audit, penetration test,
   independent review.

---

## 6. Development environment

### Repo layout

    umoja-secure/
      backend/              Fastify + PostgreSQL
      android/              Kotlin + Compose app
      docs/                 ADRs, specs, this Handoff
        architecture/       ADR-PROVISIONING-001.md
        ops/                TOR-ONION.md
        reference/          AUTH-SPEC-001.md, THREAT-MODEL-001.md,
                            canonical-matrix-test-vectors.json
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
- Commit every session. Tag after each meaningful milestone.
- Update this Handoff at the end of every session — bump the date, add
  the new tag, rewrite Section 3, re-order Section 5.
- For file writes, prefer Python heredocs over `cat > file << EOF`.
  Long bash heredocs fragment during paste and leave half-written files.
  **Correction (Session 0):** when the file content is itself long,
  prefer a text editor (`open -e <path>` on macOS, or `nano`) over a
  terminal heredoc. Terminal heredocs work for short files; they fragment
  for anything over ~150 lines.
- Placeholder markers like `<paste content here>` are never to be typed
  literally. If a file ends up suspiciously short, that's the tell.
- When debugging, log the exception before swallowing it. Silent catch
  blocks have cost hours on this project.
- For libsignal, don't hold native handles across scope boundaries in
  tests. Serialize to bytes if state must outlive the store that created
  it.
- Test count and file count are the quickest pulse check. Current:
  85 backend tests, 48 Android tests.

---

## 8. References for the provisioning session

The next session picks up TASK-P1-025 + TASK-P1-026 (Session A). Read
these before writing any code — they now all exist on disk.

### Authoritative design

- `docs/architecture/ADR-PROVISIONING-001.md` — the Session A plan.
  §2 answers the six threat-model questions. §3 is the signing protocol.
  §4 is the matrix schema. §5 is the test plan. §6 is the eleven-line
  implementation plan.
- `docs/reference/THREAT-MODEL-001.md` §5 (STRIDE), §6 (specific
  resolutions), §7 (trust boundaries), §8 (revocation enforcement).
- `docs/reference/AUTH-SPEC-001.md` §5 (identity generation), §6
  (sessions), §9 (revocation), §10 (enrollment tokens — schema and
  consumption protocol).
- `docs/US-ADD-001.md` §7 (cryptographic parameters — JCS, SHA-256,
  Ed25519, versioning).
- `UMOJA-SECURE-BUILD-MASTER.md` §3.6, §3.7, §3.8 — the frozen source
  of truth for rotation, anti-rollback, and canonicalization.

### Current code shape (minimum viable reading set)

Backend:
- `backend/src/routes/admin.ts` — admin route surface, role middleware
- `backend/src/routes/enrollment.ts` — enrollment token consumption
- `backend/src/admin/enrollmentTokens.ts` — token issue/revoke
- `backend/src/admin/devices.ts` — device list, revoke, suspend, resume
- `backend/src/enrollment/consume.ts` — token-consumption path
  (referenced by AUTH-SPEC-001 §10.3)
- `backend/src/authorization/contacts.ts` — bidirectional contact model
- `backend/src/auth/sessions.ts` — opaque session lookup + revocation

Android:
- `android/app/src/main/java/com/umoja/secure/transport/AdminApi.kt`
- `android/app/src/main/java/com/umoja/secure/transport/ContactsApi.kt`
- `android/app/src/main/java/com/umoja/secure/transport/Socks5Bridge.kt`
- `android/app/src/main/java/com/umoja/secure/crypto/DeviceKeyManager.kt`
  — **Ed25519 device authentication key** in Android Keystore. Signs
  challenges. NOT the libsignal identity key.
- `android/app/src/main/java/com/umoja/secure/crypto/SignalIdentityStore.kt`
  — **Curve25519 libsignal identity key**. NOT the device auth key.
  Provisioning touches both: the device auth key for enrollment and
  challenge-response; the Signal identity key for the matrix's
  `pub_messaging_identity_key` field.
- `android/app/src/main/java/com/umoja/secure/auth/SessionManager.kt`
- `android/app/src/main/java/com/umoja/secure/ui/admin/AdminScreen.kt`
  (will grow significantly for provisioning)

### Verify paths before reading

    find ~/umoja-secure/backend/src -name "*.ts" | grep -E "admin|enroll|contact|session" | sort
    find ~/umoja-secure/android/app/src/main/java/com/umoja/secure -name "*.kt" | grep -E "Admin|Contact|DeviceKey|SignalIdentity|Session" | sort

### Note: TASK-P1-027 numbering collision

Commit `ad89b76` is labeled "TASK-P1-027: docker deployment". The current
task registry maps TASK-P1-027 to "SBOM generation and dependency review
gate". The registry is authoritative; the commit label predates a
renumbering. When reading git history, treat TASK-P1-027 in the registry
as the current meaning. Do not "fix" the old commit label.

### Note: provenance of the canonical documents

The four canonical documents (`US-ADD-001`, `US-MASTER-001`,
`AUTH-SPEC-001`, `THREAT-MODEL-001`) were authored on 2026-10-14. They
did not exist before. Each carries its own §1 Provenance section
recording this. If a future session wonders why they read as freshly
written prose rather than ratified committee output — that's why.

If a security-relevant question arises that none of them answers, do not
guess. STOP and escalate, per Build Master §0.
