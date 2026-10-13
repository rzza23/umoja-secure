# Umoja Secure — Handoff

Last updated: 2026-10-13
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

Authoritative documents:
- UMOJA-SECURE-BUILD-MASTER.md (v1.4.2, frozen)
- docs/US-MASTER-001.md, docs/US-ADD-001.md
- docs/US-TASK-P1-001.md (task registry)
- docs/reference/AUTH-SPEC-001.md, docs/reference/THREAT-MODEL-001.md

---

## 2. Where the project stands

### Backend (complete for Phase 1 messaging)

- Node.js 24.x, Fastify 5.12.5, PostgreSQL 16
- Docker-deployable (docker compose up -d --build from repo root)
- 85 tests passing across 10 test files
- Server-blind: routes ciphertext envelopes, never decrypts

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
- POST /admin/contacts, POST /admin/contacts/:owner/:contact/revoke,
  GET /admin/contacts
- GET /admin/audit/verify
- WS /ws

### Android client (working E2EE messenger on emulators)

- Kotlin + Jetpack Compose, minSdk 30, targetSdk 36
- Package: com.umoja.secure
- Ed25519 device identity in Android Keystore (TEE-backed on real devices,
  BouncyCastle software fallback on emulator)
- libsignal 0.86.5 (client) + 0.81.1 (native AAR) integrated; PQXDH works
- Persistent SignalProtocolStore (all 6 libsignal interfaces)
- Encrypted local storage (AES-GCM key in Keystore)
- WebSocket client: auth handshake, revalidation, heartbeat, auto-reconnect
- Real-time 1:1 encrypted messaging between two emulators (verified)
- Contacts screen wired to GET /me/contacts via ContactsApi.kt
- Transport mode toggle: TransportConfig.useTor (currently false)

---

## 3. What was just done (this session)

Contact authorization enforcement — complete end to end.

- Migration 010_contacts.sql: contacts table with bidirectional model
- src/authorization/contacts.ts: isContactAuthorized, authorizeContact,
  revokeContact, listContactsForDevice, listAllContacts
- Enforcement in three places: envelope submit, prekey fetch, WebSocket
  delivery re-check
- Admin routes: create, revoke, list contacts
- Self route: GET /me/contacts
- test/contacts.test.ts — 9 tests, all passing
- Client: transport/ContactsApi.kt (canonical), ContactsScreen.kt wired
  to GET /me/contacts
- Deleted orphaned ContactApi.kt (called nonexistent /contacts)
- Lint: fixed == to ===, unused req param; added
  ESLINT_USE_FLAT_CONFIG=false to lint script

Transport config cleanly separated.

- TransportConfig.kt — single toggle for clearnet vs Tor
- Clearnet dev works: useTor = false, 127.0.0.1:8080 via adb reverse
- Tor mode: useTor = true, .onion over SOCKS at 127.0.0.1:9050
  (see Known Issues — does not yet work end to end)

---

## 4. Known issues (blocking Phase 1 completion)

### KI-001: OkHttp cannot reach .onion through SOCKS

Symptom: with useTor = true, all requests throw network_error.

Diagnosis: curl --socks5-hostname 127.0.0.1:9050 http://<onion>/health
works from the Mac, but OkHttp resolves the .onion locally and sends the
resolved IP (dummy 127.0.0.1) to the SOCKS proxy, which then fails. This
is a known OkHttp limitation.

Fix options (needs dedicated session):
1. Custom SocketFactory that delegates to SOCKS proxy for .onion
2. Swap to a different HTTP client with proper SOCKS/hostname handling
3. Test with a plain IP-based SOCKS proxy (no .onion) as a first milestone

Current state: TransportConfig.useTor = false. Clearnet is the working
dev path. Tor is a Phase 1 requirement but not yet functional.

### KI-002: Backend Docker image goes stale during iteration

Symptom: new routes return 404 even though source has them. Cause: the
running container is an old build.

Fix: docker compose up -d --build backend after backend route or
controller changes. Or run backend in dev mode on the Mac (npm run dev
in backend/) instead of Docker during active backend iteration.

---

## 5. Immediate next steps (recommended order)

1. Tor transport (KI-001). Dedicated session. Deliverables:
   - Prove OkHttp can talk to .onion through SOCKS
   - Flip useTor = true, verify enrollment + WebSocket over onion
   - Write docs/ops/TOR-ONION.md
2. Admin provisioning tool. QR ceremony, offline provisioning-key
   signing, signed authorization matrix (TASK-P1-025 + TASK-P1-026).
3. Emergency lock (TASK-P1-021a).
4. Duress wipe (TASK-P1-021b).
5. Hardware-backed Ed25519 verification on real Pixel/GrapheneOS
   (TASK-P1-034).
6. Hardening. SBOM, Android redaction audit, penetration test,
   independent review.

---

## 6. Development environment

### Repo layout

    umoja-secure/
      backend/              Fastify + PostgreSQL
      android/              Kotlin + Compose app
      docs/                 ADRs, specs, this Handoff
      infra/                docker, tor
      UMOJA-SECURE-BUILD-MASTER.md
      docker-compose.yml
      README.md

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

### Logcat

    $HOME/Library/Android/sdk/platform-tools/adb -s emulator-5554 logcat -c
    # tap in the app
    $HOME/Library/Android/sdk/platform-tools/adb -s emulator-5554 logcat -d | grep -iE "UmojaHttp|UmojaEnroll|okhttp|contacts|cleartext" | tail -40

---

## 7. Conventions

- One task per session. Do not mix unrelated work.
- Commit every session. Tag after each meaningful milestone.
- Update this Handoff at the end of every session — bump the date, add
  the new tag, rewrite Section 3, re-order Section 5.
- For file writes, prefer Python heredocs over cat > file << EOF.
  Long bash heredocs fragment during paste and leave half-written files.
- When debugging, log the exception before swallowing it. Silent catch
  blocks have cost hours on this project.
