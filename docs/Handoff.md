# Umoja Secure — Handoff

Last updated: 2026-10-14
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
- POST /admin/contacts, POST /admin/contacts/:owner/:contact/revoke,
  GET /admin/contacts
- GET /admin/audit/verify
- WS /ws

### Android client (working E2EE messenger on emulators, over Tor)

- Kotlin + Jetpack Compose, minSdk 30, targetSdk 36
- Package: com.umoja.secure
- Ed25519 device identity in Android Keystore (TEE-backed on real devices,
  BouncyCastle software fallback on emulator)
- libsignal 0.86.5 (client) + 0.81.1 (native AAR) integrated; PQXDH works
- Persistent SignalProtocolStore (all 6 libsignal interfaces)
- Encrypted local storage (AES-GCM key in Keystore)
- **Tor transport working end to end** — enrollment, auth, prekey upload,
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

## 3. What was just done (this session)

Tor transport working end to end.

The blocker was KI-001 from the previous handoff: OkHttp + Java's SOCKS
implementation resolves hostnames locally before dialing SOCKS, so
`.onion` addresses break — Java resolves them to a dummy 127.0.0.1 and
Tor then fails to connect.

Fix: a local HTTP/1.1 proxy in the app (`transport/Socks5Bridge.kt`) that
accepts OkHttp requests with `Proxy.Type.HTTP`, extracts the target host
from the request line, dials SOCKS5 to 127.0.0.1:9050 with the hostname
in ATYP=0x03 form, and relays bytes. `.onion` is never seen by Java's DNS.

- New file: `transport/Socks5Bridge.kt` (~230 lines)
- `HttpClient.kt` — replaces the SOCKS-Proxy + custom-Dns approach with
  a single `Proxy(Type.HTTP, 127.0.0.1:<bridgePort>)` when useTor is true
- `WebSocketClient.kt` — same replacement in `buildClient()`
- `WebSocketClient.connect()` made idempotent (closes any prior socket
  before opening a new one)
- Admin diagnostic logs (UmojaAdminDiag) stripped from AdminApi.kt
- `docs/ops/TOR-ONION.md` written — topology, bridge design, config,
  verification, troubleshooting, production notes

Verified:

- Backend logs show `/auth/challenge`, `/auth/verify`, `/prekeys`, `/ws`
  hitting the backend with `host: <onion>.onion` and
  `remoteAddress: 172.18.0.4` (the umoja-tor container) — proof the
  traffic came over Tor, not clearnet.
- Client logcat: `UmojaSocksBridge: bridge listening`, `UmojaWS: socket
  open`, `UmojaWS: authenticated`.
- WebSocket revalidation works over the bridge.

Committed as `v0.29-tor-transport`.

---

## 4. Known issues

### KI-001 (FIXED): OkHttp cannot reach .onion through SOCKS

Fixed in `v0.29-tor-transport` with the Socks5Bridge. See Section 3.

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

---

## 5. Immediate next steps (recommended order)

1. **Admin provisioning tool** (TASK-P1-025 + TASK-P1-026). The
   differentiator. **Read Section 8 first — it lists the specific
   references and threat-model questions this work must answer.**
   Deliverables:
   - QR ceremony: device generates keypair, displays QR with public keys
   - Admin app scans device QRs
   - Admin assigns clearance + group membership
   - Organization provisioning key (offline signing, per Build Master §3.6)
   - Signed authorization matrix distributed to devices
   - Client verifies matrix signature and populates contact list
2. Emergency lock (TASK-P1-021a).
3. Duress wipe (TASK-P1-021b).
4. Hardware-backed Ed25519 verification on real Pixel/GrapheneOS
   (TASK-P1-034). Depends on physical hardware.
5. Hardening. SBOM, Android redaction audit, penetration test,
   independent review.

---

## 6. Development environment

### Repo layout

    umoja-secure/
      backend/              Fastify + PostgreSQL
      android/              Kotlin + Compose app
      docs/                 ADRs, specs, this Handoff
        ops/                TOR-ONION.md and other operational docs
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
- When debugging, log the exception before swallowing it. Silent catch
  blocks have cost hours on this project.
- For libsignal, don't hold native handles across scope boundaries in
  tests. Serialize to bytes if state must outlive the store that created
  it.
- Test count and file count are the quickest pulse check. Current:
  85 backend tests, 48 Android tests.



## 8. References for the provisioning session

The next session picks up the admin provisioning tool (TASK-P1-025, TASK-P1-026).
Read these before writing any code.

### Composition with existing auth

`docs/reference/AUTH-SPEC-001.md` — device identity model, challenge/verify,
session lifecycle, revocation. **Provisioning MUST compose with this, not
parallel it.** Every device that provisioning touches is already, or will
become, an authenticated device via the flow in AUTH-SPEC-001. The
provisioning ceremony is an additional layer on top of the identity, not a
substitute.

Sections to read:
- §5 device identity generation (Ed25519 in Android Keystore)
- §6 session lifecycle (opaque tokens, immediate revocation)
- §7 authorization model (roles, contacts)
- §9 revocation guarantees
- §10 enrollment token authorization

### Threat model — what provisioning must resist

`docs/reference/THREAT-MODEL-001.md` — read it, then answer these specifically
in the new ADR or design doc:

1. **Rogue admin.** Can an admin device issue a matrix that grants access to
   an unauthorized device, or revoke authorization without proper audit?
   Assume the admin device is trusted; protection is via audit, role
   separation, and recovery-key revocation of a compromised provisioning
   key — not via preventing an authorized admin from acting. Confirm this
   is the intended boundary.

2. **Enrollment token replay.** A token is single-use, admin-signed, and
   expiring. What happens if intercepted in transit? Used twice
   concurrently? Presented with a different public key than the one it was
   bound to?

3. **Matrix forgery.** The matrix is signed by the organization
   provisioning key, and devices verify before trusting it. What stops a
   compromised backend from serving a stale matrix, or a matrix signed by
   a revoked provisioning key?

4. **Offline revocation gap.** Device A is revoked. Device B is offline and
   hasn't fetched the new matrix. What happens when B comes online? If B
   messages A? If B messages a third device C using the old matrix?

5. **Matrix rollback.** The matrix has a monotonic version. A device that
   has seen v5 must reject v4. What happens on first-ever fetch (no version
   seen)? What happens if a newly enrolled device receives a matrix from an
   old enrollment token that embeds an old version floor?

6. **Provisioning key compromise.** The offline signing key is stolen. Per
   Build Master §3.6, the recovery key signs a revocation notice; devices
   pin the recovery public key and reject all future matrices from the
   compromised key. Confirm this flow is implementable and add the test
   cases.

### Current code shape (minimum viable reading set)

Backend:
- `backend/src/routes/admin.ts` — admin route surface, role middleware
- `backend/src/routes/enrollment.ts` — enrollment token consumption
- `backend/src/admin/enrollmentTokens.ts` — token issue/revoke
- `backend/src/admin/devices.ts` — device list, revoke, suspend, resume
- `backend/src/authorization/contacts.ts` — bidirectional contact model
- `backend/src/auth/sessions.ts` — opaque session lookup + revocation

Android:
- `android/app/src/main/java/com/umoja/secure/transport/AdminApi.kt` — admin
  API client (create tokens, list devices, authorize contacts)
- `android/app/src/main/java/com/umoja/secure/transport/ContactsApi.kt` —
  user-facing contacts
- `android/app/src/main/java/com/umoja/secure/transport/Socks5Bridge.kt` —
  Tor transport (provisioning will not change this)
- `android/app/src/main/java/com/umoja/secure/crypto/DeviceKeyManager.kt` —
  **Ed25519 device authentication key** in Android Keystore. This is the
  key that signs challenges. NOT the libsignal identity key.
- `android/app/src/main/java/com/umoja/secure/crypto/SignalIdentityStore.kt`
  — **Curve25519 libsignal identity key** (see Build Master §3.2). Also not
  the device auth key. Provisioning touches both, for different reasons:
  the device auth key for enrollment and challenge-response, the Signal
  identity key for the authorization matrix's `pub_messaging_identity_key`
  field.
- `android/app/src/main/java/com/umoja/secure/auth/SessionManager.kt` —
  authentication flow
- `android/app/src/main/java/com/umoja/secure/ui/admin/AdminScreen.kt` —
  admin UI (will grow significantly for provisioning)

### Note: TASK-P1-027 numbering collision

Commit `ad89b76` is labeled "TASK-P1-027: docker deployment". The current
task registry maps TASK-P1-027 to "SBOM generation and dependency review
gate". The registry is authoritative; the commit label predates a
renumbering. When reading git history, treat TASK-P1-027 in the registry as
the current meaning.

Verify paths before reading: