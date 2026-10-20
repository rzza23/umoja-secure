# Umoja Secure — Handoff

Last updated: 2026-10-20 (Session Z-16 — **P1-033b DONE** at `691d27d` (Phase 1 DoD, offline signing ceremony, admin client half). `MatrixApi.push(targetDeviceId, remote, sessionToken)` returns server echo `PushResult(deviceId, version)`; `AdminScreenState` gains `importSignature` / `clearSignature` / `pushSignedMatrix` + two new StateFlows; AdminScreen gains QR render of `builtWrapperJson`, signature text field + scan launcher, push button. `MainActivity` wires `adminMatrixApi::push` into `AdminScreenState.pushFn` (single HttpClient shared with fetchFn). **Breaking API change:** `MatrixApi` constructor gains `pushFn` second param; 3 call sites updated to named `fetchFn = { }`. **Latent bug fixed:** `buildMatrix` now clears `_pushedMatrix` so rebuild re-enables push. JVM 246 → 260 (+14: +4 MatrixApiTest, +10 AdminScreenStateTest). Backend 263 unchanged. **Push UI structurally complete, end-to-end runtime verification deferred to 033e** (real signed matrix from a real ceremony). **Next: P1-033c** (signing build flavor + SigningActivity) OR P1-035 (recovery-key ceremony — design exists) OR P1-027b (needs CI provider) OR nothing — choice, not obligation.)

Purpose: Enable a new AI agent or developer session to pick up the
project without re-reading the entire chat history.

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
- docs/US-ADD-001.md (v0.2)
- docs/US-MASTER-001.md
- docs/reference/AUTH-SPEC-001.md, docs/reference/THREAT-MODEL-001.md
- docs/US-TASK-P1-001.md (task registry, v0.6)
- docs/architecture/ADR-PROVISIONING-001.md
- docs/architecture/ADR-IDENTITY-CHANGE-001.md (v0.3)
- docs/architecture/ADR-HARDENING-001.md (v0.1)
- docs/ops/TOR-ONION.md
- docs/security/DEPENDENCY-EXCEPTIONS.md (created Session A)

---

## 2. Where the project stands

### Backend (complete for Phase 1 messaging)

- Node.js 24.x, Fastify 5.12.5, PostgreSQL 16
- Docker-deployable (docker compose up -d --build from repo root)
- **263 tests passing** (20 files; verified 2026-10-20 via
  `npm test`. Sessions C–F added matrix-version, floor stamping,
  replacement-notice. Session H added identity-change services (7
  validator tests) and routes (17 route tests). Session I added the
  A-001 cross-language ack test. Sessions J, K, and L backend
  unchanged. Session M added the `sign-test-notice.ts` helper script
  (no test coverage, exercised manually). Session N design-only,
  no backend changes. Session O-1 added matrix transport: migration
  016, GET /me/matrix, 5 route tests. Session Z-15 added
  `POST /admin/matrices/:device_id` + verify-on-write + 9 route
  tests.)
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
- Ed25519 device identity in Android Keystore (TEE-backed on real
  devices, BouncyCastle software fallback on emulator)
- libsignal 0.86.5 (client) + 0.81.1 (native AAR) integrated; PQXDH
  works
- Persistent SignalProtocolStore (all 6 libsignal interfaces)
- Encrypted local storage (AES-GCM key in Keystore)
- Tor transport working end to end
- Real-time 1:1 encrypted messaging between two emulators
- Contacts screen wired to GET /me/contacts
- Admin screen (device list, enrollment tokens, contact pairs, and
  as of Session A, the TASK-P1-025 provisioning flow)
- **JVM unit tests: 260** (verified 2026-10-19 from XML; Session R-3's 1 clear() test, then Session R-4's 7 HttpClientRetryTest tests. Sessions L and M added Compose UI and lifecycle code with no JVM tests; verified manually on emulator. Session N design-only. Session O-1 backend-only. Session O-2 client work verified on emulator (highestSeenVersion=1). Session P: 038 send gate, three-case emulator acceptance. Session R-2: 040-B state machine, 12 JVM tests. Session R-3: 040-C routing rewrite, smoke verified three user flows. Session R-4: 040-D interceptor, TEST-SESSION-REVOKED-ON-DEVICE passed. Session R-5: 040-E manual acceptance, no JVM changes. Session T-1: 041 failed-verification log, 14 JVM tests. Session Z-3: AdminScreenStateTest, 22 JVM tests. Session Z-4: ChatViewModelTest, 10 JVM tests. Session Z-13: 029b ProvisioningKeysTest, 2 JVM tests. Session Z-16: 033b MatrixApiTest +4, AdminScreenStateTest +10.)
- **androidTest: 8 files, 71 tests** (verified 2026-10-18 from
  connectedAndroidTest XML aggregate `<testsuites tests="71">` -- not
  grep-summed; see §7 twelfth lesson. Session Z-1 added `AckDialogTest.kt`
  (11 Compose tests); Session Z-5 added `ChatScreenTest.kt` (14 Compose
  tests, arc session D, arc complete). Prior count 6 files / 46 tests
  from 2026-10-15;
  was wrongly recorded as 0 files in an earlier handoff — see KI-013)

Note: a prior handoff claimed 98 Android tests. That was wrong. The
actual prior count was ~1 (ExampleUnitTest only); the crypto work
brought it to 77, then 89 after P1-019, then 110 after P1-026. See §4 KI-013.

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

Four requirements-layer documents authored (US-ADD-001, US-MASTER-001,
AUTH-SPEC-001, THREAT-MODEL-001). Commits `91b5c47`, `692c672`,
`059fa5e`, `e505394`, `43dbe83`, `55ebd13`. Tags `v0.30-adr-provisioning`,
`v0.31-session-0`. See ADR-PROVISIONING-001 §7 for provenance.

### Session A — JCS, matrix schema, sign/verify, P1-025 provisioning UI

**JCS canonicalization — done both sides.**

- TS: `backend/src/crypto/jcs.ts` + 45 tests (commit `c06aaa8`).
- Kotlin number formatter: `JcsNumberFormatter.kt` + 4 tests
  (commit `ff15357`). Resolved KI-007.
- Kotlin canonicalizer: `JcsCanonicalizer.kt` + 11 tests.
- Test-scope `org.json:json:20240303` added; not a runtime dep
  (KI-011 option A).

**Cross-check harness — done** (commit `41f52b0`). Closes KI-012.

- `backend/src/crypto/jcs-dump.ts`, `JcsCrossCheckTest.kt`,
  `scripts/jcs-cross-check.sh`.
- **PASS: 38 inputs, byte-identical.**

**Matrix test vectors — populated** (commit `e6eed9b`). Closes KI-004.

- `canonical-matrix-test-vectors.json` now `generated: true`, all six
  W-series vectors filled, test public key
  `hL_X45qk5WrA9rSxtrQJyRzkDGT0eysDBtuWQosC30M`.
- Regenerate: `cd backend && npm run generate-matrix-vectors`.

**Authorization matrix schema — done both sides.**

- `backend/src/crypto/matrix-schema.ts` + 23 tests.
- `android/.../crypto/AuthorizationMatrix.kt` + 23 tests.
- One coverage gap by language constraint: TS tests
  `validateMatrix("string")`; Kotlin's `fromJsonMap(Map<String,Any?>)`
  cannot accept a String at the type level. Documented, not a bug.

**Matrix sign/verify — done both sides.**

- `backend/src/crypto/matrix-sign.ts` + 22 tests (Node built-in crypto).
- `android/.../crypto/MatrixSigner.kt` + 12 tests (BouncyCastle 1.79).
- Protocol per §3.8: JCS(wrapper) → SHA-256 → Ed25519 over 32-byte
  digest → base64url no-pad.
- Cross-language agreement proven on all 6 W-series vectors; same
  private key signs identically on Node and BouncyCastle.
- Prehash-is-load-bearing test passes both sides.

**KI-010 resolved by option B.** Node built-in `crypto` on TS;
BouncyCastle on Kotlin; `@noble/ed25519` stays scoped to
`auth/verify.ts`. Two Ed25519 paths, two protocols, no shared surface.

**US-ADD-001 §8.1 amendment** (commit `13c3a83`). Ruling: the
`com.google.*` prohibition covers Google-the-company runtime services,
not every Maven groupId. Named carve-out: `com.google.zxing:core`.
Future matching artifacts require individual review per §8.1.

**zxing dependency** (commit `4346802`).

- `com.journeyapps:zxing-android-embedded:4.3.0` pinned in
  `android/app/build.gradle.kts`.
- Transitive: `com.google.zxing:core:3.4.1` (api scope). Clean POM,
  no other deps.
- `docs/security/DEPENDENCY-EXCEPTIONS.md` created (new file),
  §2 interpretation carve-out entry recorded.

**TASK-P1-025 core crypto** (commit `42646dc`).

- `android/.../crypto/ProvisioningBundle.kt` — parses amended
  enrollment QR payload; strict schema (domain, printable-ASCII
  device_id ≤64, base64url-32 keys, no extra fields).
- `android/.../crypto/MatrixBuilder.kt` — constructs unsigned
  `{domain,matrix}` wrapper; routes through `SignedMatrix.fromJsonMap`
  for validation; sorts `permitted_contacts` for deterministic bytes.
- Tests: 16 `ProvisioningBundleTest` + 9 `MatrixBuilderTest`,
  all passing.
- TEST-PROVSCHEMA-001 reclassified as a **builder test** (the schema
  layer cannot detect a swap between two same-length base64url fields).
  Both the positive and negative builder variants pass.

**TASK-P1-025 AdminScreen UI** (commit `f605c35`).

- Provisioning section added to `AdminScreen.kt` (+168 lines).
- journeyapps ScanContract → ProvisioningBundle.parse.
- Clearance field; version field (default "1") with hint text;
  permitted_contacts multi-select over active devices excluding the
  device being provisioned.
- MatrixBuilder.build + JCS canonicalize + SHA-256 display.
- Copy-to-clipboard for wrapper and hash.
- **No signing. No QR display of output — that's TASK-P1-033.**

### Build-flavor decision

Build Master §4's "Android admin mode" means a runtime mode, not a
separate distribution artifact. The admin UI ships in the same APK as
the user client; no build flavor, no separate package. The §11
prohibition is about the provisioning private key (§3.2 keeps it off
the admin app entirely), not about shipping the UI. Decided 2026-10-14
for TASK-P1-025. If a future requirement needs distribution-level
separation, open a new task — do not re-litigate here.

### Backend token binding (commit `3d3ff60`)

- Migration `012_enrollment_tokens_bound_public_key.sql`.
- `bound_public_key BYTEA NOT NULL`, CHECK octet_length = 32.
- Sentinel 32 zero bytes for pre-existing rows; the well-formed
  base64url collision is noted in the migration comment.
- `createEnrollmentToken` validates and stores the key.
- `POST /admin/enrollment-tokens` requires it (zod regex
  `^[A-Za-z0-9_-]{43}$`); 400 on absence.
- `consumeEnrollmentToken` SELECT gains `AND bound_public_key = $2`.
  Key mismatch yields zero rows and does not mark the token consumed.
- Tests: TEST-TOKEN-BOUND-MATCH, TEST-TOKEN-SUBSTITUTION,
  TEST-TOKEN-CONCURRENT. Backend test count 175 -> 178.

### QR payload format (owner ruling, 2026-10-14)

Amended format, superseding the earlier version:

```json
{
  "domain": "umoja.enrollment-request.v1",
  "device_id": "<string, <=64 printable ASCII>",
  "pub_device_auth_key": "<base64url 32B>",
  "pub_messaging_identity_key": "<base64url 32B>",
  "pub_wipe_confirmation_key": "<base64url 32B>"
}
```

- `device_id` is device-generated (UUID v4 recommended), stored in
  DataStore, not derived from key material, public.
- Payload is NOT JCS-canonicalized and NOT signed in Phase 1.
  `domain` is documentation today; becomes load-bearing if the payload
  is ever signed by the device auth key (future hardening task).
- **Propagates to TASK-P1-019** (enrolling-device QR generator) —
  P1-019 must conform.

### Version-source ruling

Matrix `version` is admin-entered, default "1", with hint text
explaining monotonicity is device-enforced. Backend does not track a
current matrix version in Phase 1. Backend version tracking is a
future improvement, not P1-025.

### P1-025 UI verification — DONE (2026-10-15)

Manual emulator run against the amended `umoja.enrollment-request.v1`
payload, via the debug paste path (commit `44b6520`). The gate P1-025
sat on is now closed.

Verified end-to-end:

- `ProvisioningBundle.parse` accepted a synthetic 5-field payload.
- `MatrixBuilder.build` produced the wrapper.
- JCS output is correct: top-level `domain` < `matrix`; matrix keys in
  UTF-16 order; `version: 1` as bare `1` (ES6 number rule); empty array
  preserved as `[]`; all three 43-char base64url keys round-tripped.
- SHA-256 hash displayed:
  `5KRZ_e9rTv0YTxK0lXppa1eWee6JAt_-GQ1zBj--8_Q` — 43 base64url chars,
  correct length for a 32-byte digest.
- Copy buttons work for wrapper and hash.

No unit test substitutes for this. P1-025's UI is verified running,
not just compiling.

### Emulator bootstrap (2026-10-15) — operational note

The emulator was deleted and recreated during Session A troubleshooting.

- The old admin device `57ca1b67-36fb-4c04-b2fe-56a84a338b79` lost its
  private key (Android Keystore is device-local). Unrecoverable. Its
  `devices` row is a historical record; revoke it when convenient:
  `UPDATE devices SET status='revoked', revoked_at=now(), revoke_reason='emulator wiped' WHERE device_id='57ca1b67-36fb-4c04-b2fe-56a84a338b79';`
- Postgres survived the wipe. No other device rows were lost.
- A new admin was enrolled by binding a fresh enrollment token to the
  new emulator's pubkey via direct SQL — `POST /admin/enrollment-tokens`
  requires a live admin session, which we did not have.
- **Trap:** `docker compose exec postgres psql ... <<SQL ...` fails with
  `cannot attach stdin to a TTY-enabled container because stdin is not a
  terminal`. Add `-T` after `exec`: `docker compose exec -T postgres psql ...`.
  Required whenever piping a heredoc into a container.
- **`enrollment rejected` log line is permanent, not debug-only.** The
  backend logs the pubkey a device presented when enrollment fails.
  Without this, there is no way to diagnose binding mismatches. Keep it.

### Session A follow-up — enrollment.ts pubkey log (commit 7992fec)

`backend/src/routes/enrollment.ts` gained a `req.log.warn` on enrollment
rejection that prints the presented `device_public_key` and `label` beside
the error code. Applied during Session A, committed 2026-10-15.
`device_public_key` is not in the redact list (public key, not secret), so
the log prints as intended. This is the diagnostic that made binding
mismatches debuggable during the emulator bootstrap.

### WipeConfirmationKeyManager (commit 8bd4ab5, tag v0.33-wipe-key)

`android/.../crypto/WipeConfirmationKeyManager.kt` — composition wrapper
over `DeviceKeyManager` with alias `umoja.wipe.confirmation.v1`. Ed25519
keypair, distinct Keystore entry and prefs slot from the device auth key.
Public surface: `hasKey`, `ensureKeyPair`, `publicKeyBase64Url`, `sign`,
`deleteKey`. KDoc on `deleteKey` records the §3.4 single-use contract:
called by the duress-wipe flow after the wipe notification is sent,
best-effort; do not call from any other path; do not treat as
reset-and-regenerate. 7 androidTest. Prerequisite for TASK-P1-019 (the
enrolling device's QR payload includes the wipe-confirmation pubkey).

### Tor mode — worked (do not chase a phantom bug)

An early `POST /enrollment` during the bootstrap returned client-side
`network_error`. This was transient. A subsequent attempt reached the
backend over the onion:


### TASK-P1-019 — enrolling-device QR generator (commit `a4ec1f9`)

Delivered end-to-end, both halves of the ceremony now exist:

- `android/.../crypto/EnrollmentQrPayload.kt` — pure builder for the
  amended `umoja.enrollment-request.v1` payload. Manual serialization
  (not `JSONObject.toString()`) for deterministic key order across
  Android and JVM — Android's `org.json` preserves insertion order,
  the JVM test-scope artifact does not. Round-trips through
  `ProvisioningBundle.parse` as a self-check before returning.
- `android/.../crypto/DeviceIdStore.kt` — persists `device_id` (UUID v4)
  via `SecureStorage`, generate-on-first-call, never regenerated for
  the life of the entity. A wipe destroys it — that is correct.
- `android/.../ui/provisioning/EnrollmentQrScreen.kt` — renders the QR
  via `journeyapps.BarcodeEncoder`, exposes copy-to-clipboard JSON and
  inline text fallback. Reached from Settings.
- `android/.../ui/settings/SettingsScreen.kt` + `ui/navigation/MainNavigation.kt`
  — new "Enrollment QR" menu item, full-screen overlay mirroring the
  `openChat` pattern.
- `SignalIdentityStore.messagingIdentityKeyBase64Url()` — new accessor
  that strips libsignal's `0x05` type prefix so the messaging identity
  key matches the 32-byte shape the matrix and QR validators require.
  The 33-byte serialized form is preserved everywhere it already
  existed (persist, `PersistentSignalProtocolStore`); this accessor
  only adds a projection. No existing caller is affected.

**Round-trip verified on emulator (2026-10-15).** Producer JSON →
clipboard → admin paste field → parser → "Scanned device" card. All
four values preserved exactly: `device_id` `ea23e1a2-...`, and the
three public keys. Screenshot evidence captured.

**Test coverage:** `EnrollmentQrPayloadTest` — 12 JVM tests: round-trip
through parser, deterministic ordering, rejection of malformed
`device_id` and pubkeys, all-three-keys-distinct preservation.

### KI-019 (RESOLVED 2026-10-15) — two `device_id`s for one physical device

The QR payload carries a device-chosen `device_id` (from
`DeviceIdStore`, generated locally on first screen entry). The
enrollment endpoint assigns its own `device_id` (`randomUUID()` in
`consume.ts`) and inserts it into `devices`. Both identify "the same"
physical device; they diverge.

**Consequence:** the authorization matrix binds a single `device_id`.
Before TASK-P1-026 (client verification), decide which one is
authoritative. Options:
- (a) Backend accepts the QR-supplied `device_id` at enrollment.
- (b) `DeviceIdStore` reads the backend-assigned value after enrollment
  and overwrites its local copy.
- (c) Drop `device_id` from the QR payload entirely; the backend
  assigns and the device learns it post-enrollment.

**RESOLVED (2026-10-15).** Ruling: **option (a) — the backend accepts
the QR-supplied `device_id` at enrollment.** Rationale: the device
already generates it deliberately, persists it durably, and treats it
as its identity; renaming on the backend would force the device to
overwrite its own identity post-enrollment (a hostile coupling and a
bootstrapping round-trip). The QR is the natural binding point between
"a device being provisioned" and a `devices` row. `device_id` is not
a credential — the security control is the token binding on
`bound_public_key` (commit `3d3ff60`); an attacker who intercepts an
enrollment token still cannot produce the private key matching the
bound public key regardless of which `device_id` they present. Options
(b) and (c) both require a post-enrollment round-trip to convey the
assigned ID for zero security gain.

Implementation changes scoped into the `bound_public_key` wiring step
(§5 item 3):
- `backend/src/enrollment/consume.ts` — replace `randomUUID()` with
  the `device_id` from the request body.
- `backend/src/routes/enrollment.ts` — validate `device_id` on the
  same strict shape `ProvisioningBundle.kt` enforces (printable
  ASCII, ≤64, UUID v4 recommended not required); reject with 400
  before any DB write.
- Confirm `devices.device_id` unique constraint fires on collision
  (replay) — must fail closed. (It's the PRIMARY KEY; the 23505 path
  is already wired.)
- `POST /enrollment` response echoes `device_id` for client assert.
  (Field already exists; source changes from `randomUUID()` to the
  client-supplied value. No contract change.)
- Tests: TEST-ENROLL-DEVICEID-ECHO, TEST-ENROLL-DEVICEID-COLLISION.

Not a P1-019 regression — the QR round-trip that P1-019 was scoped to
prove works correctly.

### §5 item 3 — Android bound_public_key wiring + KI-019 passthrough (commit `24cf292`)

Done and verified end-to-end.

**Backend (commit `f361cb0`):**
- `backend/src/enrollment/deviceId.ts` (new): strict canonical
  hyphenated UUID schema. Extracted so the route stays a one-line
  parse and the validator is testable in isolation.
- `consume.ts`: `randomUUID()` → `input.device_id`.
- `routes/enrollment.ts`: `device_id` added to `EnrollmentBody`;
  reject with 400 `invalid_request` before any DB write; the warn
  log on the rejected path gained `device_id`.
- 14 new tests: `deviceId.test.ts` (12) plus
  TEST-ENROLL-DEVICEID-ECHO and TEST-ENROLL-DEVICEID-COLLISION.
  Backend 178 → 192.

**Android (commit `24cf292`):**
- `AdminApi.CreateTokenRequest` gains `boundPublicKey`; wire field
  `bound_public_key`.
- `EnrollmentRequest` gains `deviceId`; wire field `device_id`.
  Threaded from `DeviceIdStore.getOrCreate()` in
  `MainActivity.enrollDevice`.
- `AdminScreen`: strict A1. Scanned-device card gains the inline
  "Create enrollment token for this device" button (role hardcoded
  `"user"`, `boundPublicKey` from the bundle) and a "Copy token"
  affordance. Standalone "Create enrollment token" section deleted.
- `createdToken` state hoisted from a `key(b.deviceId)`-scoped
  `remember` to screen scope. The `key`-scoped version did not
  recompose on state write (observed on emulator: status message
  rendered, token text did not).

**Strict A1 rationale.** Removing the role picker converts a
privilege-escalation attack from "stolen admin phone + one tap"
into "stolen admin phone + backend SQL access." The offline signer
(P1-033) already keeps the provisioning private key off the admin
app; strict A1 closes the adjacent gap where the app could mint
non-`user` tokens. It removes the UI's ability to create second-
admin tokens — recorded as a follow-up (§5 item 9).

**Verification (manual, 2026-10-15).** Synthetic payload
(`device_id = 1c364f88-ab60-4f02-8b27-36f7f11568e8`, generated at
`/tmp/a1-payload.json`) loaded into the admin debug paste field.
Token created via the inline button; psql confirmed `role = user`
and `bound_public_key` byte-for-byte matching the payload's
`pub_device_auth_key`. curl `POST /enrollment` with the payload's
`device_id` returned the same value in the response body; `devices`
row carried it with `status = active`; `enrollment_tokens.used_by_
device_id` referenced it. Screenshots of the card, the token row,
and the device row captured.

**Not verified by this task:** the Android client's `device_id`
transmission at enrollment time is compile-verified only. The full
client-side round-trip is blocked by KI-020 (below).

### Session C — TASK-P1-030 3a landed (2026-10-16)

Backend tracks current matrix version per org. Closes KI-018 (hard
prerequisite for 030b). Five commits:

- `6013077` — 3a backend: migration 013 (`org_matrix_versions`),
  `matrixVersions.ts` (`assertMatrixVersion`, `getMatrixVersion`),
  `GET`/`POST /admin/matrix-version`, 6 service tests
- `c79d7f8` — registry v0.5: P1-030 decomposed into 030a–030f
- `64f4494` — pool hygiene: 5 conns/worker on `NODE_ENV=test`
  (precautionary; see KI-022)
- `4e6e096` — the actual KI-022 fix (unique org in
  `matrix-version.test.ts`)
- `8adde6b` — POOLMAX debug removal **and** the 4 matrix-version
  route tests (`admin.test.ts`). See commit-message caveat.

**Commit-message caveat.** `8adde6b`'s subject describes only the
debug-line removal, but the same commit contains the 4 route tests
(`TEST-MATRIX-VERSION-ROUTE-USER-FORBIDDEN`, `-VALIDATION`, `-OK`,
`-REJECT-LOWER`) because `admin.test.ts` was already staged when the
commit ran. Content is correct; message is incomplete. If searching
for route tests via `git log`, search the handoff, not git log.

**Phase 1 framing (load-bearing).** 3a's endpoint is admin-error-
catching, not adversary-catching. Both the version and (later) the
floor come from the same party. Purpose is cross-session and cross-
admin audit. Anti-rollback is client-side (P1-026). Full framing text
is in `docs/US-TASK-P1-001.md` v0.5 §B TASK-P1-030 and in the KDoc
of `backend/src/admin/matrixVersions.ts`.

**Honest note on session cost.** Most of Session C went to
diagnosing a bug introduced *in this session's own test file*:
`matrix-version.test.ts` used `TEST_ORG_ID = '...088'`, the same
value `auth.test.ts` uses, and its `beforeEach` deleted devices by
`org_id`. In parallel runs it deleted auth's devices mid-test.
Symptom was flaky 500s and 401s in `auth.test.ts`, appearing only
under full-suite load. Diagnosed by pair-testing: `auth + enrollment`
passes, `auth + admin` passes, `auth + matrix-version` fails 5/17.
Fixed by changing to `...0a1` / `...0a2`. KI-022 recorded and
resolved.

**Environment gaps hit during the session** (both now in §7):
- Migration 013 applied cleanly to `umoja_test` (auto-rebuilt by
  `npm test`) but not to dev `umoja` until `npm run migrate` ran.
- The dev backend container was stale (KI-002 re-hit): route returned
  404 until `docker compose up -d --build backend`.

**Verification.** Typecheck clean. Full suite 202/202 (15 files).
`auth + matrix-version` pair 17/17. `matrix-version.test.ts` alone
6/6. `admin.test.ts` alone 17/17. Unauthenticated curl to
`/admin/matrix-version` returns 401 (route live, correctly gated).

### Session D — TASK-P1-030 3b and 3c landed (2026-10-16)

Server-side floor plumbing complete. Two commits:

- `3dded33` — 030b: migration 014
  (`014_enrollment_tokens_matrix_version_floor.sql` — note: longer
  filename than the plan's `014_enrollment_matrix_version_floor.sql`,
  already applied to both DBs, do not rename) adds nullable INTEGER
  column with `CHECK (NULL OR >= 1)`. `createEnrollmentToken` reads
  `org_matrix_versions.current_version` inside its existing
  transaction and stamps on INSERT. `CreateTokenResult`,
  `ListTokenResult`, and the `enrollment_token.created` audit payload
  all carry the floor. 5 route-level tests in `admin.test.ts`.
- `420d71f` — 030c: `consumeEnrollmentToken`'s SELECT gains
  `enrollment_matrix_version_floor`; `EnrollmentResult` surfaces it.
  Route's `reply.send(result)` picks it up — no `enrollment.ts`
  change. 3 tests in `enrollment.test.ts`.

**Floor semantics: stamped at issuance, frozen.** The floor is read
from the token row at enrollment time, not re-read from
`org_matrix_versions`. If the org asserted v5 at issuance and moved to
v7 before the device actually enrolls, the token still carries
floor=5. `TEST-TOKEN-FLOOR-FROZEN` (030b) proves stamping doesn't move
with org state; `TEST-ENROLL-FLOOR-FROZEN` (030c) proves consumption
returns the stamped value, not the current one. Together they pin the
§3.7 step 1 reading of "the current matrix version at the time of
token issuance."

**Server-side flow now end-to-end:**
1. `POST /admin/matrix-version` → sets `org_matrix_versions.current_version`
2. `POST /admin/enrollment-tokens` → reads current version, stamps floor
3. `POST /enrollment` → returns token's stamped floor to client

Client receives the floor and stores it. Nothing on the client reads
it until 030d.

**One traceback worth recording.** During 030c's `consume.ts` edit,
the read-back assert expected 3 occurrences of
`enrollment_matrix_version_floor`; actual was 4. My assert was
miscalibrated — the return expression contains both the object key
*and* the property reference, so 4 is correct. The write had already
happened (`p.write_text(src)` precedes the assert); the traceback
fired on verification, not the edit. File was correct, tests passed.
New §7 convention covers this class of confusion.

**Migration 014 got the longer filename.** The plan called for
`014_enrollment_matrix_version_floor.sql`; the file landed as
`014_enrollment_tokens_matrix_version_floor.sql`. This is now baked
into `schema_migrations` on both `umoja_test` and `umoja`. Do not
rename — `runMigrations` would see the shorter name as unapplied and
fail re-adding the column.

**Verification.** Typecheck clean. Full suite 210/210 (15 files) on
two consecutive runs. `enrollment.test.ts` 14/14 (11 existing + 3
new), `admin.test.ts` 22/22 (17 existing + 5 new). Migration 014
applied to dev DB; container rebuilt; `curl /admin/matrix-version`
returns 401.

### Session E — TASK-P1-030 3d landed (2026-10-16)

Floor-aware `MatrixStore.accept` on Android. Closes 030c's client
half (store the floor from the enrollment response) and 030d
(floor-aware accept). One commit:

- `71e06c7` — 030c client half + 030d. `MatrixStore` gains
  `setEnrollmentFloor(Int?)`, `enrollmentFloor()`, and
  `KEY_ENROLLMENT_FLOOR` (prefs key). `accept()` branches:
  first-accept consults floor (`version < floor` →
  `Rejected("below_floor")`); subsequent accepts use
  `highestSeenVersion` only. `clear()` removes both keys.
  `EnrollmentResponse` gains `enrollmentMatrixVersionFloor: Int?`;
  `MainActivity.enrollDevice` calls `setEnrollmentFloor` after
  storing identity. 5 floor tests appended to `MatrixStoreTest`.

**Design: floor is store-owned state, not an `accept()` parameter.**
The P1-026 KDoc is explicit that anti-rollback lives in
`MatrixStore.accept` so callers cannot bypass the policy by calling
`MatrixVerifier` directly. A `floor` argument on `accept()` would
reopen that bypass. `setEnrollmentFloor` is the injection point,
called once by the enrollment flow with the value from
`POST /enrollment`.

**Floor semantics.** First-accept-only. Once any matrix is stored,
`highestSeenVersion` IS the floor — a new matrix's version must
strictly exceed it. The enrollment floor is never consulted on
subsequent accepts. `TEST-MATRIX-FLOOR-NOT-CONSULTED-AFTER-FIRST-ACCEPT`
proves this by setting floor=999 after a v5 accept and successfully
accepting v6.

**MatrixStoreTest pre-existed.** It was created in P1-026 with 9
tests (accept/load round-trip, tampered reject, wrong-key reject,
rollback, clear, empty state). Session E extended it to 14. The
handoff §2 "110 JVM" count already included the 9 — no correction.

**Traceback in Block 1 was calibration error again.** The read-back
assert on `MatrixStore.kt` expected 4 `KEY_ENROLLMENT_FLOOR`
occurrences; actual was 5 (`const val` + two branches in
`setEnrollmentFloor` + `enrollmentFloor()` + `clear()`). Same class
as Session D's `consume.ts` — multi-branch methods and multiple
references to the same constant defeat a "one per method" estimate.
Write count from actual code. §7 bullet refined.

**Verification.** Android JVM 110 → 115 (aggregate from XML). The
scoped `--tests "MatrixStoreTest"` run printed `BUILD SUCCESSFUL`
with no test-count line — the gradle scoping trap already in §7;
aggregate from `TEST-*.xml` is authoritative. Backend unchanged
at 210.

**Next: 030e is BLOCKED on a channel decision.** Peer
identity-change notification + ack state. Options:
- **A: Backend envelopes** (`/envelopes`). Device sends the
  notification through the existing ciphertext-routing path; peers
  receive it in their pending queue, acknowledge via another
  envelope. Server-blind is preserved — backend routes ciphertext,
  never learns key material. Reuses existing infrastructure.
  **Recommended.**
- **B: Backend-pushed over WS.** Backend learns about key changes
  and pushes them. **Violates server-blind.** Rejected on
  architecture grounds.
- **C: Out-of-band via admin.** Admin provisions the notification
  via signed matrix or QR. Works but requires admin online at
  replacement time; defeats the automated-ack intent of 030e.

Per Build Master §0, escalated rather than guessed. Next session
opens on this ruling.

### Session F — TASK-P1-030 030e-a landed (2026-10-17)

Replacement-notice schema + signing. Two commits:

- `d28c631` — TS side. `backend/src/crypto/replacement-notice.ts`
  (validate, digest, sign, verify); `canonical-replacement-notice-
  test-vectors.json` (R-001/002/003 populated); generator refactored
  to process both vector files; 7 tests. Also fixes a latent
  Buffer-key verification bug in both `replacement-notice.ts` and
  `matrix-sign.ts`.
- `f257e03` — Kotlin side. `ReplacementNotice.kt`,
  `ReplacementNoticeSigner.kt`, `ReplacementNoticeTest.kt` (7 tests
  incl. R-001 cross-language proof).

**Design ruling: separate signed artifact, not a matrix field.** In
Session E the assistant proposed embedding `contact_continuity[]` in
the matrix schema. On opening Session F that design was rejected
before coding. Three reasons: (a) the registry says "new protocol
message," not "matrix field"; (b) matrix is authorization
(machine-verified), notice is continuity (human-confirmed) —
semantically distinct claims, different trust flows; (c) embedding
would have forced conditional serialization to preserve W-001..W-006
canonical bytes, optimizing for test stability rather than
correctness. The separate artifact leaves the matrix schema untouched,
W-001..W-006 unchanged, and each claim's trust flow independent.

Signed unit (4-space indented, not a formal schema):

    {"domain":"umoja.replacement-notice.v1","notice":{
      "from_device_id":"...","from_device_auth_key":"<b64u-32>",
      "to_device_id":"...","to_device_auth_key":"<b64u-32>",
      "issued_at":"..."}}

Same protocol as the matrix (§3.8): JCS canonicalize → SHA-256 →
Ed25519 over the digest → base64url. R-001 vector proves both
languages produce byte-identical canonical bytes, digest, and
signature for the same input.

**Two bugs caught during the session, both worth recording:**

1. **`format: 'raw'` is not accepted by `createPublicKey` for Ed25519
   in this Node version.** `matrix-sign.ts` had a plain-object cast
   `as unknown as KeyObject` passed to `crypto.verify` — a type-
   system lie that would have failed at runtime. Matrix tests never
   exercised the Buffer path (they use KeyObjects from generated
   keypairs), so the lie survived. The new R-001 test exercised it
   and failed. Fix: SPKI DER wrapping (`ED25519_SPKI_PREFIX` + raw
   32 bytes → DER → createPublicKey). Same pattern
   `MatrixSigner.SPKI_PREFIX` already uses in Kotlin. Applied to both
   files. Matrix 22/22 still passes.

2. **Missed rename in `ReplacementNotice.kt`.** Declared
   `RN_ISO8601_UTC_RE` but the call site said `ISO8601_UTC_RE`,
   resolving to `AuthorizationMatrix.kt`'s file-private val →
   compile error. Caught by an ad-hoc "absence of stale pattern"
   regex added to the read-back. The presence-only read-back had
   passed. §7 bullet updated.

**Next: 030e-b** — backend `/identity-change-notices` +
`/identity-change-acks` endpoints + `identity_change_notices` /
`identity_change_acks` tables. Stores and retrieves signed artifacts;
never decrypts, never signs. Independent of any client work. Can be
done in one session.

### Session G — TASK-P1-030 030e-b ADR + migration landed (2026-10-17)

Design-first session: ADR before any code, migration verified against
the ADR, no service or route code yet. Two commits:

- `21677a9` — `docs/architecture/ADR-IDENTITY-CHANGE-001.md` (401
  lines). Resolves the three 030e-b design questions recorded end of
  Session F: (1) ack domain is `umoja.identity-change-ack.v1`,
  distinct from the replacement-notice; (2) backend DOES verify acks
  server-side using `devices.public_key` from enrollment, reusing
  `@noble/ed25519.verifyAsync` — the same primitive
  `verifyChallenge` in `auth/verify.ts` already uses; (3) peer
  discovery is Option C — backend returns all org notices, client
  filters by its own accepted matrix.
- `00f31df` — `backend/migrations/015_identity_change.sql` (69 lines).
  `identity_change_notices` + `identity_change_acks` per ADR §6. PK
  `(notice_hash, acking_device_id)` for replay idempotence. BYTEA
  canonical_bytes (not JSONB — byte identity with the signed artifact
  is the trust property).

**Two corrections landed during Session G.** Both found by reading
`auth/verify.ts` and `migrations/002_devices.sql` before writing the
ADR, rather than assuming:

1. **"Backend has not verified a device-signed artifact before"** was
   wrong in Session F's note. `POST /auth/verify` does exactly that —
   device signs a challenge with its Ed25519 device auth key, backend
   verifies against `devices.public_key`. The ack verification reuses
   this exact pattern, not a new trust boundary.
2. **"Backend can filter GET /identity-change-notices by
   permitted_contacts"** was wrong in Session F's note. The backend
   never stores the matrix — matrix verification is client-side
   (P1-026). Peer discovery had to be a genuine design decision, not
   "reuse existing state." ADR §5 resolves it as Option C, with the
   alternative rejections (A: backend stores matrices; B: client
   POSTs contact set) documented and rejected with named reasoning.

Both corrections are recorded here because the next session should
see the delta between Session F's guess and the actual code. Reading
before writing the ADR cost 15 minutes; discovering the wrong
assumption during implementation would have cost a session.

**Deliberate asymmetric trust boundaries (ADR §4).** Notices are a
relay — backend stores verbatim, does not verify provisioning
signature, because that key is client-pinned only (server-blind per
ADR-PROVISIONING-001 §2 Q3). Acks are verified — backend has the
device auth public key. The asymmetry is dictated by which keys the
backend holds, not by any design preference. Both defenses at the
correct layer.

**Schema additions beyond ADR §6 sketch.** `signature_base64url`
length CHECK (86 chars = 64 bytes Ed25519 base64url no-pad),
defense-in-depth beyond route validation, matching the pattern of
`audit_events.event_hash` and `enrollment_tokens.token_hash`. Cross-
org consistency (from_device, to_device, org_id all in the same org)
is route-validated not DB-constrained, matching the
`enrollment_tokens.org_id` pattern (bare UUID, no orgs table) —
documented in the migration comment so a future reviewer knows it is
intentional.

**Verification.** Full suite 217/217 (global-setup applies 015 in
the test DB; no test references the new tables yet, but SQL is
proven). Dev DB migrated. Both tables verified via \d — constraints,
indexes, FKs all present as designed.

**Next: 030e-b service modules + routes + tests.** Per ADR §7 four
endpoints and §8 seventeen named failure-mode tests. Route-level
tests in `backend/test/identity-change.test.ts`, `TEST_ORG_ID =
'00000000-0000-0000-0000-0000000000b1'` (per §7 convention: distinct
from existing org IDs — currently 011, 044, 055, 066, 077, 088,
099, 0a1, 0a2). File cleanup order in afterAll:
`identity_change_acks` → `identity_change_notices` → `devices` (FK
dependencies).

### Session H — TASK-P1-030 030e-b implementation + tests landed (2026-10-17)

030e-b DONE. Four commits total across Sessions G and H:

- `21677a9` (G) — ADR-IDENTITY-CHANGE-001 v0.1
- `00f31df` (G) — migration 015
- `d8b2cfc` (H) — services + routes + wiring, 7 validator tests
  (backend 217 → 224)
- `b26913a` (H) — 17 route tests, ADR v0.3 (backend 224 → 241)

Plus two pre-code design commits:
- `1c217e1` — ADR v0.2: §7 step 3 unsatisfiable fix
  (`ack.notice_hash === SHA-256(canonical_utf8 bytes)` compared a
  field against the hash of the bytes containing it);
  `TEST-ACK-HASH-MISMATCH` → `TEST-ACK-INVALID-DECISION`.
- `e6e3ecb` — handoff §7 read-back convention replaced with
  git-diff rule (deletes two accumulated caveat bullets).

**Prehash vs. direct-message protocol — the biggest catch.** ADR §3
specifies Ed25519 over SHA-256 of JCS-canonical bytes (prehash). This
diverges from `verifyChallenge` in `auth/verify.ts`, which signs the
message directly with no prehash. The implementation session caught
this by reading the ADR before writing the ack verifier — mirroring
`verifyChallenge` as "reuse the existing primitive" would have
produced a 100%-failure ack suite that looked like a cryptography
bug. Recorded in ADR §10 v0.2, ack service KDoc, and validator digest
KDoc.

**Two digest contracts, deliberately.** `replacementNoticeDigest`
re-canonicalizes (client verifies a relayed artifact; JSON-equivalence
is the contract). `identityChangeAckDigest` takes raw bytes (backend
stores verbatim then verifies byte-identity — migration 015's BYTEA
property). A reordering attacker who submits JSON-equivalent-but-
differently-serialized bytes fails at insert with the raw-byte digest;
with re-canonicalization they would poison the store with a
self-inconsistent row. Not unified.

**Typed `tx.query<T>()` and `noUncheckedIndexedAccess`.** 9 typecheck
errors after initial write — `rows[0]` is `T | undefined` and the
compiler cannot narrow through `rowCount !== 1`. Fix patterns applied:
guard-then-use (narrow to local for multi-access) and RETURNING `!`
for single guaranteed rows. Matches `matrixVersions.ts` Session C
precedent. Worth noting: `verifyChallenge` in `auth/verify.ts` uses
untyped `tx.query()` → `any` → hides this class. Typed parameters
surface it, which is a win. §7 addition for next session.

**ADR v0.3 — TEST-ACK-REVOKED-DEVICE layer correction.** §8 specified
403 `device_revoked`; reality is 401 `unauthorized` because
`lookupSession` (auth/sessions.ts) filters by device status and blocks
at the middleware. The service's `device_revoked` branch is real
defense-in-depth but unreachable via HTTP in normal operation — fires
only in the race window (session valid at middleware, device revoked
before service query). Test asserts 401 with layer KDoc; §10 v0.3
records the reasoning. Count unchanged (17).

**Pattern: third consecutive session where pre-code review or test
layer caught a real defect before production.** Session F caught the
ADR §7 step 3 unsatisfiable comparison, Session G caught two wrong
assumptions in the design note by reading code first, Session H caught
the prehash-vs-direct divergence and the TEST-ACK-REVOKED-DEVICE layer
assumption. Not a coincidence — the read-before-write and
test-as-acceptance-gate disciplines are working.

**Next: 030e-c** — Android `ReplacementNoticeStore` + block-send on
unacked notice. First client work in the identity-change flow. Per
registry v0.5:
> P1-030c — `MatrixStore`-adjacent: `ReplacementNoticeStore` on the
> client, detects unacked notices affecting accepted matrices, blocks
> outgoing sends to `to_device_id` until acked.

Design questions for 030e-c opening (not decided, recorded here):
- Where does "blocked send" surface in the UI? Toast, dialog,
  inline-on-chat-screen, all three?
- Does the block lift automatically when the sender learns the peer
  acked (polling, WS, both), or only on local state change?
- Does a rejected ack count as "acked" for send-unblock, or does
  rejection require admin intervention before any send proceeds?

### Session I — TASK-P1-030 030e-c 3a landed (2026-10-17)

030e-c scoped as four sub-tasks (3a schema+signer, 3b verifier+store,
3c transport+polling, 3d UI). 3a done end-to-end. Three commits:

- `a178e83` — `IdentityChangeAck.kt` + `IdentityChangeAckTest.kt`.
  Kotlin schema for `umoja.identity-change-ack.v1`. Mirrors
  `ReplacementNotice.kt`: `data class` inner + wrapper, companion
  `const val DOMAIN`, `require()` → `IllegalArgumentException` (no
  custom exception class — Kotlin crypto convention), `IC_` prefix on
  both declarations and call sites per §7. No extra-field rejection
  (signed artifacts — extras fail peer signature check anyway;
  differs from `ProvisioningBundle.kt`'s pre-signing rejection, which
  is correct). 9 schema tests.
- `ed271ac` — `IdentityChangeAckSigner.kt` +
  `IdentityChangeAckSignerTest.kt` + `canonical-identity-change-ack-
  test-vectors.json` (A-001) + TS `identity-change-ack.test.ts` A-001
  cross-language test. Generator extended to process the third
  vector file. 3 Kotlin signer tests + 1 TS A-001 test. Prehash
  protocol (§3), not direct-message; reuses
  `MatrixSigner.matrixDigestRaw` for SHA-256.
- `36f9a94` — timestamp refresh in matrix + notice vector files
  (`generated_at` only; `expected_*` byte-identical).

**Q1–Q3 rulings (recorded for 3b–3d implementation).**

- **Q1 — Where does "blocked send" surface?** Inline banner on chat
  screen, tap-to-expand detail dialog showing full notice (from/to
  device IDs, `issued_at`, canonical hash, verify signature) with
  Acknowledge/Reject. Toast is wrong (transient state, not event);
  dialog-only is wrong (dismissible, state disappears). Banner stays
  until local ack stored.
- **Q2 — How does the block lift?** Local ack only. "Until acked" in
  the registry means the sender's ack — the sender must consciously
  acknowledge the replacement, not depend on peer timing. Discovery
  is separate: poll `GET /identity-change-notices` on app foreground
  and chat-open, filter locally by `permitted_contacts` (ADR §5
  Option C). WS push for identity-change is a follow-up, not 030e-c.
  `recordNotice` must be idempotent with respect to already-acked
  notices — the same `notice_hash` arriving in a later poll returns
  current local state (Acked/Rejected) without re-prompting. Mirrors
  backend PK `(notice_hash, acking_device_id)`.
- **Q3 — Does rejection unblock?** No. Rejection blocks permanently
  for that specific `notice_hash`. Recovery is a new notice from the
  admin (new `issued_at`, new hash); the rejected ack is immutable
  once stored. Walked three alternatives before concluding this is
  right: unblock-on-reject is wrong (peer said "I don't trust this
  continuity"); block-forever-admin-without-new-notice is
  unrecoverable; block-until-permitted_contacts-changes has the
  paradox that `to_device_id` IS in `permitted_contacts` at the
  moment of replacement. Immutable-ack + new-notice-recovery avoids
  all three. Banner wording: "You rejected the replacement of
  device X. Sending is blocked. Contact your admin to resolve."
  No UI affordance to undo a rejection.

**Process note — placeholder overwrite.** During Block 6 of commit 2
(the Kotlin signer heredoc), I wrote a placeholder `... (Block 6
content from prior message, unchanged)` instead of the literal file
content. The heredoc executed, overwriting the 74-line signer with
one line of placeholder text. Caught immediately by the next
diagnostic (`wc -l` = 1, `git status` showing the file as ` M`).
Restored via `git checkout HEAD --` from the just-pushed `ed271ac`.
Zero data loss, zero downstream impact. **Lesson:** every heredoc in
an edit script is literal content. Placeholders are never typed
literally — this is already §7 ("Placeholders like `<paste content
here>` are never typed literally"), violated by my own output.
Worth re-reading before each multi-block message.

**Bug caught by type system — raw-bytes digest.** First TS A-001 test
draft called `identityChangeAckDigest(validated)` (the parsed
object) instead of `identityChangeAckDigest(canonicalBuf)` (raw
bytes). Typecheck caught both call sites immediately:
`identityChangeAckDigest` accepts `Buffer | string`, not the wrapper.
This is exactly the design: adding a `SignedIdentityChangeAck`
convenience overload would silently re-introduce re-canonicalization
(the vulnerability the raw-bytes contract exists to prevent).
Typecheck is the design working, not a nuisance.

**Next: 030e-c 3b** — `ReplacementNoticeVerifier.kt` +
`ReplacementNoticeStore.kt` + tests. Verifier first (client-side
signature check of incoming notice against
`ProvisioningKeys.CURRENT_PROVISIONING_PUBKEY_B64U` — separate from
the signer, same separation logic as `MatrixVerifier.kt` vs
`MatrixSigner.kt`). Store after: SecureStorage-backed via
`KeyValueStore`, public surface `recordNotice` / `pendingNotices` /
`ack` / `blockStateFor(toDeviceId)`. Store's `ack` writes the ack
through `IdentityChangeAckSigner` and POSTs via
`transport/IdentityChangeApi.kt` (new, `ContactsApi` shape).
Recovery from rejected ack: new notice from admin.

Three files to read at 3b opening, not guessed:
- `android/.../crypto/MatrixStore.kt` — envelope shape, SecureStorage
  constructor signature, KeyValueStore usage
- `android/.../crypto/MatrixVerifier.kt` — the verifier pattern
  (`Set<PublicKey>` signature)
- `android/.../transport/ContactsApi.kt` — the HTTP-client pattern for
  `IdentityChangeApi.kt` to mirror

### Session J — TASK-P1-030 030e-c 3b landed (2026-10-17)

030e-c 3b DONE end-to-end. Five commits:

- `e905426` — `ReplacementNoticeVerifier.kt` +
  `ReplacementNoticeVerifierTest.kt`. Client-side signature check of
  an incoming notice against `Set<PublicKey>` (Phase 1: singleton from
  `ProvisioningKeys`). Mirrors `MatrixVerifier.verify` exactly: raw
  canonical bytes, fails closed on empty set, stateless, delegates the
  Ed25519 primitive to `MatrixSigner.verifyRaw`. 6 tests.
- `39898ad` — `IdentityChangeAckSigner.signWithDeviceKey` +
  `IdentityChangeAckSignerTest` additions. **Production-path gap
  fix.** `sign(signed, privateKey)` is unusable in production: the
  device auth key is Keystore-backed and non-exportable. The new entry
  point takes `(ByteArray) -> ByteArray` — production wires
  `deviceKeyManager.sign(digest)`, tests wire a BouncyCastle lambda.
  Two entry points, two custody models, no convenience overload hiding
  the constraint. 3 tests.
- `031a0e5` — refactor: extract `jsonObjectToPlainMap` /
  `jsonValueToPlain` from four private copies
  (`MatrixStore`, `MatrixStoreTest`, `ReplacementNoticeTest`,
  `IdentityChangeAckSignerTest`) into `CryptoJsonHelpers.kt`
  (top-level functions). Refactor-only — 143 → 143 test count
  unchanged; the extraction touches no behavior.
- `dde60f2` — `IdentityChangeApi.kt`. Wraps
  `GET /identity-change-notices` and `POST /identity-change-acks`.
  Error taxonomy mirrors `AdminApi` / `ContactsApi`
  (`network_error` / `{error_from_json}` / `invalid_response`).
  Deliberately omitted: `POST /identity-change-notices` (admin-only,
  no consumer) and `GET /identity-change-acks/:notice_hash` (peer-ack
  visibility, 030e-d). 0 tests — exercised in `f747e37`'s store tests
  via mocked HttpClient.
- `f747e37` — `ReplacementNoticeStore.kt` +
  `ReplacementNoticeStoreTest.kt`. The client-side core: verify
  on write, trust on read; `recordNotice` / `pendingNotices` /
  `ack` / `markAcked` / `blockStateFor` / `clear`. 14 tests.

**Design decisions recorded in `f747e37`** (for 030e-d's reference):

- Constructor: `(KeyValueStore, signingFn: (ByteArray) -> ByteArray,
  ackingDeviceId: String)`. `ackingDeviceId` in the constructor (not
  per-call) prevents accidentally signing an ack for the wrong device.
  Production call site wires `DeviceIdStore.getOrCreate()` and a
  lambda `{ digest -> deviceKeyManager.sign(digest) }`.
- `ack()` returns `SignedAck(wrapper, canonicalUtf8, signatureBase64url)`
  without persisting. `markAcked()` persists only after the caller's
  HTTP POST succeeds. Crash between POST and `markAcked` recovers on
  re-ack — backend PK `(notice_hash, acking_device_id)` is
  idempotent. This is the Q2 (local-ack-unblock) contract at the store
  level.
- `blockStateFor(toDeviceId)` returns the newest notice's state for
  that device. Unblocked if no notice or newest accepted; Blocked
  (`PENDING` / `REJECTED`) otherwise. Implements Q3 (rejection blocks
  permanently for that notice hash; new notice supersedes).
- Single JSON envelope under `identity_change.notices`. `KeyValueStore`
  has no `allKeys()`; per-notice keys would need an interface change.
  Fine for Phase 1 volumes.
- Verify on write, trust on read. `recordNotice` verifies the
  signature against `trustedKeys` before parsing; `pendingNotices` /
  `blockStateFor` do not re-verify. Mirrors `MatrixStore.accept` vs
  `MatrixStore.load`.

**Count discrepancy in `f747e37`'s commit message.** The message says
`Android JVM 143 → 156`. Actual was `143 → 157` (14 store tests, not
13 — miscounted `TEST-NOTICE-STORE-CLEAR` during the tally). Fifth
consecutive session of exact-count miscalibration. Per §7's current
rule, `git diff` and test-run output are authoritative; both confirm
157. Not amended (pushed-commit convention); not fixed by follow-up
(two-commit noise for a one-digit difference). Handoff, §2, and
verified-state all show **157**. `git log` shows 156 in `f747e37`
only — do not trust commit messages for test counts.

**Process note — placeholder-overwrite postmortem widened.** Session
I's placeholder-overwrite in the Kotlin signer heredoc (`... (Block 6
content from prior message, unchanged)` executed literally, overwrote
the 74-line signer with one line) was a distinct class: my *output*
contained the placeholder, not the edit script. Session J did not
reproduce it — every heredoc in every block contained literal content.
The §7 rule ("placeholders are never typed literally") covers both
cases; re-reading before sending is the discipline.

**Next: 030e-c 3d** — UI integration. The store's contract
(`pendingNotices()`, `blockStateFor(toDeviceId)`, `ack()`,
`markAcked()`) is the surface 3d consumes. Remaining pieces:

- Read `android/.../ui/chat/ChatScreen.kt` (not yet read in any
  session) — the send-path hook and where the banner renders.
- Q1 ruling: inline banner on chat screen, tap-to-expand detail dialog
  showing full notice (from/to device IDs, `issued_at`, canonical
  hash, verify signature) with Acknowledge/Reject. Toast is wrong
  (transient, state is persistent); dialog-only is wrong (dismissible,
  state disappears). Banner stays until local ack stored.
- Q2 ruling: discovery = poll `GET /identity-change-notices` on app
  foreground and chat-open, filter locally by `permitted_contacts`
  (ADR §5 Option C). WS push deferred. Unblock = local ack only;
  does not depend on peer timing.
- Q3 ruling: rejection blocks permanently for that `notice_hash`.
  Banner wording: "You rejected the replacement of device X. Sending
  is blocked. Contact your admin to resolve." No UI affordance to
  undo. Recovery is a new notice from the admin.

3d wiring needs three production dependencies the store does not
supply: a `signingFn` (from `DeviceKeyManager`), a `sessionToken` (from
`SecureStorage` / `SessionManager`), and a polling trigger (foreground
+ chat-open). All three are established patterns elsewhere in the app;
3d reads them rather than inventing.

### Session K — TASK-P1-030 030e-c 3d-1 landed (2026-10-17)

030e-c 3d-1 DONE. One commit:

- `eea1af7` — `IdentityChangeController.kt` +
  `IdentityChangeControllerTest.kt` (12 JVM tests), plus
  `ReplacementNoticeStore.allNotices()` extension. Orchestration layer
  between `IdentityChangeApi` and `ReplacementNoticeStore`. The UI
  drives `refresh()` / `ackAndPost()` and reads `version` + `gateFor()`;
  it never calls the API or store directly.

**Design decisions recorded (for 3d-2 / 3d-3's reference):**

- **`version: StateFlow<Long>` is a write-notification, not a data
  cache.** UI collects via `collectAsState`, re-derives gate state with
  `remember(version, peerId)`. Store reads are cheap (encrypted prefs);
  caching a `StateFlow<List<StoredNotice>>` would invite drift from the
  store's truth. Any successful write path (refresh completion,
  ack-post completion) bumps version. This is the seam that makes
  polling and chat-open agree — a foreground poll from `AppRoot` while
  chat is open updates the store and bumps version, and the open chat
  screen re-derives gate state without its own `LaunchedEffect` firing.
- **`gateFor(peerId)` returns `GateState.Blocked(reason, notice)`** —
  the `StoredNotice` alongside the reason, not just the reason. The UI
  needs the notice to render "device X was replaced by device Y" in
  the banner and to populate the detail dialog (from/to IDs,
  `issued_at`, `notice_hash`, and the verify-signature affordance if
  the dialog shows it). `GateState` is deliberately a distinct type
  from the store's `BlockState` — two `BlockState`s in the same package
  would invite confusion.
- **`ackAndPost` order: sign → POST → markAcked.** The order is
  load-bearing. `store.ack()` signs without persisting; `postAck()`
  posts to the API; `store.markAcked()` persists only on POST success.
  Crash between POST and `markAcked` recovers on retry — backend PK
  `(notice_hash, acking_device_id)` is idempotent, so a second POST
  returns 201 with the same `ack_hash`. This is the Q2 contract: local
  state follows confirmed delivery, never precedes it.
- **API injected as two lambdas** (`listNotices`, `postAck`), not a
  concrete `IdentityChangeApi`. Production wires method references;
  tests wire lambdas. Same pattern as `signingFn` in
  `ReplacementNoticeStore`. Avoids extracting an interface from a
  just-shipped final class for testability.

**Store extension — `allNotices()`.** `ReplacementNoticeStore`
(f747e37) exposed `pendingNotices()` (PENDING only). The controller's
`gateFor()` needs rejected and accepted notices too — a rejected
notice that isn't in `pendingNotices()` would be invisible, and
`gateFor` would return `Unblocked` instead of `Blocked(REJECTED)`. The
store's own `blockStateFor()` uses the private `loadAll()` and
therefore does not have the gap; the public surface did not expose it.
`allNotices()` is a one-line delegation to `loadAll()`, with a KDoc
note on why it exists and a note that trust is unchanged (notices
were verified at `recordNotice` time, not re-verified on read).

**Hidden bug the test masked.** `gateFor unblocked after acceptance`
was passing before the fix — but for the wrong reason. The pre-fix
`gateFor` read `pendingNotices()`; after acceptance the store's pending
list was empty (accepted notice excluded), so `gateFor` returned
`Unblocked` coincidentally. After the fix, `allNotices()` includes the
accepted notice, its state is `ACKED_ACCEPT`, and the same test passes
via the correct branch. The assertion was right; the code path was
wrong. Worth remembering: a passing test is not a proof the path it
exercises is correct.

**Process note — three compile round-trips before this commit.** All
caught before push, none reached the repo, but the pattern is worth
recording:
1. Test file wrote to `android/app/src/main/java/...` (main source
   set) instead of `test/java/...`. Test-only dependencies (JUnit)
   are not on the main source set's classpath, so the compile failed
   with "Unresolved reference 'Test'" and similar.
2. `IdentityChangeController.kt` contained an import of
   `ReplacementNoticeStore.GateReasonAlias` — a phantom name from a
   draft that pivoted to `GateState` mid-write. The import was never
   removed.
3. `InMemoryStore` in `IdentityChangeControllerTest.kt` did not
   implement `KeyValueStore.has()` — drifted from the copy in
   `ReplacementNoticeStoreTest.kt`, which does.

All three share one root cause: **write without pre-flight mental
compile.** §7 gains a bullet on this (see below).

**§7 process win.** The commit-message count line ("Android JVM
157 → 169") was written *after* `git diff` + XML aggregate, not
before. It matched XML exactly on first try. First session since the
§7 ordering rule was added where the count did not cost a
round-trip. The discipline of ordering held; keep it.

**Next: 030e-c 3d-2 + 3d-3** — Compose UI integration. Scope:
- **3d-2** — `ChatScreen` banner + composer gate + detail dialog +
  ack flow. Extract `sendNow()` local closure inside the composable
  (the send path is currently duplicated: IME `onSend` and
  `IconButton.onClick` are byte-identical; the block gate forces this
  refactor, and it is the right shape regardless — not a separate
  commit, part of 3d-2). Query `controller.gateFor(peerId)` keyed on
  `version`; render inline banner above composer when blocked; disable
  composer; tap banner → dialog with notice details + Acknowledge /
  Reject. On ack: `controller.ackAndPost(...)`, banner disappears
  (accept) or wording changes (reject — Q3: no undo affordance). No
  JVM test — Compose composition; manual emulator verification.
- **3d-3** — polling triggers. `AppRoot` (in `MainActivity.kt`)
  foreground lifecycle observer → `controller.refresh()`. `ChatScreen`
  `LaunchedEffect(peerId)` → `controller.refresh()`. Manual
  verification.

3d-2 needs the read of `ChatScreen.kt` (already read once in Session
J's opening; re-read if any change landed between). 3d-3 needs
`MainActivity.kt` (`AppRoot` structure, `LaunchedEffect` placement
pattern) — read at 3d-3 opening, not before.

Design surface 3d-2 must decide that 3d-1 does not supply: **what the
detail dialog shows about trust.** The banner just shows state; the
dialog is where the human confirms. Does the dialog display the full
canonical bytes (long, unreadable), a hash of the canonical bytes
(`notice_hash` is already available — short, verifiable if the human
compares), or a "signature verifies against pinned key ✓" affordance
(meaningful only if the human knows what "pinned key" means)? ADR §3
does not specify dialog content. This is a 3d-2 design decision, not a
3d-1 gap.

Three files to read at 3d-2 opening, not guessed:
- `android/.../ui/chat/ChatScreen.kt` — the send path (extract
  `sendNow()`), the composer layout (where the banner lands)
- `android/.../crypto/ProvisioningKeys.kt` — the pinned key the dialog
  would verify against if the "verify signature" affordance is
  rendered
- `android/.../transport/SessionManager.kt` — the token accessor
  shape; `IdentityChangeController`'s `sessionTokenProvider` closure
  needs to be wired from here in 3d-2

### Session L — TASK-P1-030 030e-c 3d-2 landed (2026-10-17)

030e-c 3d-2 DONE. One commit:

- `ec5abf1` — `MainActivity.kt` (controller construction in AppRoot),
  `MainNavigation.kt` (param threading), `ChatScreen.kt` (full rewrite
  of the send path + banner + dialog + ack flow + chat-open polling).
  3 files, +245/-39.

**Design decisions recorded (for 3d-3b and future sessions):**

- **`sendNow()` extracted as a local closure.** The two send sites
  (IME `onSend` and `IconButton.onClick`) were byte-identical
  duplicates. The block gate forces the refactor and it is the right
  shape regardless. Both sites route through `sendNow()`.
- **Banner tappable only when `PENDING`.** REJECTED banner has no
  tap affordance — Q3: rejection blocks permanently, admin issues a
  new notice to recover. The banner text explicitly says "Contact
  your admin to resolve."
- **`AckDialog` content: from→to, issuedAt, noticeHash prefix
  (8 chars), "Signature verified on receipt against pinned
  provisioning key."** No re-verify affordance (trust anchor is the
  moment of receipt; re-verify offers nothing but a window where a
  newer `trustedKeys` set makes an old notice look bad). No canonical
  bytes display (unreadable; the trust is the provisioning signature,
  not the human reading bytes).
- **Ack flow via `rememberCoroutineScope`.** `ackAndPost` is suspend
  and returns `Result<AckResult>`. ChatScreen holds
  `ackInProgress` + `ackError` local state. On Success: dialog closes,
  version bump propagates to a re-derived gateState via
  `remember(version, peerId)`. On Failure: error code surfaces in
  dialog, banner stays, composer stays disabled. Q2 contract
  preserved.
- **`HttpClient` hoisted: one per controller lifetime.** Constructed
  inside the `remember(deviceId)` block; `listNotices` and `postAck`
  are method references on the same `IdentityChangeApi` instance. Per-
  call HttpClient would rebuild the SOCKS stack on every refresh.
  `enrollDevice`'s pre-existing HttpClient is untouched.
- **`provisioningPublicKey()` helper duplicated from
  `MatrixSigner.SPKI_PREFIX`.** Three-file threshold rule is at three
  (MatrixSigner, MatrixVerifier, IdentityChangeController) — could
  extract now, deferred to keep this commit focused on UI. Note in
  helper KDoc points to the future consolidation.
- **Chat-open polling included in 3d-2.** `LaunchedEffect(peerDeviceId)
  { controller.refresh() }`. Without this the banner can never appear
  for a notice the client hasn't fetched. 3d-2 and chat-open polling
  are coupled in practice even though the plan split them. Foreground
  lifecycle polling (3d-3b) remains separate: `DisposableEffect` +
  `LifecycleEventObserver` in AppRoot, still pending.

**Outstanding verification — manual emulator acceptance NOT RUN.**
The banner and dialog cannot be exercised on emulator yet: the client
verifies incoming notices against `ProvisioningKeys.CURRENT_
PROVISIONING_PUBKEY_B64U`, so a psql-inserted row with random bytes
would fail signature verification at `recordNotice` and never reach
the banner. To seed a pending notice the client will accept, you need
a signed wrapper from the same test key the vector generator uses:

- `HKDF-SHA256(seed="umoja-canonical-matrix-test-vectors-v1-DO-NOT-
  USE-IN-PRODUCTION", salt=empty, info="ed25519-test-key", 32 bytes)`
  → Ed25519 private key seed
- Canonicalize `{"domain":"umoja.replacement-notice.v1","notice":
  {from_device_id, from_device_auth_key, to_device_id,
  to_device_auth_key, issued_at}}` (JCS)
- SHA-256 the canonical bytes, sign with the derived key, base64url
  the 64-byte signature
- POST to `/identity-change-notices` as an admin

That's a ~20-line TS helper — not 3d-2's scope. Same helper verifies
3d-3b's foreground trigger in one pass (poll fires, banner appears).
Recorded as a follow-up for 3d-3b's session or a dedicated task.

**Count inference — not runner output.** The commit message says
"Android JVM 169 unchanged (Compose changes have no JVM tests)." That
was inference from "no test files touched," not verified against
`TEST-*.xml` this turn. Correct by reasoning (Compose source cannot
affect JVM unit-test count) but strictly per §7 the count comes from
runner output, not inference. Nil risk here; naming the pattern so
it stays honest. §7 refinement below.

**Next: 030e-c 3d-3b** — AppRoot foreground lifecycle polling.
`DisposableEffect` + `LifecycleEventObserver` on `ON_START` calling
`controller.refresh()`. Small — one commit. Then 030e-c is
structurally complete pending the manual verification pass, which
needs the seeding helper above.

### Session M — TASK-P1-030 030e-c 3d-3b + acceptance landed (2026-10-17)

030e-c DONE structurally and runtime-verified. Two commits:

- `3dd8583` — `backend/scripts/sign-test-notice.ts`. Seeds a signed
  replacement notice directly into `identity_change_notices`, signed
  with the SAME test key `ProvisioningKeys.CURRENT_PROVISIONING_
  PUBKEY_B64U` pins. Derivation is HKDF-SHA256 from
  `generate-matrix-vectors.ts`'s seed (`ed25519-test-key`, empty
  salt, 32 bytes). **Self-check before any DB touch:** derives the
  pubkey and refuses to run if it doesn't match the vector file's
  `expected_provisioning_public_key_base64url`. Session L recorded
  the HKDF-risk concern; the check makes the failure loud rather
  than letting a bad-key seed pass silently and surface as a UI
  bug. Direct DB insert (`withTransaction`), not
  `POST /identity-change-notices` — that path has 17 route tests;
  the verification goal is client-side. Idempotent for identical
  `--issued-at`.
- `eec0ee6` — AppRoot foreground lifecycle polling (3d-3b). Three
  design decisions:
  1. **Lifecycle passed as `AppRoot(lifecycle: Lifecycle)` param**,
     not fetched via `LocalLifecycleOwner`. AppRoot is already
     coupled to MainActivity; making it explicit avoids adding
     `androidx.lifecycle:lifecycle-runtime-compose` for one site.
  2. **`DisposableEffect` keyed on `(lifecycle,
     identityChangeController)`.** The controller is null
     pre-enrollment, non-null after; keying on it re-registers
     when it transitions. Without the key the observer captures
     the null value and never sees the controller — the exact
     failure mode 3d-3b exists to fix.
  3. **Immediate refresh on effect registration.** A fresh
     observer does not replay past lifecycle events; if the app
     is already STARTED when the controller becomes non-null
     (post-enrollment), `ON_START` won't fire for it. The
     immediate launch covers that window.
  `ON_START` over `ON_RESUME` — "visible" is the right threshold
  for polling; `ON_RESUME` would miss partially-obscured cases.

**Contact-pair bootstrap for the acceptance.** The `contacts` table
was empty (no bidirectional pair existed, so a chat couldn't be
opened). Direct SQL insert (two rows, `ON CONFLICT DO UPDATE` to
handle revival against `contacts_revoke_consistency`),
`authorized_by` = admin device. Same pattern as the enrollment-token
bootstrap in Session A. Prerequisite: both devices already enrolled
in the same org.

**Emulator acceptance — all 8 steps passed.** Recorded as the
load-bearing evidence; the JVM suite cannot exercise Compose, so
this is the only proof that 3d-2 + 3d-3b behave at runtime.

Setup: emulator 5554 = admin (`f697b280-91dc-478c-a8eb-58e7f5233751`),
emulator 5556 = user (`943fbeeb-6bae-41e7-b5e1-5ebcc534ea54`). Seed
`--from 943fbeeb --to f697b280`. Banner renders on 5556 (chatting
with `f697b280` = notice's `toDeviceId`).

1. Chat-open on blocked peer → banner appeared (tertiary container,
   "Device replacement awaiting your acknowledgment", View label),
   composer placeholder "Sending blocked", send icon greyed.
   Backend log confirmed `GET /identity-change-notices 200` on the
   chat-open `LaunchedEffect`. **3d-2 chat-open trigger verified.**
2. Tap banner → dialog opened. All fields correct:
   `from=943fbeeb…`, `→ f697b280…`,
   `Issued: 2026-10-17T15:58:19.558Z` (matches seed),
   `Notice: 7TrYHYAM…` (first 8 of seed hash
   `7TrYHYAM9vpkyk97ei6SpVRe6e461Ipdl0tnolPPoSo`),
   `Signature verified on receipt against pinned provisioning key.`
   No full canonical bytes, no re-verify button — matches 3d-2 KDoc
   (confirm continuity, not cryptography).
3. Tap Acknowledge → dialog dismissed, banner cleared, composer
   re-enabled, send icon blue. Controller ran sign → POST →
   markAcked.
4. Tap Back → re-open chat → **no banner**. `ACKED_ACCEPT` state
   persisted through chat close/reopen (SecureStorage write +
   reload verified). **Persistence holds.**
5. Seed second notice (`y5y0_cKTIAF7zTZ1k8C6RlEwmjK6a_GkW49MwLqOtyk`)
   while chat open and idle — chat-open `LaunchedEffect` cannot
   re-fire (peer unchanged).
6. Background the app (Home) → wait 2s → foreground.
7. **Banner appeared for the second notice without re-navigation.**
   Only path is the `DisposableEffect`'s `ON_START` observer →
   `controller.refresh()`. **3d-3b foreground trigger verified in
   isolation from chat-open.**
8. Tap banner → Reject → banner changed to error-container (red),
   text = "You rejected the replacement of this device. Sending is
   blocked. Contact your admin to resolve.", View label removed
   (non-clickable per Q3), composer stays disabled, tapping banner
   does nothing. **Q3 rejection semantics verified.**

**Pitfall recorded.** During acceptance, the first
`docker compose logs | grep -iE "identity-change"` returned zero
lines — not because the call failed, but because 3d-2/3d-3b shipped
without a client-side log tag. There is no `UmojaIdentity` tag in
the client, so `adb logcat | grep -i refresh` matches every Android
system service. Absence of a log line is NOT evidence of absence of
a call when the code has no log statement. The diagnostic that
actually worked was unfiltered `docker compose logs backend
--tail=40` — seeing `GET /me/contacts 200` proved the app was
active, and the *absence* of `/identity-change-notices` in the same
window was the signal. §7 bullet added.

**Next: 030e-d** — peer-ack visibility. `GET /identity-change-acks/
:notice_hash` (backend route exists in `identity-change.test.ts` as
`TEST-ACK-LIST-BY-NOTICE`; the API client deliberately omitted it
per `dde60f2`'s KDoc — 030e-d is the consumer that justifies adding
it). UI: dialog or banner extension showing "N peers acknowledged
this notice" or similar. Discovery likely shares the same triggers
(chat-open, `ON_START`) unless a WS extension lands first.

### Session N — Hardening design: TASK-P1-036…041 filed, ADR-HARDENING-001 landed (2026-10-17)

Design-only session. No code, no tests run. Two commits:

- `be3f287` — `docs/US-TASK-P1-001.md` v0.5 → v0.6. Filed TASK-P1-036
  through 041: 036 (rotation notice handling) and 037 (matrix transport)
  backfilled from prose follow-ups that were never formally registered;
  038–041 newly filed from the 2026-10-17 hardening review. Total
  36 → 42.
- `7a47a30` — `docs/architecture/ADR-HARDENING-001.md` (291 lines).
  Design rulings for TASK-P1-038 through 041: session state machine,
  release-build hardening, send-gating verification, out-of-scope list,
  sequencing, and four [VERIFY AT IMPLEMENTATION] items deferred to the
  tasks they're contingent on.

**Pre-flight discovery reshaped scope.** Before filing 038–041 the
session read the registry (§A headers, §C table rows) instead of
assuming 036/037 existed. Grep showed §A headers jump from 030 to end
of section; §C table lists 031–035; neither a §A section nor a §C row
for 036 or 037. The two tasks had been tracked as prose follow-ups
since Sessions F/G (rotation: ADR-PROVISIONING-001 §3.6; matrix
transport: ADR-IDENTITY-CHANGE-001 §5 open item) but were never
formally registered. Filing 038–041 without them would create a
permanent numbering gap. The fix: file all six in the same amendment.
This is the same drift the handoff's own §7 warns about — a name
carried in prose until the registry was actually read.

**Five ADR rulings, each a consequence of §1's invariant** (a fielded
user must never be unrecoverable):

1. **§2 Session state machine.** 7 states (`Unauthenticated`,
   `Authenticating`, `Authenticated`, `Reauthenticating`, `Revoked`,
   `NetworkFailure`, `EnrollmentRequired`). Single-flight mutex so
   concurrent 401s produce one re-auth (backend challenge consumption
   would otherwise make 4 of 5 fail for no user-caused reason).
   Recursion guard so `/auth/challenge` / `/auth/verify` 401s don't
   recurse. Interceptor retries the original call once. Backend
   change: `lookupSession`'s 401 gains a `device_revoked` code when
   device status is not `active`; precedent exists in
   `auth/verify.ts`'s status filter. App-start routing: expired
   `sessionExpiresAt` → silent re-auth, not a button tap (the current
   code routes on `sessionExpiresAt == null`, which misses expiry —
   the read is in §7 of the ADR).

2. **§3 Release-build hardening.** `FLAG_SECURE` on `ChatScreen`,
   `AdminScreen`, `DiagnosticsScreen`. Both `allowBackup="false"` and
   `fullBackupContent="false"` (defense in depth: the Keystore key
   doesn't transfer through auto-backup, so a restored device has
   undecryptable prefs; `allowBackup=false` removes the failure mode).
   `TransportConfig.useTor` becomes a `val` initialized from
   `BuildConfig.DEBUG`; startup assertion in `UmojaApplication` fails
   closed if release but `useTor` is false. `minifyEnabled=true` with
   libsignal keep rules; **the acceptance test is cold-start, not
   "build succeeds."**

3. **§4 Send-gating: verification-first.** Design is settled by P1-026
   ("contacts are a projection, matrix is authority"). The task
   answers whether `MessagingService.sendMessage` implements that.
   Two outcomes, both valid: gate exists → tests confirm and the task
   closes on evidence; gate missing → implemented, with UI treatment
   matching the 030e-c blocked-send banner pattern.

4. **§5 Out of scope, named so a future session doesn't expand:**
   session token rotation, refresh-token architecture, certificate
   pinning, APK obfuscation, backend session TTL tuning, penetration
   testing (TASK-P1-024), SBOM (TASK-P1-027), streaming API retry
   semantics, APK signing key custody.

5. **§6 Sequencing: 038 → 039 → 040 → 041.** 038 first because it is
   the one task that might reveal a hole rather than require new
   code. 039 second because it's mechanical and independent, and
   because verifying release builds before 040's state-machine
   changes means manual on-device verification of 040 isn't
   compounded with minification debugging. 040 last, largest,
   benefits from 039's release path being proven. 041 deferred.

**Four [VERIFY AT IMPLEMENTATION] items** — not asserted, deferred to
the task they're contingent on. This is the Session G "read before
write" discipline applied at the task-design layer, so the task can
land correctly whether the property already exists or needs adding:

- **`MessagingService.sendMessage`'s gate state** (TASK-P1-038).
  Session C/D read `MainActivity.kt` but not `MessagingService.kt`;
  whether the matrix gate is present is a code read, not an
  inference.
- **`lookupSession`'s rejection path** (TASK-P1-040). The client
  cannot distinguish "expired" from "revoked" from a plain 401
  today. If the code already surfaces device status, both the backend
  change and the client's terminal-state routing simplify.
- **`TransportConfig`'s mutability** (TASK-P1-039). Handoff §6
  records it as `var`, but the current shape is a code read.
- **`AppRoot`'s current routing** (TASK-P1-040). Session C/D read
  shows routing on `sessionExpiresAt == null`, not
  `sessionExpiresAt < now()`. A session that expired while the app
  was closed lands on `Authenticated`; the first API call 401s. This
  is the exact failure mode §2 closes.

**Why 030e-d defers.** Before this session's review, the handoff said
"Next: 030e-d — peer-ack visibility." That was correct before the
hardening gaps surfaced. After: P1-038 might reveal that
`MessagingService.sendMessage` doesn't gate on the matrix. If it
doesn't, adding a peer-ack dialog (030e-d) before closing the
authorization hole is prioritization in the wrong order. P1-038
resolves first; 030e-d opens after, or opens immediately if P1-038
closes on evidence alone (gate exists, tests pass, no code change).
The deferral is explicit, not forgotten.

**No code, no tests run this session.** Commit messages say so
explicitly. Counts unchanged: 169 Android JVM / 242 backend.
Verification of the ADR rulings happens in the task that implements
each ruling — that is the whole point of the [VERIFY AT
IMPLEMENTATION] markers.

**§8 refresh — DONE 2026-10-19 (`6b715cb`).** Bounded refresh of handoff §8's non-transport staleness (Session Z-10). §8's Authoritative design, Conformance data, and Code-shape blocks now reflect Sessions F through Z-9; the transport/ surface is deliberately deferred to the pending suspend refactor's preamble (the refactor reads those files as its intro, so documenting them now would be re-stale by the time the refactor ships). See §3 Session Z-10.

### Session O-1 — TASK-P1-037 backend landed (2026-10-17)

TASK-P1-037 is split across two sessions. O-1 (backend) DONE.
O-2 (client) pending. Three commits:

- `46a3443` — `backend/migrations/016_matrices.sql` (57 lines).
  One row per device (`device_id PRIMARY KEY`), Phase 1 shape.
  Three invariants documented at the schema, not in prose: `version`
  must equal `parse(canonical_bytes).matrix.version` (denormalized
  for queries, same pattern as migrations 013/014); `updated_at`
  must be set explicitly by the write path's UPSERT (`DEFAULT` covers
  only the initial INSERT); `matrix.device_id == row.device_id` must
  be enforced client-side — currently absent, filed as
  ADR-PROVISIONING-001 §7 future-hardening, reachable via P1-033's
  write path but not via GET (which scopes by
  `req.device.device_id`). Same `86`-char signature-length CHECK and
  no-`ON DELETE CASCADE` conventions as migration 015.
- `98fee5c` — `GET /me/matrix` in `routes/me.ts` (58 lines added).
  Response `{canonical_utf8, signature_base64url}`. Version lives
  inside canonical bytes — client derives it by parsing, never trusts
  a server-reported version. 404 `matrix_not_found` when the caller
  has no matrix row. Backend does NOT verify the provisioning
  signature (relay semantics, same as identity-change notices per
  ADR-IDENTITY-CHANGE-001 §4). JOIN on `devices` is defense-in-depth
  against a future refactor that bypasses session-derived scoping.
  Guard-then-use on `rows[0]` per §7's `noUncheckedIndexedAccess`
  pattern.
- `a6174ea` — `backend/test/matrix-transport.test.ts` (307 lines,
  5 tests): `TEST-MATRIX-TRANSPORT-FETCH`,
  `TEST-MATRIX-CROSS-DEVICE-REJECTED`, `TEST-MATRIX-404-NO-MATRIX`,
  `TEST-MATRIX-401-UNAUTHENTICATED`,
  `TEST-MATRIX-VERIFY-ON-RECEIPT-BACKEND`.

**Test-name mapping to registry v0.6 §B TASK-P1-037.** Registry lists
4; 5 shipped. The extra is `-VERIFY-ON-RECEIPT-BACKEND`, the backend
half of the registry's `-VERIFY-ON-RECEIPT` — proves the bytes
returned by the route still verify against the pinned provisioning
key, so a UTF-8 or buffer-handling regression in the response path
fails here rather than at the client. Registry's
`-STORE-ON-VERIFY-SUCCESS` is genuinely client-side; it defers to
O-2's `MatrixApiTest`. Split is recorded in the test file's KDoc so
a future reader does not think it went missing.

**Fixture strategy.** W-001 from
`canonical-matrix-test-vectors.json` — the same fixture Session A's
vector generator produced. Reconstructing the wrapper or signing
inline would duplicate `generate-matrix-vectors.ts`'s
HKDF + PKCS8 + Ed25519 path. `-VERIFY-ON-RECEIPT-BACKEND` uses the
same primitive that produced the fixture (Node crypto
`sign(null, digest, key)` over SHA-256 digest) — closing the
protocol-drift risk that would exist if the verifier used a different
Ed25519 implementation.

**`TEST_ORG_ID`.** `0c1` (primary) + `0c2` (reserved for cross-org
isolation if a future matrix test needs it). Next-free past the
011/044/055/066/077/088/099, `0a1`/`0a2`, `b1`/`b2` set per §7's
numbering discipline. `beforeEach` cleans `matrices` by
`device_id IN (SELECT ... WHERE org_id IN (0c1, 0c2))`; devices
accumulate keyed by random UUID (mirroring identity-change.test.ts).

**Count.** Backend 242 → 247 (+5). Verified from runner output.

**Next — O-2 (client half of TASK-P1-037).** Scope:
`MatrixApi.kt` (structural mirror of `ContactsApi.kt`;
`fetch(sessionToken): RemoteMatrix?`, null on 404, exception on 401
and invalid_response); `MatrixApiTest.kt` (3-4 JVM tests covering
those paths); `sign-test-matrix.ts` (HKDF derivation self-check from
`sign-test-notice.ts` + matrix wrapper + INSERT, needed for manual
emulator verification); `AppRoot` wiring (`LaunchedEffect` keyed on
`AppScreen.Authenticated`, single fetch, decode → `MatrixStore.accept`,
silent catch on verify-failure per registry §B — does not crash,
preserves existing store); manual emulator verification (seed →
force-stop → reopen → assert `highestSeenVersion`); handoff close.
ADR-HARDENING-001 §6 sequence is unchanged at task-id level — 037
must complete (both sessions) before 038 begins.

### Session O-2 — TASK-P1-037 client landed (2026-10-17)

TASK-P1-037 client half landed. With this, TASK-P1-037 is DONE
end-to-end. Seven commits:

- `f5e7fd2` — `MatrixApi.kt`: transport client, structural mirror of
  `IdentityChangeApi.kt` (lambda-injected `HttpResult` seam, not a
  concrete `HttpClient` — Session K's `IdentityChangeController`
  pattern, extending the codebase's own convention rather than
  introducing an interface for a just-shipped final class).
  `fetch(sessionToken): RemoteMatrix?` — null on 404, exception on
  401 + invalid_response. `RemoteMatrix(canonicalUtf8,
  signatureBase64url)` wire shape.
- `258673d` — `MatrixApiTest.kt`: 5 JVM tests. Happy path, 404 → null,
  401 → exception, invalid_response → exception, malformed JSON →
  exception. Lambda fake in the constructor; no HttpClient mock.
- `d03910d` — `MatrixStoreTest` strengthened:
  `TEST-MATRIX-STORE-ON-VERIFY-SUCCESS` version assertions.
- `bc1cf2c` — `sign-test-matrix.ts`: HKDF-derived test key (same seed
  as `sign-test-notice.ts`), self-check before DB touch, wrapper
  build via `MatrixBuilder.build`, direct `INSERT INTO matrices`.
- `14c39c2` — `AppRoot` wiring: `LaunchedEffect(screen, deviceId)`
  fires on `Authenticated` entry, `MatrixApi.fetch` →
  `MatrixStore.accept` on non-null. Silent catch on
  `MatrixApiException` per registry §B; preserves existing store on
  reject.
- `f2dbf43` — `DiagnosticsScreen.kt`: matrix read-back section
  (`highestSeenVersion` + contacts count) for manual verification.
- `dad5a49` — withContext fix. See failure #1.

**Acceptance chain verified on emulator 5556:** seeded matrix for
`943fbeeb` (version 1, empty contacts) → force-stop → relaunch →
app reaches `Authenticated` → effect fires → `GET /me/matrix` 200 in
backend log (`req-8`, 31ms) → Diagnostics shows
`highestSeenVersion=1 contacts=0`.

**Four failures before acceptance, each caught by the correct layer:**

1. **`NetworkOnMainThreadException` on every `Authenticated` entry**
   (app crash). `LaunchedEffect` body runs on `Dispatchers.Main`;
   `MatrixApi.fetch` → `HttpClient.get` is a blocking OkHttp call.
   Caught via `logcat -b crash`: trace named
   `MainActivityKt$AppRoot$2$1` line 194. Fix: wrap effect body in
   `withContext(Dispatchers.IO)` — the pattern `enrollDevice` and
   `IdentityChangeController.refresh()` already use. Domain `catch`
   clauses (`MatrixApiException`) do not catch
   `NetworkOnMainThreadException` (a `RuntimeException`) — the crash
   escapes and the app dies. §7 gains a bullet.

2. **`me/matrix` 404 from stale container.** O-1's route commit
   (`98fee5c`) landed in source but the running backend image was
   pre-O-1. Caught by backend log during first successful fetch
   attempt: `Route GET:/me/matrix not found`. Fix:
   `docker compose up -d --build backend`, then curl returns 401
   (route exists). Same class as Session C `/admin/matrix-version`
   and KI-002. §7's "rebuild before curl" rule re-hit via the client
   path — rule extended to "before client testing."

3. **`Connection reset` on three concurrent requests.** Both
   `DisposableEffect` (Session M, identity-change polling) and
   `LaunchedEffect(screen, deviceId)` (O-2, matrix fetch) fire on
   `Authenticated` entry. Three sockets opened simultaneously → Tor
   circuit reset all three. Caught by `logcat` (SocketException × 3,
   all within 36ms) + backend log (zero requests at that timestamp).
   Fix: `adb reverse --remove-all` + re-add. Session M's socat
   sidecar chain is unstable under concurrent first-request load.
   Not a code fix in O-2; named as a known-transient class.

4. **Stale APK during early acceptance attempts.** Reinstall at
   O-2's first manual test was pre-withContext-fix; the fix commit
   landed but the emulator APK was old. `./gradlew installDebug`
   resolved it. Not a new lesson — confirms the discipline that
   "commit pushed" ≠ "APK on device."

**Sequencing status:** TASK-P1-037 DONE. Next per ADR-HARDENING-001
§6: TASK-P1-038 (send gate).

**Caveat carried into 038.** The seeded matrix has
`permitted_contacts=[]`. 038's fail-closed gate will correctly
reject all sends against an empty matrix — right behavior (no
authorized peers → no sends) but it makes "gate works" vs. "matrix
has no permitted contacts" indistinguishable in a naive acceptance
test. 038's acceptance must include all three:
- Empty `permitted_contacts` → send rejected (fail-closed proof)
- Non-empty `permitted_contacts`, peer in set → send succeeds
- Non-empty `permitted_contacts`, peer not in set → send rejected

`sign-test-matrix.ts` needs a `--contacts` arg (or equivalent) to
seed a matrix with at least one permitted contact before 038 opens.
Confirm and extend at 038's session start.

**Counts.** Android JVM 169 → 174 (+5 MatrixApiTest). Backend
unchanged at 247. Both from runner output (XML aggregate for JVM,
`npm test | tail -4` for backend).

### Session P — TASK-P1-038 DONE (2026-10-17)

Send-path matrix enforcement landed end-to-end. Four commits:

- `78762a3` — **A: SendGate pure predicate + registry-named tests**
  (`crypto/SendGate.kt` + `SendGateTest.kt`). Fail-closed on null
  (no matrix) and empty (zero contacts). Registry-named
  TEST-SEND-GATE-EXCLUDED-PEER + TEST-SEND-GATE-PERMITTED-PEER,
  plus TEST-SEND-GATE-NULL-MATRIX + -EMPTY-MATRIX. 4 tests, JVM
  174 → 178.
- `ab9f22f` — **B: gate wired in MessagingService.sendMessage.**
  Step 0, before prekey fetch or envelope submit. `MatrixStore`
  constructed from the same `SecureStorage(context)` already read
  in `sendMessage` — no ctor arg added, no call-site ripple
  (registry §B: do not redesign the send path). `SendOutcome`
  gains `NotAuthorized(peerDeviceId)`, distinct from `Failure`.
  Sealed-class exhaustiveness forced two `when(outcome)` sites to
  update (ChatViewModel + DiagnosticsScreen), both in the commit.
  Grep confirmed no third site.
- `f1526fd` — **C: ChatScreen authorization banner + matrixStore
  threading.** Parallel banner to 030e-c's IdentityChangeBanner
  (distinct trust flows). `AppRoot` gains
  `remember(deviceId) { MatrixStore(...) }`; MainNavigation +
  ChatScreen take it as a param. `isBlocked = isIdentityBlocked OR
  not isAuthorized`. **KDoc claim in this commit was wrong** (see
  D-1).
- `475d75b` — **D-1: ChatScreen re-derives on matrix write.**
  Fix caught in Case 2 emulator acceptance: authorized peer still
  showed the banner because ChatScreen cached `isAuthorized` at
  composition time and AppRoot's fetch is async — neither
  `peerDeviceId` nor the remembered `matrixStore` identity changed
  when the fetch landed. Commit C's KDoc claimed "the matrix
  cannot change while ChatScreen is composed"; that claim fired
  wrong on cold start. Fix (mirrors 030e-c's
  `IdentityChangeController.version` idiom):
  - `MatrixStore` gains `private MutableStateFlow _version` +
    `version: StateFlow<Long>`, bumped after successful `accept`
    and `clear`. Write-notification, not a cache.
  - `MainActivity`: AppRoot's fetch calls `matrixStore.accept`
    instead of a throwaway `MatrixStore(SecureStorage(context))`.
    **This line is the load-bearing fix** — StateFlow alone is
    inert without writer-unification; if a future task adds a
    StateFlow to a store class, the writer must use the remembered
    instance, not construct a fresh one.
  - `ChatScreen`: `collectAsState()` on `matrixStore.version`;
    remember key becomes `(peerDeviceId, matrixVersion)` instead
    of `(peerDeviceId, matrixStore)`. KDoc corrected to record
    the actual failure, not the theoretical trade-off.

**Three-case emulator acceptance — all passed.** Two-layer coverage
per case: ChatScreen proves the UI gate; DiagnosticsScreen bypasses
it and calls `MessagingService.sendMessage` directly to prove the
service-layer gate. Evidence per case is the **triple** (logcat +
DB state + matrix state), not absence-of-error alone.

| Case | Seed | Layer 1 | Layer 2 | Gate behavior |
|---|---|---|---|---|
| 1 | v1, `permitted_contacts=[]` | banner shown, composer disabled | `Send blocked: peer not in permitted contacts`; logcat `sendMessage blocked by SendGate`; envelope count 0 | fail-closed ✅ |
| 2 | v2, `permitted_contacts=[f697b280]` | banner absent (post D-1; before D-1 it was stuck-present — the bug D-1 fixes) | `Sent: 6de567f5...`; logcat `sent envelope`; envelope count 0 → 1 | allow-on-match ✅ |
| 3 | v3, `permitted_contacts=[00000000-...]` | banner **reappeared** | `Send blocked`; logcat `sendMessage blocked by SendGate`; envelope count stayed 1 | re-engage-on-remove ✅ |

Case 3 is the case that distinguishes a correct gate from a
sticky-open one. Without it, "gate works" is indistinguishable
from "gate authorized once and never re-checked."

**O-2 caveat corrected.** Session O-2's "Caveat carried into 038"
claimed `sign-test-matrix.ts` "needs a `--contacts` arg." Wrong:
the flag was always wired — `--permitted-contacts` in
`parseArgs()` (`backend/scripts/sign-test-matrix.ts` line ~158),
reaching the wrapper at line ~229. No script edit was needed;
the caveat was speculation about a script that was already
complete. Same class as Session F/G design assumptions corrected
by reading actual code (Session G's ADR corrections).

**Counts.** Android JVM 174 → 178 (+4 SendGateTest). Backend
unchanged at 247. Both from XML aggregate / `npm test` runner
output. `installDebug` verified on-device via `dumpsys package`
`lastUpdateTime` — D-1's commit time is before the installed
APK's update time, so the emulator's observed behavior is
unambiguously from HEAD.

**Next: TASK-P1-039 — release-build hardening.** Per
ADR-HARDENING-001 §6 Order: `037 → 038 → 039 → 040 → 041`.
038 was the one task in the sequence that might have revealed a
hole rather than required new code — it did reveal one (the D-1
reactivity race, which is a UI-layer bug not a service-gate bug).
039 is next because it is mechanical and independent, and because
verifying release builds before 040's state-machine changes means
manual on-device verification of 040 isn't compounded with
minification debugging.

### Session Q — TASK-P1-039 DONE (2026-10-17)

Release-build hardening landed end-to-end. Five commits (A/B/C/D/doc):

- `cb7ac82` — **A: enable R8 + buildConfig + libsignal keep rules.**
  `buildFeatures { buildConfig = true }`. `optimization { enable =
  false }` → `enable = true`. New
  `android/app/src/release/keepRules/libsignal.keep` with keep rules
  for `org.signal.libsignal.**` (protocol, internal JNI bridge,
  native method names) and `org.whispersystems.libsignal.**`.

  **ADR §9 v0.2 item 7 resolved via AGP 9.4.1 API docs.**
  `Optimization.enable` gates R8 minification AND resource
  shrinking together; default Android keep rules are auto-included
  (no `getDefaultProguardFile` needed). Project keep rules use the
  AGP 9.3+ `src/<variant>/keepRules/*.keep` source set, not the
  legacy `proguard-rules.pro`. ADR §3's prose used legacy DSL
  names (`minifyEnabled`, `proguardFiles`); the intent is
  preserved, the syntax follows AGP 9.4.1 and the existing
  `optimization { }` block. Mapping recorded in the commit message
  and in `docs/ops/RELEASE-ACCEPTANCE.md`.

- `306bcd7` — **B: TransportConfig immutability + release/Tor
  assertion.** `var useTor: Boolean = true` →
  `val useTor: Boolean = !BuildConfig.DEBUG`.
  `UmojaApplication.onCreate` gains a startup assertion:
  `check(BuildConfig.DEBUG || TransportConfig.useTor)`. Behavioral
  shift per ADR §9 v0.2 item 6: dev-iteration moves to
  debug/clearnet (adb reverse tcp:8080); Tor is exercised in
  release. No test coupling — `grep useTor|TransportConfig` in
  test/ and androidTest/ returned zero matches.

- `3a98ca0` — **C: FLAG_SECURE on ChatScreen, AdminScreen,
  DiagnosticsScreen.** New `ui/common/SecureScreen.kt` — a
  `DisposableEffect` wrapper setting/clearing
  `WindowManager.LayoutParams.FLAG_SECURE` for the composition
  lifetime. Three call sites match ADR §3's scope exactly; UI
  audit confirmed no fourth sensitive surface (the seven
  `*Screen` composables are Settings, Chat, Contacts, Admin,
  EnrollmentQr, Conversations, Diagnostics; the four excluded
  ones carry no sensitive content per ADR §3).

- `93c04a4` — **D: RELEASE-ACCEPTANCE.md.** New procedural
  reference (157 lines): build + sign + cold-start + four-screen
  FLAG_SECURE matrix + misleading-diagnostic patterns learned
  this session.

- `[handoff-hash]` — this commit.

**Empirical acceptance evidence** (ADR §3: "The acceptance test is
not 'build succeeds' — minification bugs surface at cold-start,
not build time"):

- Release APK: 151,633,853 B (unminified baseline) → 103,756,048 B
  (−32%). Remaining size is native `.so` for 4 ABIs, not dex.
  ABI splits are a future optimization, not this task.
- Dex after R8: `MessagingService` / `MatrixStore` absent
  (obfuscated); `MainActivity` / `UmojaApplication` present
  (correct — AndroidManifest entry points the manifest references
  by name).
- `org/signal/libsignal` strings in release dex: 221 (keep rules
  held; native method names preserved).
- Cold launch: crash buffer empty. No
  `ClassNotFoundException`, `NoSuchMethodError`,
  `UnsatisfiedLinkError`.
- Tor transport: `UmojaWS : Tor mode: routing WS via HTTP bridge
  127.0.0.1:44023` in logcat; backend received `GET /me/matrix`
  from `172.18.0.4` (Tor container) with `.onion` host header.
  Proves `useTor = !BuildConfig.DEBUG = true` reached the request
  layer.
- Four-screen FLAG_SECURE matrix, all pass:
  - Conversations: `fl=` no SECURE, 80,356 B, UI visible.
  - Settings: `fl=` no SECURE, 105,901 B, UI visible.
  - Chat: `fl=` SECURE, ~23 KB, black content + system overlays.
  - Diagnostics: `fl=` SECURE, ~23 KB, black content + system
    overlays.
  - Optional re-verify after Chat→Settings: no SECURE, ~105 KB,
    no leak — `SecureScreen.onDispose` fires correctly.

**§7 additions earned this session** (five, all in the global §7
block below):

**Counts.** Android JVM 178 unchanged (release hardening has no
JVM-testable surface; acceptance is emulator cold-start per ADR
§3). Backend 247 unchanged. Both from runner output.

**Next: TASK-P1-040 — session lifecycle & revocation UX.** Per
ADR-HARDENING-001 §2 and §6 Order: `037 → 038 → 039 → 040 → 041`.
040 implements the 7-state SessionStateManager, single-flight
re-auth mutex, recursion guard, retry-original-call interceptor,
the backend `device_revoked` code on the 401 path (precedent in
`auth/verify.ts`), and the AppRoot routing replacement
(`sessionExpiresAt < now()` → re-auth, not the current `== null`
check). Per ADR §9 v0.2 item 2, `lookupSession` does not
currently differentiate expired from revoked; the backend change
is confirmed needed.


### Session R — TASK-P1-040-A DONE (2026-10-18)

Backend half of ADR-HARDENING-001 §2's revoked-vs-expired ruling
landed. 040-B (Android state manager), 040-C (AppRoot routing
rewrite), 040-D (interceptor), 040-E (emulator acceptance) defer to
R-2/R-3. Two commits:

- `db9fe72` — **040-A: backend device_revoked disambiguation.** Five
  source files + two test files. `lookupSession` returns
  `LookupSessionResult`, a discriminated union of
  `{ session | device_revoked | no_session }`. Session-level
  filters (revoked_at, expires_at) preserved verbatim per registry
  §B "Do NOT re-review lookupSession's filter." Device status is
  projected into the SELECT and branched in JS — **one query, not
  two**, contra ADR §9 v0.2 item 2's predicted "two queries in
  the revoked-or-expired path." Same ruling, simpler mechanism,
  no race window. The ADR prediction was written before the JOIN
  was read.

  `middleware.ts`: three-branch handler.
  `challenge.ts` + `verify.ts`: throw `AuthError('device_revoked')`
  when status !== 'active' (was `unauthorized`). `ws/server.ts`:
  union handling for initial auth + `device_revoked` in the
  revalidation branch's strict-equality check — the previous code
  happened to work because `challenge.ts` threw `unauthorized` on
  revocation, but after the split that path would have fallen
  through to close 1011 instead of 4403. Caught by TypeScript
  compile, not test.

  3 new tests in `auth.test.ts`
  (TEST-AUTH-CHALLENGE-REVOKED-DEVICE,
  TEST-AUTH-VERIFY-REVOKED-DEVICE,
  TEST-AUTH-SESSION-DEVICE-REVOKED). Backend 247 → 250.

- `5d24621` — **ADR-IDENTITY-CHANGE-001 v0.4 amendment.**
  Supersedes v0.3's "route-level assertion is 401 unauthorized"
  claim (accurate pre-040-A). TEST-ACK-REVOKED-DEVICE updated to
  assert `device_revoked`; KDoc rewritten to record both the
  middleware-level signal (post-040-A) and the service-level
  defense-in-depth (unchanged). V0.3's text preserved; v0.4 names
  the supersession — same versioning pattern as ADR-HARDENING-001's
  own v0.2 correction.

**The one test that failed during the change** — TEST-ACK-REVOKED-
DEVICE, asserting the pre-040-A middleware contract — was the
decision point, not a bug. It proves the test was testing the
actual wire contract, not just the status code. Had it been
written to pass regardless, the ADR-vs-code divergence would have
shipped silently. This is "do it right the first time" as a
demonstrated property, not a slogan.

**Curl verification on rebuilt container** (KI-002 rule: any
backend source change requires `docker compose up -d --build
backend` before any test that hits the running server):

- Active device `POST /auth/challenge` → 200 + JSON challenge
- Revoked device `POST /auth/challenge` → **401 +
  `{"error": "device_revoked"}`** — the load-bearing evidence

**Design note — union return is compile-time-enforced
correctness.** TypeScript discriminated unions are the caller-side
equivalent of `noUncheckedIndexedAccess` (Session H §7). The
`ws/server.ts` bug (#2 above) was caught by compile, not test. A
nullable return (`SessionRecord | null`) would have silently
passed through `if (!session)`; the union forces every caller to
branch on `kind`.

**Scope honestly stated.** 040-A completes the backend half. The
Android half — 7-state SessionStateManager, single-flight mutex,
recursion guard, retry-original-call interceptor, AppRoot routing
rewrite — is 040-B through 040-E, each comparable to 040-A in
scope. Session R closes with the backend half done and verified,
not with the task marked complete.


### Session R-2 — TASK-P1-040-B DONE (2026-10-18)

Android session state machine landed as a self-contained class. Zero
production integration this session — 040-C wires it into AppRoot,
040-D wires it into HttpClient. 040-B ships the class with a 12-test
JVM suite so integration has a tested foundation. One commit:

- `f9e01ab` — **040-B: SessionStateManager + tests.** New
  `auth/SessionStateManager.kt` (~218 lines), new
  `test/auth/SessionStateManagerTest.kt` (~257 lines). Android JVM
  178 → 190 (+12). Backend 250 unchanged (no backend touch).

**The load-bearing design ruling — single-flight is Mutex +
CompletableDeferred, not Mutex alone.** ADR §2 says "a mutex ...
ensures concurrent 401s produce one re-auth. Other callers block
on the same future." A bare mutex would serialize reauths — five
concurrent 401s → five lambda executions in turn, exactly what
ADR §2 says must not happen. The deferred is the "same future"
phrasing: leader acquires lock, creates deferred, releases lock,
runs reauth, completes deferred; followers acquire lock, see
existing deferred, release lock, await it. Five callers, one wire
call, one shared outcome. First `Mutex` and first
`CompletableDeferred` in the codebase — named in the class KDoc
so future readers see the two-pattern shape and don't
"simplify" it back to bare mutex.

**The boundary 040-B does NOT cross.** ADR §2 assigns two
responsibilities to the interceptor, not the state manager:

- Recursion guard — `/auth/challenge` and `/auth/verify` 401s
  must not trigger reauth; enforced by URL prefix at the
  interceptor layer (040-D).
- Retry-original-call — interceptor buffers the failed request,
  calls `reauthenticate()`, re-executes the buffer once on
  success (040-D).

The state manager transitions state and returns. Both class KDoc
and commit message state this so 040-C/D don't re-litigate it.

**Fail-toward-recovery on malformed expiry.** `isExpired()`
treats an unparseable `expiresAt` as expired. ADR §1's invariant:
a fielded user must never be stranded. An unparseable date is
indistinguishable from corruption; treating it as expired routes
through reauth (recovers if backend healthy) rather than trusting
a value we cannot read (would strand the user with a stale
token).

**Terminal-state short-circuit.** `reauthenticate()` on `Revoked`
or `EnrollmentRequired` returns immediately without invoking the
reauth lambda. Registry §B: "no retry loop."
`TEST-SESSION-REVOKED-TERMINAL` asserts `reauthCalls == 1` after
two `reauthenticate()` calls on `Revoked`.

**First-run failure was informative.** `TEST-SESSION-CONCURRENT-
401-SINGLE-REAUTH` failed on first run: `assertTrue(it is State)`
was iterating `List<Deferred<State>>` because `awaitAll()`
returns the results but does not mutate the list. Always-false
assertion. The fix: `val outcomes = results.awaitAll()` and
iterate `outcomes`. **The state machine was already correct**
(`reauthCalls == 1` held throughout); only the final assertion
was wrong. This is the class of failure a green first run would
have hidden — which is why tests run before commit, not after.

Secondary hardening: replaced two `yield()` calls with
`delay(200)` before `gate.complete`. `yield()` releases the
`runBlocking` thread but not `Dispatchers.Default` coroutines;
without real wall-clock time, followers can arrive after the
leader completes and each become a fresh leader
(`reauthCalls > 1`). No observable signal for "follower awaiting"
exists on the state manager's public surface, so a bounded delay
is the honest test seam. Assertion messages name the actual
violation if the invariant ever breaks: `"single-flight violated
during leader block: N reauths"`.

**Test framework: `runBlocking`, not `runTest`.**
`kotlinx-coroutines-test` is not on the classpath;
`IdentityChangeControllerTest` establishes the `runBlocking`
precedent. No `build.gradle.kts` change needed.

**Scope honestly stated.** 040-B delivers the class and its tests.
040-C (AppRoot routing rewrite — the bug ADR §9 v0.2 item 3
confirmed: `sessionExpiresAt == null` never checks `< now()`) is
R-3's opening task. 040-D (HttpClient interceptor — the
greenfield work ADR §2 presupposed existed; `HttpClient.kt` has
zero 401 handling, each API catches its own errors via domain
exceptions) is R-3's second commit. 040-E (emulator acceptance
for expired/revoked/network paths) is R-3's third.


### Session R-3 — TASK-P1-040-C DONE (2026-10-18)

First production integration of the session state machine. AppRoot
routing now derives `screen` from `SessionStateManager.state`; the
two old `LaunchedEffect`s that read `SecureStorage` on `deviceId` /
`sessionExpiresAt` and set `screen` imperatively are gone. Two
commits:

- `55513f2` — **040-C-1: SessionStateManager.clear() + test.**
  ~5-line method `_state.value = State.Unauthenticated`, plus
  `CLEAR-TRANSITIONS-TO-UNAUTHENTICATED` test. JVM 190 → 191.
  Without `clear()`, `onLogout` would call
  `SessionManager.clearSession()` and the state machine's
  `_state` would stay `Authenticated` — the routing effect would
  keep reporting `Authenticated` with empty storage. The KDoc
  records the deliberate non-cancellation of `reauthInFlight`
  (logout is user-initiated, not 401-triggered; the race window
  is currently unreachable, but the KDoc is the entry point if a
  future flow allows concurrency).

- `11064d6` — **040-C-2: AppRoot routing rewrite.**
  `MainActivity.kt` (~+150/−50), new
  `ui/common/SessionScreens.kt` (~+105). Key changes:
  - `sessionExpiresAt` compose var removed (6 use sites, all
    routing-related; safe per the read).
  - `sessionStateManager = remember(deviceId) { ... }` with
    `AuthOutcome → ReauthOutcome` mapping ruled inline.
  - Three routing effects replace two old ones:
    `LaunchedEffect(deviceId, sessionStateManager)` calls
    `initialize()`; `LaunchedEffect(sessionState, deviceId)`
    derives `screen` from state; `role` is re-read inside the
    Authenticated branch.
  - Four new `AppScreen` objects: `Loading`, `Revoked`,
    `NetworkFailure`, `EnrollmentRequired`.
  - `onLogout` wraps `clearSession() → clear()` in
    `coroutineScope.launch` — fixes the pre-existing
    `CoroutineScope(Dispatchers.IO)` fire-and-forget leak
    (unbounded scope survived navigation past the composable).
  - `onAuthenticated` delegates to
    `sessionStateManager.initialize()` — the state-driven effect
    then routes.
  - `onEnrolled` only updates `deviceId`; the `remember(deviceId)`
    blocks reconstruct and `LaunchedEffect(deviceId)` re-fires
    `initialize()`.

**Design rulings encoded** (documented in commit message and KDoc,
so R-4/R-5 cannot accidentally undo them):

1. **`role` stays compose state, re-read on Authenticated.**
   Extending `State.Authenticated` with role would be scope creep
   on 040-B (state manager's job is session lifecycle, not user
   metadata). The routing effect re-reads `session_role` from
   `SecureStorage` on every Authenticated emission.

2. **State-driven routing preserves Admin/Diagnostics
   sub-navigation.** The Authenticated branch retains the
   pre-existing guard (`if screen !is Admin && !is Diagnostics`)
   so a reauth cycle does not kick the user out of a sub-screen
   mid-flow. All other state branches (terminal, loading,
   Unauthenticated) intentionally preempt sub-navigation.

3. **`AuthOutcome → ReauthOutcome` mapping:** `Success → Success`;
   `Failure("device_revoked") → DeviceRevoked`;
   `Failure("device_key_missing") → EnrollmentRequired`;
   `NotEnrolled → EnrollmentRequired`; `Failure(other codes) →
   NetworkFailure`. The "other codes" bucket includes
   `unauthorized` on purpose — the client cannot distinguish
   `active + sig-fail` from genuine session invalidation on the
   wire. Mapping it to `EnrollmentRequired` would strand users
   for transient issues (clock skew, challenge expiry). Retryable
   is the safer default; ADR §1's "never strand fielded user"
   drives the choice.

4. **`onLogout` uses `coroutineScope.launch` (rememberCoroutineScope),
   not a new unbounded `CoroutineScope(IO)`.** The previous
   implementation fire-and-forgot `clearSession()` on a scope
   that survived navigation — a lifecycle leak. Wrapping in the
   composition-scoped launcher fixes it and lets
   `clearSession() → clear()` sequence deterministically.

**Empirical verification** (smoke on emulator 5556, three real
user flows):

- **Cold launch on valid session** (session expires_at
  2026-10-19T00:56 UTC, device not revoked): app lands
  **Authenticated home** (Conversations tab with existing
  conversation). Backend log at `13:00:31 UTC` (6s after
  `13:00:25` launch) shows `GET /me/matrix` — the state
  machine's `initialize()` transitioned to `Authenticated`, the
  routing effect set `screen = Authenticated`, and the matrix-
  fetch effect fired. **Proves cold-launch path end-to-end.**

- **Log out**: Settings → Log out → **Enrollment screen**
  showing "Device enrolled" + "Authenticate" button (device_id
  preserved, session cleared — correct). Sessions table confirms
  `revoked_at = 2026-10-18 12:55:48` for the pre-logout session
  — `POST /auth/logout` reached the backend.

- **Authenticate**: Enrollment → tap Authenticate → backend
  sequence fires in order: `POST /auth/challenge` →
  `POST /auth/verify` → `GET /me/matrix` all within 1s. State
  transitions Unauthenticated → Authenticating → Authenticated.
  **Proves reauth lambda + state machine + routing + fetch all
  wire correctly.**

**Three diagnostic mistakes during smoke** (recorded so future
sessions don't repeat them; §7 has the general form):

1. A screenshot from Session Q (status bar 1:47, prior day) was
   initially misread as evidence that cold launch worked. The
   timestamps didn't match the diagnostic time.

2. `grep -E "req\."` on backend logs returned empty because the
   JSON format is `"req":{` (colon), not `req.` (period). Block
   6's targeted `/me/matrix` grep was the correct check; the
   "empty block 8" misdiagnosis nearly declared a working app
   broken.

3. `--since 1m` and `--since 10m` windows truncated before the
   actual events on two diagnostic runs.

**Pre-existing findings worth follow-ups** (not introduced by
040-C-2):

- **SQLite connection leak** in logcat during cold launch:
  `SQLiteConnectionPool: A SQLiteConnection object for database
  '...umoja_local.db' was leaked!` fires ~dozens/sec.
  `MessageStore` (or its callers) opens cursors without closing
  them. Filed as a backlog item.

**Scope honestly stated.** R-3 delivered 040-C end-to-end:
`clear()` + routing rewrite + smoke verified against three real
flows. **040-C does NOT exercise 401 → reauthenticate** — that
requires an API call returning 401, which requires 040-D's
interceptor to be wired. 040-E's full acceptance (expired
session, revoked device, network-failure paths) needs both
040-D and the state machine's triggering chain. R-4 opens on
040-D.


### Session R-4 — TASK-P1-040-D DONE (2026-10-18)

HttpClient 401 interceptor wired end-to-end. TEST-SESSION-
REVOKED-ON-DEVICE passed fully — detection (Revoked terminal
screen) and recovery (Log out and try again → Authenticate →
Conversations) both verified on emulator 5556 with backend log
evidence. Three commits:

- `ae1c840` — **040-D-1: HttpClient interceptor + retry
  predicate.** Companion-scoped `on401Handler: (suspend () ->
  String?)?` rather than constructor-injected (13 HttpClient
  construction sites; only AppRoot should own the wiring).
  Handler returns **String? (fresh bearer)** not Boolean —
  critical design point ADR §2 does not specify: the retried
  request must use the fresh token from the state machine's
  reauth, or the retry hits 401 again with the pre-reauth bearer.
  Structural recursion guard via extracted `shouldRetryAfter401()`
  predicate — excludes `/auth/` prefix and `/enrollment`. 7 new
  `TEST-INTERCEPTOR-*` JVM tests. JVM 191 → 198.

- `d835821` — **040-D-2: AppRoot wires HttpClient.on401Handler
  to state machine.** `DisposableEffect(sessionStateManager)`
  registers the handler; onDispose clears it. Keyed on
  sessionStateManager so a deviceId change re-registers against
  the new instance. During reauth, the state machine's transitions
  fire the routing effect so the UI updates transparently.

- `bfe9fee` — **040-D-3: terminal-state honesty fixes
  (Revoked branch + EnrollmentScreen onAuthFailed).** Two bugs
  caught during acceptance, both ADR §1 violations:

  **Fix A — Revoked branch** — preserve device_id, "Log out and
  try again" label. The prior "Re-enroll this device" removed
  device_id, forcing the next enrollment to POST /enrollment with
  the same public_key. Backend's INSERT is pure (consume.ts:61),
  so 23505 on devices_key_unique returns 409
  device_already_enrolled — a dead end. Revocation is a backend
  state change, not a device identity change; device_id and
  Keystore keypair are intact. New action clears session but
  preserves device_id.

  **Fix B — EnrollmentScreen's onAuthFailed callback** —
  Authenticate button in EnrollmentScreen calls
  SessionManager.authenticate() directly, not through the state
  machine. On revoked device, failure was caught locally as
  "Auth error: device_revoked" and stranded the user. New
  `onAuthFailed(code)` callback re-invokes
  `sessionStateManager.reauthenticate()`, which maps the code to
  ReauthOutcome, transitions state, and the routing effect sets
  the appropriate terminal AppScreen. Brief error flash then
  auto-transition to terminal screen (~500ms).

**Chain verified end-to-end** (backend log + logcat + screenshot):

- 3 concurrent 401s (matrix fetch + 2 identity-change polls) →
  single POST /auth/challenge (single-flight held) → 0 POST
  /auth/verify (040-A's device_revoked short-circuit fires at
  challenge before verify)
- Interceptor log: `401 on /me/matrix; reauth failed or terminal,
  returning 401 to caller` (handler returned null for
  State.Revoked)
- Routing effect transitioned screen to AppScreen.Revoked
- Terminal screen rendered with the corrected label ("Log out
  and try again") and corrected message ("request reactivation")

**Nine diagnostic lessons earned** (consolidated in §7):

1. Kotlin block comments nest — `/auth/*` in KDoc opens a
   nested comment, unclosed-comment compile error at EOF
2. `when` branches with multiple statements need `{ }` —
   single-expression branches cannot be extended
3. `devices_key_unique` AND `devices_pkey` both collide on
   re-enroll — delete-and-recreate is the only clean path
4. `information_schema.key_column_usage.referenced_table_name`
   does not exist — `pg_constraint` is the correct FK source
5. `grep "GET /path"` never matches JSON logs — format is
   `"method":"GET","url":"/path"` (separate quoted fields)
6. `grep -E "req\."` never matches JSON logs — format is
   `"req":{` (colon, not period)
7. `--since N` windows truncate before slow events (3rd
   occurrence this project)
8. `Deferred.awaitAll()` returns but does not mutate the
   original list (from R-2, still worth naming)
9. **"OK" from an edit script ≠ "change is correct"** — the
   edit fires before compile; two consecutive compile failures
   this session had `OK:` lines immediately above them

Findings #5, #6, #7 are the same class: **diagnostic patterns
that don't match the actual log format**. Consolidated into one
§7 bullet naming the class, not three separate symptoms.

**State recovery procedure** (documented for the backlogged
bootstrap script): delete a device row requires ordered cleanup
of 6 NO ACTION FK dependents (enrollment_tokens,
org_matrix_versions, identity_change_notices from/to,
identity_change_acks, matrices). The other 9 FKs cascade.
Capture: 8-line transaction, psql heredoc, works.

**Scope honestly stated.** R-4 delivered 040-D end-to-end:
interceptor, wiring, and the two terminal-state honesty fixes
its acceptance exposed. **040-E remains** — the expired-session
test (`TEST-SESSION-APP-START-EXPIRED`) and network-failure
test (`TEST-SESSION-NETWORK-DURING-REAUTH`) still need manual
emulator verification; both require the interceptor in place,
which landed this session. R-5 opens on 040-E.


### Session R-5 — TASK-P1-040-E DONE (2026-10-18)

Final acceptance for TASK-P1-040. Two manual emulator tests, both
passed on the R-4 build with zero code changes. **TASK-P1-040 is
now fully DONE end-to-end.**

**TEST-SESSION-APP-START-EXPIRED** (Path B — server-side expiry):
- `UPDATE sessions SET created_at = now() - interval '2 hours',
  expires_at = now() - interval '1 hour'` on all 3 active sessions
- Cold launch on expired session → silent reauth
- Backend: `challenge=1`, `verify=1` (contrast R-4's revoked test
  where `verify=0` — auth continued past challenge because the
  device is active, not revoked)
- Logcat: `401 on /me/matrix; reauth succeeded, retrying once with
  fresh bearer` ×3 (single-flight collapse of 3 concurrent 401s)
- Post-reauth: 1 new valid session + 3 expired
- UI: **Conversations home**, no button tap
- **Path A (local expiry)** — SecureStorage token past expiry — is
  JVM-verified in 040-B's `TEST-SESSION-EXPIRED-AUTO-REAUTH` but
  **not emulator-reproducible without a debug-only "force local
  expiry" hook**: SecureStorage is AES-GCM encrypted with a
  Keystore-derived key; no `adb shell` path to mutate it. Both
  paths invoke the same `performReauth()`. ADR §2's intent
  ("user shouldn't tap a button because the app has been closed
  for 16 hours") is satisfied by Path B's emulator evidence.

**TEST-SESSION-NETWORK-DURING-REAUTH** (Path B — session cleared +
backend down):
- Log out from Settings → Enrollment with "Device enrolled"
- `docker compose stop backend` (health=000)
- Tap **Authenticate** → `onAuthFailed("network_error")` →
  `reauthenticate()` → network fails → **"Connection lost"
  terminal screen** with Retry + Log out
- Screenshot confirms title, message, primary Retry, secondary
  Log out — matches `TerminalMessageScreen` design
- Crash buffer empty — NetworkFailure is a normal terminal state
- `docker compose start backend` (health=200), tap **Retry** →
  challenge + verify + matrix chain fires → **Conversations home**
- Backend: `challenge=1`, `verify=1` (Retry-triggered reauth
  succeeded)
- Post-reauth: 1 new valid session

**One observation, not a bug:** after a 401-triggered reauth, the
backend sees two `GET /me/matrix` calls — the interceptor's
retry-with-fresh-bearer and the routing effect's
`LaunchedEffect(screen, deviceId)` firing on the
Reauthenticating → Authenticated transition. Both succeed;
`MatrixStore.accept` rejects same-version (rollback guard) so no
duplicate row. Backlogged as a minor optimization (dedupe via a
flag or by keying the fetch effect on a version that only bumps
once per reauth cycle), not a defect.

**What R-5 did NOT do:**
- No code changes — both tests passed first-attempt against the
  R-4 build
- No new JVM tests — NetworkFailure's state transition was already
  JVM-verified in 040-B; only the terminal UI needed manual
  verification

**Full 040 chain closed** — nine implementation commits (db9fe72 A,
f9e01ab B, 55513f2 C-1, 11064d6 C-2, ae1c840 D-1, d835821 D-2,
bfe9fee D-3) plus four handoff commits. Every registry §B
acceptance criterion and required test now accounted for:

| Test | Layer | Status |
|---|---|---|
| TEST-SESSION-EXPIRED-AUTO-REAUTH | JVM (040-B) | pass |
| TEST-SESSION-CONCURRENT-401-SINGLE-REAUTH | JVM (040-B) | pass |
| TEST-SESSION-REVOKED-TERMINAL | JVM (040-B) | pass |
| TEST-SESSION-NETWORK-DURING-REAUTH | JVM 040-B + UI R-5 | pass |
| TEST-SESSION-APP-START-EXPIRED | Manual R-5 | pass |
| TEST-SESSION-REVOKED-ON-DEVICE | Manual R-4 | pass |

**ADR-HARDENING-001 §9 gains a v0.3 entry** (this session's
companion commit) noting 040's completion and the 037-041 chain
being closed except 041.


### Session S-1 — bootstrap-enrollment-token.sh DONE (2026-10-18)

Backlog item filed at Session R-4 close, implemented here.
Eliminates the five-times-recurred manual psql procedure. One
commit.

**`scripts/bootstrap-enrollment-token.sh`** (~250 lines, bash).
Three modes:

- `--device <uuid>` — existing device, token bound to its current
  `public_key`. Use for revoke-and-reauth recovery after admin
  reactivates.
- `--pubkey <b64url>` — fresh enrollment, token bound to a key from
  the app's QR payload. No device row needed — row is created when
  token consumed.
- `--ghost <uuid>` — broken-state recovery. Captures the ghost
  device's public_key, mutates to `ff..ff` (frees
  `devices_key_unique`), marks revoked, issues token bound to the
  captured original. Codifies R-4's manual recovery path.

**Two design rulings** (in script KDoc):

1. Shell, not TypeScript/Python. The `sign-test-*.ts` scripts are
   TypeScript because they share backend crypto. This one has none —
   psql + token_urlsafe + sha256. Python only for two base64url/hex
   one-liners. Language follows scope.

2. GHOST, not DELETE. Full DELETE requires ordered cleanup of 6
   NO ACTION FK dependents (enrollment_tokens, org_matrix_versions,
   identity_change_notices from/to, identity_change_acks,
   matrices). That's a separate "purge device" operation — mixing
   it with "issue token" would make the destructive path too easy
   to trigger accidentally. Purge remains a manual procedure
   documented in §3 Session R-4. Script rejects re-ghosting a
   device whose public_key is already `ff..ff` (the original is
   unrecoverable, user must generate a fresh QR).

**Verification — all three modes tested against the real DB:**

- `--device`: token for 943fbeeb created, `pk_matches_device=t`
  (byte-for-byte 7500bd...), cleaned up.
- `--pubkey`: base64url dQC9F5p... decoded to 7500bd... hex
  correctly, `matches_expected=t`, cleaned up.
- `--ghost`: scratch device with ab..ab key captured, mutated to
  ff..ff + revoked, token bound to original ab..ab, re-run guard
  rejects with clear error, cleaned up.
- Validation: missing --org (exit 1), bad UUID (exit 1), mutually
  exclusive modes (exit 1), missing mode (exit 1) — all named
  messages.
- Cleanup verified: zero scratch devices, zero stray tokens.

**Portability:** `sha256sum` on Linux/GNU, falls back to
`shasum -a 256` on macOS. Both work.

**Counts.** Android JVM 198 unchanged. Backend 250 unchanged.
Script-only session.


### Session T-1 — TASK-P1-041 DONE (2026-10-18)

Failed-verification operator logging. **Closes the 037–041
hardening chain end-to-end.** One implementation commit
(`1baff75`, 10 files, +521/−7) plus the ADR amendment
(`29ff6cc`) and this handoff follow-up.

**VerificationFailureStore.kt** (~150 lines, crypto package):

- Three-way `ArtifactType { MATRIX, NOTICE, ACK }`, bounded
  `FailureEntry { timestampMs, artifactType, reason,
  canonicalTruncated }`
- MAX_ENTRIES = 20 (Phase 1; older entries age out)
- `record / entries / clear / clearOf` — all `@Synchronized`
  (concurrent write sites on Main and IO)
- Single JSON envelope under `verification.failure.log`

**Three write sites wired** via `failureLog:
VerificationFailureStore? = null` optional constructor param —
default-null is invisible to existing tests, construction sites,
and callers. Production wires at MainActivity's three sites:

- `MatrixStore.accept` — all four Rejected reasons
- `ReplacementNoticeStore.recordNotice` — Invalid signature +
  malformed
- `IdentityChangeController.ackAndPost` — all three Failure paths

**Filtered clear** (`clearOf`) — registry §B requires
matrix-store wipe to clear only matrix-failure entries;
`MatrixStore.clear()` calls `clearOf(MATRIX)` and
`ReplacementNoticeStore.clear()` calls `clearOf(NOTICE)`. Full
`clear()` is reserved for the DiagnosticsScreen debug control
where the operator wants a full-wipe view.

**Reactivity — third instance of the write-notification
pattern.** `VerificationFailureStore.version: StateFlow<Long>`
bumped on record / clear / clearOf. DiagnosticsScreen collects
via `collectAsState` and remember-keys the entry list on it.
Precedents: `IdentityChangeController.version` (Session K) and
`MatrixStore.version` (Session P D-1). Third instance
establishes the pattern as a codebase convention (§7 bullet
below).

**DiagnosticsScreen** — new "Verification failures (debug)"
section after Matrix (debug). Empty state: "No failures
recorded." Non-empty: reversed newest-first list of
`artifactType · reason · fingerprint @ HH:MM:SS` in monospace
plus "Clear failure log" button. Fingerprint =
`base64url(canonical).take(8)` matching AckDialog precedent.

**Tests — 14 new (Android JVM 198 → 212):**

`VerificationFailureStoreTest` (10, isolated):
- record/entries roundtrip, expected fields
- trim to MAX_ENTRIES, oldest-first
- empty state, clear-all, clearOf filtering both directions
- clearOf on absent type does not error
- empty canonical → empty fingerprint
- malformed JSON resilience, recovery-after-malformed

Wiring tests (4, in existing test files):
- `TEST-DIAG-VERIFICATION-FAILURE-LOGGED` (matrix) —
  registry-named
- `TEST-DIAG-VERIFICATION-LOG-CLEARED-ON-WIPE` (matrix) —
  registry-named
- `TEST-DIAG-NOTICE-FAILURE-LOGGED` (notice) — supporting
- `TEST-DIAG-ACK-FAILURE-LOGGED` (ack) — supporting

**Emulator acceptance** (all pass):
- Settings → Diagnostics → Matrix (debug)
- Paste bad canonical + signature → tap Verify and store
- Observed: `Rejected(signature)` + `matrix · signature ·
  AAAAAAAA @ 12:13:02` in the new section
- Tap Clear failure log → "No failures recorded" (reactivity
  proof — section updates without navigation)

**§7 additions earned** (three):

1. **Write-notification pattern is now a codebase convention.**
   Three instances: `IdentityChangeController.version` (K),
   `MatrixStore.version` (P D-1),
   `VerificationFailureStore.version` (T-1). When a fourth store
   class needs to notify observers, use
   `MutableStateFlow<Long>` + `StateFlow<Long>` + bump on every
   write + `collectAsState` + remember-key. Not "consider" —
   assume.

2. **Kotlin call-site edits with trailing-comma style defeat
   exact-string anchors.** Three attempts this session: paren-
   matcher appended after a trailing comma → double comma;
   whitespace anchor missed 24 leading spaces → ABORT with
   `count=0`; **line-level manipulation using the file's own
   indentation** → fixed. Rule: for multi-line call sites,
   anchor on stripped-content of the target line and compute
   indentation from the previous line; never paste whitespace
   into a Python string.

3. **Compile is the acceptance for Kotlin source; grep "^e:"
   not `tail -4`.** Three compile failures this session, three
   named errors, three one-line fixes: `/auth/*` nested-comment
   in R-4; `when` branch without `{ }` in R-4; missing
   `collectAsState` import in T-1. `tail -4` hides the error
   list; `grep "^e:"` shows every error at line:col. Zero
   guessing when the compiler reports precisely.

**Commit-split note:** `29ff6cc`'s message describes both the
ADR amendment and this handoff close, but only the ADR landed
(the handoff edit aborted on a prose anchor in the same Python
script). This follow-up commit lands the handoff edits with
range-based structural anchors. Same class as Session C's
`8adde6b` (commit message overstates scope); not amended
because already pushed. The correct fix is the follow-up with
honest framing, not a force-push.


### Session U-1 — MessageStore leak + backlog hygiene (2026-10-18)

One real defect fixed, three backlog items closed. Three commits.

- `644d5cf` — **SQLite connection leak fixed.** LocalDatabaseHelper
  was a per-instance SQLiteOpenHelper; 5 MessageStore construction
  sites across the app (ChatViewModel.refresh,
  ConversationsScreen's LaunchedEffect, MessagingService x3),
  **0 .close() calls anywhere**. Each construction opened its own
  SQLiteDatabase handle; GC logged "was leaked!" via
  SQLiteConnectionPool. Fix: LocalDatabaseHelper gains a
  companion singleton accessor (`LocalDatabaseHelper.get(context)`)
  with @Volatile + double-checked locking; MessageStore's `helper`
  field reads it. All MessageStore instances share one database
  handle, one connection pool, no per-instance leak.

  **Reproduction and verification:**
  - Baseline (cold launch to Conversations): 0 leaks
  - Enter ChatScreen + Home key (triggers GC of
    ChatViewModel's MessageStore) + wait 4s: **2 leaks**
  - After fix, same flow: **0 leaks**
  - After fix, 3 additional ChatScreen visits: **0 leaks** (proves
    the singleton holds under repeated MessageStore construction,
    not just one instance)

  The `MessageStore.close()` method remains (unused, valid escape
  hatch for future explicit lifecycle management).

- `[KI-008 hash]` — **canonicalJson extracted** to
  backend/src/audit/canonicalJson.ts. Byte-identical function was
  duplicated in audit/log.ts (write path) and audit/verify.ts
  (verify path); drift would silently break every audit chain
  verification with a misleading "broken_at: N". Extraction with
  KDoc documenting the shallow-sort pre-existing concern (nested
  payload keys could reorder via Postgres JSONB; fixing it would
  require a chain migration, not a small fix; out of scope).
  Backend 250/250 passing proves write and verify paths still
  agree on HMAC.

- `[KI-016 hash]` — **crypto validation helpers extracted** to
  crypto/Base64UrlValidation.kt. Three private copies
  (ProvisioningBundle, AuthorizationMatrix, ReplacementNotice)
  consolidated to one shared `internal` definition. Scope bounded:
  PRINTABLE_ASCII_RE / requirePrintableAscii stays in PB;
  ISO8601_UTC_RE / requirePositiveInt / requireStringList stays in
  AM; EnrollmentQrPayload's variant stays put (different regex +
  input type -- genuine different validation). KDoc records
  Session F's `RN_` prefix discipline as superseded by extraction
  (the discipline defended against wrong-file references when
  three file-private copies existed; one shared definition
  eliminates the state that required the prefix).

  Verification: ProvisioningBundleTest 16/16, AuthorizationMatrixTest
  23/23, ReplacementNoticeTest 7/7 -- the three validation
  consumers still pass, proving byte-identical behavior.

- **KI-018 marked RESOLVED** (doc-only). Session C landed
  `backend/migrations/013_org_matrix_versions.sql` +
  `backend/src/admin/matrixVersions.ts` on 2026-10-16. §4 of this
  handoff still says "(NEW)". This session fixes that staleness.
  No code change.

**Four §7 additions earned** (from actual failures this session):

1. **If a class has `close()` and grep finds zero call sites,
   either the class is a leak or `close()` is a design lie.**
   The MessageStore leak had this exact signature:
   `close() { helper.close() }` existed, nothing called it,
   `LocalDatabaseHelper(context)` opened a fresh handle per
   MessageStore construction, ~0 close calls. Audit `close()`
   call sites as a first-class check, not an afterthought. Same
   class as R-3/R-4's diagnostic-pattern-grep lessons (a grep
   that finds zero can mean "not used" or "not wired").

2. **Byte-identical private helpers across files are a drift
   hazard, and extraction beats the RN_-prefix defense.**
   Session F's `RN_` prefix was a valid local-edit-time
   discipline when three file-private copies existed
   (`RN_requireBase64Url32` couldn't silently resolve to
   AuthorizationMatrix's copy). Once extraction leaves one
   shared `internal` definition, the discipline's purpose is
   served by construction -- there's nothing to confuse.
   **Supersession is the correct response to extraction, not
   preservation.**

3. **The `tail -N` family of commands truncates diagnostic
   output in exactly the way that hides errors.**
   Consolidated from T-1 and reinforced this session: `grep
   "^e:"` on the compiler output is the acceptance; `tail -4`
   hides the error list. Same class as `--since N` (R-3/R-4)
   truncating windows before slow events. All three are
   output-truncation failures.

4. **Brace-walk removal beats fixed-string function removal
   in Python edit scripts.** Three attempts in U-1: exact-string
   `replace()` on `requireBase64Url32` failed because PB's body
   has single-line exception formatting but AM's had multi-line
   (from the exact same visual shape in the earlier read).
   Robust alternative: find header line, walk brace depth to
   find closing brace, replace the whole function block. Works
   regardless of body formatting. Same class as T-1's
   line-level-manipulation fix for call sites.

**Deferred to U-2** (backlog hygiene continued):

- Migration 017: `enrollment_tokens.used_by_device_id ON DELETE
  SET NULL`. Schema change with a design decision (SET NULL vs
  CASCADE vs NO ACTION preserves audit chain); deserves its own
  focused session.
- Double-matrix-fetch dedupe (R-5 §7 note). Requires StateFlow or
  fetch-flag design; risk of new reactivity bug exceeds the
  payoff of one saved round-trip.

**Counts.** Android JVM 212 unchanged (deduplication preserves
behavior; the tests prove it). Backend 250 unchanged. Full-suite
green after every command.


### Session U-2 — backlog finish (2026-10-18)

Two code+doc commits + one handoff. **Backlog closed except for
standing conditions** -- three items actioned, three named as
standing, none silently deferred.

- `3b0c33a` -- **Migration 017:
  `enrollment_tokens.used_by_device_id` FK gains `ON DELETE SET
  NULL`.** Session R-4's observation became a real fix. Before:
  deleting a device that had consumed a token failed on the FK
  (confdeltype 'a' = NO ACTION). Every backend test worked around
  this by deleting tokens before devices in `afterAll` --
  load-bearing workaround, not design. After: token row survives
  with `used_by_device_id` nulled; `used_at` preserved (audit
  trail intact). New test
  `TEST-MIGRATION-017-DEVICE-DELETE-PRESERVES-TOKEN` exercises
  the full lifecycle. TEST_ORG_ID = `0d1` (grep'd first per
  Session C's discipline). Backend 250 → 251 (+1 test, 20 files).

- `2bb3cf3` -- **`docs/reference/USER-ONBOARDING.md` written.**
  Referenced by Build Master §2 and §3.4 since before Session A;
  absent until now. 241 lines, 1430 words, user-facing companion
  to the implementer-facing specs. Different register, same claims;
  every major claim carries a `Source:` line. All four recovery
  states from ADR-HARDENING-001 §1 documented. Cryptographic
  erasure guarantee preserved verbatim (the "does **not**
  guarantee physical recovery" caveat is intact -- overclaiming
  here would be the exact drift the spec exists to prevent).
  Cross-references to all five authoritative docs verified to
  resolve on disk. Closes KI-006.

**KI-005 marked STANDING CONDITION** (not closed as a task).
"Requirements layer authored after code; conformance sweeps have
been partial" describes project state, not a discrete task. A full
conformance sweep would be multi-session: re-read four canonical
docs against code and close gaps. No such sweep is scheduled.
Standing condition = accepted as the current state of the project,
not a defect to be closed. If a future session runs the sweep, that
session replaces this entry with the findings.

**Two items named as standing deferrals:**

- **Double-matrix-fetch dedupe (R-5 §7 observation).** The fix
  requires a new StateFlow or previous-state tracking on the routing
  effect; current cost is one saved HTTP round-trip per reauth
  cycle (2 fetches instead of 1, both succeed, `MatrixStore.accept`
  rejects same-version). **Cost of fix > payoff.** Revisit only if
  reauth frequency becomes measurable perf burden.

- **Instrumented Compose tests for admin flows.** Requires adding a
  Compose test rule to the build config. Belongs in a dedicated
  test-coverage session, not backlog hygiene. Zero fielded-user
  impact; the Android JVM suite (212 tests) plus manual emulator
  acceptance covers the flows.

**No new §7 additions this session** -- U-2 was mechanically
straightforward. The U-1 §7 additions
(close()-with-zero-callers, extraction-supersedes-prefix,
truncation-commands, brace-walk) covered everything U-2 hit.
Recording that so a future reader doesn't wonder why this
session's §7 count is zero -- it means the previous additions
applied cleanly, not that the session was less rigorous.

**Counts.** Backend 250 → 251 (+1 migration-017 test). Android
JVM 212 unchanged (doc + backend migration; no Android touch).

**Project state at U-2 close:**

No blocking work. The 037-041 hardening chain closed at T-1. The
one real defect (SQLite leak) fixed at U-1. Three dedup/extraction
backlog items closed at U-1 and U-2. USER-ONBOARDING.md closed at
U-2. What remains is Phase 2 preparation (choice, not obligation)
and standing conditions (KI-005, double-fetch, instrumented tests).


### Session U-3 — KI-005 sweep: AUTH-SPEC-001 v0.1 → v0.2 + TASK-P1-042 filed (2026-10-18)

First document of the KI-005 four-document conformance sweep. Method:
read every auth-related file at HEAD, compare each spec claim against
actual behavior, classify each divergence. Doc-only session; no code
written, no tests run. One commit:

- `349b268` — **AUTH-SPEC-001 v0.1 → v0.2 + TASK-P1-042 filed.**
  Four claims amended to match code, one real gap filed, three
  hypotheses refuted. US-TASK-P1-001 v0.6 → v0.7 (total count
  42 → 43).

**Sweep verdict.** One real gap (F13): §9.3 defense (2) — "full
reconciliation on listener reconnect" — is unimplemented.
`ws/revocation.ts`'s `on('error')` handler logs but does not
reconnect or re-reconcile. Mid-run listener drops are covered by
the 5-minute revalidation cycle (defense 3), not by
reconciliation-on-reconnect. The WS-close timing claim in §9.2 is
≤5s when the listener is healthy, ≤5min when it's disconnected.
Filed as TASK-P1-042 with three named tests.

Two doc-drift findings. §10.2 floor nullability: migration 014's
nullable-INTEGER-with-CHECK is correct; the spec's `NOT NULL` would
make fresh-org first enrollment impossible. §10.3 consumption
mechanism: `SELECT FOR UPDATE` + INSERT + UPDATE inside
`withTransaction`; single-consumer property holds, the spec's
single-UPDATE prose was wrong.

One precision finding. §6.2 gains v0.2 notes on the 64-byte sig
length check, the `public_key_alg !== 'ed25519' → 501
unsupported_algorithm` branch, and the `session_context` field
(always null in Phase 1, but in canonical bytes).

**Three hypotheses from the prediction table refuted by reading:**

1. §10.3 atomicity "hole" — `FOR UPDATE` serializes; no TOCTOU.
2. §6.3 revalidation "hole" — the 5-min revalidation loop IS a real
   `setInterval` in `ws/server.ts`, not replaced by 040's reactive
   auth.
3. §9.2 LISTEN/NOTIFY "hole" — exists in `ws/revocation.ts`,
   started from `src/server.ts:14`, fired by `admin/devices.ts:95`
   on revocation. My block-2 conclusion of "no LISTEN/NOTIFY
   anywhere" was a scope error: read `ws/server.ts` alone,
   concluded about `ws/` as a directory. `ws/revocation.ts` sat
   next to it unread.

**The refutation worth remembering.** Two of the three predicted
"holes" were false because the code is more careful than the spec
prose. The real gap (F13) was the one I hadn't emphasized —
reconciliation-on-reconnect was named in the spec, but I didn't
read `ws/revocation.ts`'s error handler carefully enough to catch
it until block 4. Same shape as Session P's D-1 finding: the case
that distinguishes correct from sticky-open is the one not in the
initial hypothesis set.

**Scope honestly stated.** One document of four swept. Remaining:
US-ADD-001, US-MASTER-001, THREAT-MODEL-001. Each is same-shape
reconnaissance (session per document). No blocking work depends on
any of them.

### Session V-1 — KI-005 sweep: THREAT-MODEL-001 v0.1 → v0.2 (2026-10-18)

Second document of the KI-005 four-document conformance sweep
(AUTH-SPEC-001 was first, Session U-3). Method: read the doc
verbatim, inventory every specific claim, read the actual code the
claim references, classify. Doc-only session; no code, no tests.
One commit:

- `5655318` — **THREAT-MODEL-001 v0.1 → v0.2.** Eight amendments
  across six sections, one real gap cross-referenced, ten claims
  verified holding.

**Sweep verdict — a different shape than U-3.**

AUTH-SPEC-001 (U-3) was almost entirely *shipped behavior*: findings
were mostly precision corrections to prose that described the actual
code imprecisely. The one real gap (reconciliation-on-reconnect)
came from a claim that described intended-but-unimplemented behavior.

THREAT-MODEL-001 spans a broader surface that includes **design
intent for unimplemented features.** Three of its six threat
sections (§6.3 duress wipe, §6.4 wipe notification, §6.7
rotation/recovery) describe Phase 1 features that are specified but
not shipped:

- §6.3 — TASK-P1-021b status "Updated"; the wipe-confirmation key
  exists (Session A, `8bd4ab5`), the destroy-keys-in-≤5s flow is
  designed but not built.
- §6.4 — same dependency; no backend endpoint accepts a wipe
  notification and no client sends one. Zero `device_reported_wipe`
  matches in either codebase.
- §6.7 — TASK-P1-036 status "Proposed"; `ProvisioningKeys.kt`
  carries structural seams but no notice handler, no
  `key_rotation`/`key_revocation` parsing exists.

**This required a fourth classification bucket in the sweep
methodology: `completeness`** — prose describes a feature the code
doesn't yet implement. Not "doc-drift" (code contradicts prose); the
prose is the target and the code is behind. The v0.2 amendments
mark these `planned-not-shipped` with current-state notes rather
than weakening the claims — the doc keeps its authority as the
design spec while stating what's actually true today.

**Two doc-drifts found:**

- §6.2 consumption mechanism: v0.1 described a single
  `UPDATE ... RETURNING`. Actual: `SELECT ... FOR UPDATE` →
  `INSERT INTO devices` → `UPDATE enrollment_tokens`, inside
  `withTransaction`. **Same correction U-3 made to AUTH-SPEC-001
  §10.3 v0.2.** The doc-drift was already corrected in a sibling
  document; V-1 propagated the fix.
- §8 reconciliation query: v0.1 said `status = 'revoked' AND
  revoked_at > last_reconciliation_time`. Actual: unconditional
  `SELECT device_id FROM devices WHERE status = 'revoked'`. No
  incremental filter.

**One real gap cross-referenced (not re-filed):**

§8's "full reconciliation on listener reconnect" — same gap
AUTH-SPEC-001 §9.3 defense 2 named. `ws/revocation.ts`'s
`on('error')` handler logs but does not reconnect or re-reconcile.
Mid-run coverage is via the 5-minute revalidation timer (defense
3), not reconciliation-on-reconnect. Cross-references the existing
TASK-P1-042 rather than filing a duplicate.

**One precision amendment:**

§5 STRIDE R-repudiation cell said "audit log, hash-chained
(TASK-P1-031)". Actual: the chain is implemented in
`audit/log.ts` (HMAC + `pg_advisory_xact_lock`, verified end-to-end
at U-1's extraction); TASK-P1-031 tracks the *verification
endpoint* (`GET /admin/audit/verify`), not chain creation. Amended
to name both.

**Three predicted holes refuted by reading:**

1. §6.2 mechanism — assumed wrong; was, but *already corrected* in
   AUTH-SPEC-001 v0.2. Sibling-doc drift propagation.
2. §7 pinned-key assertion — assumed incomplete; fully implemented
   in `ProvisioningKeys.kt` (both pubkeys + `highest_recovery_key_
   version` slot).
3. §9 composition with AUTH-SPEC-001 — assumed decoupled; verified
   correctly coupled (`pub_device_auth_key` and
   `pub_messaging_identity_key` remain distinct keys in distinct
   systems; matrix cannot conflate them).

The refutation shape is the same as U-3's: the case that
distinguishes correct from sticky-open was not in the initial
hypothesis set. §6.2 looked wrong (it was, corrected elsewhere);
§8 reconciliation looked fine in prose but the *query shape* was
wrong; the completeness markers in §6.3/§6.4/§6.7 were visible
only after checking task status.

**Cross-document propagation as a sweep discipline.** §6.2's fix
duplicates U-3's AUTH-SPEC-001 §10.3 fix because both docs made the
same claim about the same code. **This is the pattern the sweep
exists to catch** — when a claim is corrected in one doc, sibling
docs with the same claim need the same fix *in the same pass*, not
in a follow-up session. V-1 grep'd the doc set for the offending
claim's phrasing before closing (see §7 addition below).

**Scope honestly stated.** Two of four documents swept
(AUTH-SPEC-001, THREAT-MODEL-001). Remaining: US-ADD-001,
US-MASTER-001. Each is one session of reconnaissance-plus-
amendment. No blocking work depends on any of them.


### Session W-1 — KI-005 sweep COMPLETE: US-ADD-001 v0.3 + US-MASTER-001 v0.2 (2026-10-18)

Third and final KI-005 sweep session (U-3 AUTH-SPEC-001, V-1
THREAT-MODEL-001, W-1 both). Two documents in one session because
Command 1's size preflight showed combined 512 lines (US-ADD-001
275, US-MASTER-001 237) — the size check itself determined the plan
rather than guessing. Two commits:

- `20771af` — **US-ADD-001 v0.2 → v0.3.** Seven amendments: four
  completeness markers on parameter-register rows (§5
  `Local storage | SQLCipher`, §5 `Tor | tor-android embedded`,
  §6 `Enrollment attestation | Android Key Attestation`, §7
  `Recovery key version` — all describe build-time targets not yet
  shipped), header version bump, revision history v0.3 row, and a
  pre-existing staleness fix (end-of-doc line said v0.1 while header
  was already v0.2).

- `3720b59` — **US-MASTER-001 v0.1 → v0.2.** Five amendments: §3.5
  cross-document propagation of THREAT-MODEL-001 §8's
  reconciliation-drift correction (same gap, same code,
  cross-references TASK-P1-042); §7 canonical document set gains
  `USER-ONBOARDING.md` (written Session U-2, referenced by Build
  Master §2); version bump, revision history v0.2 row,
  end-of-doc line.

**Sweep verdict — the parameter-register-vs-architecture split.**

US-ADD-001 and US-MASTER-001 have fundamentally different finding
shapes:

- **US-ADD-001 is a register** — mixed current-state assertions
  (§4 backend params all accurate: Node 24, Fastify 5.12.5,
  PostgreSQL 16) and build-time-target assertions (§5/§6/§7
  describe Phase 1 target stack as if in place). Four completeness
  markers resulted, none behavioral. This is the **parametric form
  of completeness** — different from THREAT-MODEL-001's behavioral
  form (§6.3/§6.4/§6.7 described features as shipped; US-ADD-001
  described stack as current). Both are `completeness`; the
  amendment shape differs (behavioral → "planned per TASK-P1-YYY";
  parametric → "current: X, target: Y, pending Z").

- **US-MASTER-001 is a summary** — its §3.1-£3.6 restate AUTH-SPEC-001,
  THREAT-MODEL-001, and ADR-PROVISIONING-001. When those sources
  drift, US-MASTER-001's restatement drifts too. Its only finding
  was §3.5 propagating THREAT-MODEL-001 §8's reconciliation-drift
  correction. **Found via V-1's cross-document propagation
  discipline, applied as W-1's first action.**

**V-1's cross-document propagation discipline worked as designed.**
V-1's §7 addition said "grep the doc set for the offending phrase
before closing the sweep." W-1 opened with exactly that grep
(`grep -r 'on listener reconnect' docs/`) and found US-MASTER-001
§3.5 in one shot, ~20 lines into the sweep. Reading US-MASTER-001
in isolation would not have found this — the summary was internally
consistent with its own sections; the drift is only visible against
the sibling document's correction. **Discipline notes in §7 earn
their value when the next session reads them before the writes
start, not after.**

**Refuted predictions from the pre-sweep hypothesis set:**

- US-ADD-001 §3.1's Phase 1 in-scope list including TASK-P1-021a
  and TASK-P1-021b looked like a completeness finding — verified
  it's a *scoping decision*, not a status claim. Scoping a Phase 1
  feature as in-scope while the task is queued is accurate; only
  behavioral claims ("the app wipes in ≤5s") would be findings.
- US-ADD-001 §4 (backend parameters) looked like it would drift —
  verified all accurate against the actual stack.
- US-ADD-001 §7 (cryptographic protocol) looked like it would
  drift — verified all rules hold (JCS, SHA-256 digest, Ed25519
  over digest, base64url, monotonic version, enrollment floor,
  recovery version monotonicity is designed but not exercised —
  that last one is the §7 completeness marker).

**The completeness bucket's parametric form is a new pattern.**
V-1 introduced `completeness` for "prose describes a not-yet-shipped
behavioral feature." W-1 discovered the parametric form: "prose
describes a target stack/value as current." Same classification,
different amendment shape. See §7 addition below.

**Scope honestly stated.** Four of four documents swept.
AUTH-SPEC-001 v0.2, THREAT-MODEL-001 v0.2, US-ADD-001 v0.3,
US-MASTER-001 v0.2. KI-005 is RESOLVED.

**What the full sweep produced:**

| Class | Count | Locations |
|---|---|---|
| Doc-drift | 4 | AUTH-SPEC-001 §10.3 mechanism; THREAT-MODEL-001 §6.2 mechanism + §8 query; US-MASTER-001 §3.5 cross-doc; US-ADD-001 stale end-of-doc line |
| Real gap cross-ref | 1 | THREAT-MODEL-001 §8 reconciliation-on-reconnect — TASK-P1-042 (filed at U-3, reconfirmed at V-1, propagated to US-MASTER-001 §3.5 at W-1) |
| Completeness (behavioral) | 3 | THREAT-MODEL-001 §6.3 duress wipe, §6.4 wipe notification, §6.7 rotation |
| Completeness (parametric) | 4 | US-ADD-001 §5 SQLCipher, §5 Tor embedded, §6 enrollment attestation, §7 recovery version |
| Precision | 2 | AUTH-SPEC-001 §6.2; THREAT-MODEL-001 §5 P1-031 scope |
| Cross-doc completeness | 1 | US-MASTER-001 §7 missing USER-ONBOARDING.md |
| Holds | ~30 | Across all four docs |

One new task could have been filed (P1-042 already existed from U-3);
zero new tasks filed in W-1. One document under `USER-ONBOARDING.md`
mentioned as needed (U-2 wrote it; the sweep confirmed its inclusion
in US-MASTER-001 §7).


### Session X-1 — TASK-P1-042 DONE: WS revocation listener reconnect + re-reconcile (2026-10-18)

**The one real gap identified across the KI-005 sweep, closed.**
Fix + tests at `07cc2b4`; three doc amendments at `ed47e7a`
(AUTH-SPEC-001), `f2371c0` (US-MASTER-001), `5259aec`
(THREAT-MODEL-001). Code change + doc amendments in one session
because the docs' current "filed as P1-042" notes were stale the
moment the fix shipped.

**The gap.** `ws/revocation.ts` opened one LISTEN connection and
reconciled once at process startup. On connection loss the
`error` handler logged but did not reconnect; reconciliation
never ran again. A device revoked during the listener-disconnected
window stayed connected until the next 5-minute revalidation
cycle — violating the ≤5s closure guarantee for that window.
Named in three docs at their v0.2: AUTH-SPEC-001 §9.2/§9.3,
THREAT-MODEL-001 §8, US-MASTER-001 §3.5.

**The fix.** Extracted the listener into
`createRevocationListener(deps)` factory with injected `connect` /
`reconcile` / `scheduleReconnect` / `cancelReconnect` /
`onNotification` / `logger`. The factory:

- **Reconnects on `end` event, not `error`** — pg emits both on
  connection loss; `error` fires on transient issues that don't
  always mean disconnect. `end` is definitive.
- **Reconciles on every successful connect** — startup is a
  connect; reconnects are connects; same reconcile path. Task
  acceptance: "reconciliation runs before the listener resumes
  consuming notifications."
- **Reconcile ordering intentional** — LISTEN first, then
  reconcile. A revocation during the gap is caught by the
  reconcile query; a revocation after reconcile-start fires the
  notification handler. No window where both are off.
- **`stop()` cancels pending reconnect** — both at post-await and
  timer-fire via `isStopping` guard; a stop-mid-connect releases
  the client without storing it.
- **5-min revalidation cycle untouched** — per task non-goals;
  remains the independent mid-run backstop.

Production wiring at file bottom with real deps. Exports
`startRevocationListener` / `stopRevocationListener` /
`notifyDeviceRevoked` unchanged — zero call-site churn in
`src/server.ts` and `test/ws.test.ts`.

**Tests (3 named, per registry).**
`TEST-REVOCATION-RECONNECT-ON-ERROR` (connect throws, timer
advances, second connect succeeds);
`TEST-REVOCATION-RECONCILES-AFTER-RECONNECT` (connect,
`error` + `end` emits, timer advances, `reconcileCount` goes
1 → 2); `TEST-REVOCATION-STOP-CANCELS-RECONNECT` (connect fails,
reconnect pending, `stop()` cancels, advancing timers does not
re-connect). `vi.useFakeTimers()` + real `setTimeout` in the
harness lets `vi.advanceTimersByTimeAsync(5000)` fire the
reconnect AND await its continuations — assertions see
fully-executed state, not a racy snapshot. Backend 251 → 254 (+3).

**Doc amendments.** Each of the three sweep-named docs gets a
v0.3 commit:
- AUTH-SPEC-001 (`ed47e7a`): §9.2 listener-disconnected row
  updated to reflect the reconnect mechanism; §9.3 defense 2
  rewritten to describe fixed behavior with cross-reference to
  commit.
- THREAT-MODEL-001 (`5259aec`): §8 v0.2 correction blockquote
  gains a v0.3 fix blockquote. **End-of-doc line also fixed** —
  V-1 left it at "v0.1" while bumping the header to v0.2 — same
  class as US-ADD-001's stale end-of-doc line fixed at W-1.
- US-MASTER-001 (`f2371c0`): §3.5 v0.2 correction blockquote
  gains a v0.3 fix blockquote.

**The three-doc cross-reference is now a fix-reference, not a
"filed as" placeholder.** U-3 filed P1-042, V-1 seconded the gap
from THREAT-MODEL-001, W-1 propagated it to US-MASTER-001. X-1
fixed it and amended all three docs to say "fixed at 07cc2b4"
instead of "filed as P1-042." **The sweep's mechanism carried all
the way to a code fix** — naming the gap in three docs is what
made it hard to lose.

**§7 additions from this session:**

1. **Per-block preflight is not a top-level abort.** A shell
   block with multiple `python3 <<'PYEOF'` heredocs runs each
   independently. A top-level preflight that `sys.exit`s stops
   only its own process; the shell continues to the next
   heredoc. Session X-1's Command 5 demonstrated this: the
   top-level preflight failed on THREAT-MODEL-001's end-of-doc
   anchor, but the AUTH-SPEC-001 and US-MASTER-001 write blocks
   each ran because their own internal anchors passed, while
   THREAT-MODEL-001's write block aborted on its own check.
   Two of three files landed. The advisory
   `PREFLIGHT FAILED — no writes will run` message was literally
   false. **Fix: `set -e` at the top of the shell block, or a
   single Python process per file (all-or-nothing per file), or
   one process for the whole batch. The advisory line pattern
   is misleading — drop it or `set -e`.** Command 8 (this
   session close) uses `set -e`.

2. **End-of-doc version lines are a staleness surface separate
   from header and revision history.** V-1's THREAT-MODEL-001
   v0.1 → v0.2 bump updated the header and revision-history row
   but left `— end of THREAT-MODEL-001 v0.1 draft —` unchanged.
   X-1's v0.2 → v0.3 bump assumed the line was v0.2 and the
   preflight failed on that assumption (fixed in the corrected
   Command 6, which anchored on the actual `v0.1` text). W-1's
   US-ADD-001 v0.2 → v0.3 bump caught the same staleness
   because its end-of-doc anchor was `v0.1` and the file
   actually said `v0.1` — accidental alignment, not prevention.
   **Rule for any version-bump commit: preflight all three
   surfaces — header (`^Version:`), revision-history row
   (`| X.Y |`), end-of-doc line (`— end of DOC vX.Y draft —`).
   When one is stale relative to the others, fix the staleness
   in the same commit that bumps the others; don't ship a bump
   that leaves the file's own version metadata inconsistent
   across sections.**

**Counts.** Backend 251 → 254 (+3 named tests). Android JVM
212 unchanged. androidTest 46 unchanged.

**Project state at X-1 close.** No blocking work. The 037-041
hardening chain closed at T-1. The one real defect (SQLite leak)
fixed at U-1. Three dedup/extraction backlog items closed at
U-1/U-2. KI-005 (conformance sweep) closed at W-1; **the sweep's
one real gap (P1-042) closed at X-1.** The sweep's findings are
fully resolved. Remaining: Phase 2 preparation (choice) and the
three standing conditions (double-fetch dedupe, instrumented
Compose tests, KI-005 re-sweep cadence as needed). No task in
the registry is `Proposed` for a blocking gap.


### Session Y-1 — doc-hygiene pass closing X-1's own last paragraph (2026-10-18)

X-1's close file named two §7 lessons as "belong in §7 at the next
handoff edit" and left three other documentation staleness items
unlanded. Y-1 closes all of it in one bounded doc-hygiene commit.
No code, no tests, no registry changes, no new tasks.

**Fixes in this session:**

1. **Two pending §7 lessons added** — the ones X-1's close
   explicitly named as still-owed:
   - `set -e` + `grep -c` returning 0 aborts the shell (the
     Command 8 failure mode).
   - Regex capture-group substitutions lie silently when a group's
     role is misread (the `ad2187d` `DONEProposed` bug, fixed
     at `bf5faf1`).

2. **§2 backend count corrected** — was "247 tests passing
   (16 files; verified 2026-10-17)", stale from Session O-1. Now
   "254 tests passing (20 files; verified 2026-10-18)". §2 is a
   summary index; §3 session entries are authoritative for what
   each session added.

3. **§7 Current verified state corrected** — was "251 backend
   tests (2026-10-18, 20 files)", stale from W-1's close (the
   three TASK-P1-042 tests added at X-1 weren't reflected). Now
   "254 backend tests (2026-10-18, 20 files)".

4. **R-4's `bfe9fee` placeholder filled** — two
   occurrences at §3 Session R-4 entry's commit list (line
   ~2209) and §5 item 16's cross-reference (line ~3819). Both
   replaced with `bfe9fee`. A two-character fix per occurrence
   that removes a fresh-reader stumbling block; the placeholder
   was correct at write-time (before `bfe9fee` existed) and stale
   by X-1's close.

**Scope explicitly NOT expanded:**

- §2's full backend prose is not rewritten to reflect each of
  R-2 through X-1's test additions. §2 is a summary index; §3
  is authoritative. Rewriting would double §2's length for no
  reader benefit.
- KI-005's RESOLVED state untouched (correctly resolved at W-1).
- The KI-005 sweep not reopened — all four docs swept, one real
  gap closed at X-1.
- Phase 2 not proposed — Y-1 is doc hygiene; Phase 2 is a
  separate choice.

**The pending-lessons pattern this closes.** X-1's close file
said the two lessons "belong in §7 at the next handoff edit" and
shipped anyway. That's a defensible deferral — the primary task
was done; the two lessons were a follow-up edit. But the
deferral means a fresh session reading the handoff would not see
them. **Rule for future sessions:** when a session entry names a
doc-hygiene item as "the next handoff edit," either land it in
the same commit (making the entry self-contained), or explicitly
file the pending item as a backlog entry so it survives the
session boundary. A sentence in the close file is not a
persistent tracker; the handoff is.

**Counts.** Backend 254, Android JVM 212, androidTest 46 — all
unchanged (doc-only session).



### Session Z-1 — two standing deferrals addressed (2026-10-18)

Both U-2 standing deferrals closed or re-scoped on evidence, not
convenience. Two commits:

- `2637610` — **Double-matrix-fetch dedupe fixed.** Routing-layer
  fix, not the MutableStateFlow the R-5 note sketched. Splits the
  combined `Authenticating, Reauthenticating` branch in AppRoot's
  routing effect; `Reauthenticating` becomes a no-op so `screen` does
  not oscillate during silent reauth. Matrix-fetch effect key
  `(screen, deviceId)` unchanged -> does not re-fire. The
  interceptor's retry inside the effect body still produces one fetch
  with a fresh bearer. Verified post-trigger: 3 requests -> 2 (single
  fetch + retry on same remotePort). U-2's cost > payoff ruling was
  correct given the ruling's assumed fix; the actual fix was one
  branch edit and also corrected a UX drift (Loading flash during
  reauth, contrary to ADR-HARDENING-001 §2's "silent reauth"
  intent).

- `bf13dcc` — **AckDialog Compose tests + Espresso 3.7.0 bump.**
  First Compose test in the project (11 tests). Covers Session I's
  Q1-Q3 rulings at the UI layer: dialog shows full notice, two
  confirmation affordances, no undo path. `AckDialog` visibility
  `private -> internal` (androidTest source set access). Espresso
  bumped 3.5.1 -> 3.7.0 because 3.5.1 calls removed
  `InputManager.getInstance()` via reflection; every test on our API
  37 emulators failed at `InputManagerEventInjectionStrategy.initialize`
  with `NoSuchMethodException` before the first assertion ran. The
  version bump is the reason the tests pass; committed together.

**Scope pivot named honestly.** The standing deferral's label was
"Compose tests for admin flows." This delivery is AckDialog. That is
a security-value slice (Session I Q1-Q3 are the confirmation interface
for key replacement — the repeated interaction that compromises the
user if rendered wrong), not closure of the deferral. Admin flows and
ChatScreen integration require ViewModel extraction: `AdminScreen`
self-constructs `AdminApi(HttpClient(...))` and `SecureStorage` (18
`remember` vars, 2 `LaunchedEffect`s); `ChatScreen` takes 3 concrete
controller/store objects as params. Either is a real refactor. The
handoff §4 deferral re-scoped to reflect that.

**Verification.** Compile clean; both APKs installed on emulator-5556;
`am instrument -w -e class com.umoja.secure.ui.chat.AckDialogTest`
returned `OK (11 tests)`. Post-trigger `/me/matrix` count = 2
(expected; pre-fix 3). API 37 confirmed via
`getprop ro.build.version.sdk`.

**Counts.** androidTest 46 → 57 (+11, 6 → 7 files). Backend 254
and Android JVM 212 unchanged.

**Six new §7 lessons** — see below. The session cost more round-trips
than a linear session would have: five failed assumptions about
environment (psql user, gradlew path, APK deployment, expiry constraint,
count window) and one about test infrastructure (Espresso version).
Each was caught by a verification step rather than shipped, which is
the honest summary: the discipline worked, the initial assumptions did
not always hold.


### Session Z-2 — Compose refactor arc, session A: AdminScreen extract (2026-10-18)

First of four planned sessions for the Compose test coverage deferral
(§4). This session delivers the refactor that makes AdminScreen
testable at the JVM layer; sessions B, C, D deliver the tests. One
commit:

- `2804427` — **refactor(admin): extract AdminScreenState from
  composable.** AdminScreen.kt 425 → 326 lines; new
  AdminScreenState.kt 191 lines; MainActivity.kt call site rewired
  (~17-line block replacing 6-line single expression).

**THE PATTERN (this is what the handoff needs to know).** Option C
— plain Kotlin class, ChatViewModel precedent: `MutableStateFlow`
backing, no androidx ViewModel, no lifecycle awareness, no Context
dependency. Five injected lambdas (`sessionToken`, `listDevicesFn`,
`listContactsFn`, `createTokenFn`, `authorizeContactFn`) give tests
control over every backend call. Nine `StateFlow`s expose
server/action state. Methods: `load`, `loadBundle`,
`createTokenForScannedDevice`, `authorize`, `buildMatrix`,
`setStatusMessage`.

**THE CORRECTION THIS SESSION OWES THE HANDOFF.** Z-1's §4 re-scope
said the remaining Compose coverage "requires ViewModel extraction."
The actual pattern used is **not** androidx ViewModel — it's the
ChatViewModel-style plain class. Reasoning: the codebase's own
existing "ViewModel" is a plain class with `MutableStateFlow`, no
androidx.lifecycle dependency; adding `lifecycle-viewmodel-compose`
for a behavior-preserving refactor would be a bigger dependency
change than the refactor itself. Option A (lambda injection with
state still in the composable) was rejected because the logic is
exactly where bugs live — leaving `load`/`createToken`/
`authorize`/`buildMatrix` untestable at JVM layer defeats the
purpose. Option C is the correct target. §4 is being corrected in
this same handoff edit (block 4h) so session B opens with the
accurate pattern.

**BEHAVIOR-PRESERVATION EVIDENCE** (the refactor's correctness
criterion is *behavior-preserving*, not *feature-adding*):

  JVM: 212/212 pass, no collateral regression. Compile: BUILD
  SUCCESSFUL. API call pattern from a two-Admin-entry walk on
  emulator-5556 (backend log, /admin/* endpoints only):
    req-1lp  GET /admin/devices   port 60268
    req-1lq  GET /admin/contacts  port 60268
    req-1m3  GET /admin/devices   port 62882  (post-Back, re-entry)
    req-1m4  GET /admin/contacts  port 62882
  Same-port pairs = `state.load()` ran `listDevices` + `listContacts`
  in sequence twice. Identical to pre-refactor. Zero 4xx/5xx on any
  admin endpoint. Manual walk (9 steps): Settings → Admin; device
  list rendered with data; Provision section showed scan button +
  debug paste + Enrollment JSON input; Authorize section showed both
  fields + button; Back returned to Conversations; re-entry
  re-fetched. All rendered identically to pre-refactor.

**MULTI-SESSION ARC, NAMED.** This session is A. Remaining:
  B — `AdminScreenStateTest` (JVM): 15-20 tests exercising load
      success/error, createToken, authorize, buildMatrix, null
      sessionToken. The class exists for this. Fast, deterministic,
      no emulator, no backend.
  C — ChatScreen refactor (same Option C pattern). Block-1 recon
      confirmed ChatScreen is a genuinely different shape (3 concrete
      controller/store params + 6 LaunchedEffects + MessagingService.
      messagesVersion companion subscription) — hence its own session,
      not folded in.
  D — ChatScreen Compose test.

**SCOPE EXCLUSIONS, NAMED.** No androidx ViewModel. No new
dependencies. No ChatScreen touch. No AdminApi/SecureStorage changes.
Form-input state (ownerDeviceId, contactDeviceId, provisionClearance,
provisionVersion, provisionContacts, debugPasteText) stays in the
composable — UI input is not state-class concern; Compose tests
exercise it.

**One §7 lesson earned** (block 4c's substring-anchor bug) — see
§7 below.

**Counts.** All unchanged: Backend 254, Android JVM 212, androidTest
57. This session adds no tests — that's session B and D.


### Session Z-3 — Compose refactor arc, session B: AdminScreenStateTest (2026-10-18)

Second of four planned sessions for the Compose test coverage deferral
(§4). Session A refactored AdminScreen to AdminScreenState; this session
writes the tests that refactor exists for. One commit:

- `a6de609` — **test(admin): AdminScreenStateTest -- 22 JVM tests.**
  New file at `android/app/src/test/java/com/umoja/secure/ui/admin/`.
  No production code changed. No new dependencies.

**COVERAGE.** 22 tests grouped by method-under-test: load (4),
loadBundle (3), createTokenForScannedDevice (5), authorize (4),
buildMatrix (5), setStatusMessage (1). Every method's happy path, error
path, and null-guard path covered. Method-level breakdown and evidence
types are in the commit message.

**TEST SHAPE.** `runBlocking` -- kotlinx-coroutines-test is not on the
classpath; same precedent as IdentityChangeControllerTest (Session K)
and SessionStateManagerTest (Session R-2). Lambda injection (5 injected
lambdas from AdminScreenState's constructor). JUnit4 + backtick method
names + per-group sections, mirroring MatrixApiTest. Fake helpers:
`device()`, `contact()`, `token()`, `validBundleJson()`, `stateWith()`.

**ONE TEST-SETUP FIX DURING THE SESSION.** First scoped run: 21/22.
`buildMatrix clears prior error on success` failed on
`expected null, but was:<Build failed: clearance: empty string not
permitted>`. MatrixBuilder correctly rejects empty clearance (its own
contract from Session A); AdminScreenState correctly propagated. The
test's second buildMatrix call used `clearance = ""` when it intended
to assert the success path. Fix: `"" -> "SECRET"` on that one call.
Class unchanged. Assertion unchanged. The alternative -- "fix the class
by removing clearance validation" -- would have been catastrophic;
naming it because the response to a failing test is to distinguish
test-setup vs assertion vs class bug, and here it was test-setup.

**Verification.** Scoped: 22/22 pass. Full suite: 234/234 pass
(212 + 22). Aggregate count from XML, not from "new test file should
add 22" inference.

**Counts.** Android JVM 212 -> 234 (+22). androidTest 57 unchanged.
Backend 254 unchanged.

**Arc status.** A done (`2804427`, `8da90d7`). B done (this session,
`a6de609`). C = ChatScreen refactor pending. D = ChatScreen Compose test
pending. C is a bigger session than A -- ChatScreen has 3 concrete
controller/store params + 6 LaunchedEffects + MessagingService.
messagesVersion companion subscription. Block-1 recon evidence is in
Z-2's §3 entry.

**One §7 lesson earned** (the "already exists?" check must target the
new entry identifier, not strings the entry references). See §7 below.


### Session Z-4 — Compose refactor arc, session C: ChatViewModel testability + tests (2026-10-18)

Third of four planned sessions for the Compose test coverage deferral
(§4). One commit:

- `bd8a6e7` — **refactor(chat): ChatViewModel injectable + ChatViewModelTest
  (10 JVM tests).** ChatViewModel 62 → 94 lines. MainNavigation.kt one-line
  caller change. New ChatViewModelTest.kt 177 lines. No production
  behavior change to the message-send path or the UI.

**PLAN REVISION, EXPLICIT.** Z-2 §4 planned this session as "ChatScreen
refactor" — extract ChatScreenState mirroring session A's AdminScreenState.
Session C's opening reconnaissance (block C1, full 421-line ChatScreen
read) showed that was the wrong target:

- ChatScreen is a composition shell. 6 UI-flag remember vars (input,
  sending, status, showDialog, ackInProgress, ackError), 2 derived states
  that already call pure functions (gateFor, SendGate.authorized), 2
  actions that already delegate to injected holders (viewModel.send,
  identityChangeController.ackAndPost). Zero trapped business logic. A
  ChatScreenState class would wrap, unwrap, and pass through to holders
  that already exist — indirection without testability.
- The actual untested logic lives in ChatViewModel: a Context-bound final
  class with hardcoded MessageStore + MessagingService construction, zero
  test coverage, and no seam for injection. That is the target.

ChatScreenState is CANCELLED. Sessions E/F (ChatScreenState class) are
dropped. The arc is A (AdminScreenState refactor) / B (AdminScreenStateTest)
/ C (ChatViewModel testability + tests, this session) / D (ChatScreen
Compose tests, enabled by C — pending). Total four sessions, but C and D
changed target on evidence. Named here because a future reader seeing
"C = ChatViewModel" will reasonably ask "wasn't C ChatScreen?" — the
answer is this paragraph.

**WHAT CHANGED.**
- `ChatViewModel.kt`: constructor now takes `(listMessagesFn,
  sendMessageFn, scope)`. Two suspend lambdas replace hardcoded
  MessageStore and MessagingService calls. Scope injected so tests use
  Unconfined for determinism. Public surface (messages StateFlow, observe,
  refresh, send) UNCHANGED — ChatScreen's call sites compile unchanged.
  Companion `create(context)` factory wires the real dependencies + the
  same scope shape the old constructor used inline.
- `MainNavigation.kt`: one-line `ChatViewModel(context)` →
  `ChatViewModel.create(context)`.
- `ChatViewModelTest.kt` (new): 10 JVM tests. runBlocking + injected
  Unconfined scope + CompletableDeferred where callbacks need to signal
  completion. Coverage: observe loads, exactly-one-list-call,
  refresh-without-observe is no-op, observe switches peer, refresh
  re-queries; send success → null, failure → code, NotAuthorized →
  "not_authorized", lambda gets peer+text, sendMessageFn invoked exactly
  once per call.

**BEHAVIOR PRESERVATION — THE LOAD-BEARING PROPERTY.** The refactor's one
real risk is losing the FIRE-AND-FORGET property of send(). Currently
ChatViewModel.send launches on its own scope (previously constructed
inline; now injected but same shape), independent of ChatScreen's
composition. If a user hits send and navigates back within ~1 second,
the message must still complete.

Unit tests structurally cannot verify this — the Unconfined scope is
always alive in the test process; the property is about the scope
outliving the composition in production. So the session's commit is gated
on emulator walk + backend-log evidence, not tests alone:

- Walk (emulator-5556): baseline send → POST /envelopes 201; fire-and-
  forget send → tap Send then IMMEDIATELY tap Back → wait 5s → reopen
  chat → message present in history. Proves the coroutine completed
  after screen exit and persisted via the store, then was picked up on
  refresh.
- Backend log evidence (commit gated on this): ≥ 2 POST /envelopes with
  0 errors during the walk window. C7's evidence gate refused to commit
  if the walk evidence was missing. This is the practice this session
  encoded: "the refactor is correct" is a claim made from tests + a
  documented end-to-end walk, not from tests alone.

**ARC STATUS.** A done (`2804427`, `8da90d7`). B done (`a6de609`,
`2775367`). C done (this session, `bd8a6e7`). D = ChatScreen Compose
tests pending — now enabled: ChatViewModel is injectable,
IdentityChangeController is lambda-injected (session K), MatrixStore is
KeyValueStore-injected (P1-026), AckDialog is internal (session Z-1).
All three ChatScreen deps can be faked.

**No new §7 lessons this session.** The session's discipline held
(preflight caught the correct number of buildMatrix calls; sanity greps
used ASCII-only patterns per the seventh §7 lesson; the C7 evidence gate
is a practice rather than a new failure-class lesson). Adding lessons for
methodical sessions dilutes the section's signal — recording the absence
is honest.


### Session Z-5 — Compose refactor arc, session D: ChatScreenTest, ARC COMPLETE (2026-10-18)

Fourth and final session of the Compose test coverage arc. One commit:

- `9bfdfab` — **test(chat): ChatScreenTest -- 14 Compose tests, arc
  session D complete.** New ChatScreenTest.kt, 363 lines, 14 tests. Zero
  production code changes. No new dependencies.

**WHAT D DELIVERED.** 14 Compose tests covering ChatScreen's rendering
paths, with fixtures seeded through the same `KeyValueStore` surface the
production stores read from:

- 3 unauthorized-peer tests (banner appears, composer placeholder
  "Sending blocked", send icon disabled when no matrix seeded)
- 3 authorized-peer tests (banner absent, placeholder "Message...",
  send enabled after text entry when matrix permits the peer)
- 4 identity-banner tests (pending renders; pending tap opens dialog;
  rejected renders error banner; rejected has no View affordance per
  Session I's Q3 ruling)
- 1 both-conditions test (unauthorized + pending notice → both banners)
- 2 message-list tests (empty state, bubbles render)
- 1 send-action test (tap Send fires sendMessageFn with peer + text)

**`createComposeRule()` BET PAID OFF.** D1's `SecureScreen` read showed
its `LocalView.current.context as? Activity` cast is null-safe (per its
own KDoc: "a null activity is a silent no-op"). That made pure
`createComposeRule()` composition safe for ChatScreen tests -- FLAG_SECURE
is silently skipped when no host Activity is present. Verified empirically:
14/14 pass on `createComposeRule()`, no need for
`createAndroidComposeRule<ComponentActivity>()`. If the bet had been wrong,
the D4-fix compile would have still passed but D5's instrumentation run
would have failed all 14 with the same exception -- the fallback was one
line, but not needed.

**FIXTURES ON FIRST TRY (one constructor exception).** Both seed helpers
(`seedAuthorizedMatrix`, `seedNotice`) produced valid seed data from the
D3-read shapes on the first compile. The one fix during the session was
`ReplacementNoticeStore(kv)` requiring its full constructor
`(store, signingFn, ackingDeviceId)` -- the D4 compile error was exact
(line 161, two missing params), the fix was mechanical (identity
passthrough for `signingFn`, arbitrary string for `ackingDeviceId`; both
paths are never invoked by these 14 tests).

**THE MEASUREMENT DEBUGGING CHAIN -- the session's actual cost.** Where the
code went right on the first run, the verification did not. Three failed
grep approaches to reading JUnit XML before a structural parser worked:

1. **D6:** `grep -o 'tests="[0-9]*"'` summed both the `<testsuites>` outer
   attribute (71) AND every `<testsuite>` child attribute (sum = 71) = 142.
   Committed nothing; gate blocked correctly.
2. **D6-fix:** Python `re.search` (first-match-only) parsed just
   `ExampleInstrumentedTest` with `tests=1`, reported aggregate 1.
   Committed nothing; gate blocked correctly.
3. **D6-retry:** `grep 'name="com.umoja.secure.ui.chat.ChatScreenTest"'`
   matched both the `<testsuite name="...">` line AND all 14
   `<testcase classname="...">` lines (substring: `name=` in `classname=`),
   reported 15 entries where 1 expected. Committed nothing; gate blocked
   correctly.
4. **D6-final:** `xml.etree.ElementTree` parsed the file as XML. Correct
   aggregate (71), correct ChatScreenTest presence (1 suite, tests=14),
   gate passed. Committed.

The gate blocked a commit three times on measurement bugs. That is the
correct response: unexplained count → diagnose → change measurement →
commit. The content was correct every time. Three failures of the same
measurement class in one block chain is the signal that the **tool** was
wrong, not the third invocation: structured data needs a structural
parser. Recorded as three new §7 lessons.

**THE ARC IN RETROSPECT.** Four sessions, two plan revisions on evidence,
one cancelled sub-session, five landed sub-deliverables:

- A (Z-2, `2804427` + `8da90d7`): AdminScreen → AdminScreenState plain-
  class refactor. Delivered the pattern. Option C (not androidx ViewModel),
  matching the codebase's own ChatViewModel precedent.
- B (Z-3, `a6de609` + `2775367`): AdminScreenStateTest, 22 JVM tests.
  RunBlocking precedent (kotlinx-coroutines-test not on classpath).
- C (Z-4, `bd8a6e7` + `b8f0f04`): ChatViewModel injectable + test.
  **PLAN REVISION:** Z-2 planned a ChatScreenState refactor; C1's full
  ChatScreen read showed ChatScreen is a composition shell (6 UI-flag
  remember vars, 2 derived states already calling pure functions, 2
  actions already delegating to holders, zero trapped logic). The actual
  untested surface was ChatViewModel. Refactored that instead.
  ChatScreenState cancelled.
- D (Z-5, `9bfdfab`): ChatScreenTest, 14 Compose tests. Enabled by C's
  injectability work.

Total across the arc: +56 tests (22 JVM + 10 JVM + 14 androidTest + 11
androidTest from Z-1 that this arc closed out as the deferral's first
sub-deliverable). Zero production behavior changes. Every sub-deliverable
verified by its own test suite plus (for the behavior-preserving refactors
in A and C) emulator acceptance.

**Three new §7 lessons earned** (the measurement chain) — see below.


### Session Z-6 — Phase 2 opening: ADR-SIGNAL-UPGRADE-001 (2026-10-18)

First Phase-2 session. Design-only. One commit: `aa6860e` —
`ADR-SIGNAL-UPGRADE-001` v0.1 (306 lines, 11 sections). No code, no
version bumps, no test changes.

**WHY DESIGN-FIRST.** TASK-P1-005's registry status is **"Proposed
(blocked until human approves native code path)"**, with acceptance
criterion "Human approved all native-code work." Build Master §0 says
escalate, do not guess. The right first move is not to plan the
upgrade execution — it is to make the approval question concrete
enough that a human can answer it. Session G (ADR-IDENTITY-CHANGE-001,
401 lines of design, zero code) is the precedent this session follows.

**WHAT THE ADR CONTAINS.** From a full reconnaissance read at HEAD
`80dc9e3`:

- §2 Current-state inventory: 3 files with libsignal imports
  (`PersistentSignalProtocolStore` 410 lines, `SignalIdentityStore`
  172, `MessagingService` 396); 31 distinct libsignal imports
  enumerated; 6 fragility points named (FP-1 through FP-6) where the
  code depends on shape, not just type — 33-byte identity
  serialization with 0x05 prefix, split pub/priv workaround (KDoc
  says the alternative crashes JNI on some emulators), markKyber
  PreKeyUsed signature, PREKEY_TYPE/WHISPER_TYPE constants,
  InMemorySignalProtocolStore constructor, IdentityChange enum names;
  28 androidTests across 3 files (635 lines) as the regression suite.

- §3 Version decision: three candidates (A: stay at 0.81.1/0.86.5 —
  zero risk, no security fixes; B: 0.94.0 Signal-Android — latest
  Android-context version, but not on Maven Central, requires Signal's
  artifact repo; C: 0.99.3 upstream — latest protocol, but not an
  Android distribution and may not be Maven-published). **Recommends B
  contingent on two external verifications at execution time:** Maven
  Central's current latest, and Signal-Android artifact access path.
  Names what collapses each candidate. Does not settle the choice.

- §4 Breaking-change checklist: 31 imports tiered by expected
  stability (Tier 1 likely stable, Tier 2 needs changelog verification,
  Tier 3 known-fragile = FP-1..FP-6). Comparison method: read the
  changelog, read the target source, compile against the target — in
  that order. Do not guess at API stability.

- §5 **Human approval gate**: TASK-P1-005 status restated; four
  questions the human is being asked (version choice; supply-chain
  change off Maven Central if B or C; AGPLv3 posture for the newer
  artifact; regression-discipline commitment); the three things the
  ADR cannot answer (all external facts); what-happens-if-denied
  (pins stay, mismatch documented as deliberate, project continues).

- §6 Execution path contingent on approval: 4–5 sessions P2-2
  through P2-5 (external verification + AGPL notice; catalog migration
  + review; bump + adaptation + integration doc; regression
  verification). Ordering: external verification is the gate for
  everything else; catalog migration before version bump so rollback
  of the bump doesn't also need to roll back the migration.

- §7 Regression gate: 28 androidTests must pass. Do not edit tests to
  pass a broken upgrade; production code absorbs API changes, tests
  assert invariants (never change) vs construct fixtures via API (may
  change).

- §8–§11: pin migration to libs.versions.toml (behavior-neutral,
  separate commit); rollback plan (one-commit-or-none at each phase,
  never partial-revert); out-of-scope list; revision history.

**THE ADR DOES NOT SETTLE WHICH OF A/B/C IS CORRECT.** It names the
recommendation and the two external facts that would collapse the
candidate set. Human approves the target version after those facts
are confirmed at execution time.

**Escalation, not execution.** Denying approval is a legitimate
outcome (§5.3). The ADR makes the question concrete; the human
decides. If approved, P2-2 opens as a new session. If denied, the
ADR records the reasoning and the project continues with current
pins.

**Process note.** This session also confirmed the §7 heredoc rule
exists for a reason: a 250-line ADR draft was initially attempted as
a single heredoc, the paste fragmented mid-block, and the recovery
was to write via TextEdit + verify with grep (the §7 "prefer a text
editor for content over ~150 lines" rule). The rule was on disk; it
was the correct response to the failure; no new §7 lesson added
because the existing one covers it exactly.

**Counts.** Backend 254, Android JVM 244, androidTest 71 — all
unchanged (docs-only session).


### Session Z-7 — ADR approval round: ADR-SIGNAL-UPGRADE-001 v0.1 → v0.2 (2026-10-18)

Second Phase-2 session. Doc-only. One commit: `5fd44aa` — ADR v0.2,
405 lines (up from 306). No code, no version bumps, no test changes.

**WHAT HAPPENED.** The human's four section-5 questions from the
Session Z-6 close were escalated, then verified, then answered. The
external facts named in v0.1's §5.2 as "cannot answer" became the
following verified facts in v0.2's §5.2:

- **F-1: Maven Central is at 0.86.5** for both artifacts, last updated
  2025-11-17. Nothing newer. Candidate A (stay) is not a neutral option —
  it means staying at 0.86.5 indefinitely, with the mismatched pins
  (0.86.5 client / 0.81.1 AAR) as a latent correctness issue.

- **F-2: Signal-Android ships 0.105.0** from
  `https://build-artifacts.signal.org/libraries/maven/`, **anonymously**.
  Verifiable from Signal-Android's `gradle/libs.versions.toml`
  (`libsignal-client = "0.105.0"` for both artifacts) and
  `settings.gradle.kts` (repo declared, no credentials block — contrast
  with the adjacent build-cache repo which does have credentials).

- **F-3: Upstream is at 0.105.1** (2026-10-15). One patch ahead of
  Signal-Android's production pin. Not Android-targeted; not consumed by
  Signal-Android yet.

**THE VERSION CORRECTION.** v0.1's recommendation was 0.94.0, contingent
on verification. The verification showed the recommendation was based on
a stale source — the registry note (US-TASK-P1-001 line 703, written
2026-10-17) said "Maven 0.86.5; upstream 0.99.3; Signal-Android 0.94.0."
The upstream and Signal-Android figures were already ~15 releases stale
*when written*, not when read. Approved target: **0.105.0**.

**FOUR QUESTIONS ANSWERED** (§5.4 approval record):

1. Target version: **0.105.0** (both artifacts aligned). Rejects A
   (11 months of missing security updates); defers C (0.105.1 is one
   patch ahead but not Android-targeted).
2. Supply-chain: **Approved.** Signal's official Maven repo, anonymously
   accessible. No new trust relationship beyond what libsignal already
   implies.
3. AGPLv3: **Confirm only.** Execution reads the LICENSE bundled in the
   0.105.0 artifact; if still AGPLv3 with no additional clauses, proceed.
   Material change means stop and re-escalate.
4. Regression rule: **Approved as absolute.** 28 androidTests must pass.
   Mechanical API renames at test call sites allowed; no test deletions,
   no weakened assertions.

**PLAN REVISION.** v0.1 estimated 4–5 sessions (P2-2 through P2-5).
P2-2 was scoped as "read external changelog + confirm artifact
availability + write AGPL-NOTICE" — those verifications happened in
the approval round itself. v0.2's §6.1 revised plan: **2–3 sessions**
(P2-3 execution, P2-4 regression verification). May collapse to one
session if the 0.86.5→0.105.0 API diff is mechanical.

**VERSION-NOTE STALENESS — the session's durable lesson.** The registry
note was 15 releases stale when written, not when read. Version notes
in static documents go stale fast; verify at execution time, not from
the document. Same class as KI-013 (do not propagate test counts from
prior handoffs) and the §7 rule "counts from runner output." Recorded
in v0.2 §6.1 so a future session reading the ADR encounters the lesson
at the point of relevance.

**THE ONE FACT STILL PENDING.** The exact 0.86.5 → 0.105.0
breaking-change inventory (v0.1 §4's checklist). v0.2 §5.2's "Fact
still pending at execution" paragraph names the method: read the
per-version release notes on GitHub (0.86.6 through 0.105.1), then
compile against target — in that order, per §4's "do not guess at
API stability" rule. This is P2-3's first task, not an unverified fact
slipping past the approval.

**PROCESS NOTE.** The session included a recovery from a bad input: a
pasted AI response recommended 0.94.0 based on the same stale registry
note. The response's *structural reasoning* was sound — use Signal's
repo, treat AGPL as confirm-only, back the 28-test rule — but its
version numbers were wrong. The response's URL
(`build-artifacts.signal.org`) turned out to be correct; its version
claims did not. The handling: incorporate the structural points,
reject the version numbers, verify everything against primary sources
(Signal-Android's build files, Maven Central metadata, GitHub
releases). Same discipline as V-1's cross-document propagation —
citation-by-primary-source, not citation-by-prior-claim.

**Counts.** Backend 254, Android JVM 244, androidTest 71 — all
unchanged.


### Session Z-8 — Phase 2, session P2-3: libsignal upgrade executed (2026-10-18/19)

Third Phase-2 session, the execution of the plan approved in Z-7. One
code commit: `97279b1` — 8 files (5 modified, 3 new docs). The
libsignal arc is **CLOSED**.

**WHAT THE SESSION DID.** Four sequential mechanical-fix rounds, each
found by a specific discovery mechanism:

1. **Constructor arity** — compile surfaced that `SessionBuilder` and
   `SessionCipher` in 0.105.0 take a third argument (`localAddress`).
   Fixed: 5 sites in `MessagingService.kt`, threaded `localAddress`
   from `SecureStorage.get("device_id")`.

2. **Property → method accessors** — `PreKeySignalMessage.getPreKeyId()`
   returns `Optional<Integer>` (Kotlin cannot auto-synthesize property
   from Optional); `getSignedPreKeyId()` returns `int` (same issue).
   Fixed: 2 call sites in production, 18 in test.

3. **Catalog swap** — two hardcoded `implementation("org.signal:...")`
   lines → `libs.libsignal.android` / `libs.libsignal.client` catalog
   refs. Version 0.105.0 in `libs.versions.toml`. Signal repo declared
   in `settings.gradle.kts` (org.signal.* scoped, anonymously accessible
   verified from Signal-Android's own build config).

4. **Argument-order asymmetry** (the session's largest finding) —
   compile-clean upgrade failed at runtime with
   `NoSessionException: session with bob.1 not found: message_encrypt`.
   Read of libsignal v0.105.0 source confirmed:
   `SessionBuilder(store, remoteAddress, localAddress)` vs
   `SessionCipher(store, localAddress, remoteAddress)` — siblings with
   opposite order. Fixed by swapping SessionBuilder's args only;
   SessionCipher's (local, remote) was already correct. Documented in
   `LIBSIGNAL-REVIEW.md` §4.1 as a load-bearing asymmetry with a
   "do not consistify" warning: future maintainers who notice and
   unify will get a runtime failure the compiler cannot catch.

**WHY RELEASE NOTES WERE USELESS.** 0 of 68 versions in
[0.86.6, 0.105.1] have GitHub release bodies. The compile+test gate
is the only working inventory mechanism, documented in
`LIBSIGNAL-REVIEW.md` §5 as the cadence for future upgrades (bump
only after ADR update; both mechanisms required, neither substitutes).

**ADR §5.4 INTERPRETATION RULING, NAMED.** §5.4 allowed "mechanical
API renames only; no test deletions, no weakened assertions." A
parameter reorder is not literally a rename. Interpretation: the
"mechanical" spirit covers deterministic adaptations to published API
shape — arg reorder conforms to libsignal source, involves no
protocol-behavior decision, required no test-assertion changes. Named
explicitly in the commit body so the ruling is visible to future
sessions rather than silently applied.

**GATE EVIDENCE.** Full androidTest suite run (no filter — after a
class-filter quirk on the first attempt) on both emulators:
**71/71 per emulator, zero failures, zero errors.** Target classes at
full count: X3DHInMemoryTest 7, PersistentSignalProtocolStoreTest 14,
LibsignalSmokeTest 8 = **29/29** (X3DH's 7/7 proves the runtime arg-
order fix); non-target classes also at full count (zero regressions).

**28→29 CORRECTION.** The "28 androidTests" figure throughout ADR
v0.1/v0.2 came from a preliminary count during ADR v0.1 drafting. The
verified count at HEAD was 29. Corrected in `LIBSIGNAL-REVIEW.md` §6;
ADR §7 left as historical record of the count-at-approval-time. Both
ADR §7 and LIBSIGNAL-REVIEW §5 gates are satisfied by "29/29 pass."

**THREE DOCS WRITTEN.** AGPL-NOTICE (license factual record, no
independent legal review asserted), LIBSIGNAL-REVIEW (version rationale
+ both API quirks + future cadence), LIBSIGNAL-INTEGRATION (two-artifact
split + JNI workaround preserved + emulator-vs-device caveat). These
satisfy TASK-P1-005's three remaining acceptance criteria (AGPLv3
documented, JNI documented, version review documented).

**PROCESS NOTES** (documented for honesty, not as new lessons):
- Two heredoc fragmentations during doc writes (ADR earlier, and
  LIBSIGNAL-REVIEW first attempt). Both times the recovery was
  editor + paste, which is §7's own rule for content over 150 lines.
  Rule applied, not re-learned.
- One preflight abort in the commit attempt (P2-3f): my
  `git status --short | grep -c .` gate returned 7 for 8 files
  because `docs/crypto/` and `docs/legal/` count as 1 line each
  (dirs, not contained files). Recovery: gate on
  `git diff --cached --name-only | grep -c .` after `git add`.
  Same family as Z-5's XML parent/child double-count lesson.

**Counts.** Backend 254, Android JVM 244, androidTest 71 — all
unchanged (only version swap + mechanical adaptation; no test adds).


### Session Z-9 — Phase 2, TASK-P1-027(a): dependency review executed (2026-10-19)

Fourth Phase-2 session. Two commits: `9a1173e` (ws CVE fix) +
`0071aa6` (review record + artifacts + registry split).

**SCOPE RECOGNITION.** TASK-P1-027's title — "SBOM + dependency
review gate" — exceeded what the project can execute today. The
SBOM and review halves are executable; the gate half requires CI
that doesn't exist (no `.github/`, no pipeline config, no automation).
Splitting the task was the honest response, not narrowing the work.
Same class as Sessions C and V-1's plan revisions on evidence.

**WHAT THE EXECUTION FOUND.** One HIGH-severity CVE — the first
REAL security finding of the project, not a doc inconsistency.

- `ws@8.18.0` had two advisories: GHSA-58qx-3vcg-4xpx (CVSS 4.4,
  uninitialized memory disclosure) and GHSA-96hv-2xvq-fx4p
  (CVSS 7.5, memory-exhaustion DoS). npm audit aggregates to HIGH.
- Reached by both the direct devDependency (`^8.18.0`) and
  transitively via `@fastify/websocket@11.0.1` (`^8.16.0`).
- Per Build Master §6: "HIGH/CRITICAL: PR blocked until fixed or
  documented exception." Per §6: "Agent must not add
  `.npmrc` overrides to silence warnings." Sanctioned path was
  direct range bump — → `^8.22.0`, resolved to 8.22.0.
- `npm audit` after: 0 critical, 0 high, 0 moderate, 0 low.
- Backend test suite: 254/254 green, no behavior regression.
- Fix commit `9a1173e` (2 files: package.json + package-lock.json).

**FOUR MORE FINDINGS, NONE CVE-grade:**

- `fsevents@2.3.3` install script un-covered by `allowScripts` —
  observed, not a defect (the discipline is working correctly).
- `artifacts/` directory was absent despite Build Master §6 step 3
  naming `artifacts/dep-tree.json`. Created this session.
- No CI exists. Deferred to P1-027b.
- Android has no dependency tooling. Deferred to P1-027b (gradle
  task + CI both required).

**THE FOUR DELIVERABLES.**

1. `docs/security/DEPENDENCY-REVIEW.md` (new, 6 sections): scope,
   inventory (22 direct backend deps, depth distribution), method
   (exact commands + structural SBOM parse), findings log (5 entries),
   cadence (manual-review gap named), related documents.
2. `DEPENDENCY-EXCEPTIONS.md` §1: RESOLVED entry for ws — both
   GHSAs, CVSS, mitigation, fix-commit reference, plus an explicit
   "Distinction from an active exception" paragraph so no future
   reader mistakes it for a retention entry.
3. `artifacts/` (new): `README.md` (refresh discipline) +
   `dep-tree.json` (first committed snapshot, 22 direct deps,
   post-ws-fix state). Per the README, snapshot refreshes when
   lockfile changes only.
4. Registry v0.7 → v0.8: P1-027 split into §A entries for 027a
   ("Executed 2026-10-19") and 027b ("New, blocked on CI-provider
   decision"). §C row split, total 43 → 44.

**PROCESS NOTES.**

- **Partial-write discovered mid-session:** The version bump block
(P4-1g-4b) preflighted on `Version: 0.7` at count 0. Actual was
  `Version: 0.8` — a prior block had partially written the field.
  Robust-fix approach: regex anchor + read current value + only
  change if different. This is the correct pattern when a mid-
  session abort leaves the target in partial state. Worth noting
  because the alternative (abort again on unexpected current value)
  would have looped without progress.
- **The count=2 class of sanity-gate failures** recurred four times
  this session (arc CLOSED, git-status grep, zxing, 97279b1). Each
  was legitimate content at count=2 (heading + body reference, or
  two independent mentions). Same family as Z-4/Z-5's lessons —
  already on disk (§7 twelfth/thirteenth). Applied via `grep -n`
  verification before re-gating, not re-learned as new lessons.

**Counts.** Backend 254, Android JVM 244, androidTest 71 per
emulator — all unchanged (fix + docs only; no test adds).


### Session Z-10 — Phase 2, handoff §8 refresh (bounded) (2026-10-19)

Fifth Phase-2 session, first of the two 'close last known debt
before opening new ground' sequence. One commit: `6b715cb` — 98
insertions, 8 deletions in `handoff.md` only. No code touched.

**SCOPE DECISION, NAMED.** The backlog said "rename §8 **or**
replace its code-shape list." R-2 established the specific scope:
refresh the **non-transport** staleness, defer the `transport/`
section to the suspend refactor’s preamble. Reasoning: the
refactor reads `HttpClient` + every `*Api` class as its preamble
anyway, so documenting them in §8 now would be re-stale by the
time the refactor ships. The genuinely stale parts are the crypto
surface and non-transport auth/ui files. That scoping is what the
commit reflects.

**WHAT LANDED.** §8's content grew to reflect Sessions F through
Z-9's additions (a stretch §8's Session-A provenance didn’t
anticipate):

- Authoritative design: 5 items → 10. Added ADR-HARDENING-001,
  ADR-IDENTITY-CHANGE-001, ADR-SIGNAL-UPGRADE-001, US-MASTER-001,
  USER-ONBOARDING with version tags and session references. Updated
  ADR-PROVISIONING-001 to name §7.1.1 (Session A `4abcf53`);
  THREAT-MODEL-001 / AUTH-SPEC-001 / US-ADD-001 now carry sweep
  versions and session references.
- Conformance data: 3 items → 5. Added canonical-replacement-notice
  (Session F `d28c631`) and canonical-identity-change-ack (Session I
  `ed271ac`) vector files.
- New "Code shape — added post-Session-A" block: ~20 files —
  MatrixStore, MatrixVerifier, ProvisioningKeys, DeviceIdStore,
  EnrollmentQrPayload, Base64UrlValidation, CryptoJsonHelpers,
  CryptoException, WipeConfirmationKeyManager, ReplacementNotice*,
  IdentityChangeAck*, IdentityChangeController, SendGate,
  VerificationFailureStore (Android); SessionStateManager,
  SessionScreens, SecureScreen (auth/ui); replacement-notice.ts,
  identity-change-ack.ts, backend/src/identityChange/,
  ws/revocation.ts, sign-test-notice.ts, sign-test-matrix.ts
  (backend).
- Verify-path find-greps widened on both sides to catch the new
  file names (previously missed SendGate, Verification*,
  ReplacementNotice*, EnrollmentQr, Http, Api; backend missed
  identity|replacement|ws/|audit|auth).
- New §8 currency note in "Notes for a new agent" explaining the
  outgrowth and the transport deferral mechanism.
- Title provenance note at section top: names origin (Session A),
  outgrowth, and points to the added block. **Title deliberately
  not renamed** — renaming would cascade through cross-references
  for a label still accurate as provenance. The note names it
  instead.

**TRANSPORT DEFERRAL — explicit.** §8's new "Deferred —
`transport/` surface." paragraph names `HttpClient`, `AdminApi`,
`ContactsApi`, `EnvelopeApi`, `PreKeyApi`, `MatrixApi`,
`IdentityChangeApi`, `Socks5Bridge`, `WebSocketClient` and points to
the suspend refactor as the place they’ll be documented. This
prevents a future reader from thinking the refresh missed them.

**TWO PROCESS FAILURES, NAMED (no new §7 lesson).**

- **Python apostrophe SyntaxError.** First R-3 write attempt failed
  at parse time: `'...the section's title...'` — a literal apostrophe
  inside a Python single-quoted string terminates the string early.
  Fixed by `\u2019` (right single quote, U+2019), renders identically
  in Markdown. **Lesson is on disk**: twelfth §7 addition ("the
  tool’s quoting rules are load-bearing, not cosmetic") is the same
  family as the em-dash-in-grep and JSON-in-shell lessons. Not
  re-recorded.
- **Line-bound greps gave false-negatives.** R-3-fix showed empty
  results for ADR-HARDENING-001 and ADR-IDENTITY-CHANGE-001 because
  my patterns required same-line matching; the file paths and the
  session refs are on adjacent wrapped lines. **Fifth/sixth count/
  measurement failure this session's arc.** R-4 verification used
  line-range awk instead. Same family as twelfth/thirteenth
  (measurement-tool unit vs question unit); applied, not
  re-learned. Same discipline: verify with grep -n before
  concluding content is wrong.

**BACKLOG ITEM CLOSED.** The handoff's \"§8’s title is stale\"
  entry in §5's backlog is now resolved (bounded refresh, transport
  deferred by intent). §5 updated accordingly.

**Counts.** Backend 254, Android JVM 244, androidTest 71 — all
unchanged (doc-only session).


### Session Z-11 — Phase 2, suspend HTTP surface refactor (2026-10-19)

Sixth Phase-2 session, and the last substantive Phase-2 item. One
commit: `6c7830e` — 12 files (10 production + 1 test + 1 doc), +71
/ -60. Executes 040-D-1's "Phase 2: HTTP layer becomes suspend; this
bridge disappears" claim.

**WHAT LANDED.** `HttpClient.postJson`/`get`/`execute`/`executeWith
Retry` all `suspend fun`; the `runBlocking { handler!!.invoke() }`
bridge became a direct suspend call; `import kotlinx.coroutines.run
Blocking` removed. `HttpClient` KDoc rewritten — the Phase-1 bridge
rationale is now history; the current KDoc names the suspend surface
and the **dispatcher-discipline rule** (suspend fun does not imply IO
dispatch; callers must `withContext(Dispatchers.IO)` before calling).
All 8 API classes' public methods `suspend fun` (25 signatures).
`MatrixApi.fetchFn` param became `suspend`; `IdentityChange
Controller`'s `listNotices`/`postAck` lambda params became `suspend`
(their methods were already suspend, only param types needed
alignment). `MatrixApiTest` gained `import kotlinx.coroutines.run
Blocking` and wrapped 5 `api.fetch("test-token")` call sites; the
uniform fix wraps the fetch call, not the test method, because
`assertThrows` takes a non-suspend Java Executable.

**ZERO CALLER CHANGES — verified exhaustively before the write.**
Every existing caller was already in a suspend context:
`ContactsScreen`/`ContactsViewModel` inside `scope.launch(IO)`;
`MainActivity` matrix fetch and enrollment in `withContext(IO)`;
`SessionManager`, `PreKeyUploader`, `MessagingService` in suspend
funs; `IdentityChangeController` methods already suspend. Kotlin
coerces `fun`-to-`suspend` at method-reference and lambda-inference
boundaries, so wiring sites (`adminApi::listDevices`, `api::
getNotices`, `MatrixApi { t -> http.get(...) }`) adapt without
source edits.

**BEHAVIOR-PRESERVATION, NAMED.** OkHttp's blocking `client.newCall
(request).execute()` **stays** inside `executeWithRetry`. The
calling thread still blocks during the HTTP round-trip, but it is
inside `withContext(Dispatchers.IO)`. The suspend refactor did NOT
convert OkHttp to its async callback form (`enqueue` /
`suspendCancellableCoroutine`). That is a **separate** refactor with
its own cancellation-semantics question, and P5-2's stated goal was
solely to remove the `runBlocking` bridge. **Cancellation of an
in-flight HTTP call remains deferred.** A future session reading
"HTTP is suspend" should not assume the layer is async-cancellable —
it is suspend-shaped, but the underlying call is blocking.

**GATES.** `compileDebugKotlin`, `compileDebugAndroidTestKotlin`,
`compileDebugUnitTestKotlin` all clean. JVM 244/244 (baseline 244) —
**includes `HttpClientRetryTest`'s 7 tests unchanged** (`shouldRetry
After401` predicate untouched; the retry-decision rule is
behavior-identical, the pipeline behind it changed shape). android
Test 71/71 per emulator, both machines, zero failures/errors (all 8
classes at full count: Example 1, DeviceKeyManager 9, LibsignalSmoke
8, PersistentSignalProtocolStore 14, WipeConfirmationKeyManager 7,
X3DHInMemory 7, AckDialog 11, ChatScreen 14).

**§8 TRANSPORT DEFERRAL CLOSED.** Z-10's "Deferred — `transport/`
surface" paragraph replaced with the current transport listing
(HttpClient suspend signatures + dispatcher discipline; the 8 API
classes; the two MatrixApi / IdentityChangeController lambda-param
changes; Socks5Bridge/WebSocketClient unchanged; zero caller
changes). Closes the Z-10 deferral in the same commit that
invalidates it — no intermediate state has a §8 that lies about
what's deferred.

**PROCESS NOTE (no new §7 lesson).** The session included another
line-bound grep miss (`suspend fun postJson` searched for in
handoff.md, but the prose says `` `postJson`/`get`/`execute`/`execute
WithRetry` are `suspend fun` `` — same literal not present). Content
was correct; the verification pattern was line-bound. Sixth/
seventh miss of this class across the Z-5..P5-2 arc; same family as
the twelfth §7 addition (measurement-tool unit vs question unit).
Applied, not re-learned.

**Counts.** Backend 254 (Android-only refactor), Android JVM 244,
androidTest 71 per emulator — all unchanged.


### Session Z-12 — Phase 1 DoD, TASK-P1-029 design: KEY-CUSTODY.md (2026-10-19)

Seventh Phase-1-DoD session (after Phase 2 closure). One commit:
`29cd7bf` — `docs/ops/KEY-CUSTODY.md` (287 lines, 9 sections). No
code changes, no test changes. The doc explicitly required by Build
Master §3.6: "docs/ops/KEY-CUSTODY.md (TASK-P1-029) documents
generation ceremony, storage, access control, use procedure,
rotation, retirement, and audit for both the provisioning key and
the recovery key."

**THE DECISION.** Dedicated Android device (Pixel 7+, StrongBox /
Titan M2) chosen over YubiKey (Ed25519) and air-gapped-computer
alternatives. Reasoning captured in the doc's §1 with a decision
matrix:

- **StrongBox is a dedicated secure element**, not a TEE. Key
  material generated in StrongBox never enters the Android OS
  address space, not even the TEE's. Highest key-at-rest assurance
  on commodity mobile hardware in 2026.
- **Zero new hardware category** — the project already targets
  GrapheneOS on Pixel. Pixel 7+ has Titan M2. Verified.
- **`MatrixSigner` unchanged.** The offline signing app is the
  admin app with the network stack removed and a "sign this
  matrix" button. `MatrixSigner.sign(signed: SignedMatrix,
  privateKey: PrivateKey): String` already exists.
- **Operationally bounded.** YubiHSM 2 requires PKCS#11 tooling and
  ~$650 hardware; YubiKey needs a hardened host machine; Option 3
  keeps the key in extractable form during signing. None are strong
  enough for the primary trust anchor of a government/security
  product.

**CAVEATS NAMED, NOT HIDDEN.** StrongBox requires Pixel 7 or later —
the doc says Pixel 6 and earlier are NOT acceptable. Hardware
attestation at generation is a ceremony step, not an assumption.
Firmware updates are allowed only via signed OTA on physical media
(ceremony lead installs, no network). A stolen offline device with
StrongBox is a brick (key non-extractable) but can be used to sign
arbitrary matrices if unlocked — two-person control + strong
passcode + safe storage are the countermeasures. Recovery-key
compromise has no cryptographic recovery path — physical
re-provisioning of all devices is the terminal state, which is why
recovery custody is the strictest control in the system.

**WHAT THE DOC COVERS** (9 sections): decision + alternatives matrix;
provisioning key (8-step generation, Safe #1 + two-person control,
9-step use procedure per §3.6, routine + emergency rotation,
retirement, audit); recovery key (separate device, Safe #2 different
physical location, three-person ceremony, annual rotation, terminal
state if compromised, audit); offline device spec (Pixel 7+
StrongBox, GrapheneOS, ADB install, `dumpsys connectivity`
pre-ceremony check, tamper bag); client implementation notes
(ProvisioningKeys.kt DEBUG/PROD split design, ProvisioningKeysTest
new assertion, rotation seam usage); drill schedule (annual
test-signing + annual recovery-retrieval); threats matrix (7
threats); related docs; approval.

**TASK-P1-029 SPLIT, IMPLICIT.** The task covers design +
implementation. This session completes the design half. The
implementation half — `ProvisioningKeys.kt`'s DEBUG/PROD split,
`ProvisioningKeysTest`'s new assertion that production differs from
test seed, and the client wiring that consumes the new constant —
is the next session. Same split pattern as TASK-P1-027 →
027a/027b. The registry row is split in this session's close commit
to reflect both halves.

**PHASE-1 DoD PROGRESS.** The DoD tier surfaced in Z-11's correction
named P1-029 as the highest-priority unblocked item because the
current provisioning key is a test key. That gap is now closed at
the design layer; implementation lands next. P1-033 (offline
signer) now has the design to build against; P1-035 (recovery key
ceremony) has the ceremony spec it will operationalize.

**Counts.** Backend 254, Android JVM 244, androidTest 71 per
emulator — all unchanged (doc-only session).


### Session Z-13 — TASK-P1-029b DONE: ProvisioningKeys DEBUG/PROD split (2026-10-19)

The implementation half of the P1-029 split. **P1-029 is now DONE
end-to-end.** One commit: `7c02d16` (3 files, ~164 insertions, ~16
deletions).

**WHAT CHANGED — three files.**

`ProvisioningKeys.kt` (62 → 114 lines):
  - `TEST_PROVISIONING_PUBKEY_B64U` (new `const val`) — the current
    test seed, byte-identical to `canonical-matrix-test-vectors.json`'s
    `expected_provisioning_public_key_base64url`.
  - `PRODUCTION_PROVISIONING_PUBKEY_B64U` (new `const val`) — 43
    underscores decoding to 32 bytes of 0xFF. Not a valid Ed25519
    public key; a release that ships it fails matrix verification at
    runtime (safe failure, not silent-accept). Replaced by P1-033's
    ceremony.
  - `CURRENT_PROVISIONING_PUBKEY_B64U` (was `const val`, now `val`) —
    `if (BuildConfig.DEBUG) TEST else PRODUCTION`.
  - Class KDoc rewritten: names all three constants and their roles;
    corrects prior drift that claimed both keys were P1-029's
    (recovery is P1-035's).
  - `import com.umoja.secure.BuildConfig` added.

`ProvisioningKeysTest.kt` (53 → 73 lines):
  - +2 tests per §5.1: `production provisioning pubkey differs from
    test key` (`assertNotEquals`); `production provisioning pubkey
    decodes to 32 bytes`.
  - Existing 3 tests unchanged (they reference `CURRENT`, which still
    resolves the same value in debug).

`UmojaApplication.kt` (43 → 71 lines):
  - Startup assertion parallel to the existing `TransportConfig.useTor`
    canary: `check(BuildConfig.DEBUG || CURRENT != TEST) { "..." }`.
  - Comment names the dangerous case it catches (release build with
    broken routing → CURRENT = TEST → ships the test trust anchor)
    and the fail-safe case it does NOT catch (release build with
    PRODUCTION still placeholder → matrix verification fails at
    runtime, not silent-accept).

**WHY THE STARTUP ASSERTION IS IN THIS COMMIT — scope beyond §5.1's
literal text.** §5.1's two tests catch copy-paste (`PROD == TEST`)
and wrong-length (PROD decodes wrong). Neither catches the *routing*
failure — the case where `if (BuildConfig.DEBUG)` is broken, removed,
or bypassed so `CURRENT` resolves to `TEST` in release. That's the
case that ships the test key, and it's exactly what P1-029b exists to
prevent.

The codebase already has the answer: `UmojaApplication.onCreate`'s
`TransportConfig` assertion (Session Q, TASK-P1-039) is a canary for
the same class of problem. The `ProvisioningKeys` assertion is the
parallel application of an existing pattern, not new architecture.
Session Z-12's close message named this gap and deferred it; this
session closes it in the same task, on the grounds that a
copy-paste-only test does not ensure "release build cannot ship the
test key."

**Scope honestly stated: what this session does NOT do.**

- Recovery key untouched. §5.1 is provisioning-only; recovery
  custody is TASK-P1-035's (`docs/ops/KEY-CUSTODY.md` §3).
  `RECOVERY_PUBKEY_B64U` stays `const val` placeholder; its KDoc now
  names P1-035 explicitly.
- No offline signer (TASK-P1-033). `PRODUCTION_*` is a placeholder;
  the ceremony generating the real value is P1-033's.
- No matrix/notice/identity-change code touched. The 4 consumers of
  `CURRENT_*` all do runtime `Base64.getUrlDecoder().decode(...)`;
  none require `const`, so the `const → val` transition is
  compile-only, no caller edits.

**Verification.**

  Build: `./gradlew :app:testDebugUnitTest --rerun-tasks`, exit 0,
  0 compile errors, 0 test failures.
  Tests: 246 (244 prior + 2 new §5.1). `ProvisioningKeysTest`: 5
  tests (3 existing + 2 new), 0 failures. XML aggregate, not
  grep-summed.

  Runtime verification of the `UmojaApplication` assertion's *release*
  path is NOT done. The debug path short-circuits (`BuildConfig.DEBUG`
  true). The release path fires only when `CURRENT` resolves to
  `TEST` — not reachable in a debug build. Exercising it would
  require a temporary constant override; the assertion is a canary,
  not a state-machine. Same precedent as the `TransportConfig`
  assertion, whose comment says "tautological on the current code."
  Recorded as a manual verification candidate for the release-build
  acceptance pass.

**Counts.** Backend 254 unchanged. Android JVM 244 → 246 (+2).
androidTest 71 unchanged. Registry v0.9 unchanged (029b status:
New → Executed 2026-10-19; no count change — split was at Z-12).


### Session Z-14 — TASK-P1-033 SPLIT into 033a–033e (2026-10-20)

Preparatory session. Registry v0.9 → v0.10, total 45 → 49
(+4 net: P1-033 was 1 task, is now 5). No code written. The commit
is the registry amendment plus this handoff close.

**WHY THE SPLIT, ON EVIDENCE.** Reconnaissance found three things
that changed P1-033's shape since its 40-line §B body was drafted:

1. **P1-037 landed.** The `GET /me/matrix` read path exists
   (`me.ts`, O-1); the `POST` write path does not. The signing
   ceremony's final step ("admin attaches signature and pushes")
   has no backend target today — that's now a first-class sub-task
   (033a), not an implicit dependency.
2. **The offline-app packaging decision is resolvable.** Earlier
   framing implied a separate module or source set. KEY-CUSTODY §4.3
   makes the primary control physical (`dumpsys connectivity` check,
   no-network device); compile-time guards are defense-in-depth, not
   the enforcement. A `signing` build flavor + `SIGNING_ONLY` guards
   is one session, not two. 033c reflects that.
3. **Two acceptance criteria have different owners.** The current
   §B body lists "Key rotation procedure documented and tested"
   and "Key revocation procedure documented and tested" as P1-033
   criteria. Rotation is P1-036's (trusted-set change during overlap);
   revocation is P1-035's (recovery-key-authorized). The split moves
   those two criteria and their tests (TEST-PROVSIGN-004, -005) to
   the correct sibling tasks — not deleted, deferred with named
   owner.

**THREE ARCHITECTURAL DECISIONS RECORDED.** Named in §B P1-033's
body and settled here so 033a opens without re-litigation:

- **Verify-on-write, relay-on-read.** `POST /me/matrix` verifies the
  provisioning signature server-side. `GET /me/matrix` continues to
  relay (its KDoc names the asymmetry). Justification: GET relays
  because the backend has no provisioning pubkey (ADR-IDENTITY-CHANGE-
  001 §4's ruling: verify when you can, relay when you can't).
  Adding `PROVISIONING_PUBKEY_B64U` config gives the backend the key
  — the ADR's own logic then requires verification at the write
  boundary. Clients continue to verify on receipt (P1-037 defense in
  depth). Verification primitive: `@noble/ed25519.verifyAsync` (same
  as `auth/verify.ts`; matrix *signing* uses Node's built-in `crypto`
  via SPKI wrapping, but verification with a raw-32 pubkey uses
  `@noble`).
- **Non-monotonic pushes rejected 409.** `version <= existing.version`
  → 409 `matrix_version_not_monotonic`. Same rule `MatrixStore.accept`
  enforces (P1-026), applied at the write boundary. Prevents a
  compromised admin session from downgrading a matrix. New test:
  `TEST-MATRIX-PUSH-VERSION-NOT-MONOTONIC` (033a's 6th test; the
  original plan had 5).
- **Signing app = build flavor, not separate module.** The physical
  device enforces network isolation (KEY-CUSTODY §4.3). Compile-time
  guards (skip WebSocket at startup, throw if `TransportConfig`
  accessed) are defense-in-depth. A separate source set for a control
  that runs on an air-gapped device would be over-engineering.

**WHAT THE REGISTRY AMENDMENT DID.**

- §B P1-033 body expanded: Dependencies gains TASK-P1-037; one new
  acceptance criterion (verify-on-write); Required-tests list trimmed
  to the 5 tests 033 delivers (was 7; 004/005 deferred); added
  "Deferred to sibling tasks" note; added "Sub-task breakdown
  (v0.10, 2026-10-20)" with 5 named sub-tasks; added "Architectural
  decisions (v0.10, 2026-10-20)" with the 3 rulings above; Status:
  Proposed → Split.
- §C: 1 row (033) → 5 rows (033a–e) with weights 1/1/1/0.5/0.5.
- Version: 0.9 → 0.10.
- Total: 45 → 49 with range update "030–042" →
  "030–032, 033a–033e, 034–042".

**ARITHMETIC CORRECTION.** The plan drafted earlier in the session
said total 45 → 50. That was an oversight: splitting 033 (1 task)
into 033a–e (5 tasks) adds **4 net**, so 45 → 49, not 50. Verified
by range-sum arithmetic and corrected before the write. The registry
carries 49.

**TWO PROCESS ANOMALIES, BOTH CAUGHT AND RECOVERED.**

1. **1a's `ABORT: §B P1-033 header not found` was a preflight bug,
   not absent content.** §B headers use two formats in
   `US-TASK-P1-001.md`: colon-style (`### TASK-P1-033: title`) and
   emdash-style (`### TASK-P1-029 — title`). 1a's check used
   `startswith('### TASK-P1-033 ')` — space after the number, which
   matches emdash-style but not colon-style. Same for the
   `grep -c '^### TASK-P1-033 '` in 1d-1. The false abort would have
   caused a duplicate §B write. Caught by the next read (1d-2's `sed`).
   Same § family: **a preflight returning 0 or not-found is ambiguous
   between content absent and pattern wrong**. Widen the pattern before
   concluding.
2. **1d-2's first write attempt failed with `NameError: body_lines`.**
   `body_lines` was defined in 1d-2's *preflight* heredoc, not the
   *write* heredoc — two separate Python processes, no shared state.
   Failure was benign: the exception fired on an `actions.append(f'...')`
   after `src` was in memory but before `p.write_text(src)`, so no
   partial write. Fix: recompute `body_lines = end - start` in the
   write script. Same family as §7's "edit scripts start with `cd`"
   — a variable assumption crossing a process boundary. Not a new
   §7 bullet (one instance), but a note for future blocks that
   re-use preflight variables in the write phase.

**COUNTS (unchanged by this session).**

  Backend:     254
  Android JVM: 246
  androidTest: 71 per emulator
  Registry:    v0.10, total 49 (033a–e all New)

**NEXT: P1-033a** — backend POST /me/matrix + signature verification.
1 session. Six tests (5 original + TEST-MATRIX-PUSH-VERSION-NOT-MONOTONIC).
Env config `PROVISIONING_PUBKEY_B64U` test default; required in
production. Rot seam named in KDoc (single key today; P1-036 extends
to `{previous, current}` set). GET /me/matrix KDoc gains the
verify-on-write/relay-on-read asymmetry note in the same commit.


### Session Z-15 — TASK-P1-033a DONE: POST /admin/matrices/:device_id (2026-10-20)

First code session of the P1-033 arc. Backend write path for the
offline signing ceremony. Three files, one commit: `221c98f`.
**033a DONE end-to-end.**

**WHAT SHIPPED.**

- `backend/src/routes/admin.ts` +151: `POST /admin/matrices/:device_id`
  (`requireAdmin`). Verify-on-write via `verifyMatrix` (which
  re-canonicalizes per §3.8, so non-canonical JSON that parses to
  the same matrix fails at verify — correct, the ceremony requires
  JCS). Enforces `parse(canonical).matrix.device_id === urlParam`
  (migration 016's pre-announced missing invariant). Enforces
  `version = parse(canonical).version` (migration 016's column
  invariant). Rejects `version <= existing.version` with 409
  `matrix_version_not_monotonic` (mirrors `MatrixStore.accept`'s
  client rule at the write boundary). Stores `jcsCanonicalize(parsed)`
  as `canonical_bytes` — the exact form the signature verified.
  Rotation seam named in KDoc: single key today, P1-036 extends to
  `{previous, current}` set.
- `backend/src/config/env.ts` +48: `PROVISIONING_PUBKEY_B64U` schema
  field (43-char base64url, optional at zod level). `loadEnv`
  enforces: `NODE_ENV=test` + absent → test-key default;
  `NODE_ENV=prod` + absent → exit(1); `NODE_ENV=prod` + == test
  key → exit(1); `NODE_ENV=prod` + == placeholder (43 underscores)
  → exit(1). Parallel to P1-029b's client-side check; both sides of
  the ceremony fail closed on the same conditions from the same
  spec (`KEY-CUSTODY.md` §5.1).
- `backend/test/matrix-transport.test.ts` +336/-1: 9 new tests
  (`TEST-MATRIX-PUSH-VALID`, `-INVALID-SIG`, `-INVALID-BODY`,
  `-INVALID-MATRIX`, `-DEVICE-ID-MISMATCH`, `-NON-MONOTONIC`,
  `-DEVICE-NOT-FOUND`, `-UNAUTHENTICATED`, `-FORBIDDEN-USER`). 5
  existing GET tests preserved.

**VERIFY-ON-WRITE EXECUTED.** The split (Z-14) named this decision
based on ADR-IDENTITY-CHANGE-001 §4: before 033a the backend held
no provisioning pubkey, so GET /me/matrix's relay was correct. Adding
`PROVISIONING_PUBKEY_B64U` gives the backend the key — the ADR's
own logic ("verify when you can, relay when you can't") then requires
verification at the write boundary. Asymmetry is named in the POST
route's KDoc (GET KDoc unchanged — its claim is still accurate for
its path). Client verification on receipt remains (P1-037 defense in
depth).

**THE FINDING THAT MATTERED — caught at first test run.** First
run of the 9 POST tests: 5 failed with `invalid input syntax for
type uuid: "device-001"`. W-001's `matrix.device_id` is the literal
string `"device-001"` — a placeholder from Session A's vector
generator, not UUID-shaped. The route's URL param validator requires
UUID (`devices.device_id` is a UUID PRIMARY KEY). Tests calling
`createTargetDevice(TEST_ORG_ID, w001.device_id)` failed at the
INSERT before any assertion ran.

Two responses were available:

1. **Edit W-001** to use a UUID. **Rejected.** W-001 is ground truth
   (§7: "Corpus files are ground truth"); its signature is over the
   exact bytes in the file. Editing `device_id` invalidates the
   signature, breaking the 5 GET tests that assert byte-for-byte
   round-trip.
2. **Build freshly-signed matrices in the tests.** Chosen. New
   `deriveTestPrivateKey()` + `buildSignedMatrix()` helpers derive
   the same test seed the vector generator uses (HKDF-SHA256 →
   PKCS8 Ed25519, mirroring `sign-test-matrix.ts`) and sign a
   matrix with a real UUID `device_id`. `beforeAll` gains a
   self-check: derives the pubkey, asserts it matches
   `w001.pubkey_raw` — if HKDF derivation ever drifts from the
   generator, the suite fails loudly at `beforeAll` (before any POST
   test), not silently as 9 `invalid_signature` failures.

The recon-first discipline is what caught this: the failing tests
were diagnostic, not destructive — nothing shipped with a broken
route. Had the tests been written to pass without asserting against
a real UUID-shaped device, the route would have passed review while
being untestable on the first real push. Same class as Session P's
D-1 finding: the case that distinguishes correct from sticky-open
is the one not in the initial hypothesis set.

**A SECOND FINDING — the typecheck fix.** First typecheck run
caught one error: `admin.ts(276,34): error TS2532: Object is
possibly 'undefined'` on `existing.rows[0].version` behind an
`existing.rowCount === 1` guard. `noUncheckedIndexedAccess` doesn't
narrow through `rowCount` checks. Fix: extract `const existingRow =
existing.rows[0]` then guard `existingRow !== undefined` — pattern
(a) from Session H's typed-query lessons. Same family as `tx.query<T>()`
in `identityChange` services; not a new §7 lesson.

**NO NEW §7 LESSONS.** Both findings belong to families already on
disk:

- W-001-not-UUID: same family as Session P's D-1 (initial-hypothesis
  set misses the distinguishing case) and §7's "corpus files are
  ground truth."
- `rows[0]` typecheck: same family as Session H's typed-query lessons
  (§7 pattern (a) and (b)).

Recording the absence is honest — the discipline applied, the
lessons held, no fourteenth bullet was needed.

**COUNTS.**

  Backend:     254 → 263 (+9)
  Android JVM: 246 (unchanged)
  androidTest: 71  (unchanged)
  Registry:    v0.10, total 49 (033a status: New → Executed 2026-10-20)

**NEXT: P1-033b** — admin-side signing flow. `MatrixApi.push()`
(`suspend fun push(targetDeviceId: String, remote: RemoteMatrix,
sessionToken: String)`), `AdminScreenState` gains
`exportForSigning()` / `importSignature()` / `pushSignedMatrix()`.
AdminScreen UI: QR render of canonical + hash, signature ingest (QR
scanner or paste field per P1-025's debug path), push button. Error
states mirror `AdminApiException` taxonomy. ~1 session.


### Session Z-16 — TASK-P1-033b DONE: admin-side signing flow (2026-10-20)

Second code session of the P1-033 arc. Admin app can now construct,
receive a signature for, and push a signed authorization matrix to
TASK-P1-033a's route. Six files, one commit: `691d27d`. **033b DONE.**

**WHAT SHIPPED.**

- `MatrixApi.kt` (+58): `pushFn` ctor param (default = `error(...)`);
  `push(targetDeviceId, remote, sessionToken): PushResult`; `data
  class PushResult(deviceId, version)` (server echo). Body sends
  `{canonical_utf8, signature_base64url}` to
  `/admin/matrices/:device_id`; expects 201; error taxonomy mirrors
  `fetch()` (network_error / {error_code} / invalid_response).
- `MatrixApiTest.kt` (+110): 2 helpers updated to named `fetchFn = { }`;
  4 new push tests. Existing 5 fetch tests compile unchanged.
- `AdminScreenState.kt` (+100): `pushFn` 6th ctor param (default =
  error); `importedSignature` / `pushedMatrix` StateFlows;
  `importSignature` (86-char base64url regex, clears pushedMatrix),
  `clearSignature` (preserves built wrapper/hash), `pushSignedMatrix`
  (4 precondition guards before network). `buildMatrix` now clears
  `_pushedMatrix` on success — **latent bug fix**: rebuild must
  re-enable the push button; without it, a successful push left the
  button disabled with "Pushed" label after every subsequent build.
- `AdminScreenStateTest.kt` (+180): `stateWith` gains `pushFn` 6th
  param (default = error); 10 new tests (importSignature 3,
  clearSignature 1, pushSignedMatrix 5 boundary/success/failure).
  Existing 22 compile unchanged.
- `AdminScreen.kt` (+75): 4 imports (`Image`, `asImageBitmap`,
  `BarcodeEncoder`, `BarcodeFormat`); `pushScope` (rememberCoroutineScope);
  `importedSigText` state; `sigScanLauncher` (2nd ScanContract);
  2 collectAsState; push Card before Authorize section: QR render of
  `builtWrapperJson` (wrapper, not hash — offline device needs bytes
  to re-canonicalize and confirm), signature text field, Scan +
  Import buttons, "Signature imported: <12>..." echo, Push button
  (disabled after success), "Pushed: <id8>... at v<n>" echo.
- `MainActivity.kt` (+9): `adminMatrixApi` remember block — one
  HttpClient shared between fetchFn and pushFn; `pushFn =
  adminMatrixApi::push` wired into `AdminScreenState`.

**BREAKING API CHANGE — MATRIXAPI CONSTRUCTOR.** Adding `pushFn` as
second param breaks trailing-lambda syntax: `MatrixApi { t -> ... }`
would bind to `pushFn` (3 args) instead of `fetchFn` (1 arg). Callers
updated to `MatrixApi(fetchFn = { ... })`: 2 in `MatrixApiTest`, 1 in
`MainActivity`. Zero behavior change — same lambda, same fetch path.
The compile error (`No value passed for parameter 'fetchFn'`) is the
acceptance that the change was caught, not silently mis-bound.

**SCOPE HONESTY — push UI runtime verification deferred.** The push
UI is structurally complete and compiles; it is NOT runtime-verified
this session. A real end-to-end test requires a real signed matrix
from a real offline ceremony — that is TASK-P1-033e's scope. What
033b proves: admin app can construct the push payload, validate the
signature input, and call `pushFn` with right arguments (10 JVM
tests). What it does NOT prove: that a real backend accepts the
push and a real device accepts the matrix. That proof is 033e's.

**THE LATENT BUG FIXED.** `buildMatrix` populated `_builtWrapperJson`
and `_builtHash` but did NOT clear `_pushedMatrix` from a prior
successful push. Post-033b UX: push succeeds → button becomes "Pushed"
disabled → user rebuilds → button stays disabled because
`_pushedMatrix` still holds the old result. Fixed with one line:
`_pushedMatrix.value = null` in `buildMatrix`'s success branch. Same
class of bug as Session R-5's double-fetch (state consistency across
orthogonal actions). Not a §7 lesson — single-line fix, family
already covered by "remember cache keys must include the state-flow
trigger" (Session P D-1).

**VERIFICATION.**

  typecheck:    compile clean (grep ^e: empty)
  JVM tests:    260 / 260 (246 prior + 4 + 10)
                MatrixApiTest: 9 (5 existing + 4 new)
                AdminScreenStateTest: 32 (22 existing + 10 new)
  XML aggregate from <testsuite tests=> per file
  Backend:      263 (unchanged)
  androidTest:  71 (unchanged)

**COUNTS.** Backend 263 unchanged. Android JVM 246 → 260 (+14).
androidTest 71 unchanged. Registry v0.10 unchanged (033b status:
New → Executed 2026-10-20; no count change — split was at Z-14).

**NEXT: P1-033c** — offline signing app. `signing` build flavor in
`app/build.gradle.kts`; `SIGNING_ONLY` guards at `UmojaApplication`
(skip WebSocket) and `TransportConfig` (throw on use); `SigningActivity`
/ `SigningScreen` with QR-scan canonical, re-canonicalize + confirm
hash, sign SHA-256 digest via `MatrixSigner.sign()` with provisioning
key from `DeviceKeyManager`, QR-emit signature. ~1 session. Physical
network isolation is KEY-CUSTODY §4.3's domain; `SIGNING_ONLY`
guards are defense-in-depth.

---

## 4. Known issues

### KI-001 (FIXED): OkHttp cannot reach .onion through SOCKS

Fixed in `v0.29-tor-transport` with the Socks5Bridge.

### KI-002: Backend Docker image goes stale during iteration
`docker compose up -d --build backend` after backend changes, or run
`npm run dev` on the Mac during iteration.

### KI-003: Emulator loses app data on cold boot
Shut down emulator cleanly (menu -> Power off). Or accept re-enrollment.

### KI-004 (RESOLVED): Canonical-matrix test vectors were scaffold
Resolved by commit `e6eed9b`. File has `generated: true`, all six
W-series vectors populated.

### KI-005 (RESOLVED 2026-10-18, Sessions U-3 / V-1 / W-1): Requirements layer authored after the code
**All four canonical documents swept.**

| Doc | Version | Sweep session | Commit | Findings |
|---|---|---|---|---|
| AUTH-SPEC-001 | v0.1 → v0.2 | U-3 | `349b268` | 1 precision, 1 doc-drift, 1 real gap (filed P1-042), 3 hypotheses refuted |
| THREAT-MODEL-001 | v0.1 → v0.2 | V-1 | `5655318` | 2 doc-drift, 1 real gap (cross-ref P1-042), 3 completeness behavioral, 1 precision, 10 holds |
| US-ADD-001 | v0.2 → v0.3 | W-1 | `20771af` | 4 completeness parametric, 1 stale-end-of-doc, 10 holds |
| US-MASTER-001 | v0.1 → v0.2 | W-1 | `3720b59` | 1 cross-doc propagation, 1 doc-set completeness, 10 holds |

**Total across the sweep:** 4 doc-drift, 1 real gap (P1-042), 3
behavioral completeness, 4 parametric completeness, 2 precision,
1 cross-doc completeness, ~30 claims verified holding.

**One real gap:** the WS revocation listener does not
reconnect-and-re-reconcile. Named at U-3 (§9.3 defense 2), V-1
(§8), and W-1 (US-MASTER-001 §3.5). Filed as TASK-P1-042. Until
that ships: WS-close timing is ≤5s when the listener is healthy,
≤5min when disconnected.

**No new task filed by the sweep itself** — the real gap was
already filed at U-3; every other finding was a prose correction.

**Methodology lessons captured in §7** (below):
- `completeness` as a fourth classification bucket (V-1).
- `completeness` has two forms — behavioral (V-1) and parametric
  (W-1). Same bucket, different amendment shape.
- Cross-document propagation (V-1 named it, W-1 applied it and
  found US-MASTER-001 §3.5 in one shot).

**Re-sweep cadence:** the four documents are now marked
"conformance-swept 2026-10-18." A future re-sweep is warranted if
a document's scope changes materially or a code refactor touches
claims the sweep verified. No scheduled cadence; the docs'
version histories record the sweep's findings, and future
divergence shows up as a doc claiming something the code
doesn't do — the same mechanism every drifted claim in this sweep
had.

### KI-006 (RESOLVED 2026-10-18, Session U-2): USER-ONBOARDING.md written
`docs/reference/USER-ONBOARDING.md` written at Session U-2.
241 lines, 1430 words. User-facing companion to the implementer
docs; every claim restated from an authoritative source (with
`Source:` lines); cryptographic erasure guarantee preserved
verbatim (Build Master §3.4's "does not guarantee every physical
storage remnant is forensically unrecoverable" caveat intact);
all four recovery states from ADR-HARDENING-001 §1 documented.
Absent since before Session A; closed Session U-2.

### KI-007 (RESOLVED): Kotlin number serialization
Resolved by `ff15357`.

### KI-008 (RESOLVED 2026-10-18, Session U-1): Three canonicalizers coexist

| Encoder | Serves | Prehash? |
|---|---|---|
| `canonicalizeChallenge` (TS) / `CanonicalChallenge.encode` (KT) | challenge-response | no |
| `canonicalJson` (TS) | audit hash chain | no |
| `jcsCanonicalize` (TS) / `jcsCanonicalizeString` (KT) | matrix signing | yes (SHA-256) |

Still three canonicalizers, still not unified -- different
protocols, different signing rules. But the duplication of
`canonicalJson` between `audit/log.ts` and `audit/verify.ts`
was extracted to `audit/canonicalJson.ts` (single source; KDoc
documents the shallow-sort pre-existing concern). Backend
250/250 passing proves write and verify paths agree on HMAC.

### KI-009: Backend test suite requires Postgres
`vitest run` triggers `test/global-setup.ts` -> Postgres connection.
Fix: Docker up, or a conditional in `global-setup.ts`.

### KI-010 (RESOLVED by option B): @noble/ed25519 approval
See §3. Matrix path uses Node built-in crypto (TS) and BouncyCastle
(Kotlin). `@noble/ed25519` stays scoped to `auth/verify.ts`.

**Not resolved:** whether `@noble/ed25519` was ever formally approved
for the auth path. §6 audit item when auth is next touched.

### KI-011 (RESOLVED): Kotlin canonicalizer corpus test parser
Resolved by adding test-scope `org.json:json:20240303`.

### KI-012 (RESOLVED): JCS implementations must be cross-checked
Resolved by commit `41f52b0`. PASS on 38 inputs.

### KI-013 (NEW): Handoff test counts were fabricated
The prior handoff claimed "85 backend tests, 48 Android tests"
(baseline), then "98 Android tests" after Session A crypto work.
Actual JVM unit-test count after Session A is 77; androidTest is 0
files. Backend count verified this session: 175 (later raised to 178 by commit 3d3ff60, the token-binding work).

The androidTest count was also wrong in an earlier handoff ("0 files",
actual 6 files / 46 tests as of 2026-10-15). Same failure mode: counts
propagated without verification against runner output.

**Consequence:** do not propagate test counts from prior handoffs.
Recount from test-runner output.

### KI-014 (NEW): ADR-PROVISIONING-001 §7 residual item
The ADR asked for file-level verification of Q1/Q4 against
THREAT-MODEL-001 and AUTH-SPEC-001 "at Session A kickoff." Those two
files were authored *after* the ADR, from the same attestations the
ADR recorded. File-level verification is therefore definitional, not
independent. Recorded as documented exception (b). Amendment landed in
ADR §7.1.1 (commit `4abcf53`).

### KI-015 (RESOLVED 2026-10-15, commit `407bbac`): six tracked backup files
`git ls-files | grep -E '\.bak|\.orig|\.swp|~$'` returns six:
`MainActivity.kt.bak`, `MainActivity.kt.bak-navdiag`,
`AdminScreen.kt.bak-navdiag`, `MainNavigation.kt.bak`,
`MainNavigation.kt.bak-tab-sync`, `backend/package.json.bak`.

The prior text said "one file" and claimed it "ends up on classpath."
Both wrong. Gradle's Kotlin compiler ignores `.bak` — the file does
not reach the classpath. The actual harm is repo pollution and
search noise. All six were deleted in commit `407bbac`.

### KI-016 (RESOLVED 2026-10-18, Session U-1): Duplicated base64url validators
`ProvisioningBundle.kt`, `AuthorizationMatrix.kt`, and
`ReplacementNotice.kt` each defined file-private
`requireBase64Url32` / `requireString` / `BASE64URL_RE` (three
copies, not two -- the original note missed ReplacementNotice).
Extracted to `crypto/Base64UrlValidation.kt` with `internal`
visibility. Scope bounded: PRINTABLE_ASCII_RE /
requirePrintableAscii stayed in PB; ISO8601_UTC_RE /
requirePositiveInt / requireStringList stayed in AM;
EnrollmentQrPayload's variant stayed put (genuine different
validation). Session F's `RN_` prefix discipline superseded by
extraction (KDoc records the reasoning).

### KI-017 (NEW): QR payload not signed
The enrollment QR payload carries public keys and a device_id with no
signature. In Phase 1 this is spec-conformant (§3.2: public material
only). A future hardening task could have the device sign the payload
with its auth key — at which point the `domain` field becomes
load-bearing and the payload should be JCS-canonicalized. Not Phase 1.

### KI-018 (RESOLVED 2026-10-16, Session C; marked 2026-10-18, U-1)
Backend tracks current matrix version per org.
`backend/migrations/013_org_matrix_versions.sql` +
`backend/src/admin/matrixVersions.ts` landed in Session C
(commits 6013077, 4e6e096, 8adde6b). This entry was stale --
still said "(NEW)" in the handoff until Session U-1's doc
hygiene pass. No code change needed.

### KI-020 (RESOLVED 2026-10-15): EnrollmentQrScreen unreachable before authentication
`EnrollmentQrScreen` was reached only via Settings → "Enrollment QR",
which is behind `AppScreen.Authenticated`. A fresh device could not
reach it. Fixed by adding a "Show enrollment QR" `TextButton` on the
unenrolled `EnrollmentScreen`, opening the QR as a full-screen overlay
via an `openEnrollmentQr` boolean in `AppRoot` (mirrors the pattern
already in `MainNavigation`). Button is gated on the inverse of
`isBusy`.

**Known papercut.** `EnrollmentScreen`'s local `tokenInput` and
`labelInput` do not survive the QR round-trip: the early `return`
short-circuits the `when` dispatcher, `EnrollmentScreen` leaves the
composition, and its `remember` slots are discarded. Not exercised
by the documented workflow (QR-first, then token). If this becomes
a real problem, the fix options are (2) hoist the two fields to
`AppRoot`, or (3) occlude via `Box` rather than early-returning —
the latter keeps `EnrollmentScreen` composed, which is fine today
(no `LaunchedEffect`) but a latent hazard if any are added later.
Recorded, not fixed.

### §5 item 6 — P1-026 client verification and storage (commit `a76a9a1`)

Done and verified end-to-end.

**Code:**
- `crypto/MatrixVerifier.kt` — new. `verify(canonical, sig,
  trustedKeys: Set<PublicKey>)`. Iterates the set, fails closed on
  empty set and malformed signature. Stateless, no anti-rollback.
  The set is the seam for the rotation overlap window; Phase 1 uses
  a singleton.
- `crypto/MatrixSigner.kt` — added `matrixDigestRaw(canonical)` and
  `verifyRaw(canonical, sig, pubkey): Boolean`. `verify(signed, ...)`
  keeps its existing throw-on-malformed contract (MatrixSignerTest
  asserts it) and now delegates to a shared private `verifyDigest`.
  The throw-vs-false distinction is provenance: parsed `SignedMatrix`
  means programming error, wire bytes mean untrusted data.
- `crypto/ProvisioningKeys.kt` — new. `CURRENT_PROVISIONING_PUBKEY_
  B64U` derived from the vector file's test seed; `RECOVERY_PUBKEY_
  B64U` is a visibly-fake placeholder. Both are TEST KEYS; TASK-P1-029
  replaces them before any production build. Cross-checked against
  the vector file by `ProvisioningKeysTest`.
- `crypto/MatrixStore.kt` — new. Single JSON envelope
  `{"canonical": "<b64u>", "signature": "<b64u>"}` under one
  SecureStorage key. `accept` = verify → parse → anti-rollback check
  → persist. `load`, `highestSeenVersion`, `permittedContacts` derive
  from the stored canonical bytes; nothing is stored twice.
- `storage/KeyValueStore.kt` — new interface, four methods. Exists so
  `MatrixStore` is JVM-testable without a `Context`.
- `storage/SecureStorage.kt` — implements `KeyValueStore`.
- `ui/diagnostics/DiagnosticsScreen.kt` — debug-only (FLAG_DEBUGGABLE)
  Matrix section: two paste fields, Verify and store, Clear stored
  matrix, read-back display.

**Design rulings recorded (2026-10-15):**
- Storage: SecureStorage, single JSON envelope. Verification on read
  is hash-then-verify; no re-canonicalization in the trust path.
  Parse is convenience, not trust — the stored bytes remain verified
  against the signature even if `AuthorizationMatrix.fromJsonMap`
  widens in future.
- `highest_seen_version` derived from `matrix.version`, not stored
  separately. Closes a crash-window inconsistency.
- Two distinct trusted sets. Matrix-verification set: provisioning
  keys only. Notice-verification set: recovery key only. Never
  conflate — matrices are never verified against the recovery key.
- Structural seams for rotation ship in P1-026 (`previous_
  provisioning_pubkey` and `highest_recovery_key_version` present in
  `ProvisioningKeys` but unused; `verifyMatrix` takes a Set). Handlers
  deferred to TASK-P1-036.
- Contacts are a projection of the verified matrix. `/me/contacts`
  is a convenience view, not a trust source. P1-026 exposes
  `permitted_contacts[]` as an accessor; wiring `ContactsScreen` to
  consult it is a follow-up UI decision.
- Anti-rollback lives in `MatrixStore.accept`, not `MatrixVerifier`.
  Separating policy state from the stateless crypto primitive means
  the rule cannot be bypassed by calling the verifier directly.

**Manual emulator verification (Pixel_9, emulator-5554):**
1. Loaded W-001's canonical bytes and signature via the Diagnostics
   debug section. Tap "Verify and store" → `Accepted(version=1)`,
   read-back `highestSeenVersion=1 contacts=1`.
2. Force-stopped the app. Reopened. Re-pasted identical values. Tap
   "Verify and store" → `Rejected(rollback)`, read-back unchanged.

Step 2 is the load-bearing verification. It proves persistence (the
version came from disk, not in-memory state), anti-rollback (`1 ≤ 1`
fired the policy check), and store-unchanged-on-rejection.

**Not covered by this task:** transport. How the signed matrix
reaches the device — HTTP, QR, or both — is deferred. Authority comes
from the signature and the pinned key, not the transport
(THREAT-MODEL-001 §7, ADR §2 Q3). Named follow-up: TASK-P1-037 —
matrix transport (`/me/matrix` HTTP endpoint + client fetch).

**Follow-ups filed:**
- TASK-P1-036 — provisioning-key rotation and recovery-key
  revocation notice handling.
- TASK-P1-037 — matrix transport.
- Token bootstrap: 5554 was wiped by an earlier `pm clear` during
  KI-020 verification, so re-enrollment used the direct-SQL path
  from §3's emulator bootstrap note. Second occurrence. Candidate
  for a debug-only bootstrap affordance or a `scripts/` helper, if
  it recurs.

### P1-030 scoping (2026-10-16)

§3.7 of the Build Master specifies the replacement-device flow as an
11-step integrated test. Mapping against existing code shows P1-030
is six sub-tasks, not one session, and KI-018 is a hard prerequisite:

- **3a** — backend tracks current matrix version per org. Closes
  KI-018. §3.7 step 1 requires the backend to record "the current
  matrix version at the time of token issuance"; KI-018 defers that
  tracking today.
- **3b** — migration: `enrollment_matrix_version_floor` on
  `enrollment_tokens`. Issuance records the current version.
- **3c** — `POST /enrollment` response carries the floor. Client
  stores it.
- **3d** — `MatrixStore.accept` gains floor-aware mode. Accepts
  `version >= floor` during initial enrollment, strictly-greater
  thereafter. Current implementation is strictly-greater always.
- **3e** — peer identity-change notification + ack state. New
  protocol message. Peers block sending to the replacement device
  until they acknowledge its new key.
- **3f** — integrated test: the 11-step scenario in §3.7.

**Transport caveat.** Steps 5 and 7 of the integrated test push a
matrix to a device — no delivery transport exists (TASK-P1-037).
Interim path: the P1-026 c2b Diagnostics debug paste field can drive
those steps, since the floor semantics are orthogonal to transport.
Steps 8–9 (identity-change notification) are peer-to-peer and likely
need a real channel; decision pending.

**Recommended sequence:** 3a alone next session.

**Registry:** P1-030 should be re-registered as six sub-tasks in
`docs/US-TASK-P1-001.md` so a future agent does not read it as one
session's work.

### KI-021 (RESOLVED 2026-10-16): emulator 5556 black screen after cold boot
`Pixel_9_API35` (or `Pixel_9_API35_B` — the AVD name in the launch
log did not match the handoff's recorded name) boots to a black
framebuffer on cold boot. `adb` connects, `sys.boot_completed = 1`,
but the display is black. Likely GPU/environment config, not a
project bug. Not blocking. Rebuilds and reinstalls land cleanly if
the device is targeted explicitly with `-gpu swiftshader_indirect`.
Not verified this session — set aside for Path 1 + 3 verification.

**RESOLVED 2026-10-16.** Host reboot. The black screen was a stale
qemu process surviving a prior crash; a full Mac restart cleared it.
Next time this symptom appears: try reboot before deeper diagnosis.

### KI-022 (RESOLVED 2026-10-16): auth.test.ts flaky under full-suite load

Two to three tests in `auth.test.ts` intermittently failed with
`POST /auth/challenge` returning 500 and (once) 401 on "returns
challenge for active device." Same file passed 11/11 alone. Three
occurrences across a session.

**Cause.** `matrix-version.test.ts` used
`TEST_ORG_ID = '00000000-0000-0000-0000-000000000088'` — the same
constant `auth.test.ts` uses — and its `beforeEach` runs
`DELETE FROM devices WHERE org_id = '...088'`. Under parallel test
execution, matrix-version's cleanup deleted auth's devices mid-test.

**Diagnosis path.** Pair-testing isolated it: `auth + enrollment`
17/17 pass, `auth + admin` 28/28 pass, `auth + matrix-version` 5/17
fail. A grep across `test/*.ts` for the org constants showed the
collision.

**Fix.** `matrix-version.test.ts` constants changed to
`...0a1` / `...0a2`. Commit `4e6e096`.

**Not the cause** (recorded so it isn't re-litigated): pool
exhaustion. Vitest defaults to maxWorkers = cores - 1; pool max was
20 per worker; 220 worst-case against Postgres `max_connections: 100`
is a real risk, so `64f4494` reduced test-mode pool to 5 as
precautionary hygiene. But it was not the flake's cause — three
consecutive full-suite runs after the pool change still showed
failures.

---

## 5. Immediate next steps (recommended order)

**1. ADR-PROVISIONING-001 §7 amendment — DONE** (commit `4abcf53`).
Recorded:

- Flag 2 / KI-014: exception (b). The four reference docs postdate the
  ADR and were authored from the same attestations, so file-level
  verification is definitional, not independent.
- TEST-PROVSCHEMA-001 reclassification: it is a **builder test**, not
  a schema test. The schema cannot detect a swap between two
  same-length base64url fields. Restate in §5.
- QR payload format record: add the amended `umoja.enrollment-request.v1`
  format from §3 to §6 step 5. Flag that TASK-P1-019 must conform.
- Version-source note: manual entry, default 1; backend tracking is a
  future improvement.
- P1-019 propagation flag: the QR format is authoritative in the ADR;
  the enrolling-device generator must match.

**2. Verify TASK-P1-025 AdminScreen on emulator — DONE**
(2026-10-15, commit 44b6520). See §3 for the evidence.

`ScanContract` has no injectable path on an emulator without a second
device or virtual-camera setup. A `FLAG_DEBUGGABLE`-gated paste field
is added inline in the "Provision new device" section (no
`BuildConfig` change; AGP 8.x does not generate it unless
`buildConfig = true`). Zero production behavior change.

**3. Android `bound_public_key` wiring + KI-019 passthrough — DONE** (commits `f361cb0`, `24cf292`). See §3 for evidence.
Backend landed (commit `3d3ff60`, migration `012_enrollment_tokens_bound_public_key.sql`,
tests 175 → 178). Android + backend remaining work, now fully specified
by rulings 2026-10-15.

**Ruling (UI): A1 — inline in the "Scanned device" card.** The admin
provisions one device end-to-end while holding it: scan QR → name →
clearance → contacts → build matrix → create token → hand over. One
continuous action on one screen. The standalone "Create enrollment
token" section is deleted in this task; token lifecycle management
(list unused, revoke) is a separate follow-up if needed. No bulk
pre-provisioning — the workflow doesn't support it.

**Ruling (binding): no `device_id` in the token.** The token binds a
public key. That is the complete credential binding. `device_id` is a
client-chosen identifier (KI-019), not a secret, not a claim the
backend can verify. Binding it adds no threat-model value — a leaked
token still requires the private key matching the bound pubkey, and
an attacker holding that key already controls the device. No migration
013. No second predicate in `consumeEnrollmentToken`. Recorded here
so it isn't re-litigated.

Change list:
- `backend/src/enrollment/consume.ts` — replace `randomUUID()` with
  the `device_id` from the request body.
- `backend/src/routes/enrollment.ts` — validate `device_id` on the
  same strict shape `ProvisioningBundle.kt` enforces (printable
  ASCII, ≤64, UUID v4 recommended not required); reject with 400
  before any DB write. Response `device_id` field already exists;
  source changes from `randomUUID()` to the client-supplied value.
- `AdminApi.CreateTokenRequest` gains `boundPublicKey: String`.
- `AdminScreen.kt` — "Scanned device" card gains a "Create token for
  this device" button that reads `scannedBundle.pubDeviceAuthKey` and
  passes it. Enrollment POST carries `scannedBundle.deviceId`
  (KI-019). The standalone "Create enrollment token" section is
  deleted.
- Tests: TEST-ENROLL-DEVICEID-ECHO (response value equals the sent
  value — not a new-field test), TEST-ENROLL-DEVICEID-COLLISION
  (existing PK → 23505 → `device_already_enrolled` path fires).

**Note on the echo.** The response `device_id` is a sanity check, not
a security control. The client generated the value and the backend
now echoes it back, so the check can only surface a backend bug. Name
it that way in code and tests; do not imply it is a binding.

**Follow-up (separate task):** token lifecycle management — list
unused tokens, revoke. Once the standalone section is deleted the
admin has no UI to see tokens already in the DB; the follow-up
restores that under the new inline flow.

**4. TASK-P1-033 — offline provisioning-key signing workflow.**

- Admin app displays hash + matrix; offline signer re-canonicalizes,
  confirms hash, displays matrix for human confirmation, signs via
  `MatrixSigner` (loaded key), returns signature.
- Admin app attaches signature and pushes signed matrix.
- **The admin app never holds the provisioning private key.**

**5. TASK-P1-019 — enrolling-device QR generator — DONE** (commit `a4ec1f9`). See §3 for evidence.
Must emit the amended `umoja.enrollment-request.v1` format. Device
generates `device_id` (UUID v4) at first entry to the new
`EnrollmentQrScreen`, stores in `SecureStorage` (not DataStore — the
handoff's "DataStore" wording was descriptive, not prescriptive; see
Commit 2 notes when they land). QR is rendered via
`com.journeyapps.barcodescanner.BarcodeEncoder` (already a dependency).
Payload builder is a pure function; unit-tested against
`ProvisioningBundle.parse` for producer/consumer interop. Manual
round-trip required (generate on emulator, scan with admin app).

Wipe-confirmation key prerequisite: DONE — `WipeConfirmationKeyManager`
(commit `8bd4ab5`).

**6. TASK-P1-026 — client verification and storage — DONE** (commits
`bcd0375`, `e56f832`, `b750e48`, `a76a9a1`). See §3 for the manual
verification evidence.

**Design decisions (ruled 2026-10-15, before implementation):**

- **Storage.** SecureStorage, single JSON envelope under one key:
  `{"canonical": "<base64url>", "signature": "<base64url>"}`.
  Canonical bytes stored once at receipt. Verification on read is
  hash then Ed25519 verify; no re-canonicalization, no parse in the
  trust path. Field access parses the stored bytes; parse is
  convenience, not trust. Record that invariant in the MatrixStore
  KDoc when the code lands — if `AuthorizationMatrix.fromJsonMap`
  is ever widened, the stored bytes remain verified against the
  signature, so no parse-based bypass exists.
- **highest_seen_version is derived**, not stored separately. It is
  `parse(stored_bytes).version`. Separate storage invites a
  crash-window inconsistency: write matrix, crash before writing
  version, accept a rollback on next launch.
- **Two distinct trusted sets.** Matrix-verification set:
  `{current_provisioning_pubkey} ∪ {previous_provisioning_pubkey if
  a rotation notice has been received and the overlap window is
  open}`. For Phase 1 that is just `{current}`. Notice-verification
  set: `{recovery_pubkey}`, used only when a `key_rotation` or
  `key_revocation` notice arrives. Matrices are never verified
  against the recovery key.
- **Structural guards for rotation.** P1-026 ships the seams, not
  the handlers:
  - `current_provisioning_pubkey`, `recovery_pubkey` — consts in
    the APK.
  - `previous_provisioning_pubkey` — SecureStorage key, initialized
    absent; nothing writes it in P1-026.
  - `highest_recovery_key_version` — SecureStorage key, initialized
    0; nothing increments it in P1-026.
  - `verifyMatrix(wrapper, signature, trustedProvisioningKeys:
    Set<PublicKey>): Boolean` takes a set even though it is size 1
    in P1-026. That is the seam.
  - Fail-closed if a rotation notice arrives before the follow-up:
    the notice is ignored (no handler), `previous_provisioning_pubkey`
    stays absent, new-key-signed matrices are rejected. Safe.
- **Contacts are a projection.** The verified matrix is authoritative
  for who is authorized. `GET /me/contacts` is a convenience view
  that should match but is not trusted. Divergence is a
  server-compromise signal, not a client-confusion signal. P1-026
  exposes `permitted_contacts[]` as a read accessor on the verified
  matrix; wiring `ContactsScreen` to consult it (or cross-check) is
  a follow-up UI decision.
- **Follow-up task:** TASK-P1-036 — provisioning-key rotation and
  recovery-key revocation notice handling.

Re-canonicalize wrapper; verify Ed25519 against the trusted
provisioning key set; enforce `highest_seen_version`
(post-enrollment) or inclusive floor (replacement device); expose
contacts from `permitted_contacts[]`.

**7. TASK-P1-030 — replacement-device flow (integrated test per
Build Master §3.7). 3a DONE 2026-10-16 (`6013077` backend +
`c79d7f8` registry v0.5). 3b DONE (`3dded33`). 3c DONE (`420d71f`).
3d DONE (`71e06c7`). 030e-a DONE 2026-10-17 (`d28c631` TS +
`f257e03` Kotlin). 030e-b DONE 2026-10-17 (`21677a9` ADR v0.1 +
`00f31df` migration 015 + `d8b2cfc` services/routes + `b26913a`
17 route tests + ADR v0.3). 030e-c 3a DONE 2026-10-17 (`a178e83`
schema + `ed271ac` signer + A-001 + `36f9a94` timestamp refresh).
030e-c 3b DONE 2026-10-17 (`e905426` verifier + `39898ad`
production signer + `031a0e5` helper extraction + `dde60f2` API +
`f747e37` store). 030e-c 3d-1 DONE 2026-10-17 (`eea1af7`
IdentityChangeController + allNotices() store extension). 030e-c
3d-2 DONE 2026-10-17 (`ec5abf1` ChatScreen banner + gate + dialog
+ ack + chat-open polling). 030e-c 3d-3b DONE 2026-10-17 (`eec0ee6`
AppRoot foreground lifecycle polling + `3dd8583` sign-test-notice.ts
helper). All 8 acceptance steps passed on emulator (Session M entry
records the evidence). 030e-d (peer-ack visibility) DEFERRED behind
the hardening pass (item 16). Next: finish **TASK-P1-037** (O-2
client half), then **TASK-P1-038** — send-gate verification. 038
goes before 039/040 per ADR-HARDENING-001 §6; the ADR argues it
runs before the larger state-machine change because it is the one
task that might reveal a hole rather than require new code.**

**030e-d design notes (captured while fresh, deferred not canceled).**
When 030e-d opens, the analysis is:
- Backend: nothing new. `GET /identity-change-acks/:notice_hash`
  exists (Session H `TEST-ACK-LIST-BY-NOTICE`). Response shape
  `{acks: [{acking_device_id, decision, created_at}]}`.
- Android API: `IdentityChangeApi.getAcks(noticeHash, sessionToken)`.
  `dde60f2`'s KDoc records the omission — 030e-d is the consumer
  that justifies adding it.
- Controller: `acksFor(noticeHash): Result<List<AckEntry>>` — thin
  wrapper, same shape as `refresh()` / `ackAndPost()`.
- UI: `AckDialog` in `ChatScreen.kt` gains a peer-ack section below
  the notice metadata. Polls on dialog open only — no persistent
  polling; the section is only shown while the human is looking.

Two open design questions:
1. **Peer labels.** `acking_device_id` is a UUID. Three options:
   raw-UUID prefix (`f697b280… accept`), join with `/me/contacts`,
   or add a label field to the ack-list response server-side (small
   backend change, but modifies a shipped route). Last is cleanest;
   needs a ruling before coding.
2. **"N of M".** `permitted_contacts.size - 1` gives M client-side,
   null if matrix isn't loaded. Ship without denominator first;
   add `of M` if friction develops.

Scope: two or three commits, one session. Crypto protocol, transport,
discovery, gating, lifecycle all proven from 030e-c. Genuinely small.

**030e-b design questions** — RESOLVED in ADR-IDENTITY-CHANGE-001
(`21677a9`, design), backed by migration 015 (`00f31df`, schema).
Do NOT re-open these; the ADR is the authoritative ruling.

- Q1 ack signature domain → ADR §3: `umoja.identity-change-ack.v1`,
  distinct from `umoja.replacement-notice.v1`.
- Q2 backend verifies device-signed artifacts → ADR §4: yes, reuses
  `@noble/ed25519.verifyAsync` per `auth/verify.ts`. Session F's note
  that backend had not done this before was wrong — that is exactly
  what session auth does.
- Q3 peer discovery → ADR §5: Option C (backend returns all org
  notices, client filters by accepted matrix). Options A and B
  rejected with named reasoning.

Original phrasing preserved below for history:

1. **Ack signature domain.** The peer signs "I have seen notice H and
   accept it." Is that a new domain (`umoja.identity-change-ack.v1`),
   a distinct artifact with its own schema, or a variant of the
   replacement-notice shape? Different claim, probably warrants a
   distinct domain — but the ruling belongs to the session that writes
   the schema.
2. **Backend verification of device-signed artifacts is new.** The
   backend already verifies admin provisioning signatures (matrix
   verification is client-side, but the admin routes verify sessions
   and the audit chain verifies HMACs). It has NOT verified a
   device-signed artifact before. 030e-b's ack endpoint would be the
   first: `POST /identity-change-acks` receives a peer-signed ack,
   backend verifies against the peer's device auth key (already on
   file from enrollment), and stores it only on successful
   verification. Design carefully — this is a new trust boundary in
   backend code.
3. **Peer discovery of the notice.** `GET /identity-change-notices`
   filters by "notices referencing devices in the caller's
   `permitted_contacts[]`." The backend can do this without breaking
   server-blind: the matrix is a signed public authorization artifact,
   not ciphertext, so reading `permitted_contacts` is allowed.
   Confirm this boundary explicitly in the code comments — a future
   reviewer will ask "isn't the backend supposed to be blind?" and the
   answer needs to be in the file, not in this handoff.

**After Session A:**

8. **KI-020 fix — EnrollmentQrScreen reachable before auth — DONE.**
   UI change; unblocks the real QR provisioning flow. See §4 KI-020.
9. **Deliberate role-elevation flow.** Strict A1 (commit `24cf292`)
   removed the admin UI's ability to mint non-`user` tokens.
   Second-admin provisioning currently requires direct SQL. Add a
   guarded CLI, dedicated screen behind re-auth, or offline process.
   Not a UI affordance in the provisioning card.
10. **Token lifecycle UI.** The A1 change deleted the standalone
    "Create enrollment token" section, which was the admin's only
    view of tokens already in the DB. Restore list-unused + revoke
    under the inline flow.
11. Emergency lock (TASK-P1-021a).
12. Duress wipe (TASK-P1-021b).
13. Signing-key custody (TASK-P1-029), recovery key (TASK-P1-035).
14. Hardware-backed Ed25519 verification (TASK-P1-034). Requires
    physical hardware.
15. Hardening: SBOM, Android redaction audit, penetration test,
    independent review.
16. **P1 hardening pass (TASK-P1-037 → 041)** — ADR-HARDENING-001
    v0.2. Read findings from the v0.2 session (six reads executed):
    - Send gate **absent** in `MessagingService.sendMessage`.
      TASK-P1-038 is implementation, not verification.
    - `lookupSession` does **not** differentiate expired from revoked.
      Backend change confirmed.
    - `AppRoot` routing **incomplete** — never checks
      `sessionExpiresAt < now()`.
    - `FLAG_SECURE` **absent** on all screens.
    - Backup flags **already set** — `allowBackup="false"` +
      `fullBackupContent="false"` both present.
    - `TransportConfig.useTor` is `var`; `buildConfig = false`
      means `BuildConfig.DEBUG` unavailable — task 039 enables
      `buildConfig = true`.
    - **AGP 9.4.1** (not 8.x as v0.1 assumed). Release uses
      `optimization { enable = false }` (AGP 9 DSL), which currently
      ships unoptimized. Exact semantics deferred to 039's docs read.

    **Sequencing correction:** v0.1 said `038 → 039 → 040 → 041`.
    Read findings + fail-closed ruling change this to
    **`037 → 038 → 039 → 040 → 041`** — matrix transport is 038's
    hard prerequisite. Fail-closed gate blocks all sends until a
    matrix exists on-device; shipping 038 without 037 produces green
    tests and a gate that never fires in production.

    **TASK-P1-037 DONE 2026-10-17** across two sessions. O-1 backend
    (migration 016 `46a3443`, `GET /me/matrix` `98fee5c`, 5 route
    tests `a6174ea`); O-2 client (`f5e7fd2` MatrixApi, `258673d` +
    `d03910d` tests, `bc1cf2c` seed script, `14c39c2` + `f2dbf43`
    AppRoot + Diagnostics wiring, `dad5a49` withContext fix).
    Verified on emulator: seed → force-stop → relaunch →
    `highestSeenVersion=1 contacts=0`. See Session O-2 entry in §3.

    **TASK-P1-038 DONE 2026-10-17.** Four commits (A/B/C/D-1);
    three-case acceptance passed end-to-end. See §3 Session P entry.
    030e-d remains deferred behind the whole 037–041 pass.

    **TASK-P1-039 DONE 2026-10-17.** Five commits (A/B/C/D/doc);
    see §3 Session Q entry. Empirical acceptance: release APK cold-
    starts with no crash, Tor transport active (`.onion` request
    seen at backend from 172.18.0.4), four-screen FLAG_SECURE
    matrix passes. ADR §9 v0.2 item 7 (optimization.enable
    semantics) resolved to `optimization { enable = true }` +
    `src/release/keepRules/*.keep` per AGP 9.4.1 docs. See
    `docs/ops/RELEASE-ACCEPTANCE.md` for the reproduction procedure.

    **TASK-P1-040-A DONE 2026-10-18.** Backend device_revoked
    disambiguation (`db9fe72`) + ADR-IDENTITY-CHANGE-001 v0.4
    amendment (`5d24621`). `lookupSession` returns discriminated
    union; middleware/challenge/verify/ws all handle device_revoked.
    Backend 247 → 250. Curl verified active→200, revoked→401
    `device_revoked`. See §3 Session R entry.

    **TASK-P1-040-B DONE 2026-10-18.** Android session state
    machine landed (`f9e01ab`). `SessionStateManager` with 7 states,
    single-flight Mutex+CompletableDeferred, fail-toward-recovery on
    malformed expiry, terminal-state short-circuit. 12 JVM tests,
    178 → 190. Zero production integration this commit — 040-C wires
    it into AppRoot, 040-D wires it into HttpClient. See §3 Session
    R-2 entry.

    **TASK-P1-040-C DONE 2026-10-18.** AppRoot routing rewrite
    landed across two commits. `55513f2` adds
    `SessionStateManager.clear()` + test (JVM 190 → 191).
    `11064d6` rewires AppRoot: `sessionExpiresAt` compose var
    removed, state machine wired in with `AuthOutcome →
    ReauthOutcome` mapping, 4 new AppScreen branches (Loading,
    Revoked, NetworkFailure, EnrollmentRequired), 3 routing
    effects replacing 2 old ones, `SessionScreens.kt` new file
    (~105 lines). Smoke verified on emulator 5556: cold launch →
    Authenticated home + `/me/matrix` fired; logout → Enrollment
    + backend logout confirmed in sessions table; authenticate →
    POST /auth/challenge → POST /auth/verify → GET /me/matrix
    chain fires. See §3 Session R-3 entry.

    **TASK-P1-040-D DONE 2026-10-18.** HttpClient 401 interceptor
    landed across three commits (`ae1c840` D-1 interceptor +
    predicate + 7 JVM tests, `d835821` D-2 AppRoot wiring,
    `bfe9fee` D-3 terminal-state honesty fixes).
    TEST-SESSION-REVOKED-ON-DEVICE passed fully — detection
    (Revoked terminal screen) and recovery (Log out and try again
    → Authenticate → Conversations) both verified. See §3 Session
    R-4 entry.

    **TASK-P1-040-E DONE 2026-10-18, TASK-P1-040 fully DONE.**
    Both manual acceptance tests passed on the R-4 build with zero
    code changes:
    - TEST-SESSION-APP-START-EXPIRED: cold launch on expired
      session → silent reauth (challenge=1, verify=1, new session
      created, Conversations home, no button tap)
    - TEST-SESSION-NETWORK-DURING-REAUTH: backend stopped, tap
      Authenticate → NetworkFailure terminal with Retry; backend
      restarted, tap Retry → Conversations home
    See §3 Session R-5 entry. All six registry §B tests now
    accounted for. ADR-HARDENING-001 §9 v0.3 amendment lands
    with this handoff.

    **TASK-P1-041 DONE 2026-10-18. The 037-041 hardening pass is
    fully closed.** VerificationFailureStore + 3-site wiring (matrix,
    notice, ack) + DiagnosticsScreen section + reactivity StateFlow.
    14 new JVM tests (Android JVM 198 → 212). Emulator acceptance
    verified. See §3 Session T-1 entry. ADR-HARDENING-001 §9 v0.4
    amendment lands via commit `29ff6cc`.

    **No blocking tasks remain.** The next session's shape is a
    choice, not a backlog obligation:
    - **Phase 2 preparation** — **suspend HTTP surface refactor
      DONE** at `6c7830e` (Session Z-11). All API classes suspend;
      `runBlocking` bridge removed; §8 transport deferral closed.
      `HttpClientRetryTest` 7 tests unchanged; JVM 244/244;
      androidTest 71/71 per emulator.
    - **Phase-1 DoD gaps (Build Master §10) — P1-033 IN PROGRESS.**
      **P1-029 DONE:** design `29cd7bf` (`KEY-CUSTODY.md`, 287 lines);
      implementation `7c02d16` (ProvisioningKeys DEBUG/PROD split,
      `UmojaApplication` startup assertion). **P1-033 split into
      033a–033e (Z-14). 033a DONE at `221c98f`** — backend
      `POST /admin/matrices/:device_id` with verify-on-write,
      device_id-match invariant, non-monotonic reject. **033b DONE at
      `691d27d`** — `MatrixApi.push` + `AdminScreenState`
      (`importSignature` / `clearSignature` / `pushSignedMatrix`) +
      AdminScreen push Card (QR + sig scan + push button). **Next:**
      033c (signing build flavor: `SIGNING_ONLY` guards + SigningActivity)
      → 033d (ceremony runbook) → 033e (end-to-end drill). **Also
      unblocked:** P1-035 (recovery key ceremony — design exists in
      `docs/ops/KEY-CUSTODY.md` §3). **Hardware-blocked:** P1-021a
      (emergency lock), P1-021b (duress wipe), P1-034 (TEE Ed25519
      verification on target hardware). **Organizational-blocked:**
      P1-027b (CI-provider decision). **Independent of all:** P1-024
      (external security review), scheduled against a candidate release.
    - **TASK-P1-027b** — CI enforcement gate + Android dependency
      tooling. Blocked on CI-provider decision (organizational, not
      technical). Session opens when that decision exists.
    - **Backlog hygiene** — `MessageStore` SQLite connection leak
      (production bug, dozens/sec during cold launch); KI-016
      base64url validator dedupe; KI-008 `canonicalJson` dedupe;
      KI-018 backend current-matrix-version tracking; migration 017
      for `enrollment_tokens.used_by_device_id ON DELETE SET NULL`;
      double-matrix-fetch dedupe (R-5 §7 note).

**Backlog items (not scheduled):**
- ~~Instrumented Compose tests for admin flows~~ — **RESOLVED
  2026-10-18, arc complete. 5 of 5 sub-deliverables landed.**
  **Delivered across the arc:** AckDialog (`bf13dcc`, 11 Compose
  tests), AdminScreen → `AdminScreenState` refactor (`2804427`),
  AdminScreenStateTest (`a6de609`, 22 JVM tests), **ChatViewModel
  refactor + testability** (`bd8a6e7`, 10 JVM tests), ChatScreenTest
  (`9bfdfab`, 14 Compose tests).
  **Plan revisions during the arc, named honestly:** Z-2 §4 planned
  session C as "ChatScreen refactor" (extract ChatScreenState mirroring
  session A's AdminScreenState). Session C's C1 reconnaissance showed
  ChatScreen is a composition shell, not a logic container; the actual
  untested surface was ChatViewModel. **ChatScreenState is cancelled.**
  The arc reached 5 of 5 by targeting the right surface, not by
  executing the Z-2 plan verbatim.
  **Coverage at arc close:** AckDialog (11 androidTest), AdminScreenState
  (22 JVM), ChatViewModel (10 JVM), ChatScreen (14 androidTest). All four
  surfaces are now covered by named tests. Zero production behavior
  changes across the arc (both refactors were behavior-preserving, A and
  C each verified by emulator acceptance in addition to unit tests).
  **Deferral closed.** See §3 Session Z-5 entry for the full arc
  retrospective.
- Deduplicate base64url validators (KI-016).
- `canonicalJson` deduplication between `audit/log.ts` and
  `audit/verify.ts` (KI-008).
- Backend current-matrix-version tracking (KI-018).
- **`scripts/bootstrap-enrollment-token.sh` — DONE Session S-1.**
  See §3 Session S-1 entry. Eliminated the manual psql procedure
  that recurred 5x across Sessions A–R-4.
- ~~**Dedupe the double-matrix-fetch after 401-triggered reauth**~~
  — **RESOLVED 2026-10-18 at `2637610`.** Fixed at the routing
  layer (Reauthenticating branch becomes no-op; screen does not
  oscillate during silent reauth), not via the MutableStateFlow the
  R-5 note sketched. The U-2 cost > payoff ruling was correct given
  the ruling's assumed fix; the actual fix was one branch edit and
  also corrected a UX drift from ADR-HARDENING-001 §2. Verified:
  post-trigger `/me/matrix` count 3 → 2 (single fetch + interceptor
  retry on same port). Full session entry in §3 Session Z-1.
- **Consider making `enrollment_tokens.used_by_device_id`
  `ON DELETE SET NULL`.** Session R-4's device-row deletion hit
  the `NO ACTION` FK, requiring manual token cleanup. In a test
  environment that's noise; in production it might be a
  deliberate audit-preservation choice. **Migration 017
  territory, not a fix for R-4.** Either adopt `SET NULL` (keeps
  the token row, drops the FK to the deleted device) or document
  that device deletion requires pre-cleaning enrollment_tokens.
- **`MessageStore` SQLite connection leak** (Session R-3): logcat
  shows `SQLiteConnectionPool: A SQLiteConnection object for
  database '...umoja_local.db' was leaked!` at ~dozens/sec during
  cold launch. Pre-dates 040-C-2. Cursors opened without closing,
  or `messagesVersion` bump loop in `ChatScreen`. Not blocking.

---

## 6. Development environment

### Repo layout

    umoja-secure/
      backend/
        src/
          crypto/           jcs.ts, jcs.test.ts,
                            jcs-dump.ts, matrix-schema.ts,
                            matrix-schema.test.ts,
                            matrix-sign.ts, matrix-sign.test.ts
          auth/             canonical.ts, verify.ts
          audit/            log.ts, verify.ts
          admin/, enrollment/, authorization/, routes/, ws/ ...
        scripts/            generate-matrix-vectors.ts
      android/
        app/
          build.gradle.kts  (org.json test-scope;
                             journeyapps:zxing-android-embedded:4.3.0)
          src/
            main/java/com/umoja/secure/
              crypto/       DeviceKeyManager.kt, DeviceIdentity.kt,
                            SignalIdentityStore.kt,
                            JcsNumberFormatter.kt,
                            JcsCanonicalizer.kt,
                            AuthorizationMatrix.kt,
                            MatrixSigner.kt,
                            ProvisioningBundle.kt,
                            MatrixBuilder.kt
              auth/         CanonicalChallenge.kt, SessionManager.kt
              transport/    AdminApi.kt, ContactsApi.kt, Socks5Bridge.kt
              ui/           admin/, contacts/, chat/, conversations/,
                            navigation/, settings/, diagnostics/, theme/
            test/java/com/umoja/secure/
              ExampleUnitTest.kt
              crypto/       JcsNumberFormatterTest.kt,
                            JcsCanonicalizerTest.kt,
                            JcsCrossCheckTest.kt,
                            AuthorizationMatrixTest.kt,
                            MatrixSignerTest.kt,
                            ProvisioningBundleTest.kt,
                            MatrixBuilderTest.kt
      docs/
        architecture/       ADR-PROVISIONING-001.md
        ops/                TOR-ONION.md
        reference/
          AUTH-SPEC-001.md
          THREAT-MODEL-001.md
          canonical-matrix-test-vectors.json  (generated: true)
          rfc8785-number-samples.json         (24 samples)
          jcs-conformance/                    (6 pairs, Apache 2.0)
        security/
          DEPENDENCY-EXCEPTIONS.md
      infra/
      scripts/              jcs-cross-check.sh
      UMOJA-SECURE-BUILD-MASTER.md
      docker-compose.yml
      handoff.md

### Start of session

> **Dev-environment notes (2026-10-16).** Three things routinely need
> re-doing after a host update or reboot, and none is obvious from
> the failure symptoms:
>
> - **adb reverse ports are per-boot.** Set them for both emulators
>   before testing. Missing `tcp:9050` presents as `network_error` in
>   the app; missing `tcp:8080` affects clearnet paths only.
> - **Mac Tor can degrade after host sleep or OS updates.** Symptom:
>   curl to the onion times out even though the container's Tor is
>   healthy. Diagnose with `docker compose exec -T tor curl
>   --socks5-hostname 127.0.0.1:9050 http://<onion>/health` — if that
>   works but the Mac's curl doesn't, it's the host Tor. Workaround: a
>   socat sidecar bridging host:9150 -> umoja-tor:9050, with the
>   emulator's reverse re-pointed. See commit a7f31e9.
> - **Direct-SQL enrollment bootstrap** is the recovery path when
>   app data is cleared (host update, AVD reset, `pm clear`). Three
>   occurrences so far. Procedure is in §3's emulator bootstrap note.
>   A `scripts/bootstrap-enrollment-token.sh` helper is queued.

    # Docker Desktop must be running.
    cd ~/umoja-secure
    docker compose up -d

    # Emulators (two for two-device tests).
    # Available AVDs: ls ~/.android/avd/*.avd
    #   Current: Pixel_9, Pixel_9_2, Pixel_9_API35
    $HOME/Library/Android/sdk/emulator/emulator -avd Pixel_9 &
    $HOME/Library/Android/sdk/emulator/emulator -avd Pixel_9_2 -memory 1535 &

    # Reverse ports. First emulator is emulator-5554, second is emulator-5556.
    $HOME/Library/Android/sdk/platform-tools/adb -s emulator-5554 reverse tcp:8080 tcp:8080
    $HOME/Library/Android/sdk/platform-tools/adb -s emulator-5554 reverse tcp:9050 tcp:9050
    $HOME/Library/Android/sdk/platform-tools/adb -s emulator-5556 reverse tcp:8080 tcp:8080
    $HOME/Library/Android/sdk/platform-tools/adb -s emulator-5556 reverse tcp:9050 tcp:9050

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

    # Total count — recount, don't trust the handoff number:
    grep -h -o 'tests="[0-9]*"' app/build/test-results/testDebugUnitTest/TEST-*.xml \
      | awk -F'"' '{s+=$2} END {print s}'

### Android app build / device install

    cd ~/umoja-secure/android
    ./gradlew installDebug
    ./gradlew connectedAndroidTest   # currently 0 tests (KI-013)

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
- Every commit block ends with `git push origin main`. Tags: follow
  with `git push origin --tags`.
- Update this Handoff at the end of every session.
- For file writes, prefer a text editor (`open -e <path>`, `nano`) over
  terminal heredocs for anything over ~150 lines. Heredocs fragment on
  paste — and as of Session A, so does TextEdit for content over ~400
  lines. Chunk large writes.
- **No shell-block comments.** Two shell traps bit Session A:
  - zsh without `interactive_comments` treats `#` as a command word:
    `zsh: command not found: #`.
  - zsh tilde expansion fires inside what looks like a comment:
    `zsh: no such user or named directory: 190`.
  Put annotations in prose above the block, not inside it.
- **Prefer `python3` + `assert count == 1` over multi-hunk `git apply`
  patches.** Session A: three multi-hunk patches failed on paste
  truncation or hunk drift. Direct file edits with a count guard are
  self-verifying and verbose on failure.
- Placeholders like `<paste content here>` are never typed literally.
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
- **Do not propagate test counts from prior handoffs.** Recount from
  test-runner output. See KI-013.
- **Read the edit script's RESULTS block before typing the commit
  message.** `raise SystemExit` guards the file write, not the commit;
  the shell runs the next command regardless. Two pushed commits
  (1a0069c, 60350cd) claimed work their scripts didn't land. The
  second step must read the first's output.
- **Edit scripts must read back their changes.** `raise SystemExit`
  guards anchor drift; it does not guard omitted steps. The c2a
  SecureStorage.kt edit replaced strings in memory, passed every
  anchor check, and exited 0 — but `write_text` was never called.
  Every edit script now re-reads each modified file and asserts the
  target string is present before exiting.
- **Ground truth for JCS is the vendored corpus**, not either
  implementation. If TS and corpus ever disagree, TS is wrong. Same
  for Kotlin.
- **`toJSON` rejection is a deliberate deviation.** Both
  implementations reject objects with a `toJSON` method even though
  RFC 8785's reference code calls it. Do not "fix" this.
- **Edit scripts start with `cd ~/umoja-secure`** and use repo-root-
  relative paths. A cwd mismatch silently created a failed write and a
  re-run compounded it to a doubled file. Session C. Do not omit the
  `cd` prefix on the assumption the shell is already at root.
- **Edit scripts guard before writing.** `if marker in src: raise
  SystemExit(...)` at the top. The read-back assert after `write_text`
  catches corruption *after* the fact; the guard prevents the write
  in the first place. Session C.
- **Every test file must use a unique `TEST_ORG_ID`.** Grep
  `test/*.ts` before picking a value. Currently in use: `011`, `044`,
  `055`, `066`, `077`, `088`, `099`, `0a1`, `0a2`. Reuse causes
  cross-file deletion via `beforeEach` cleanup — that's KI-022, a
  whole session's debugging burned on an org collision.
- **Every migration commit note includes `npm run migrate` against
  `umoja`.** `npm test` auto-rebuilds `umoja_test` but never touches
  dev `umoja`. Migration 013 was applied to test DB by global-setup
  and to dev DB only when `npm run migrate` was run manually. Session
  C hit 404 on `/admin/matrix-version` for this reason (compounded by
  KI-002).
- **After any backend route change, `docker compose up -d --build
  backend` before curl testing.** KI-002 re-hit in Session C: route
  added, tests passed, curl returned 404 because the container was
  still running the old image.
- **Read-back is `git diff`, not content asserts in the edit
  script.** Four consecutive sessions (D, E, F, G) had a read-back
  assert fire on my own miscalibration — never on an actual edit
  failure. The pattern is predictable: exact-count asserts fire when
  the final file has more references to an identifier than the number
  of intentional insertions (D: expected 3, actual 4 — return
  expression has both key and property ref; E: expected 4, actual 5 —
  const val plus two branches plus getter plus clear). Presence checks
  miss rename bugs when old and new coexist in different files (F:
  `ISO8601_UTC_RE` vs `RN_ISO8601_UTC_RE` in a second file; presence
  passed, compile failed). Absence checks fire when the new content
  intentionally cites the old name for historical documentation (G:
  §10's v0.2 entry says "TEST-ACK-HASH-MISMATCH described the
  unsatisfiable comparison" — a legitimate historical reference; the
  `not in back` assert fired anyway, expected count 1 vs actual 2).
  **Replace content asserts entirely.** The edit script does its
  write and exits. `git diff` before commit is the authoritative
  read-back — it shows exactly what changed, whether the old
  identifier was removed or retained, and whether the shape matches
  intent. A `git diff` review costs 10 seconds; a wrong count assert
  costs 30 seconds of confusion and 5 minutes of verification.
- **`git diff` shows unstaged changes; after `git add`, use
  `git diff --cached`.** Session O-1 lost one round-trip when
  `git diff --stat <file>` returned empty because the file was
  already staged. The staged view is `git diff --cached` (alias
  `--staged`). Two acceptable patterns: review *before* `git add`
  (historical), or always use `git diff --cached` after staging.
  Either is fine — the current §7 phrasing ("`git diff` before
  commit is the authoritative read-back") is ambiguous on which side
  of `git add` it applies to. Cost of the mistake: one round-trip
  asking "where is the diff?". A clarity gap, not a discipline
  failure — the diff review happened, just on the wrong command.
- **File-private helpers with common names get prefixed when a second
  file introduces similar helpers.** `AuthorizationMatrix.kt` and
  `ReplacementNotice.kt` both declare `requireString` and
  `requireBase64Url32` as file-private. Kotlin resolves them
  file-locally — fine in principle — but during editing an unprefixed
  call site silently resolves to the wrong file's copy and fails
  compile. Prefix the declarations (`RN_` for ReplacementNotice) so
  wrong-file references fail visibly.
- **The exact-count-assert pattern keeps failing.** Sessions D, E,
  F: three consecutive sessions of miscounting (3≠4, 4≠5, 4≠5).
  Content-count asserts are unreliable for multi-branch methods and
  repeated references to the same constant. Replace with
  `assert back.count(X) >= N` where N = intentional insertions. Or
  drop content-count asserts entirely — typecheck + test already
  proves correctness, and the read-back was meant to catch
  edit-script bugs, not validate file content.
- **`generated_at` timestamp changes in `canonical-matrix-test-
  vectors.json` are committed as-is.** Running
  `generate-matrix-vectors.ts` after any change to the generator
  updates `generated_at`. Verify with the `MATRIX_VECTORS_IDENTICAL`
  python check that `expected_*` fields are unchanged; commit the
  timestamp refresh in the same commit as the generator change.
- **Session workflow — accumulated discipline (Sessions C–F, applied
  cleanly in G).** Four practices, each earned by a specific failure,
  together preventing the failure classes seen across Sessions C–F.
  (a) Compile between edits, not after — Session F Round 1 shipped
  three files with type errors that a mid-script compile would have
  caught one edit earlier. (b) Grep `test/*.ts` for existing fixture
  IDs before picking a new one — Session C's cross-test org collision
  cost a full session of debugging; the pre-flight grep is 30 seconds.
  (c) Pre-flight every edit block: cwd, target file exists, anchor
  unique — Session C's first edit failed on cwd, and its read-back
  pass-through compounded to a doubled file. (d) Before `git commit`,
  verify the staged set matches what the message describes — Session
  C's `8adde6b` message described half its content because `git add`
  swept in an already-staged file. Session G applied all four from
  the first edit; no mid-session correction required.

- **Typed `tx.query<T>()` + `noUncheckedIndexedAccess` = `rows[0]`
  is `T | undefined`.** The compiler cannot narrow through
  `rowCount !== 1` checks. Two patterns, both demonstrated in
  identityChange services (Session H):
  (a) guard-then-use — extract to a local with explicit undefined
  check, then use the local; narrowing applies to all subsequent
  accesses, and multi-branch methods (like the status + alg + key
  reads on `device`) are covered by one extract.
  (b) RETURNING-clause `rows[0]!` — for INSERT...RETURNING and
  SELECT-after-INSERT where row existence is guaranteed by SQL
  semantics; matches `matrixVersions.ts` Session C precedent.
  Note: `verifyChallenge` in `auth/verify.ts` uses untyped
  `tx.query()` → `any` → hides this class. Typed parameters surface
  it; do not remove type parameters to silence the error.
- **Pre-flight mental compile before pasting any edit block.**
  Session K had three compile round-trips before a single commit
  could land: (1) test file wrote to `main/java` instead of
  `test/java` — wrong source set, test deps not on classpath; (2)
  controller import contained `GateReasonAlias` — leftover from a
  design pivot to `GateState` mid-draft, never removed; (3) the test's
  in-memory `KeyValueStore` implementation was missing `has()` —
  drifted from the copy in `ReplacementNoticeStoreTest`. All three
  share one root cause: write without pre-flight. Before pasting,
  read the resulting file with three questions: do the imports
  resolve, are abstract members implemented, is the path under the
  correct source set. If any answer is not obvious, `grep` or `ls`
  first, not after. Cost of the read: thirty seconds. Cost of a
  compile round-trip: a full turn.
- **Count lines reflect runner output from the current commit, not
  inference from which files changed.** Sessions K and L both had
  count lines in commit messages. Session K ran `npm test` / gradle
  and matched the XML aggregate; Session L inferred "169 unchanged"
  from "no test files touched." Correct by reasoning in that case
  (Compose source cannot affect JVM unit-test count), but the
  inference pattern is fragile: a refactor that *looks* like it
  doesn't touch tests can still change the count, and "no test files
  touched" is not the same as "no test count changed" when a test
  file imports the changed code. Rule: run the tests as part of the
  commit's verification, or say explicitly in the message "count not
  verified this commit — inferred from no test-file changes."
  Inference labeled as inference is honest; inference presented as
  verification is not.
- **Absence of a log line is not evidence of absence of a call when
  the code has no log statement.** Session M's acceptance debugging
  started with `docker compose logs | grep identity-change`
  returning zero lines, which looked like "the app never called."
  It wasn't — the app called; 3d-2/3d-3b shipped without a
  client-side log tag (no `UmojaIdentity`), and the backend grep
  was too narrow. The diagnostic that worked was unfiltered
  `docker compose logs backend --tail=40` — seeing `/me/contacts
  200` proved the app was active, and the *absence* of
  `/identity-change-notices` in the same window was the signal
  that the call wasn't firing. Same principle applied to logcat:
  `grep -i refresh` matched every Android system service
  (DisplayManager, TapAndPay, etc.); a filter that matches
  everything is equivalent to no filter. Rule: when a debug grep
  returns zero lines, widen the grep before concluding anything.
  If it returns many but irrelevant lines, tighten it to a
  specific tag you know exists in the code.
- **Multi-source statements must be updated atomically across files.**
  Three places state "the next task": handoff.md line 3, handoff.md
  §5 item 16, ADR-HARDENING-001 §6 Order line. Any commit that changes
  one must change all three, in the same commit. Failure mode:
  `d133878` updated §5 but not the header; the header contradicted §5
  for two commits until `eeee151`. Consistency check after any
  'next task' change:

      sed -n '3p' handoff.md | grep -oE "Next: TASK-P1-0[0-9]{2}"
      grep "Next session opens on" handoff.md | grep -oE "TASK-P1-0[0-9]{2}"
      grep "Order (v0.2 correction)" docs/architecture/ADR-HARDENING-001.md

  All three must print the same task ID. Same principle applies to any
  statement duplicated across the doc set — test counts in §2 and §7,
  ADR versions in the handoff §1 and the ADR itself, sequencing in
  ADR §6 and §9. Multiple sources are correct for cross-checking;
  they are a drift hazard if updated independently.
- **`LaunchedEffect` (and `DisposableEffect`, `SideEffect`) bodies run
  on `Dispatchers.Main`.** Any blocking I/O — `HttpClient.get` /
  `postJson`, `SecureStorage` Keystore reads, file I/O — must be
  wrapped in `withContext(Dispatchers.IO)`. Failure mode: Session O-2
  shipped a matrix-fetch effect that called `MatrixApi.fetch` directly;
  debug build threw `NetworkOnMainThreadException` on every
  `Authenticated` entry, crashing the app. `catch` clauses for domain
  exceptions (`MatrixApiException`) do not catch
  `NetworkOnMainThreadException` (a `RuntimeException`) — the crash
  escapes the try and the app dies. `IdentityChangeController.refresh()`
  KDoc is the reference pattern (internal `withContext(IO)`). Fix is a
  one-line wrap; the diagnostic is `adb logcat -b crash`.
- **`docker compose up -d --build backend` before CLIENT testing, not
  just before curl.** KI-002's rule says "before curl testing"; the
  same failure re-hit in Session O-2 as a client-visible 404 because
  curl was not the diagnostic step — emulator logcat was. Route source
  `98fee5c` (`GET /me/matrix`) landed but the container was stale;
  the app's `MatrixApi.fetch` hit `Route GET:/me/matrix not found` in
  the backend log; five minutes lost. Extended rule: any commit
  touching `backend/src/routes/*.ts` or `backend/migrations/*.sql`
  requires the rebuild step before ANY testing that uses the running
  backend — emulator verification included, not just curl.
- **`!` inside `git commit -m "..."` triggers zsh history expansion
  and aborts before git runs.** Symptom: `zsh: event not found:
  <word>.` Same family as §7's `#`-in-shell-block trap. The `!`
  expands even inside double quotes; `git commit` never runs; the
  push finds nothing to push. Fix: `git commit -F- <<'EOF' ...
  EOF` (quoted delimiter prevents all expansion) — not `set +H`
  (silently changes shell behavior for the rest of the session).
  Every commit message that quotes Kotlin or TypeScript code
  containing `!` — `!isAuthorized`, `!authorized`, `!=`, `!!` —
  needs `-F-` heredoc. Session P.
- **`cd <subdir>` in a multi-block paste leaks cwd to subsequent
  blocks.** Same class as Session C's "edit scripts start with
  `cd ~/umoja-secure`." In Session P, block C did
  `cd ~/umoja-secure/android` and never returned; block F worked
  by luck (docker compose finds the parent compose file), block G
  failed honestly (`grep backend/scripts/sign-test-matrix.ts` from
  the wrong cwd). Fix: start every command block with
  `cd ~/umoja-secure`, or use subshells (`( cd subdir && ... )`),
  or absolute paths. Session P.
- **`\d <table>` before any ad-hoc psql query — do not guess
  column names.** Session P guessed `devices.created_at` (actual:
  `enrolled_at`), `contacts.device_id` (actual:
  `owner_device_id`), and `contacts.revoked_at`/`status` shape
  without confirming the actual column set — each guess cost a
  round-trip and a silent-read failure (the returned `ERROR` went
  past in a multi-block paste twice before the third block caught
  it). `\d` costs one line; three wrong guesses cost three
  round-trips. Rule: first `\d table`, then query. Session P.
- **Empty logcat is only meaningful paired with state.** Refines
  Session M's rule. In Session P: Case 1's empty `POST /envelopes`
  was evidence **because** the `sendMessage blocked by SendGate`
  logcat line was present and envelope count was 0 — the triple
  proved the gate fired. Case 3's empty `POST /envelopes` alone
  was not enough; the present `sendMessage blocked by SendGate`
  line paired with the stable envelope count is what closed it.
  Do not infer "gate works" from absence-of-error; pair it with
  the corroborating DB state. Session P.
- **`remember` cache keys must include the state-flow trigger, not
  the object identity, when the underlying state is stored in an
  unobservable class.** Session P's D-1 bug: `remember(peerDeviceId,
  matrixStore)` did not re-derive when the matrix changed because
  `matrixStore` identity is stable — only `matrixStore.version`
  changes. The pattern from 030e-c (`remember(version,
  peerDeviceId)`) is the reference; when a class gains a write-
  notification flow, the remember key switches from object identity
  to flow value. Additionally, StateFlow alone is inert without
  writer-unification: the writer (accept) must use the same
  remembered instance the observer (ChatScreen) collects from, or
  the bump goes to a throwaway object and the observer never sees
  it. Session P D-1.
- **`grep FLAG_SECURE` on `dumpsys window` returns nothing by
  design.** dumpsys emits `SECURE` (the symbolic name inside the
  `fl=` line), not the fully-prefixed `FLAG_SECURE` constant name.
  Any FLAG_SECURE diagnostic needs to match
  `grep -E '^\s+fl=.*SECURE'`. Session Q.
- **`screencap` uniform-black PNGs are ~20–25 KB, not <20 KB.** The
  platform's black framebuffer includes the system status bar
  overlay, which compresses to 20–25 KB, not 5–10 KB. A threshold
  of `<20000` incorrectly labels correct black captures as
  "FLAG_SECURE ABSENT." Correct threshold for the check:
  `<50000` (safe margin between ~23 KB black and 80–105 KB UI).
  Session Q.
- **`sed -n '/X/,/^$/p'` is the reliable `dumpsys window` scoping
  pattern.** `grep -A40 | head -3` truncates before the `fl=` line
  because `mAttrs` and other fields precede `fl=` in the window
  block. Section-scoped extraction (sed) is required, not
  count-based grep. Session Q.
- **FLAG_SECURE screenshot signature: black content + visible
  system overlays.** The status bar (top) and home indicator
  (bottom) render normally — they are system windows, not the app
  window. A fully-black screenshot with no overlays means
  something else is wrong (R8 stripped the UI, or screencap is
  reading a dead framebuffer). Overlays surviving is the marker
  that FLAG_SECURE is doing exactly what it should. Session Q.
- **Batched `screencap` across screens returns byte-identical
  PNGs.** Navigation happens in the emulator UI between pastes,
  not within. Four `screencap` commands in one paste all capture
  the same framebuffer. One paste, one probe, one navigation
  between probes. Session Q.
- **Discriminated-union return types force caller updates at
  compile time.** Session R changed `lookupSession`'s return from
  `SessionRecord | null` to `{ kind: 'session' | 'device_revoked' |
  'no_session' }`. A nullable return silently passes through
  `if (!session)`; a union forces every caller to branch on `kind`.
  The `ws/server.ts` bug — strict-equality `err.code ===
  'unauthorized'` that would have fallen through after the new
  `device_revoked` code landed, closing with 1011 instead of 4403 —
  was caught by TypeScript compile, not by test. Same class of
  safety as Session H's `tx.query<T>()` note: the compiler enforces
  what an `any` return hides. Session R.
- **A test failing during a contract change is evidence the test is
  real.** Session R's TEST-ACK-REVOKED-DEVICE failed with
  `unauthorized != device_revoked` when the middleware's 401 code
  split. The failing assertion is what proved the test asserts the
  actual wire contract, not just `statusCode === 401`. Had it
  passed (e.g. only asserted status), the ADR-vs-code divergence
  would have shipped silently. A test that breaks when the contract
  changes is doing its job; a test that would pass regardless is
  not testing the contract. Session R.
- **`Deferred.awaitAll()` returns the results but does not mutate
  the original list.** Session R-2's `TEST-SESSION-CONCURRENT-401-
  SINGLE-REAUTH` failed on first run because `assertTrue(it is
  State)` iterated `List<Deferred<State>>` after `awaitAll()` --
  the deferred is not the value; the assertion was always false.
  The failure compiles cleanly (any `is` check on the wrong type
  compiles). Fix: `val outcomes = list.awaitAll()` and iterate
  `outcomes`. Diagnostic discipline: assertion messages must name
  the actual value, not just the predicate --
  `assertTrue("result[$i] should be X, got $r", r is X)`.
  Otherwise the failure points at a predicate and not at the
  value that was wrong. Session R-2.
- **`yield()` releases the current thread's coroutine; it does not
  release coroutines on other dispatchers.** A `runBlocking`
  thread yielding does not give `Dispatchers.Default` coroutines
  real wall-clock time to reach a synchronization point. For
  cross-dispatcher test synchronization, use `delay(ms)` with a
  bounded value, or a `CompletableDeferred` the code sets. The
  delay is not flakiness -- it is the honest test seam when the
  production API has no observable "arrived" signal. If the
  bounded delay still leaves the test flaky, the fix is exposing
  a signal (e.g. a `StateFlow` emitting on entry), not increasing
  the delay. Session R-2.
- **`grep -E "req\."` on backend JSON logs is always wrong — the
  format is `"req":{`, not `req.`.** Session R-3's block 8 returned
  empty (interpreted as "no app requests") while block 6's specific
  `/me/matrix` grep on the same window showed the request clearly.
  Two greps on the same data giving different answers is a pattern
  bug, not an evidence bug. Fix: quote the JSON key literally
  (`'"req":'`) or grep the specific endpoint. Session R-3.
- **`docker compose logs --since N` windows truncate before slow
  events.** Session R-3 hit this twice: `--since 1m` fired 8s after
  a launch showed "empty" because the fetch landed 4m later at
  obs 5's reauth; `--since 10m` fired at 08:52 excluded an event
  at 13:00. When a specific endpoint is under investigation, grep
  it across a wide window (`--since 30m`) rather than trying to
  calibrate the window to the event. Session R-3.
- **A screenshot from a prior session is not current-session
  evidence.** Session R-3 nearly concluded cold launch worked
  based on a screenshot whose status bar read `1:47` while the
  diagnostic ran at `08:49` UTC. Always compare the screenshot's
  visible time to the current `date -u`. When in doubt, take a
  fresh screenshot; the acceptance is "proven now," not "proof
  from earlier still applies." Session R-3.
- **Kotlin block comments nest — `/path/*` in KDoc opens a nested
  comment.** Session R-4's HttpClient interceptor KDoc contained
  `Auth-free paths (\`/auth/*\`, ...)`, which the Kotlin compiler
  parsed as opening a nested `/* */` block. The KDoc's closing
  `*/` closed the *nested* comment, leaving the outer KDoc
  unterminated. Compile signature: `"Unclosed comment"` at EOF
  plus `"Missing '}'"` at the last line before the offending
  KDoc. Fix: rephrase to `/auth/` prefix (no glob). Grep balance
  check (`grep -c "/*" == grep -c "*/"`) before commit catches
  it. Same class as Session Q's FLAG_SECURE grep trap — a syntax
  construct in a comment has side effects the compiler honors.
  Session R-4.
- **A `when` branch with one expression cannot be extended by
  adding a second statement.** Kotlin's single-expression `when`
  branches (`is Foo -> statement()`) are not blocks; adding a
  newline + statement after the first does not extend the branch
  — the new statement is parsed as the beginning of the next
  branch. Compile signature:
  `"'when' expression must be exhaustive. Add the 'X' branch"` on
  the branch following the edit, plus syntax errors on the
  mis-parsed statement. Fix: wrap both statements in `{ }`. Session
  R-4.
- **`devices_key_unique` AND `devices_pkey` both collide on
  re-enrollment.** A device that loses its `device_id` (e.g., from
  a `SecureStorage.remove("device_id")`) generates a fresh UUID
  on next Enroll, but its Keystore keypair is unchanged — so
  `POST /enrollment`'s `INSERT INTO devices` collides on
  `public_key` (`devices_key_unique`, from the old row) AND on
  `device_id` (`devices_pkey`, if the old row survived). Both are
  23505; both return `device_already_enrolled` 409. The only
  clean path is delete-and-recreate the device row with all 6
  NO ACTION FK dependents cleaned first. Session R-4.
- **PostgreSQL FK enumeration uses `pg_constraint`, not
  `information_schema.key_column_usage`.** The latter has no
  `referenced_table_name` column. Correct query:
  `SELECT conrelid::regclass, conname, confdeltype FROM
  pg_constraint WHERE contype = 'f' AND confrelid = '<table>'::regclass;`
  `confdeltype` names the action: 'a'=NO ACTION, 'r'=RESTRICT,
  'c'=CASCADE, 'n'=SET NULL, 'd'=SET DEFAULT. Any "delete a
  device row" procedure must start here — the 6 NO ACTION
  dependencies are non-obvious without it. Session R-4.
- **Diagnostic patterns that don't match the log format — a
  recurring class.** Three occurrences across R-3 and R-4, all
  yielding empty grep results against populated logs:
  - `grep "GET /me/matrix"` — the backend JSON is
    `"method":"GET","url":"/me/matrix"` (separate fields). Grep
    the URL value: `grep '"url":"/me/matrix"'`
  - `grep -E "req\."` — the JSON is `"req":{` (colon, not
    period)
  - `--since 1m` / `--since 10m` — windows truncate before slow
    events (sleeps, screencaps, diagnostic block assembly)
  When a grep returns empty on a known-active window, **verify
  the pattern matches the log format before concluding "no
  event occurred."** If a specific endpoint is under
  investigation, grep it across a wide window (`--since 30m`)
  rather than calibrating the window to the event. Session R-3,
  Session R-4.
- **"OK" from an edit script ≠ "change is correct."** The edit
  script fires `sys.exit()` after `write_text()`; "OK" means the
  bytes landed, not that they compile. Two consecutive compile
  failures in R-4 had `OK:` lines immediately above them
  (`/auth/*` nested-comment trap, `when` branch without `{ }`).
  The compile is the acceptance; "OK" is the write-confirmed
  signal. Run the compile in the same turn as the edit, and read
  `^e:` lines (not `tail -4`) when it fails. Session R-4.
- **Double-matrix-fetch after 401-triggered reauth — harmless but
  worth knowing.** After the interceptor's retry-with-fresh-bearer
  succeeds, the routing effect's `LaunchedEffect(screen, deviceId)`
  also fires because `screen` transitioned Reauthenticating →
  Authenticated. Both fetch `/me/matrix`; both succeed;
  `MatrixStore.accept` rejects the second (same-version rollback
  guard). One extra round-trip per reauth cycle. Not a defect --
  the guard prevents the duplicate from mattering -- but a future
  session looking at request logs should expect the pair and not
  chase a bug. Session R-5.
- **Choose script language by scope, not habit.** The
  `scripts/sign-test-*.ts` helpers are TypeScript because they
  share backend JCS/Ed25519 primitives — re-deriving that crypto in
  shell would be a second implementation. `bootstrap-enrollment-
  token.sh` is shell because it needs psql + `secrets.token_urlsafe`
  + `sha256sum` and nothing else. Python appears twice in the shell
  script for one-line base64url/hex transforms, but the file's
  identity is bash. **Rule:** before picking language for a script,
  name the library you'd need — crypto goes TypeScript, DB/OS goes
  shell, small transforms go Python one-liners. Mixing habits
  (Python-for-everything, shell-for-everything) produces scripts
  that are correct but wrong-shaped for their job. Session S-1.
- **Write-notification pattern is now a codebase convention.**
  Three instances: `IdentityChangeController.version` (Session K,
  `eea1af7`), `MatrixStore.version` (Session P D-1, `475d75b`),
  `VerificationFailureStore.version` (Session T-1). When a fourth
  store class needs to notify observers of state changes: use
  `private val _version = MutableStateFlow(0L)` + `val version:
  StateFlow<Long> = _version.asStateFlow()`, bump on every write
  path (`record` / `clear` / `clearOf` / `accept` / `markAcked`),
  and have the UI collect via `collectAsState` + remember-key the
  derived state on the version value. **Not "consider" — assume.**
  Three precedents is enough for the pattern to be load-bearing;
  reinventing a fourth mechanism would be a regression.
- **Kotlin call-site edits with trailing-comma style defeat
  exact-string anchors.** Three attempts in Session T-1: paren-
  matcher appended after a trailing comma → double comma;
  whitespace anchor missed 24 leading spaces → ABORT with
  `count=0`; **line-level manipulation using the file's own
  indentation** (stripped-content match on the broken line,
  compute indentation from the previous line, write back with
  computed whitespace) → fixed. Rule: for multi-line call sites,
  anchor on stripped-content and compute whitespace from
  neighbors; never paste whitespace into a Python string.
- **Compile is the acceptance for Kotlin source; grep "^e:" not
  `tail -4`.** Three compile failures this session, three named
  errors, three one-line fixes: `/auth/*` nested-comment in R-4
  (Kotlin block comments nest); `when` branch without `{ }` in
  R-4 (single-expression branches cannot be extended); missing
  `collectAsState` import in T-1 (Compose Runtime extension not
  auto-imported). `tail -4` hides the error list; `grep "^e:"`
  shows every error at line:col. Zero guessing when the
  compiler reports precisely.
- **Prose anchors wrapping mid-phrase defeat single-line
  `src.find()`.** Session T-1's §5 item 16 anchor
  `**Next task: TASK-P1-041 — failed-verification operator
  logging.**` wrapped across a line break in the file, so
  `src.find()` returned -1 before any edit ran and the whole
  handoff edit block aborted. **Range-based anchors** (start
  marker + end marker, replace the whole span) are the robust
  form for multi-line prose. Same class as R-3/R-4's grep
  patterns that didn't match JSON log format — anchors on
  assumed text shape, not actual text shape.
- **If a class has `close()` and grep finds zero call sites,
  either the class is a leak or `close()` is a design lie.**
  Session U-1's MessageStore leak had this exact signature:
  `close() { helper.close() }` existed, nothing called it, and
  `LocalDatabaseHelper(context)` opened a fresh SQLite handle
  per MessageStore construction with ~0 close() calls. Audit
  `close()` call sites as a first-class check when reading any
  resource-holding class. A close() with no callers is a signal
  about design, not just a missing call -- either the lifecycle
  needs wiring (this session's fix: singleton helper eliminates
  the need for close) or the method shouldn't exist.
- **Byte-identical private helpers across files are a drift
  hazard, and extraction supersedes the RN_-prefix defense.**
  Session F's `RN_` prefix on `requireBase64Url32` / `requireString`
  / `RN_BASE64URL_RE` was correct for its state: three file-private
  copies, one shared name, a wrong-file reference would fail
  compile visibly. Once extraction leaves one shared `internal`
  definition, the state that required the prefix is gone --
  there's one definition, one name, nothing to confuse. **Supersession
  is the correct response to extraction, not preservation.**
  Session F's note stays in the handoff as history; the KDoc
  in `Base64UrlValidation.kt` records the supersession so a
  future reader sees why.
- **Truncated output commands hide exactly the errors you need.**
  Consolidated from T-1 (`tail -4` hides the compile error list)
  and R-3/R-4 (`--since N` truncates before slow events). Three
  failures this class across the R-S-T-U chain: (a) `tail -4` on
  a Gradle build hides `^e:` lines; (b) `--since 1m` / `--since
  10m` on `docker compose logs` truncates before the sleep +
  screencap + diagnostic assembly completes; (c) `tail -N` on a
  multi-line grep match hides everything past the last match.
  **Rule: grep `^e:` for compile output, `--since 30m` for
  container logs (wide), and `head` the first few matches when
  the error count is what matters.** Same family as the
  log-format grep lessons (R-3/R-4): truncation is silent, and
  the failure mode is "no output" being read as "no event."
- **Brace-walk removal beats fixed-string function removal in
  Python edit scripts.** Session U-1 attempted exact-string
  `replace()` on `requireBase64Url32` three times; the third
  time succeeded only after switching to a brace-walk approach
  (find header line, walk `{`/`}` depth to find closing brace,
  replace the whole function block). Fixed-string removal fails
  when body formatting differs between the source files --
  single-line exception vs multi-line exception in PB vs AM
  produced identical-looking bodies that weren't textually
  identical. Same class as T-1's line-level-manipulation fix
  for Kotlin call sites: **for multi-line code edits, anchor on
  structure (line positions, brace depth) and compute
  indentation from the file, never paste whitespace or full
  bodies into Python strings.**

- **Scope a negative finding to files actually read, not to the
  directory they're in.** Session U-3's block-2 read of
  `ws/server.ts` produced the statement "no `LISTEN/NOTIFY`
  anywhere in `ws/`" — true of `server.ts`, generalized to the
  directory. The mechanism lives in `ws/revocation.ts`, which
  block 3's `find` listed and I did not read before concluding.
  When a negative finding drives a session decision (file a task,
  amend a spec), verify the negative against every file in the
  scope the finding covers, not just the one you read. Cost of
  one extra `cat` is trivial; cost of a wrong classification is
  a session's worth of follow-up. Same class as Session M's
  "empty logcat is not evidence of absence" — but at the
  conclusion layer, not the search layer.

- **Preflight-first re-earns its keep on prose-anchor wrap bugs.**
  Session U-3's first edit script anchored on "the newly enrolled
  device will accept at first enrollment" — the file wraps the
  sentence at "the\nnewly". Preflight returned `count=0` for that
  anchor; nothing was written. This is §7's existing "prose anchors
  wrapping mid-phrase" rule re-earned — which is the point.
  Discipline rules don't survive by citation; they survive by
  costing nothing when they fire. The pattern generalizes: when
  the file's own wrapping is unknown, anchor on a fragment
  entirely on one line, or use a full-line anchor with explicit
  `\n` boundaries.

- **macOS `wc -l` pads output to 8 columns; `$(... | wc -l)` is
  not comparable to a bare `"2"`.** Session U-3's block-8 first
  attempt: `if [ "$(git status ... | wc -l)" != "2" ]` fired
  `ABORT: expected exactly 2 modified files` on a clean tree
  because the actual value was `"       2"` (7 spaces + `2`). The
  abort was correct behavior from a broken gate — no writes
  reached the repo. Fix: `grep -c .` (counts non-empty lines, no
  padding) or `| tr -d ' '`. Any shell count-check that compares
  command substitution against a bare number needs this.
  Portable across every repo; not a Umoja-specific fix.

- **Sweep findings aren't uniform across documents — allow for
  a fourth classification bucket: `completeness`.** Session U-3's
  AUTH-SPEC-001 sweep was almost entirely shipped behavior:
  findings were precision and one real gap. The bucket set
  (holds / doc-drift / real-gap / hypothesis-refuted) was
  sufficient. Session V-1's THREAT-MODEL-001 sweep needed
  `completeness` — prose describes a feature that is specified
  but not yet built (§6.3 duress wipe, §6.4 wipe notification,
  §6.7 rotation/recovery). Without the bucket, "the doc says
  this works" reads as "this works" when it means "this is the
  design target." The distinction matters because the fix
  differs: doc-drift amends the prose; completeness adds a
  status note without weakening the claim. Both preserve the
  document's authority; only one writes code eventually.

- **Cross-document fix propagation is part of a sweep pass, not
  a follow-up.** Session V-1's §6.2 mechanism correction
  duplicated U-3's AUTH-SPEC-001 §10.3 v0.2 correction because
  both documents made the same claim about the same code.
  Without checking the sibling documents' phrasing before
  closing V-1, the drift would have been "fixed" in one doc and
  left standing in another — a re-audit would then find the
  same drift twice. Rule: after classifying a doc-drift,
  `grep -r` the doc set for the offending phrase before closing
  the sweep. Cost is one grep; cost of skipping is a future
  session's finding.

- **`completeness` has two forms: behavioral and parametric.** V-1
  introduced `completeness` for behavioral features described as
  shipped (THREAT-MODEL-001 §6.3 duress wipe, §6.4 wipe
  notification, §6.7 rotation). W-1 discovered the parametric form:
  target-stack values asserted as current (US-ADD-001 §5 SQLCipher,
  §5 tor-android embedded, §6 enrollment attestation, §7 recovery
  version). Same classification bucket, different amendment shape.
  Behavioral → "planned per TASK-P1-YYY." Parametric → "current:
  X, target: Y, pending Z." Both preserve the doc's authority as
  design target while stating today's truth. **Rule:** when a
  document mixes current-state and build-time-target assertions
  (registers do; summaries usually don't), expect both forms and
  amend each with its own shape — not one with the other.

- **Cross-document propagation discipline earned its keep the
  session after it was written.** V-1's §7 addition said "after
  classifying a doc-drift, grep the doc set for the offending
  phrase before closing the sweep." W-1 opened with exactly that
  grep (`grep -r 'on listener reconnect' docs/`) and found
  US-MASTER-001 §3.5's instance in one shot, ~20 lines into the
  sweep. **Not a finding W-1 would have produced alone** — reading
  US-MASTER-001 in isolation finds internal consistency; the drift
  is only visible against THREAT-MODEL-001 §8 v0.2's correction.
  The lesson is that **§7 notes must be read before the writes
  start, not after**. A discipline note that's read after the work
  is a postmortem; a discipline note that's read before is a
  decision lever. V-1's note was read at W-1's Command 1, applied
  at Command 3, and it changed the outcome. Preserve the pattern:
  **when a §7 addition names a pre-write action, the next session
  must run that action in its first command block, not somewhere
  mid-sweep.**

- **Per-block preflight is not a top-level abort.** A shell block
  with multiple `python3 <<'PYEOF'` heredocs runs each independently.
  A top-level preflight that `sys.exit`s stops only its own process;
  the shell continues to the next heredoc. Session X-1's Command 5
  demonstrated this: the top-level preflight failed on
  THREAT-MODEL-001's end-of-doc anchor, but AUTH-SPEC-001 and
  US-MASTER-001 write blocks each ran because their own internal
  anchors passed, while THREAT-MODEL-001's write block aborted on
  its own check. Two of three files landed; the advisory
  `PREFLIGHT FAILED — no writes will run` message was literally
  false. **Fix: `set -e` at the top of the shell block, or a
  single Python process per file (all-or-nothing per file), or
  one process for the whole batch. The advisory-line pattern is
  misleading — either `set -e` or drop the advisory text.** The
  session close's Command 8 uses `set -e`.

- **End-of-doc version lines are a staleness surface separate
  from header and revision history.** V-1's THREAT-MODEL-001
  v0.1 → v0.2 bump updated header + revision-history row but left
  the trailing `— end of THREAT-MODEL-001 v0.1 draft —`
  unchanged. X-1's v0.2 → v0.3 bump assumed the line was v0.2
  and preflight failed on that assumption; corrected Command 6
  anchored on actual `v0.1` text and fixed it in the same commit.
  W-1's US-ADD-001 v0.2 → v0.3 caught the same staleness by
  accidental alignment (end-of-doc anchor was `v0.1`, file said
  `v0.1`). **Rule for any version-bump commit: preflight all
  three surfaces** — header (`^Version:`), revision-history row
  (`| X.Y |`), end-of-doc line (`— end of DOC vX.Y draft —`).
  When one is stale relative to the others, fix staleness in the
  same commit that bumps the others; don't ship a bump that
  leaves the file's own version metadata inconsistent across
  sections.
- **`set -e` + `grep -c` returning 0 aborts the shell.** Session
  X-1's Command 8 used `set -e` at the top of a write-then-verify
  shell block (the fix for the per-block-preflight bug from
  Command 5). Then a spot-check `grep -c` on a pattern containing
  a Python-style Unicode escape (literal `u2014` in the grep
  pattern, rather than the em-dash character the file actually
  contains) returned 0 — the pattern searched for the literal
  characters, not the em-dash. `grep -c` exits 1 on zero
  matches; under `set -e` that killed the shell mid-command.
  Commits never ran; two files landed uncommitted. Recovery took
  a full command cycle. **Rule:** the `set -e` protection for
  write-phase failures has a side effect on the verify phase —
  any grep that can legitimately return zero matches will abort
  the script. Use `set +e` before the spot-check block and
  `set -e` again after; or `|| true` on each grep; or
  `if grep -q; then...fi` guards. Simpler: don't put Python-style
  Unicode escapes in bash grep patterns — anchor on ASCII-only
  substrings, or use `$'\uXXXX'` (ANSI-C quoting) if the
  character must be present.

- **Regex capture-group substitutions lie silently when a group's
  role is misread.** Session X-1's Command 8 used a substitution
  with the pattern `(| TASK-P1-042 |[^\n]*?| )(Proposed)( |)` and
  the replacement `\1DONE\2` — where `\2` refers to "Proposed"
  (the target), not the trailing " |" separator (group 3). The
  result was `...| 1 | DONEProposed` (concatenated, trailing pipe
  dropped) rather than `...| 1 | DONE |`. The corruption passed
  any grep for the substituted text ("DONE" is present) but
  failed any grep that anchors on row structure (`| DONE |`).
  X-1's close caught it in the same session via the row-structure
  spot-check that returned 0; the fix at bf5faf1 anchored on the
  minimal unique substring `DONEProposed`, not on the
  fully-formed assumed value `| DONEProposed |` — the corruption
  was *missing* a character (the trailing pipe), and the wider
  anchor that assumed its presence failed to match. **Rule:** a
  substitution anchored on `(...)(target)(suffix)` risks
  group-numbering bugs; the correct form is `\1NEW\3` (or
  `sed -E 's/| Proposed |/| DONE |/'` for a fixed literal
  target — no capture groups at all). When a corruption is
  found, **anchor the fix on the minimal unique substring that
  names it**, not on the fully-formed assumed corrupted value.


- **`exit 1` in a pasted block can terminate the interactive shell,**
  even inside a subshell. Session Z-1 hit this in block 3 (subshell
  `exit 1` fired after a compile check, zsh terminated). The abort
  was correct -- the shell should not continue past a failed gate --
  but the terminal going away loses scrollback and forces a re-paste.
  **Flag-based flow is the fix:** `RESULT=0; ( ... ) || RESULT=$?;`
  then `if [ "$RESULT" -ne 0 ]; then echo "FAILED"; fi`. The
  subshell isolates `cd` and status, no `exit` anywhere, the shell
  survives, the failure is still visible in the output, downstream
  decisions are plain `if` branches. This is the form every write
  block in Z-1's late arc used.

- **`git commit` != `installDebug` != APK on emulator.** Three distinct
  steps in three distinct places. A commit that lands and a test that
  fails is not a code failure -- it might be that the APK was never
  deployed. Session Z-1's block 6d ran 3 fetches post-trigger and the
  fix commit existed; block 6f's `installDebug` was the missing step.
  **Confirm deployment via `dumpsys package com.umoja.secure | grep
  lastUpdateTime` -- if the timestamp is before the fix commit time,
  the fix is not on the device. Do this before drawing any conclusion
  from the emulator's behavior.** Same class as O-2 failure #4 but
  re-earned at a different scale (session-wide, not just once).

- **`--since N` windows over-count as well as truncate.** R-3/R-4
  established that `--since 1m` can truncate before slow events. Z-1's
  block 6g demonstrated the other end of the window: `--since 2m`
  caught a pre-trigger request from 58 seconds earlier, making a count
  of 2 read as 3. **Anchor on trigger time, not a fixed window:**
  capture `TRIGGER_TS=$(date -u +%s)` before the action, then compute
  the window as `--since $(( $(date -u +%s) - TRIGGER_TS + 5 ))s`, or
  filter the log lines by their numeric `"time":` field against the
  trigger epoch. Both forms prove the count is post-trigger.

- **Espresso < 3.6.1 fails deterministically on API 33+ with
  `NoSuchMethodException: InputManager.getInstance`.** The method was
  removed in API 33; Espresso's `InputManagerEventInjectionStrategy`
  calls it reflectively for input-injection setup. Every Compose test
  using `createComposeRule()` fails on the first `runUntilIdle()` call,
  before the first assertion runs. Symptom is uniform: 11/11 fail,
  same stack trace, `InputManagerEventInjectionStrategy.initialize`
  in every trace. **Fix: pin espresso-core 3.6.1+ (3.7.0 for API 36+).**
  One-line version bump, no test code change. If a project's
  `libs.versions.toml` has `espressoCore = "3.5.x"` or older, this is
  the failure waiting to happen on modern emulators.

- **`am instrument` exit code is not the test result.** Exit 0 means
  "JUnitRunner finished," not "tests passed." A block that gates on
  `[ $? -eq 0 ]` after `am instrument` succeeds when the tests failed.
  **The authoritative signals are `INSTRUMENTATION_RESULT: stream=`
  and the JUnitRunner summary line `OK (N tests)` / `FAILURES!!!`.**
  Grep those, not the exit code. Z-1's block 12 printed `am instrument
  exit: 0` alongside `FAILURES!!! Tests run: 11, Failures: 11` -- both
  true, only one load-bearing.

- **Postgres container user is `umoja`, not `postgres`.** The handoff
  §6 psql invocations run as `psql` with no `-U` (defaults to the
  exec user inside the container, which happens to be correct in the
  historical setup); Session Z-1 assumed `-U postgres` and hit
  `role "postgres" does not exist`. **`docker compose exec -T backend
  env | grep DATABASE` gives the authoritative user**: in this project
  it's `postgres://umoja:umoja@postgres:5432/umoja`, so the correct
  psql invocation is `docker compose exec -T postgres psql -U umoja
  -d umoja`. First psql call on a new environment should always read
  DATABASE_URL, not guess.

- **A grep verification returning 0 is ambiguous between "content
  absent" and "pattern wrong."** Session Z-1's block 17 landed all
  7 handoff edits correctly, but three sanity greps returned wrong
  results: (1) a pattern using a backslash-u escape in double quotes
  searched for the literal escape characters, not the em-dash -- use
  a literal em-dash in the pattern, or `grep -F`, or `$'...'` ANSI-C
  quoting; (2) a multi-line content match against a single-line
  pattern failed because grep cannot cross `\n` -- split into two
  greps or use `-A`/`-B` context; (3) a pattern starting with `--` was
  parsed as a grep flag, not a pattern -- use `-e` or `--` separator.
  **Rule: a verification that returns 0 must be proven against
  known-matching content before concluding the content is missing.**
  Use a substring that cannot be mis-parsed (`PARTIAL,` not the full
  multi-line phrase), or `grep -F` for literal matches, or `grep -e`
  for leading-dash patterns. The block that writes and the block
  that verifies should use different pattern shapes so a pattern bug
  in one does not mask a content bug in the other.

- **Substring anchors match prefixes of longer identifiers.**
  Session Z-2's block 4c-fix used anchor
  `import com.umoja.secure.transport.MatrixApi` which also matches
  `import com.umoja.secure.transport.MatrixApiException` -- preflight
  returned `count=2`, aborted before any write. The fix: newline-
  terminated anchors on import lines specifically, because imports
  always end with `\n`, so `\nimport X\n` is unique. Same family as
  Z-1's `--since` grep-pattern bug: pattern bugs are not content
  bugs; fix the pattern, do not conclude the content is wrong. The
  count==1 discipline caught this in preflight before any corruption
  landed -- preflight-paid-for-itself at the exact moment it mattered.

- **The "already exists?" check must target the new entry identifier,
  not strings the entry references.** Session Z-3's block B5 preflight
  used `AdminScreenStateTest` as the check that the new §3 entry had
  not yet been written. But that string already appeared 3 times in the
  handoff -- Z-2's header, Z-2's §3 arc-plan, and Z-2's §4 deferral
  re-scope all named the future test class as a forward reference.
  Preflight returned count=3, which blocked the write (correctly), but
  for the wrong reason: the string was expected in the file already.
  **Rule: the "already exists?" indicator must be a string that ONLY
  the current edit produces** -- for a session entry, that's
  `### Session Z-N`, not any class/file/commit name the session will
  reference. Forward references from prior sessions are legitimate
  content, not drift. When the count is nonzero, grep the occurrences
  before concluding; the file may already contain the reference by
  design. Same family as the eighth lesson (substring anchors match
  prefixes) and the seventh (grep returning 0 is ambiguous) -- the
  pattern or the check assumption is not the content.

- **JUnit XML has two aggregate levels; sum only one.** The outer
  `<testsuites tests="N">` attribute is the authoritative total
  computed by the test runner. Each `<testsuite tests="M">` child
  carries its own class's count; the M values partition the run and
  sum to N. Session Z-5's first reading of the connected-AndroidTest
  XML summed every `tests=` attribute in the file (parent N + all
  children M) and reported 142 for a run of 71. The 142 was
  arithmetically correct as an extraction -- it just answered the
  wrong question. **Read `<testsuites tests=>` for the total; read
  each `<testsuite tests=>` only for per-class breakdown.** Do not
  sum across both levels. When the total looks wrong, `head -2` the
  raw file to see the `<testsuites>` line before concluding the
  content is wrong. Same family as the seventh (grep 0 is ambiguous)
  and eighth (substring anchors) lessons: measurement bugs are not
  content bugs.

- **Grep on attribute values is fragile because common attribute names
  are substrings of longer ones.** Session Z-5's D6-retry grep for
  `name="com.umoja.secure.ui.chat.ChatScreenTest"` matched both the
  `<testsuite name="...">` line AND all 14 `<testcase
  classname="...">` lines, because `name=` is a substring of
  `classname=`. Reported 15 entries where 1 expected. `tests=` is a
  substring of `testsuite=`; `id=` of `android:id=`; the pattern
  generalizes. **When measuring structured data by attribute, use a
  structural parser (`xml.etree`, `json.loads`, DOM), not text
  matching.** A parser reads the attribute as the data model defines
  it; grep reads the byte sequence. When the same measurement fails
  three different ways in one block chain, that is the signal the
  tool is wrong -- change the tool, not the third invocation. Z-5
  demonstrated this with three failed grep approaches (parent-sum,
  first-match, substring) before `xml.etree.ElementTree` produced the
  correct 71 in one attempt.

- **Verification code is code and gets the same discipline as
  production code.** Session Z-5's production refactors (ChatScreenTest
  fixtures) passed compile-check on the first try because `compile`
  is an unforgiving oracle. The verification blocks (grep-based XML
  reading) had no compiler guarding them -- a grep for a substring is
  syntactically valid and produces a plausible number that happens to
  be wrong. Three measurement blocks in this session produced 142, 1,
  and 15 for what should have been a single correct answer: 71. Each
  wrong number was syntactically a successful measurement. **When
  writing a verification check, read the data format before writing
  the pattern; if the check fails, verify the check before concluding
  the content is wrong; when the same class of check fails more than
  once, the class (not the instance) is wrong.** The evidence gate's
  refusal to commit on an unexplained count is what made this a
  productive failure rather than a shipped overclaim: three blocked
  commits cost a round-trip each and produced a correct final commit,
  versus a single shipped commit whose verification internally
  contradicted itself.

- **`git status --short | grep -c .` counts directories as 1 line
  each, not files inside.** Session Z-8's commit preflight expected
  `N=8` (5 modified + 3 new docs) and saw `N=7` because
  `docs/crypto/` and `docs/legal/` are each one line in `git status
  --short` regardless of how many files they contain. The abort was
  correct behavior from a broken gate — the metric (line count)
  didn't match the question (file count). **Fix: gate on
  `git diff --cached --name-only | grep -c .` after `git add`, which
  lists the file paths that were staged, not the git-status
  representation.** Same family as Z-5's XML parent/child double-
  count (twelfth lesson): the tool's unit of measurement is not the
  question's unit. When N looks wrong, verify the metric before
  concluding the content is wrong.

Current verified state: **260 Android JVM tests** (2026-10-20),
**71 androidTest** (2026-10-18, 8 files, from connectedAndroidTest XML
aggregate `<testsuites tests="71">` -- not grep-summed), and **263
backend tests** (2026-10-20, 20 files), all from runner output.
Android JVM and androidTest are tracked separately — they run on different
infrastructure (Mac vs emulator) and must not be summed.

---

## 8. References for the matrix implementation session

**Provenance note (2026-10-19, Session R-3):** title is from Session A
(2026-10-15). Section content has been extended since to cover all
current crypto/code shape; see the "added post-Session-A" block below.

### Authoritative design

- `docs/architecture/ADR-PROVISIONING-001.md` — §2 (threat-model
  answers), §3 (signing protocol), §4 (matrix schema), §5 (test plan),
  §6 (11-line plan), §7.1.1 (Q1/Q4 verification exception; landed
  Session A at `4abcf53`).
- `docs/architecture/ADR-IDENTITY-CHANGE-001.md` (v0.4, amended Session
  R-4 at `5d24621`) — identity-change ack schema, backend relay/verify
  asymmetry (§4), peer discovery (§5), device_revoked-code
  propagation (§10 v0.4).
- `docs/architecture/ADR-HARDENING-001.md` (§9 amendments v0.2/v0.3/v0.4
  through Session T-1 at `29ff6cc`) — session state machine (§2),
  release-build hardening (§3), send-gating verification (§4),
  out-of-scope list (§5), sequencing (§6), 037–041 completion
  record (§9).
- `docs/architecture/ADR-SIGNAL-UPGRADE-001.md` (v0.2, Session Z-7 at
  `5fd44aa`) — libsignal version decision, verified facts (§5.2),
  human approval record (§5.4), execution path (§6), regression
  gate (§7). Executed at `97279b1`.
- `docs/reference/THREAT-MODEL-001.md` (v0.2, conformance-swept Session
  V-1 at `5655318`) §5–§9. Reconciliation-drift correction propagated
  to US-MASTER-001 §3.5.
- `docs/reference/AUTH-SPEC-001.md` (v0.3, conformance-swept Session U-3
  at `349b268`; §9.2/§9.3 amended at X-1 `ed47e7a`) §5, §6, §9, §10.
- `docs/US-ADD-001.md` (v0.3, conformance-swept Session W-1 at
  `20771af`) §7, §8, §8.1 (com.google.* interpretation).
- `docs/US-MASTER-001.md` (v0.2, Session W-1 at `3720b59`) — summary /
  synthesis; propagates fixes from AUTH-SPEC/THREAT-MODEL/ADR-PROVISIONING
  (see §3.5 for the cross-document propagation pattern).
- `docs/reference/USER-ONBOARDING.md` — user-facing companion to the
  implementer-facing specs (Session U-2 at `2bb3cf3`). Same claims,
  different register; every claim carries a `Source:` line.
- `UMOJA-SECURE-BUILD-MASTER.md` §3.6, §3.7, §3.8, §6, §11.

### Conformance data

- `docs/reference/rfc8785-number-samples.json` — 24 samples.
- `docs/reference/jcs-conformance/` — 6 pairs (Apache 2.0).
- `docs/reference/canonical-matrix-test-vectors.json` — generated
  (W-001..W-006, Session A `e6eed9b`).
- `docs/reference/canonical-replacement-notice-test-vectors.json` —
  generated (R-001..R-003, Session F `d28c631`).
- `docs/reference/canonical-identity-change-ack-test-vectors.json` —
  generated (A-001, Session I `ed271ac`).

### Current code shape

JCS + matrix crypto (the Session A work):
- `backend/src/crypto/jcs.ts` — TS reference
- `backend/src/crypto/jcs.test.ts` — 45 tests
- `backend/src/crypto/jcs-dump.ts` — TS producer for cross-check
- `backend/src/crypto/matrix-schema.ts` + `.test.ts` — 23 tests
- `backend/src/crypto/matrix-sign.ts` + `.test.ts` — 22 tests
- `backend/scripts/generate-matrix-vectors.ts`
- `android/.../crypto/JcsNumberFormatter.kt` — 4 tests
- `android/.../crypto/JcsCanonicalizer.kt` — 11 tests
- `android/.../crypto/JcsCrossCheckTest.kt` — 1 test
- `android/.../crypto/AuthorizationMatrix.kt` — 23 tests
- `android/.../crypto/MatrixSigner.kt` — 12 tests
- `android/.../crypto/ProvisioningBundle.kt` — 16 tests
- `android/.../crypto/MatrixBuilder.kt` — 9 tests
- `scripts/jcs-cross-check.sh` — the harness

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
- `android/.../ui/admin/AdminScreen.kt` — extended in P1-025

### Code shape — added post-Session-A

Surfaces added by Sessions F through Z-9. File names abbreviated
for scannability; the source files carry full KDoc.

Android `crypto/` (new):
- `MatrixVerifier.kt` — Ed25519 verify against trusted set (A c2)
- `MatrixStore.kt` — verified-matrix persistence; anti-rollback (E);
  `version: StateFlow<Long>` write-notification (P D-1)
- `ProvisioningKeys.kt` — pinned pubkeys; current/recovery/previous
  seams for rotation (A)
- `DeviceIdStore.kt` — durable client-chosen `device_id` (A/P1-019)
- `EnrollmentQrPayload.kt` — QR producer matching P1-025 parser (A)
- `Base64UrlValidation.kt` — shared internal validators (U-1 dedupe)
- `CryptoJsonHelpers.kt`, `CryptoException.kt` — shared helpers (J)
- `WipeConfirmationKeyManager.kt` — one-shot wipe key (A)
- `ReplacementNotice{,Signer,Verifier,Store}.kt` — identity-change
  continuity (F, J, K)
- `IdentityChangeAck{,Signer}.kt`, `IdentityChangeController.kt` — ack
  schema/sign/orchestration (I, K)
- `SendGate.kt` — fail-closed send-path predicate (P)
- `VerificationFailureStore.kt` — operator failure log (T-1)

Android `auth/` and `ui/` (new):
- `SessionStateManager.kt` — 7-state session lifecycle (R-2);
  single-flight Mutex + CompletableDeferred
- `SessionScreens.kt` — terminal-state composables (R-3)
- `SecureScreen.kt` — `FLAG_SECURE` composition wrapper (Q)

Backend (new):
- `backend/src/crypto/replacement-notice.ts` — signed notice schema (F)
- `backend/src/crypto/identity-change-ack.ts` — signed ack schema + verify (I)
- `backend/src/identityChange/` — services + routes for notices/acks
  relay (H); `relay → store-verbatim → verify-on-ack` asymmetry per
  ADR-IDENTITY-CHANGE-001 §4
- `backend/src/ws/revocation.ts` — LISTEN/NOTIFY prompt-wake with
  reconnect + reconcile (P1-042, X-1)
- `backend/scripts/sign-test-notice.ts`, `sign-test-matrix.ts` — signed
  fixture seeders (M, O-2)

`transport/` surface (Session P5-2, suspend refactor landed):
- `HttpClient.kt` — `postJson`/`get`/`execute`/`executeWithRetry` are
  `suspend fun`. The `runBlocking` bridge from 040-D is gone; the
  `on401Handler` is invoked directly. **Dispatcher discipline**: `suspend`
  does not imply IO dispatch — callers MUST `withContext(Dispatchers.IO)`
  before calling (all current callers do).
- `AuthApi.kt`, `ContactsApi.kt`, `AdminApi.kt`, `PreKeyApi.kt`,
  `EnrollmentApi.kt`, `EnvelopeApi.kt`, `IdentityChangeApi.kt`,
  `MatrixApi.kt` — all methods `suspend fun`; `MatrixApi` ctor `fetchFn`
  is `suspend`; `IdentityChangeController`'s `listNotices`/`postAck`
  lambda params are `suspend`.
- `Socks5Bridge.kt`, `WebSocketClient.kt` — unchanged (Socks5Bridge is
  plain JVM; WebSocketClient is callback-driven, not suspend).
- Zero caller source changes: every existing caller already ran inside
  `withContext(Dispatchers.IO)` / `LaunchedEffect` / `scope.launch`.
- Verification: `HttpClientRetryTest` 7 tests unchanged (predicate
  `shouldRetryAfter401` untouched); full JVM 244/244; androidTest per
  emulator clean.

### Verify paths before reading

    find ~/umoja-secure/backend/src -name "*.ts" | grep -E "crypto|admin|enroll|contact|session|canonical|identity|replacement|ws/|audit|auth" | sort
    find ~/umoja-secure/android/app/src -name "*.kt" | grep -E "Admin|Contact|Device|Signal|Session|Canonical|Jcs|Matrix|Provisioning|Identity|Replacement|SendGate|Verification|SecureScreen|EnrollmentQr|Http|Api" | sort

### Notes for a new agent

**TASK-P1-027 numbering collision.** Commit `ad89b76` is labeled
"TASK-P1-027: docker deployment". The current registry maps TASK-P1-027
to "SBOM generation and dependency review gate". Registry is
authoritative. Do not "fix" the old commit label.

**Canonical document provenance.** `US-ADD-001`, `US-MASTER-001`,
`AUTH-SPEC-001`, `THREAT-MODEL-001` were authored 2026-10-14. They did
not exist before. Each carries a §1 Provenance section recording this.

**§8 currency (2026-10-19).** The "Current code shape" section was
accurate as of Session A. The "added post-Session-A" block above
catches the crypto surface added by Sessions F through Z-9. The
`transport/` surface is deliberately deferred to the pending suspend
refactor’s preamble — the refactor reads those files anyway, so
updating the listing now would be re-stale by the refactor. The
section title still says "matrix implementation session"; the
content has outgrown that scope, and the provenance note at the
top names it.

**If a security-relevant question arises that none of these answers,
do not guess. STOP and escalate, per Build Master §0.**
