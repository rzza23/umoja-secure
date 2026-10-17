# Umoja Secure — Handoff

Last updated: 2026-10-17 (Session N + v0.2 correction — registry v0.6, ADR-HARDENING-001 v0.2. Next: TASK-P1-037 — matrix transport, prerequisite for 038's send gate.)

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
- **242 tests passing** (15 files; verified 2026-10-17 via
  `npm test`. Sessions C–F added matrix-version, floor stamping,
  replacement-notice. Session H added identity-change services (7
  validator tests) and routes (17 route tests). Session I added the
  A-001 cross-language ack test. Sessions J, K, and L backend
  unchanged. Session M added the `sign-test-notice.ts` helper script
  (no test coverage, exercised manually). Session N design-only,
  no backend changes.)
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
- **JVM unit tests: 169** (verified 2026-10-17 from XML; Session K's 12 IdentityChangeController tests are the most recent addition. Sessions L and M added Compose UI and lifecycle code with no JVM tests; verified manually on emulator. Session N design-only, no Android changes.)
- **androidTest: 6 files, 46 tests** (verified 2026-10-15 from
  connectedAndroidTest XML; was wrongly recorded as 0 files in an
  earlier handoff — see KI-013)

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

**§8's title is stale, worth a backlog item.** §8 says "References
for the matrix implementation session" — accurate as of Session A,
but Sessions H–M added `identityChange/`, `replacement-notice/`,
new ADRs, and helpers not reflected in §8's "Current code shape"
list. §8 is now a partial reference, not a complete one. Filed as a
backlog item: rename §8 or replace its code-shape list with an
authoritative reference. Not done this session — bigger than a
handoff edit, and restructuring mid-session risks introducing more
drift than it removes.

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

### KI-005: Requirements layer authored after the code
The four canonical documents were written 2026-10-14. Conformance
sweeps have been partial.

### KI-006: USER-ONBOARDING.md still missing
Referenced by Build Master §2 and §3.4. Not blocking.

### KI-007 (RESOLVED): Kotlin number serialization
Resolved by `ff15357`.

### KI-008: Three canonicalizers coexist

| Encoder | Serves | Prehash? |
|---|---|---|
| `canonicalizeChallenge` (TS) / `CanonicalChallenge.encode` (KT) | challenge-response | no |
| `canonicalJson` (TS, duplicated) | audit hash chain | no |
| `jcsCanonicalize` (TS) / `jcsCanonicalizeString` (KT) | matrix signing | yes (SHA-256) |

Do not unify. Different protocols, different signing rules.

Optional cleanup: `canonicalJson` is duplicated between
`backend/src/audit/log.ts` and `audit/verify.ts`.

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

### KI-016 (NEW): Duplicated base64url validators
`ProvisioningBundle.kt` and `AuthorizationMatrix.kt` each define
file-private `requireBase64Url32` / `requireString` / `BASE64URL_RE`.
~30 lines duplicated. Optional cleanup; do not fold into unrelated
tasks.

### KI-017 (NEW): QR payload not signed
The enrollment QR payload carries public keys and a device_id with no
signature. In Phase 1 this is spec-conformant (§3.2: public material
only). A future hardening task could have the device sign the payload
with its auth key — at which point the `domain` field becomes
load-bearing and the payload should be JCS-canonicalized. Not Phase 1.

### KI-018 (NEW): Backend does not track current matrix version
Matrix `version` is admin-entered with no server-side source of truth.
Monotonicity is device-enforced (§3.7), so a bad number fails safe,
but the admin has no way to query "what version is currently
authorized." Future improvement.

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
the hardening pass (item 16). Next task: TASK-P1-038 — send-gate
verification. The ADR argues it goes first because it is the one task
that might reveal a hole rather than require new code.**

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

    Next session opens on **TASK-P1-037** (matrix transport):
    `GET /me/matrix` backend route + `MatrixApi.fetch()` client +
    wire into `Authenticated` state entry. 030e-d deferred behind
    the whole pass.

**Backlog items (not scheduled):**
- Instrumented Compose tests for admin flows (no test rule configured;
  belongs with TASK-P1-022 or a new task).
- Deduplicate base64url validators (KI-016).
- `canonicalJson` deduplication between `audit/log.ts` and
  `audit/verify.ts` (KI-008).
- Backend current-matrix-version tracking (KI-018).
- `scripts/bootstrap-enrollment-token.sh` — one-command enrollment
  recovery. Reads the device's QR JSON, generates a token, inserts
  the enrollment_tokens row, prints the token. Three occurrences of
  the manual procedure make it worth scripting.

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

Current verified state: **169 Android JVM tests** (2026-10-17),
**46 androidTest** (2026-10-15, 6 files, from connectedAndroidTest XML),
and **242 backend tests** (2026-10-17, 15 files), all from runner output.
Android JVM and androidTest are tracked separately — they run on different
infrastructure (Mac vs emulator) and must not be summed.

---

## 8. References for the matrix implementation session

### Authoritative design

- `docs/architecture/ADR-PROVISIONING-001.md` — §2 (threat-model
  answers), §3 (signing protocol), §4 (matrix schema), §5 (test plan),
  §6 (11-line plan). Amendment pending (see §5 step 1).
- `docs/reference/THREAT-MODEL-001.md` §5–§8.
- `docs/reference/AUTH-SPEC-001.md` §5, §6, §9, §10.
- `docs/US-ADD-001.md` §7, §8, §8.1 (com.google.* interpretation).
- `UMOJA-SECURE-BUILD-MASTER.md` §3.6, §3.7, §3.8, §6, §11.

### Conformance data

- `docs/reference/rfc8785-number-samples.json` — 24 samples.
- `docs/reference/jcs-conformance/` — 6 pairs.
- `docs/reference/canonical-matrix-test-vectors.json` — generated.

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

### Verify paths before reading

    find ~/umoja-secure/backend/src -name "*.ts" | grep -E "crypto|admin|enroll|contact|session|canonical" | sort
    find ~/umoja-secure/android/app/src -name "*.kt" | grep -E "Admin|Contact|Device|Signal|Session|Canonical|Jcs|Matrix|Provisioning" | sort

### Notes for a new agent

**TASK-P1-027 numbering collision.** Commit `ad89b76` is labeled
"TASK-P1-027: docker deployment". The current registry maps TASK-P1-027
to "SBOM generation and dependency review gate". Registry is
authoritative. Do not "fix" the old commit label.

**Canonical document provenance.** `US-ADD-001`, `US-MASTER-001`,
`AUTH-SPEC-001`, `THREAT-MODEL-001` were authored 2026-10-14. They did
not exist before. Each carries a §1 Provenance section recording this.

**If a security-relevant question arises that none of these answers,
do not guess. STOP and escalate, per Build Master §0.**
