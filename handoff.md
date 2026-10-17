# Umoja Secure — Handoff

Last updated: 2026-10-17 (Session G — TASK-P1-030 030e-b ADR + migration landed. Next: 030e-b service modules, routes, tests.)

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
- docs/US-TASK-P1-001.md (task registry, v0.4)
- docs/architecture/ADR-PROVISIONING-001.md
- docs/ops/TOR-ONION.md
- docs/security/DEPENDENCY-EXCEPTIONS.md (new, this session)

---

## 2. Where the project stands

### Backend (complete for Phase 1 messaging)

- Node.js 24.x, Fastify 5.12.5, PostgreSQL 16
- Docker-deployable (docker compose up -d --build from repo root)
- **217 tests passing** (15 files; verified 2026-10-17 via
  `npm test`. Grew through Sessions C–F: matrix-version, token floor,
  enrollment floor echo, replacement-notice.)
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
- **JVM unit tests: 122** (verified 2026-10-17 from XML; +5 floor tests Session E, +7 ReplacementNotice Session F)
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
`f257e03` Kotlin). 030e-b ADR + schema DONE 2026-10-17 (`21677a9`
ADR + `00f31df` migration 015). Next: 030e-b service modules +
routes + tests.**

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

Current verified state: **122 Android JVM tests** (2026-10-17),
**46 androidTest** (2026-10-15, 6 files, from connectedAndroidTest XML),
and **217 backend tests** (2026-10-17, 15 files), all from runner output.
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
