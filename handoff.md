# Umoja Secure — Handoff

Last updated: 2026-10-15 (Session A — P1-019 done; KI-019 resolved (a); §5 item 3 fully specified; next: §5 item 3)

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
- **178 tests passing** (13 test files; verified 2026-10-15 via
  `npm test`).
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
- **JVM unit tests: 89** (verified 2026-10-15; +12 EnrollmentQrPayloadTest)
- **androidTest: 6 files, 46 tests** (verified 2026-10-15 from
  connectedAndroidTest XML; was wrongly recorded as 0 files in an
  earlier handoff — see KI-013)

Note: a prior handoff claimed 98 Android tests. That was wrong. The
actual prior count was ~1 (ExampleUnitTest only); the crypto work
brought it to 77, then 89 after P1-019. See §4 KI-013.

### Tor (dev)

- umoja-tor container publishes <onion>.onion → backend:8080
- Mac Homebrew tor on 127.0.0.1:9050, emulator reaches it via
  `adb reverse tcp:9050 tcp:9050`
- transport/Socks5Bridge.kt — HTTP→SOCKS5 bridge inside the app. Solves
  Java's local-DNS-for-SOCKS bug that broke .onion.
- Onion: `vsf2kjuapla74qea4wp4vwbahyqzftq3aywsjd3hknlcvgbtzn6xjad.onion`
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

### KI-015 (NEW): `AdminScreen.kt.bak-navdiag` is tracked
`android/app/src/main/java/com/umoja/secure/ui/admin/AdminScreen.kt.bak-navdiag`
is in `git ls-files`. Backup file in a source tree — pollutes the
package, ends up on classpath. Delete in a small cleanup commit.
Not folded into P1-025.

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

**3. Android `bound_public_key` wiring + KI-019 passthrough — FOLLOW-UP.**
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
  (existing PK → 23505 → `device_not_already_enrolled` path fires).

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

**6. TASK-P1-026 remainder — client verification and storage.**
KI-019 resolved (option a, 2026-10-15) — this task is now writable.
Re-canonicalize wrapper; verify Ed25519 against pinned provisioning
public key; enforce `highest_seen_version` (post-enrollment) or
inclusive floor (replacement device); populate contacts from
`permitted_contacts[]`; store `highest_seen_version` locally.

**7. TASK-P1-030 — replacement-device flow (integrated test per
Build Master §3.7).**

**After Session A:**

8. Emergency lock (TASK-P1-021a).
9. Duress wipe (TASK-P1-021b).
10. Signing-key custody (TASK-P1-029), recovery key (TASK-P1-035).
11. Hardware-backed Ed25519 verification (TASK-P1-034). Requires
    physical hardware.
12. Hardening: SBOM, Android redaction audit, penetration test,
    independent review.

**Backlog items (not scheduled):**
- Instrumented Compose tests for admin flows (no test rule configured;
  belongs with TASK-P1-022 or a new task).
- Delete `AdminScreen.kt.bak-navdiag` (KI-015).
- Deduplicate base64url validators (KI-016).
- `canonicalJson` deduplication between `audit/log.ts` and
  `audit/verify.ts` (KI-008).
- Backend current-matrix-version tracking (KI-018).

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
      http://vsf2kjuapla74qea4wp4vwbahyqzftq3aywsjd3hknlcvgbtzn6xjad.onion/health

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
- **Ground truth for JCS is the vendored corpus**, not either
  implementation. If TS and corpus ever disagree, TS is wrong. Same
  for Kotlin.
- **`toJSON` rejection is a deliberate deviation.** Both
  implementations reject objects with a `toJSON` method even though
  RFC 8785's reference code calls it. Do not "fix" this.

Current verified state: **89 Android JVM tests** (2026-10-15),
**46 androidTest** (2026-10-15, 6 files, from connectedAndroidTest XML),
and **178 backend tests** (2026-10-15, 13 files), all from runner output.
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
