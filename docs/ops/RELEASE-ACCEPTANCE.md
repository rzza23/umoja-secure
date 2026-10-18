# Release-build acceptance — TASK-P1-039

Procedure for verifying a release build of Umoja Secure.
`ADR-HARDENING-001` §3 is the design; this file is how to run the
acceptance. Future sessions should read this file before reproducing
the acceptance, not re-derive it.

## Prerequisites (in the build config as of commit `cb7ac82`)

- `android/app/build.gradle.kts`:
  - `buildFeatures { buildConfig = true }`
  - `buildTypes.release.optimization { enable = true }` (AGP 9.4.1 DSL;
    gates R8 minification AND resource shrinking together; default
    Android keep rules auto-included)
- `android/app/src/release/keepRules/libsignal.keep` — R8 keep rules
  for `org.signal.libsignal.**` (protocol, internal JNI bridge,
  native method names) and `org.whispersystems.libsignal.**`.
  AGP 9.3+ source set; not the legacy `proguard-rules.pro`.
- `TransportConfig.useTor = !BuildConfig.DEBUG` (commit `306bcd7`).
  Release → true; debug → false.
- `UmojaApplication.onCreate` assertion:
  `check(BuildConfig.DEBUG || TransportConfig.useTor)`. Fails closed
  if a future regression reintroduces mutable transport config.

## Build and sign

    cd ~/umoja-secure/android
    ./gradlew :app:assembleRelease

    SIGNED_APK=app/build/outputs/apk/release/app-release-signed.apk
    BUILD_TOOLS=$(find ~/Library/Android/sdk/build-tools -maxdepth 1 -type d | sort -V | tail -1)
    "$BUILD_TOOLS/apksigner" sign \
      --ks ~/.android/debug.keystore \
      --ks-pass pass:android \
      --key-pass pass:android \
      --ks-key-alias androiddebugkey \
      --out "$SIGNED_APK" \
      app/build/outputs/apk/release/app-release-unsigned.apk

The debug keystore is used for Phase 1 dev acceptance. Production
signing key custody is out of scope (ADR-HARDENING-001 §5, TASK-P1-035).

## Baseline sanity before install

- APK size: **~104 MB** (unminified baseline was ~152 MB; remaining
  size is native `.so` for 4 ABIs; ABI splits are a future
  optimization, not this task).
- `unzip -p $SIGNED_APK classes.dex | strings | grep -c "org/signal/libsignal"`
  → **~221** (keep rules held; native method names preserved).

If libsignal strings hit 0, the keep rules failed — do NOT install;
R8 will crash at first libsignal call.

## Cold-start acceptance (the load-bearing test)

ADR §3: "The acceptance test is not 'build succeeds' — minification
bugs surface at cold-start, not build time."

1. `adb -s <device> install -r $SIGNED_APK`
2. `adb -s <device> shell am force-stop com.umoja.secure`
3. `adb -s <device> logcat -c`
4. `adb -s <device> shell am start -n com.umoja.secure/.MainActivity`
5. Wait 10s. Verify three signals — all must pass:

   **Crash buffer empty**
       adb -s <device> logcat -d -b crash | tail -20
   Empty (or no FATAL EXCEPTION) = R8 didn't strip a runtime dependency.

   **Tor transport active**
       adb -s <device> logcat -d | grep "Tor mode"
   Should show `UmojaWS: Tor mode: routing WS via HTTP bridge`
   and/or `UmojaHttp: Tor mode: routing via HTTP bridge`. This proves
   `useTor = !BuildConfig.DEBUG = true` reached the transport layer.

   **Backend received a request from the Tor container**
       docker compose logs backend --since 2m | grep "me/matrix"
   `remoteAddress: 172.18.0.4` (Tor container) and
   `host: <onion>.onion`. If `remoteAddress: 127.0.0.1` or
   `host: localhost:8080`, the release build used clearnet — invariant
   broken; roll back and diagnose.

## FLAG_SECURE four-screen matrix

ADR §3 scope: ChatScreen, AdminScreen, DiagnosticsScreen. To
distinguish "flag correctly scoped" from "flag applied globally" or
"flag not applied," test four screens.

| Screen | ADR §3 | Expected `fl=` | Expected screenshot |
|---|---|---|---|
| Conversations | non-secure | no SECURE | UI visible, ~80 KB |
| Settings | non-secure | no SECURE | UI visible, ~105 KB |
| Chat | SECURE | SECURE | black + system overlays, ~23 KB |
| Diagnostics | SECURE | SECURE | black + system overlays, ~23 KB |

Optional fifth probe: after Chat → back → Settings, re-verify no
SECURE. Catches a `SecureScreen.onDispose` leak if one regresses.

Probe per screen (one paste per probe — see "Known-misleading
diagnostics" item 4):

    ADB=$HOME/Library/Android/sdk/platform-tools/adb
    $ADB -s <device> shell dumpsys window windows | \
      sed -n '/umoja.secure\/com.umoja.secure.MainActivity/,/^ *$/p' | \
      grep -E "^\s+fl=" | head -1
    TS=$(date +%H%M%S)
    $ADB -s <device> shell screencap -p /sdcard/p-$TS.png
    $ADB -s <device> pull /sdcard/p-$TS.png /tmp/p-$TS.png
    ls -la /tmp/p-$TS.png

Pass criteria: `fl=` line contains (or omits) SECURE per the table,
AND screenshot size class matches (large = UI visible; ~20–25 KB =
uniform black).

## Full-screenshot signature (FLAG_SECURE active)

The correct signature:
- Content area: pure black (uniform)
- Status bar at top: visible (system window, not the app window)
- Home/gesture indicator at bottom: visible (system overlay)

A **fully**-black screenshot with no system overlays means something
else is wrong (R8 stripped the UI, or screencap is reading a dead
framebuffer). The system overlays surviving is the marker that
FLAG_SECURE is doing exactly what it should.

## Known-misleading diagnostics (learned in Session Q)

1. **`grep FLAG_SECURE` on `dumpsys window` returns nothing.**
   dumpsys emits `SECURE` (substring of `fl=... SECURE ...`), not
   `FLAG_SECURE`. Correct pattern:
   `grep -E '^\s+fl=.*SECURE'` or `grep -E '^\s+fl=' | grep -q SECURE`.

2. **`grep -A40 "umoja" | head -3` truncates before the `fl=` line.**
   `mAttrs` and other fields precede `fl=` in the window block. The
   reliable scoping pattern is
   `sed -n '/umoja.secure\/.*MainActivity/,/^ *$/p' | grep '^\s+fl='`.

3. **Screencap uniform-black is ~20–25 KB, not <20 KB.** My first
   threshold of `<20000` incorrectly labeled correct black captures
   as "FLAG_SECURE ABSENT." Correct threshold: `<50000` (safe margin
   between 23 KB black and 80–105 KB UI).

4. **Batched `screencap` across screens returns byte-identical PNGs.**
   Navigation happens in the emulator UI between pastes, not within.
   Four `screencap` commands in one paste all capture the same
   framebuffer. One paste, one probe, one navigation between probes.

## What "pass" looks like for TASK-P1-039

- A, B, C all committed and pushed.
- Cold-start crash buffer empty.
- Tor mode active in logcat + backend sees `.onion` request from Tor
  container.
- Four-screen FLAG_SECURE matrix passes with correct `fl=` and size
  class per screen.

Recorded in handoff §3 Session Q with the empirical evidence.
