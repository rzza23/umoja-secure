package com.umoja.secure.signing

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import com.umoja.secure.crypto.DeviceKeyManager

/**
 * Entry point for the offline signing app (TASK-P1-033c).
 *
 * **Two invocation modes**, selected via an intent extra:
 *
 *   CEREMONY (first-run only):
 *     adb shell am start \
 *       -n com.umoja.secure.signing/com.umoja.secure.signing.SigningActivity \
 *       --es mode ceremony
 *     Generates the provisioning key in StrongBox/TEE (KEY-CUSTODY §2),
 *     shows the public key as QR + copyable text for the ceremony log.
 *     Refuses if a key already exists — regeneration is the documented
 *     recovery procedure (KEY-CUSTODY §2), not an app button.
 *
 *   OPERATING (routine signing):
 *     adb shell am start \
 *       -n com.umoja.secure.signing/com.umoja.secure.signing.SigningActivity \
 *       --es mode operating
 *     Refuses to sign if the key is missing (fail-closed). Otherwise
 *     accepts a canonical matrix via QR-scan or paste, validates JCS,
 *     shows the SHA-256 digest, signs on confirmation, shows the
 *     signature as QR + copyable text.
 *
 * **Why no LAUNCHER intent-filter.** src/signing/AndroidManifest.xml
 * removes MainActivity and declares this activity exported but without
 * a LAUNCHER. The signing APK therefore has no home-screen icon and
 * is unreachable from the UI. The ADB intent is the only entry point.
 * The physical ceremony's control is that ADB is not available to the
 * device operator after setup — USB access is part of the ceremony
 * workstation, removed after.
 *
 * **Why no app-companion theme.** MaterialTheme default — the signing
 * app is an air-gapped tool, not the branded messenger. Keeping UI
 * minimal makes visual verification of "this is the signing app, not
 * the messenger" unambiguous (screenshots go in the ceremony log).
 *
 * Task: TASK-P1-033c
 * Design: docs/ops/KEY-CUSTODY.md §2, §4
 */
class SigningActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val modeExtra = intent.getStringExtra("mode")
        val initialMode = when (modeExtra) {
            "ceremony" -> SigningMode.CEREMONY
            "operating" -> SigningMode.OPERATING
            else -> null
        }

        // Single Keystore-backed manager; all four lambdas point at
        // the same DeviceKeyManager instance so key presence, key
        // generation, public-key projection, and signing all operate
        // on one Keystore entry (DeviceKeyManager.PROVISIONING_ALIAS).
        val keyManager = DeviceKeyManager(this, DeviceKeyManager.PROVISIONING_ALIAS)

        val state = SigningState(
            hasKeyFn = keyManager::hasKey,
            ensureKeyPairFn = keyManager::ensureKeyPair,
            publicKeyFn = keyManager::publicKey,
            signFn = keyManager::sign,
        )

        setContent {
            MaterialTheme {
                Surface {
                    SigningScreen(state = state, initialMode = initialMode)
                }
            }
        }
    }
}
