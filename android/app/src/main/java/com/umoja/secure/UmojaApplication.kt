package com.umoja.secure

import android.app.Application
import com.umoja.secure.crypto.ProvisioningKeys
import com.umoja.secure.transport.TransportConfig
import com.umoja.secure.transport.WebSocketClient

/**
 * Umoja Secure application entry point.
 *
 * Holds the WebSocketClient singleton so its connection state survives
 * Activity recreation. Future tasks will migrate this to a proper DI graph.
 */
class UmojaApplication : Application() {

    lateinit var webSocketClient: WebSocketClient
        private set

    override fun onCreate() {
        super.onCreate()
        // ADR-HARDENING-001 §3 startup assertion. Today
        // TransportConfig.useTor is `val = !BuildConfig.DEBUG`, so
        // this check is satisfied by construction — tautological on
        // the current code. Its purpose is canary, not validation:
        // it fails closed if a future change reintroduces mutability
        // or adds a debug hook that a release build could
        // accidentally inherit. Release builds must not operate
        // over clearnet.
        check(BuildConfig.DEBUG || TransportConfig.useTor) {
            "Release build must use Tor (ADR-HARDENING-001 §3). " +
                "TransportConfig.useTor=${TransportConfig.useTor}, " +
                "BuildConfig.DEBUG=${BuildConfig.DEBUG}"
        }
        // TASK-P1-029b startup assertion. Parallel to the TransportConfig
        // check above: canary, not validation. In debug builds CURRENT
        // resolves to TEST; in release builds it resolves to PRODUCTION
        // (injected at build time from the custody ceremony). This check
        // catches the DANGEROUS case: a release build where the
        // BuildConfig.DEBUG routing has failed and CURRENT resolves to
        // TEST — a usable Ed25519 key that would verify matrices signed
        // by the test seed, silently shipping the test trust anchor.
        //
        // It does NOT catch the FAIL-SAFE case: release build where
        // CURRENT resolves to PRODUCTION but PRODUCTION is still the
        // 32-byte 0xFF placeholder. That placeholder is not a valid
        // Ed25519 public key, so every matrix verification fails at
        // runtime — a safe failure, not a silent-accept failure. If
        // that case ever needs a loud startup failure, add a parse +
        // validate step here; §5.1 does not require it.
        check(
            BuildConfig.DEBUG ||
                ProvisioningKeys.CURRENT_PROVISIONING_PUBKEY_B64U !=
                ProvisioningKeys.TEST_PROVISIONING_PUBKEY_B64U
        ) {
            "Release build is using the test provisioning key; " +
                "refusing to start. ProvisioningKeys." +
                "PRODUCTION_PROVISIONING_PUBKEY_B64U has not been " +
                "replaced from the ceremony placeholder " +
                "(see docs/ops/KEY-CUSTODY.md §5.1)."
        }
        webSocketClient = WebSocketClient(
            url = TransportConfig.wsUrl,
            appContext = applicationContext,
        )
    }

    override fun onTerminate() {
        webSocketClient.shutdown()
        super.onTerminate()
    }
}
