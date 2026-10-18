package com.umoja.secure

import android.app.Application
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
