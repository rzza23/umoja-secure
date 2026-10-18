package com.umoja.secure.transport

import com.umoja.secure.BuildConfig

/**
 * Centralized transport configuration.
 *
 * Two modes:
 *   - Clearnet dev: 127.0.0.1:8080 (via adb reverse), no SOCKS.
 *   - Tor: <onion>.onion over SOCKS through the host's Tor (also via adb
 *     reverse for 9050). No clearnet fallback.
 *
 * The .onion address is the backend's published onion service (see
 * docs/ops/TOR-ONION.md). In production, this would be provisioned at
 * enrollment, not hard-coded.
 *
 * useTor is a build-time toggle for the Phase 1 dev setup. Production will
 * always be Tor with embedded tor-android; this flag is only a shortcut for
 * iterating on the app without spinning up Tor.
 */
object TransportConfig {

    /**
     * Transport mode. Debug builds default to clearnet (127.0.0.1 via
     * adb reverse) for iteration speed; release builds default to Tor
     * (.onion via SOCKS). See ADR-HARDENING-001 §3 / §9 v0.2 item 6.
     *
     * `val`, not `var`: the ADR's ruling is that mutable transport
     * config is a security regression waiting to happen — a
     * contributor can flip it during debugging and forget. The
     * startup assertion in `UmojaApplication` fails closed if this
     * ever regresses to release-with-clearnet.
     */
    val useTor: Boolean = !BuildConfig.DEBUG

    private const val CLEARNET_HTTP = "http://127.0.0.1:8080"
    private const val CLEARNET_WS = "ws://127.0.0.1:8080/ws"

    private const val TOR_HTTP =
        "http://vsf2kj6uapla74qea4wp4vwbahyqzftq3aywsjd3hknlcvgbtzn6xjad.onion"
    private const val TOR_WS =
        "ws://vsf2kj6uapla74qea4wp4vwbahyqzftq3aywsjd3hknlcvgbtzn6xjad.onion/ws"

    // SOCKS endpoint reachable from the emulator. In dev this is
    // adb-reversed to the host's Tor. In production this will be the
    // embedded tor-android SOCKS port.
    const val SOCKS_HOST: String = "127.0.0.1"
    const val SOCKS_PORT: Int = 9050

    val httpBaseUrl: String get() = if (useTor) TOR_HTTP else CLEARNET_HTTP
    val wsUrl: String get() = if (useTor) TOR_WS else CLEARNET_WS
}
