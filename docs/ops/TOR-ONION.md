# Tor Onion Service — Umoja Secure

Status: Working in dev (Phase 1).
Last updated: 2026-10-14

## Overview

Umoja Secure routes all messaging and call signaling through Tor. The
backend is exposed as a v3 onion service. There is no clearnet fallback
in production. In dev, TransportConfig.useTor selects between:

- **false** — clearnet 127.0.0.1:8080 via adb reverse. Fast iteration.
- **true**  — .onion over SOCKS via a local HTTP→SOCKS5 bridge in the app.

## Topology (dev)

    Emulator
      ↓ adb reverse tcp:9050 / tcp:8080
    Mac
      ├── Homebrew tor (127.0.0.1:9050) — client-side Tor
      └── Docker umoja-tor — publishes <onion>.onion → backend:8080
      └── Docker umoja-backend — Fastify, port 8080

The emulator reaches both ports through `adb reverse`. Tor does not run
inside the emulator in dev — only the bridge lives there.

## The bridge (transport/Socks5Bridge.kt)

Java's SOCKS socket implementation resolves hostnames locally before
dialing SOCKS, so `.onion` addresses break: OkHttp resolves them to a
dummy 127.0.0.1 and passes the IP to Tor, which then fails.

The bridge is a tiny HTTP/1.1 proxy on 127.0.0.1:<ephemeral> inside the
app. It accepts HTTP requests from OkHttp (Proxy.Type.HTTP), extracts the
target hostname from the request line, dials SOCKS5 to 127.0.0.1:9050
with ATYP=0x03 (domain name), and relays bytes. The hostname — including
`.onion` — is resolved by Tor, not by Java.

Both HttpClient and WebSocketClient start the bridge once via
Socks5Bridge.start() (idempotent) and use it as their HTTP proxy when
TransportConfig.useTor is true.

## Config

    // transport/TransportConfig.kt
    var useTor: Boolean = false    // true for Tor mode

    private const val TOR_HTTP = "http://<onion>.onion"
    private const val TOR_WS   = "ws://<onion>.onion/ws"
    const val SOCKS_HOST = "127.0.0.1"
    const val SOCKS_PORT = 9050

The onion address is the one published by the Docker tor container. Find
it with:

    docker compose exec tor cat /var/lib/tor/umoja-backend/hostname

## Verifying Tor works

From the Mac (bypassing the app entirely):

    curl --socks5-hostname 127.0.0.1:9050 \
      http://<onion>.onion/health
    # {"status":"ok","version":"0.1.0","uptime":...}

In logcat:

    adb logcat -s UmojaSocksBridge UmojaWS UmojaHttp
    # UmojaSocksBridge: bridge listening on 127.0.0.1:<port> -> SOCKS 127.0.0.1:9050
    # UmojaWS : Tor mode: routing WS via HTTP bridge 127.0.0.1:<port>
    # UmojaHttp: Tor mode: routing via HTTP bridge 127.0.0.1:<port>
    # UmojaWS : socket open
    # UmojaWS : authenticated

Backend:

    docker compose logs backend --tail=20
    # Look for: "host":"<onion>.onion","remoteAddress":"172.18.0.4"
    # 172.18.0.4 is the umoja-tor container — proof the request came
    # through Tor, not clearnet.

## Troubleshooting

**All HTTP calls fail with network_error:**
- `adb -s emulator-5554 reverse tcp:9050 tcp:9050` — if missing, the
  bridge has nowhere to dial SOCKS.
- Confirm Homebrew tor is running: `lsof -iTCP:9050 -sTCP:LISTEN`.

**Bridge logs "origin-form request not supported":**
- OkHttp sent `GET /path` without absolute-URI. This means the proxy
  wasn't actually installed — check that TransportConfig.useTor was true
  at HttpClient construction time.

**SOCKS5 CONNECT failed rep=0x04 (host unreachable):**
- Tor found the onion descriptor but couldn't build a circuit. Wait 10-
  30s and retry; Tor circuits for new onions take time.

**Onion works from curl but not from the app:**
- Check that TransportConfig.useTor is true and the app was rebuilt
  after flipping it. The flag is read at HttpClient construction time.

## Production (Phase 2+)

- Embedded tor-android replaces the Mac's Homebrew tor. No adb reverse.
- Onion address provisioned at enrollment, not hard-coded.
- Client rejects any request that is not over the onion.
- TURN for calls is out of scope for Tor (see ADR-007).

## Security notes

- No clearnet fallback. If Tor is unavailable, requests fail; the client
  does not silently downgrade.
- The bridge listens only on 127.0.0.1. It is not reachable off-device.
- The bridge does not inspect or modify request bodies. It relays bytes.
- The backend sees requests from the umoja-tor container, not from the
  client. IP-level metadata is bounded by Tor's anonymity.
