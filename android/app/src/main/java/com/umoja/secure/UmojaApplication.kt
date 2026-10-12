package com.umoja.secure

import android.app.Application
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
        webSocketClient = WebSocketClient(
            url = WS_URL,
            appContext = applicationContext,
        )
    }

    override fun onTerminate() {
        webSocketClient.shutdown()
        super.onTerminate()
    }

    companion object {
        // Dev-only. In production this is a Tor onion service.
        const val WS_URL = "ws://127.0.0.1:8080/ws"
    }
}
