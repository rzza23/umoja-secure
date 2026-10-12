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
