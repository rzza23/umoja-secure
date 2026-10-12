package com.umoja.secure.transport

import android.content.Context
import android.util.Base64
import android.util.Log
import com.umoja.secure.auth.CanonicalChallenge
import com.umoja.secure.auth.Challenge
import com.umoja.secure.crypto.DeviceKeyManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * Persistent WebSocket to the backend.
 *
 * Flow:
 *   1. connect() opens the socket.
 *   2. On open, we send an auth frame with the session token.
 *   3. Backend responds auth_ok with revalidate interval, or auth_fail + close.
 *   4. Server periodically sends revalidate with a challenge.
 *      We sign it with the device key and reply revalidate_response.
 *   5. Server sends ping; we reply pong.
 *   6. Server pushes envelope frames on new messages.
 *   7. Server sends revoked + close 4403 on device revocation.
 *
 * The client auto-reconnects with exponential backoff for network errors,
 * but does not reconnect after auth_fail (4401) or revoked (4403).
 */
class WebSocketClient(
    private val url: String,
    private val appContext: Context,
) {
    companion object {
        private const val TAG = "UmojaWS"
        private const val MAX_BACKOFF_SECONDS = 30L
        private const val AUTH_CLOSE_CODE = 4401
        private const val REVOKED_CLOSE_CODE = 4403
    }

    sealed class State {
        object Disconnected : State()
        object Connecting : State()
        object Authenticating : State()
        object Ready : State()
        object Reconnecting : State()
        data class Failed(val reason: String) : State()
        object Revoked : State()
    }

    private val httpClient: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(0, TimeUnit.SECONDS)
        .writeTimeout(15, TimeUnit.SECONDS)
        .pingInterval(0, TimeUnit.SECONDS) // server drives heartbeats
        .build()

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private val _state = MutableStateFlow<State>(State.Disconnected)
    val state: StateFlow<State> = _state.asStateFlow()

    private val _envelopes = MutableSharedFlow<JSONObject>(extraBufferCapacity = 100)
    val envelopes: SharedFlow<JSONObject> = _envelopes.asSharedFlow()

    private var webSocket: WebSocket? = null
    private var currentToken: String? = null
    private var reconnectAttempt = 0
    private var reconnectJob: Job? = null
    private var shouldReconnect = false

    fun connect(sessionToken: String) {
        currentToken = sessionToken
        shouldReconnect = true
        reconnectAttempt = 0
        reconnectJob?.cancel()
        openSocket()
    }

    fun disconnect() {
        shouldReconnect = false
        reconnectJob?.cancel()
        webSocket?.close(1000, "client_disconnect")
        webSocket = null
        _state.value = State.Disconnected
    }

    fun shutdown() {
        disconnect()
    }

    private fun openSocket() {
        _state.value = State.Connecting
        val request = Request.Builder().url(url).build()
        webSocket = httpClient.newWebSocket(request, wsListener)
    }

    private val wsListener = object : WebSocketListener() {
        override fun onOpen(webSocket: WebSocket, response: Response) {
            Log.i(TAG, "socket open")
            _state.value = State.Authenticating
            val token = currentToken
            if (token == null) {
                webSocket.close(AUTH_CLOSE_CODE, "no_token")
                return
            }
            val authFrame = JSONObject().apply {
                put("type", "auth")
                put("session_token", token)
            }
            webSocket.send(authFrame.toString())
        }

        override fun onMessage(webSocket: WebSocket, text: String) {
            handleFrame(webSocket, text)
        }

        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
            webSocket.close(1000, null)
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            Log.i(TAG, "socket closed code=$code reason=$reason")
            handleClose(code)
        }

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            Log.w(TAG, "socket failure: ${t.message}")
            handleFailure()
        }
    }

    private fun handleFrame(ws: WebSocket, text: String) {
        val frame = try {
            JSONObject(text)
        } catch (e: Exception) {
            Log.w(TAG, "bad json frame", e)
            return
        }
        when (frame.optString("type")) {
            "auth_ok" -> {
                reconnectAttempt = 0
                _state.value = State.Ready
                Log.i(TAG, "authenticated")
            }
            "auth_fail" -> {
                shouldReconnect = false
                _state.value = State.Failed("auth_fail")
                Log.w(TAG, "auth rejected")
            }
            "revalidate" -> {
                val challengeJson = frame.optJSONObject("challenge") ?: return
                respondToRevalidate(ws, challengeJson)
            }
            "revalidate_ok" -> {
                Log.d(TAG, "revalidation ok")
            }
            "ping" -> {
                ws.send(JSONObject().put("type", "pong").toString())
            }
            "envelope" -> {
                val accepted = _envelopes.tryEmit(frame)
                if (!accepted) Log.w(TAG, "envelope buffer full; dropped")
            }
            "revoked" -> {
                shouldReconnect = false
                _state.value = State.Revoked
                Log.w(TAG, "device revoked")
            }
            else -> {
                Log.d(TAG, "unhandled frame type: ${frame.optString("type")}")
            }
        }
    }

    private fun respondToRevalidate(ws: WebSocket, challengeJson: JSONObject) {
        try {
            val challenge = Challenge(
                v = challengeJson.getInt("v"),
                purpose = challengeJson.getString("purpose"),
                challengeId = challengeJson.getString("challenge_id"),
                nonce = challengeJson.getString("nonce"),
                deviceId = challengeJson.getString("device_id"),
                sessionContext = if (challengeJson.isNull("session_context")) null
                    else challengeJson.getString("session_context"),
                issuedAt = challengeJson.getString("issued_at"),
                expiresAt = challengeJson.getString("expires_at"),
                serverId = challengeJson.getString("server_id"),
            )
            val canonicalBytes = CanonicalChallenge.encode(challenge)
            val keyManager = DeviceKeyManager(context = appContext)
            val signature = keyManager.sign(canonicalBytes)
            val signatureB64 = Base64.encodeToString(
                signature,
                Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
            )
            val response = JSONObject().apply {
                put("type", "revalidate_response")
                put("signature", signatureB64)
            }
            ws.send(response.toString())
        } catch (e: Exception) {
            Log.e(TAG, "revalidate signing failed", e)
            ws.close(AUTH_CLOSE_CODE, "revalidate_failed")
        }
    }

    private fun handleClose(code: Int) {
        webSocket = null
        when (code) {
            AUTH_CLOSE_CODE -> {
                shouldReconnect = false
                _state.value = State.Failed("session_expired")
            }
            REVOKED_CLOSE_CODE -> {
                shouldReconnect = false
                _state.value = State.Revoked
            }
            else -> {
                if (shouldReconnect) scheduleReconnect()
                else _state.value = State.Disconnected
            }
        }
    }

    private fun handleFailure() {
        webSocket = null
        if (shouldReconnect) scheduleReconnect()
        else _state.value = State.Disconnected
    }

    private fun scheduleReconnect() {
        reconnectJob?.cancel()
        reconnectJob = scope.launch {
            val delayMs = backoffMs(reconnectAttempt)
            reconnectAttempt++
            _state.value = State.Reconnecting
            Log.i(TAG, "reconnecting in ${delayMs}ms (attempt $reconnectAttempt)")
            delay(delayMs)
            if (shouldReconnect) openSocket()
        }
    }

    private fun backoffMs(attempt: Int): Long {
        val capped = attempt.coerceAtMost(5)
        val seconds = 1L shl capped
        return minOf(seconds, MAX_BACKOFF_SECONDS) * 1000L
    }
}
