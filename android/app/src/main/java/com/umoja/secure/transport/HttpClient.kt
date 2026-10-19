package com.umoja.secure.transport

import android.util.Log
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit

/**
 * HTTP client wrapper for talking to the Umoja backend.
 *
 * Tor mode: instead of asking OkHttp to use SOCKS directly (which
 * resolves hostnames locally and breaks .onion), we start a local
 * HTTP-to-SOCKS5 bridge and point OkHttp at it with Proxy.Type.HTTP.
 * The bridge sees the request in absolute-URI form, extracts the
 * hostname, and dials SOCKS5 with ATYP=0x03 so Tor handles the .onion
 * resolution.
 *
 * Clearnet mode: no proxy, plain HTTP to 127.0.0.1:8080 via adb reverse.
 */
class HttpClient(baseUrl: String) {

    companion object {
        private const val TAG = "UmojaHttp"

        val DEV_BASE_URL: String get() = TransportConfig.httpBaseUrl

        private val JSON = "application/json; charset=utf-8".toMediaType()

        private const val CONNECT_TIMEOUT_SECONDS = 90L
        private const val READ_TIMEOUT_SECONDS = 90L
        private const val WRITE_TIMEOUT_SECONDS = 90L

        /**
         * Invoked on any 401 from a non-auth-free path. Returns the
         * fresh bearer token to retry with, or null for terminal
         * failure (reauth rejected, network failure, enrollment
         * required). See [shouldRetryAfter401] and [executeWithRetry].
         *
         * **Companion-scoped, not constructor-injected** -- 13
         * HttpClient construction sites exist today, most of them
         * pre-existing and outside 040-D's scope. Constructor
         * injection would ripple through all of them for no gain:
         * the handler is a singleton concern (at most one session
         * state machine exists at a time; AppRoot's
         * remember(deviceId) is the sole owner). [@Volatile] for
         * cross-thread visibility: setter runs on Main (AppRoot's
         * DisposableEffect), reader runs on whatever dispatcher the
         * API call used.
         *
         * Auth-free paths (`/auth/` prefix, `/enrollment`) skip the handler
         * entirely via [shouldRetryAfter401] -- this is the ADR §2
         * recursion guard, structural rather than flag-based.
         *
         * Set/cleared by AppRoot's DisposableEffect(sessionStateManager).
         * A de-composed AppRoot clears the handler so a stale lambda
         * cannot retain the state manager across composition cycles.
         *
         * TASK-P1-040-D, ADR-HARDENING-001 §2 "Retry-the-original-call".
         */
        @Volatile
        var on401Handler: (suspend () -> String?)? = null
    }

    private val baseUrl: String = baseUrl.trimEnd('/')
    private val client: OkHttpClient = buildClient()

    private fun buildClient(): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .connectTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(READ_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .writeTimeout(WRITE_TIMEOUT_SECONDS, TimeUnit.SECONDS)

        if (TransportConfig.useTor) {
            val bridgePort = Socks5Bridge.start()
            builder.proxy(
                Proxy(
                    Proxy.Type.HTTP,
                    InetSocketAddress("127.0.0.1", bridgePort),
                ),
            )
            // Each request should get a fresh SOCKS session. Pooling
            // doesn't help behind Tor anyway (latency dominates).
            builder.connectionPool(okhttp3.ConnectionPool(0, 1, TimeUnit.MILLISECONDS))
            Log.i(TAG, "Tor mode: routing via HTTP bridge 127.0.0.1:$bridgePort")
        }

        return builder.build()
    }

    suspend fun postJson(path: String, body: String, bearer: String? = null): HttpResult {
        val request = Request.Builder()
            .url(baseUrl + path)
            .post(body.toRequestBody(JSON))
            .apply { if (bearer != null) header("Authorization", "Bearer $bearer") }
            .build()
        return execute(request)
    }

    suspend fun get(path: String, bearer: String? = null): HttpResult {
        val request = Request.Builder()
            .url(baseUrl + path)
            .get()
            .apply { if (bearer != null) header("Authorization", "Bearer $bearer") }
            .build()
        return execute(request)
    }

    private suspend fun execute(request: Request): HttpResult =
        executeWithRetry(request, retryDepth = 0)

    /**
     * Synchronous execute with one 401 retry. See [shouldRetryAfter401]
     * for the predicate. The retry re-issues the *same* request shape
     * with a **fresh** bearer from the handler -- a key design point
     * the ADR does not specify. Without the fresh bearer, the retry
     * re-sends the pre-reauth token and hits 401 again (the state
     * machine's reauth wrote a new token to storage; the buffered
     * request still carries the old one).
     *
     * **Suspend surface (Phase 2 completed).** [execute] is `suspend fun`.
     * Every API class (AdminApi, ContactsApi, IdentityChangeApi,
     * EnvelopeApi, PreKeyApi, MatrixApi) is `suspend`; the
     * IdentityChangeController lambda params are `suspend`. Their callers
     * were already in suspend contexts (`withContext(Dispatchers.IO)` at
     * API boundaries, `LaunchedEffect`, `scope.launch`), so **zero caller
     * changes were needed**. The handler is invoked directly -- no
     * `runBlocking` bridge. The single-point bridge was the honest Phase 1
     * trade-off (040-D KDoc, superseded); Phase 2 removed it by making
     * the entire HTTP surface suspend.
     *
     * **Dispatcher discipline unchanged.** `suspend fun` does not imply
     * IO dispatch. Callers MUST dispatch to IO before calling -- a caller
     * on Main will throw `NetworkOnMainThreadException` from OkHttp
     * *before* reaching the interceptor. All current callers satisfy
     * this; future callers must too.
     *
     * Verified by: `HttpClientRetryTest` (7 tests, `shouldRetryAfter401`
     * unchanged predicate), full JVM suite, androidTest per emulator.
     */
    private suspend fun executeWithRetry(request: Request, retryDepth: Int): HttpResult {
        val result = try {
            client.newCall(request).execute().use { response ->
                HttpResult(
                    code = response.code,
                    body = response.body?.string() ?: "",
                )
            }
        } catch (e: IOException) {
            Log.e(
                TAG,
                "HTTP ${request.method} ${request.url} failed: " +
                    "${e.javaClass.simpleName}: ${e.message}",
                e,
            )
            throw HttpException("network_error", e)
        }

        val handler = on401Handler
        val path = request.url.encodedPath
        if (retryDepth == 0 && shouldRetryAfter401(path, result.code, handler != null)) {
            val freshBearer = try {
                handler!!.invoke()
            } catch (e: Exception) {
                Log.e(
                    TAG,
                    "on401 handler threw: ${e.javaClass.simpleName}: ${e.message}",
                    e,
                )
                null
            }
            if (freshBearer != null) {
                Log.i(TAG, "401 on $path; reauth succeeded, retrying once with fresh bearer")
                val retried = request.newBuilder()
                    .header("Authorization", "Bearer $freshBearer")
                    .build()
                return executeWithRetry(retried, retryDepth = 1)
            }
            Log.w(TAG, "401 on $path; reauth failed or terminal, returning 401 to caller")
        }

        return result
    }
}

/**
 * Pure predicate for the interceptor's retry decision. Extracted
 * from [HttpClient.executeWithRetry] so the decision logic is
 * JVM-testable without mocking OkHttp (which would require
 * okhttp3-mockwebserver on the classpath -- not currently present,
 * and adding it would be scope creep for 040-D).
 *
 * Returns true iff the response is 401 AND a handler is registered
 * AND the path is not auth-free. Auth-free = `/auth/` prefix (challenge,
 * verify, logout) or `/enrollment` (pre-auth; a 401 here means an
 * invalid enrollment token, not a stale session).
 *
 * The retry-with-fresh-bearer flow itself (challenge -> verify ->
 * retry) is verified at the emulator layer; see TASK-P1-040-E.
 */
internal fun shouldRetryAfter401(path: String, code: Int, hasHandler: Boolean): Boolean =
    code == 401 &&
    hasHandler &&
    !path.startsWith("/auth/") &&
    !path.startsWith("/enrollment")

data class HttpResult(val code: Int, val body: String)

class HttpException(message: String, cause: Throwable? = null) :
    Exception(message, cause)
