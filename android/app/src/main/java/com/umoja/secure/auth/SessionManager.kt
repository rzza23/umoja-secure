package com.umoja.secure.auth

import android.content.Context
import android.util.Base64
import android.util.Log
import com.umoja.secure.crypto.DeviceKeyManager
import com.umoja.secure.storage.SecureStorage
import com.umoja.secure.transport.AuthApi
import com.umoja.secure.transport.AuthApiException
import com.umoja.secure.transport.HttpClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Orchestrates the full authentication flow:
 *   1. Read device_id from encrypted storage.
 *   2. Request a challenge from the backend.
 *   3. Canonicalize the challenge and sign it with the device key.
 *   4. Submit the signature to the backend.
 *   5. Store the returned session token (encrypted at rest).
 *
 * All network work runs on Dispatchers.IO.
 */
class SessionManager(private val context: Context) {

    companion object {
        private const val TAG = "UmojaAuth"
    }

    sealed class AuthOutcome {
        data class Success(
            val sessionToken: String,
            val expiresAt: String,
            val role: String,
        ) : AuthOutcome()

        data class Failure(val code: String) : AuthOutcome()
        object NotEnrolled : AuthOutcome()
    }

    suspend fun authenticate(): AuthOutcome = withContext(Dispatchers.IO) {
        val storage = SecureStorage(context)
        val deviceId = storage.get("device_id")
            ?: return@withContext AuthOutcome.NotEnrolled

        try {
            val keyManager = DeviceKeyManager(context = context)
            if (!keyManager.hasKey()) {
                return@withContext AuthOutcome.Failure("device_key_missing")
            }

            val http = HttpClient(HttpClient.DEV_BASE_URL)
            val api = AuthApi(http)

            val challenge = api.requestChallenge(deviceId)
            val canonicalBytes = CanonicalChallenge.encode(challenge)
            val signature = keyManager.sign(canonicalBytes)
            val signatureB64Url = Base64.encodeToString(
                signature,
                Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
            )

            val session = api.verify(challenge.challengeId, signatureB64Url)

            storage.put("session_token", session.sessionToken)
            storage.put("session_expires_at", session.expiresAt)
            storage.put("session_role", session.role)

            AuthOutcome.Success(
                sessionToken = session.sessionToken,
                expiresAt = session.expiresAt,
                role = session.role,
            )
        } catch (e: AuthApiException) {
            Log.e(TAG, "AuthApiException: ${e.code}", e)
            AuthOutcome.Failure(e.code)
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected exception during auth", e)
            AuthOutcome.Failure("unexpected_error")
        }
    }

    fun currentSession(): StoredSession? {
        val storage = SecureStorage(context)
        val token = storage.get("session_token") ?: return null
        val expiresAt = storage.get("session_expires_at") ?: return null
        val role = storage.get("session_role") ?: return null
        return StoredSession(token, expiresAt, role)
    }

    /**
     * Revoke the session on the backend (best-effort), then clear local state.
     * If the backend is unreachable, local state is still cleared — the
     * backend session will expire on its own.
     */
    suspend fun clearSession() = withContext(Dispatchers.IO) {
        val storage = SecureStorage(context)
        val token = storage.get("session_token")
        if (token != null) {
            val http = HttpClient(HttpClient.DEV_BASE_URL)
            val api = AuthApi(http)
            api.logout(token)
        }
        storage.remove("session_token")
        storage.remove("session_expires_at")
        storage.remove("session_role")
    }
}

data class StoredSession(
    val sessionToken: String,
    val expiresAt: String,
    val role: String,
)
