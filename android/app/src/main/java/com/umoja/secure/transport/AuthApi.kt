package com.umoja.secure.transport

import com.umoja.secure.auth.Challenge
import org.json.JSONObject

data class SessionResponse(
    val sessionToken: String,
    val expiresAt: String,
    val deviceId: String,
    val role: String,
)

class AuthApi(private val http: HttpClient) {

    fun requestChallenge(deviceId: String): Challenge {
        val body = JSONObject().apply {
            put("device_id", deviceId)
            put("purpose", "auth")
        }.toString()

        val result = try {
            http.postJson("/auth/challenge", body)
        } catch (e: HttpException) {
            throw AuthApiException("network_error", e)
        }

        if (result.code != 200) {
            throw AuthApiException(errorCodeFrom(result), null, result.code)
        }

        return try {
            val ch = JSONObject(result.body).getJSONObject("challenge")
            Challenge(
                v = ch.getInt("v"),
                purpose = ch.getString("purpose"),
                challengeId = ch.getString("challenge_id"),
                nonce = ch.getString("nonce"),
                deviceId = ch.getString("device_id"),
                sessionContext = if (ch.isNull("session_context")) null
                    else ch.getString("session_context"),
                issuedAt = ch.getString("issued_at"),
                expiresAt = ch.getString("expires_at"),
                serverId = ch.getString("server_id"),
            )
        } catch (e: Exception) {
            throw AuthApiException("invalid_response", e)
        }
    }

    fun verify(challengeId: String, signatureB64Url: String): SessionResponse {
        val body = JSONObject().apply {
            put("challenge_id", challengeId)
            put("signature", signatureB64Url)
        }.toString()

        val result = try {
            http.postJson("/auth/verify", body)
        } catch (e: HttpException) {
            throw AuthApiException("network_error", e)
        }

        if (result.code != 200) {
            throw AuthApiException(errorCodeFrom(result), null, result.code)
        }

        return try {
            val json = JSONObject(result.body)
            SessionResponse(
                sessionToken = json.getString("session_token"),
                expiresAt = json.getString("expires_at"),
                deviceId = json.getString("device_id"),
                role = json.getString("role"),
            )
        } catch (e: Exception) {
            throw AuthApiException("invalid_response", e)
        }
    }

    /**
     * Revoke the current session on the backend.
     * Best-effort: network failures are swallowed (the caller has already
     * cleared local state and the backend session will expire on its own).
     */
    fun logout(sessionToken: String) {
        try {
            http.postJson("/auth/logout", "{}", bearer = sessionToken)
        } catch (_: Exception) {
            // Best-effort
        }
    }

    private fun errorCodeFrom(result: HttpResult): String = try {
        JSONObject(result.body).optString("error", "unknown_error")
    } catch (_: Exception) {
        "unknown_error"
    }
}

class AuthApiException(
    val code: String,
    cause: Throwable? = null,
    val httpCode: Int? = null,
) : Exception("auth failed: $code", cause)
