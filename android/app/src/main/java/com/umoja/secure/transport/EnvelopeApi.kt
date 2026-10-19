package com.umoja.secure.transport

import org.json.JSONArray
import org.json.JSONObject

data class EnvelopeSubmitResponse(
    val envelopeId: String,
    val expiresAt: String,
)

data class PendingEnvelope(
    val envelopeId: String,
    val senderDeviceId: String,
    val envelopeType: String,
    val createdAt: String,
    val expiresAt: String,
)

data class EnvelopeBody(
    val envelopeId: String,
    val senderDeviceId: String,
    val envelopeType: String,
    val ciphertext: String,
    val createdAt: String,
)

class EnvelopeApi(private val http: HttpClient) {

    suspend fun submit(
        recipientDeviceId: String,
        ciphertextB64: String,
        sessionToken: String,
        envelopeType: String = "message",
    ): EnvelopeSubmitResponse {
        val body = JSONObject().apply {
            put("recipient_device_id", recipientDeviceId)
            put("ciphertext", ciphertextB64)
            put("envelope_type", envelopeType)
        }.toString()

        val result = try {
            http.postJson("/envelopes", body, bearer = sessionToken)
        } catch (e: HttpException) {
            throw EnvelopeApiException("network_error", e)
        }

        if (result.code != 201) {
            throw EnvelopeApiException(errorCodeFrom(result), null, result.code)
        }

        return try {
            val json = JSONObject(result.body)
            EnvelopeSubmitResponse(
                envelopeId = json.getString("envelope_id"),
                expiresAt = json.getString("expires_at"),
            )
        } catch (e: Exception) {
            throw EnvelopeApiException("invalid_response", e)
        }
    }

    suspend fun listPending(sessionToken: String): List<PendingEnvelope> {
        val result = try {
            http.get("/envelopes/pending", bearer = sessionToken)
        } catch (e: HttpException) {
            throw EnvelopeApiException("network_error", e)
        }

        if (result.code != 200) {
            throw EnvelopeApiException(errorCodeFrom(result), null, result.code)
        }

        return try {
            val arr = JSONObject(result.body).getJSONArray("envelopes")
            (0 until arr.length()).map { i ->
                val item = arr.getJSONObject(i)
                PendingEnvelope(
                    envelopeId = item.getString("envelope_id"),
                    senderDeviceId = item.getString("sender_device_id"),
                    envelopeType = item.getString("envelope_type"),
                    createdAt = item.getString("created_at"),
                    expiresAt = item.getString("expires_at"),
                )
            }
        } catch (e: Exception) {
            throw EnvelopeApiException("invalid_response", e)
        }
    }

    suspend fun fetch(envelopeId: String, sessionToken: String): EnvelopeBody {
        val result = try {
            http.get("/envelopes/$envelopeId", bearer = sessionToken)
        } catch (e: HttpException) {
            throw EnvelopeApiException("network_error", e)
        }

        if (result.code != 200) {
            throw EnvelopeApiException(errorCodeFrom(result), null, result.code)
        }

        return try {
            val json = JSONObject(result.body)
            EnvelopeBody(
                envelopeId = json.getString("envelope_id"),
                senderDeviceId = json.getString("sender_device_id"),
                envelopeType = json.getString("envelope_type"),
                ciphertext = json.getString("ciphertext"),
                createdAt = json.getString("created_at"),
            )
        } catch (e: Exception) {
            throw EnvelopeApiException("invalid_response", e)
        }
    }

    suspend fun ack(envelopeId: String, sessionToken: String) {
        try {
            http.postJson("/envelopes/$envelopeId/ack", "{}", bearer = sessionToken)
        } catch (_: Exception) {
            // Best-effort: envelope will remain 'delivered' if ack fails.
            // Client may re-ack on next poll; server is idempotent.
        }
    }

    private fun errorCodeFrom(result: HttpResult): String = try {
        JSONObject(result.body).optString("error", "unknown_error")
    } catch (_: Exception) {
        "unknown_error"
    }
}

class EnvelopeApiException(
    val code: String,
    cause: Throwable? = null,
    val httpCode: Int? = null,
) : Exception("envelope api failed: $code", cause)
