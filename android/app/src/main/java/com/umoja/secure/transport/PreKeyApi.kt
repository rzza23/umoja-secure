package com.umoja.secure.transport

import org.json.JSONArray
import org.json.JSONObject

data class PreKeyUploadRequest(
    val identityKeyB64: String,
    val signedPreKeyId: Int,
    val signedPreKeyPublicB64: String,
    val signedPreKeySignatureB64: String,
    val registrationId: Int,
    val oneTimePreKeys: List<OneTimePreKeyEntry>,
)

data class OneTimePreKeyEntry(
    val id: Int,
    val publicKeyB64: String,
)

data class PreKeyUploadResponse(
    val storedPrekeys: Int,
    val totalUnconsumed: Int,
)

data class PreKeyStatusResponse(
    val hasBundle: Boolean,
    val unconsumedPrekeys: Int,
    val signedPrekeyId: Int?,
    val updatedAt: String?,
)

data class PeerPreKeyBundle(
    val deviceId: String,
    val identityKeyB64: String,
    val signedPreKeyId: Int,
    val signedPreKeyPublicB64: String,
    val signedPreKeySignatureB64: String,
    val registrationId: Int,
    val oneTimePreKeyId: Int?,
    val oneTimePreKeyPublicB64: String?,
)

class PreKeyApi(private val http: HttpClient) {

    fun upload(request: PreKeyUploadRequest, sessionToken: String): PreKeyUploadResponse {
        val oneTimeArray = JSONArray()
        request.oneTimePreKeys.forEach { otp ->
            oneTimeArray.put(JSONObject().apply {
                put("id", otp.id)
                put("public_key", otp.publicKeyB64)
            })
        }

        val body = JSONObject().apply {
            put("identity_key", request.identityKeyB64)
            put("signed_prekey_id", request.signedPreKeyId)
            put("signed_prekey_public", request.signedPreKeyPublicB64)
            put("signed_prekey_signature", request.signedPreKeySignatureB64)
            put("registration_id", request.registrationId)
            put("one_time_prekeys", oneTimeArray)
        }.toString()

        val result = try {
            http.postJson("/prekeys", body, bearer = sessionToken)
        } catch (e: HttpException) {
            throw PreKeyApiException("network_error", e)
        }

        if (result.code != 200) {
            throw PreKeyApiException(errorCodeFrom(result), null, result.code)
        }

        return try {
            val json = JSONObject(result.body)
            PreKeyUploadResponse(
                storedPrekeys = json.getInt("stored_prekeys"),
                totalUnconsumed = json.getInt("total_unconsumed"),
            )
        } catch (e: Exception) {
            throw PreKeyApiException("invalid_response", e)
        }
    }

    fun status(sessionToken: String): PreKeyStatusResponse {
        val result = try {
            http.get("/prekeys/status", bearer = sessionToken)
        } catch (e: HttpException) {
            throw PreKeyApiException("network_error", e)
        }

        if (result.code != 200) {
            throw PreKeyApiException(errorCodeFrom(result), null, result.code)
        }

        return try {
            val json = JSONObject(result.body)
            PreKeyStatusResponse(
                hasBundle = json.getBoolean("has_bundle"),
                unconsumedPrekeys = json.getInt("unconsumed_prekeys"),
                signedPrekeyId = if (json.isNull("signed_prekey_id")) null
                    else json.getInt("signed_prekey_id"),
                updatedAt = if (json.isNull("updated_at")) null
                    else json.getString("updated_at"),
            )
        } catch (e: Exception) {
            throw PreKeyApiException("invalid_response", e)
        }
    }

    private fun errorCodeFrom(result: HttpResult): String = try {
        JSONObject(result.body).optString("error", "unknown_error")
    } catch (_: Exception) {
        "unknown_error"
    }
}

class PreKeyApiException(
    val code: String,
    cause: Throwable? = null,
    val httpCode: Int? = null,
) : Exception("prekey api failed: $code", cause)
