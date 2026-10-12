package com.umoja.secure.transport

import org.json.JSONArray
import org.json.JSONObject

data class PreKeyUploadRequest(
    val identityKeyB64: String,
    val signedPreKeyId: Int,
    val signedPreKeyPublicB64: String,
    val signedPreKeySignatureB64: String,
    val registrationId: Int,
    val kyberPreKeyId: Int,
    val kyberPreKeyPublicB64: String,
    val kyberPreKeySignatureB64: String,
    val oneTimePreKeys: List<OneTimePreKeyEntry>,
    val oneTimeKyberPreKeys: List<OneTimePreKeyEntry>,
)

data class OneTimePreKeyEntry(
    val id: Int,
    val publicKeyB64: String,
)

data class PreKeyUploadResponse(
    val storedPrekeys: Int,
    val totalUnconsumed: Int,
    val storedKyberPrekeys: Int,
    val totalKyberUnconsumed: Int,
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
    val kyberPreKeyId: Int,
    val kyberPreKeyPublicB64: String,
    val kyberPreKeySignatureB64: String,
    val oneTimePreKeyId: Int?,
    val oneTimePreKeyPublicB64: String?,
    val oneTimeKyberPreKeyId: Int?,
    val oneTimeKyberPreKeyPublicB64: String?,
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

        val oneTimeKyberArray = JSONArray()
        request.oneTimeKyberPreKeys.forEach { otp ->
            oneTimeKyberArray.put(JSONObject().apply {
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
            put("kyber_prekey_id", request.kyberPreKeyId)
            put("kyber_prekey_public", request.kyberPreKeyPublicB64)
            put("kyber_prekey_signature", request.kyberPreKeySignatureB64)
            put("one_time_prekeys", oneTimeArray)
            put("one_time_kyber_prekeys", oneTimeKyberArray)
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
                storedKyberPrekeys = json.optInt("stored_kyber_prekeys", 0),
                totalKyberUnconsumed = json.optInt("total_kyber_unconsumed", 0),
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

    fun fetchBundle(deviceId: String, sessionToken: String): PeerPreKeyBundle {
        val result = try {
            http.get("/prekeys/$deviceId", bearer = sessionToken)
        } catch (e: HttpException) {
            throw PreKeyApiException("network_error", e)
        }

        if (result.code != 200) {
            throw PreKeyApiException(errorCodeFrom(result), null, result.code)
        }

        return try {
            val json = JSONObject(result.body)
            PeerPreKeyBundle(
                deviceId = json.getString("device_id"),
                identityKeyB64 = json.getString("identity_key"),
                signedPreKeyId = json.getInt("signed_prekey_id"),
                signedPreKeyPublicB64 = json.getString("signed_prekey_public"),
                signedPreKeySignatureB64 = json.getString("signed_prekey_signature"),
                registrationId = json.getInt("registration_id"),
                kyberPreKeyId = json.getInt("kyber_prekey_id"),
                kyberPreKeyPublicB64 = json.getString("kyber_prekey_public"),
                kyberPreKeySignatureB64 = json.getString("kyber_prekey_signature"),
                oneTimePreKeyId = json.optJSONObject("one_time_prekey")?.getInt("id"),
                oneTimePreKeyPublicB64 = json.optJSONObject("one_time_prekey")?.getString("public_key"),
                oneTimeKyberPreKeyId = json.optJSONObject("one_time_kyber_prekey")?.getInt("id"),
                oneTimeKyberPreKeyPublicB64 = json.optJSONObject("one_time_kyber_prekey")?.getString("public_key"),
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
