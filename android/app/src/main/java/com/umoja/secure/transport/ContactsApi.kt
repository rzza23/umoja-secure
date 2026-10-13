package com.umoja.secure.transport

import org.json.JSONObject

data class ContactEntry(
    val peerDeviceId: String,
    val peerLabel: String,
    val verificationLevel: String,
    val authorizedAt: String,
)

class ContactsApi(private val http: HttpClient) {

    /**
     * Fetch the authorized contacts for the current device.
     * The backend returns only pairs where both directions are active,
     * so this list is the enforced view. The client uses it to
     * populate the Contacts screen and to gate sending.
     */
    fun list(sessionToken: String): List<ContactEntry> {
        val result = try {
            http.get("/me/contacts", bearer = sessionToken)
        } catch (e: HttpException) {
            throw ContactsApiException("network_error", e)
        }
        if (result.code != 200) {
            throw ContactsApiException(errorCodeFrom(result), null, result.code)
        }
        return try {
            val root = JSONObject(result.body)
            val arr = root.getJSONArray("contacts")
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                ContactEntry(
                    peerDeviceId = o.getString("peer_device_id"),
                    peerLabel = o.getString("peer_label"),
                    verificationLevel = o.optString("verification_level", "directory"),
                    authorizedAt = o.optString("authorized_at", ""),
                )
            }
        } catch (e: Exception) {
            throw ContactsApiException("invalid_response", e)
        }
    }

    private fun errorCodeFrom(result: HttpResult): String = try {
        JSONObject(result.body).optString("error", "unknown_error")
    } catch (_: Exception) {
        "unknown_error"
    }
}

class ContactsApiException(
    val code: String,
    cause: Throwable? = null,
    val httpCode: Int? = null,
) : Exception("contacts api failed: $code", cause)
