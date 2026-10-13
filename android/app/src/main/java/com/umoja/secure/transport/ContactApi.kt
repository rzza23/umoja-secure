package com.umoja.secure.transport

import org.json.JSONObject

/**
 * Fetches the authorized contact list for the current device.
 * The backend enforces that this device is authenticated and active.
 */
class ContactApi(private val http: HttpClient) {

    data class Contact(
        val deviceId: String,
        val label: String,
        val verificationLevel: String,
        val authorizedAt: String,
    )

    fun listMyContacts(sessionToken: String): List<Contact> {
        val result = try {
            http.get("/contacts", bearer = sessionToken)
        } catch (e: HttpException) {
            throw ContactApiException("network_error", e)
        }
        if (result.code != 200) {
            throw ContactApiException(errorCodeFrom(result), null, result.code)
        }
        return try {
            val arr = JSONObject(result.body).getJSONArray("contacts")
            (0 until arr.length()).map { i ->
                val c = arr.getJSONObject(i)
                Contact(
                    deviceId = c.getString("device_id"),
                    label = c.getString("label"),
                    verificationLevel = c.getString("verification_level"),
                    authorizedAt = c.getString("authorized_at"),
                )
            }
        } catch (e: Exception) {
            throw ContactApiException("invalid_response", e)
        }
    }

    private fun errorCodeFrom(result: HttpResult): String = try {
        JSONObject(result.body).optString("error", "unknown_error")
    } catch (_: Exception) {
        "unknown_error"
    }
}

class ContactApiException(
    val code: String,
    cause: Throwable? = null,
    val httpCode: Int? = null,
) : Exception("contacts api failed: $code", cause)
