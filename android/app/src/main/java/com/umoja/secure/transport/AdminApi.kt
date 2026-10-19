package com.umoja.secure.transport

import org.json.JSONArray
import org.json.JSONObject

/**
 * Admin API client.
 *
 * Wraps the admin endpoints under /admin. The caller is responsible for ensuring the
 * session belongs to a device with role owner or admin; the backend also
 * enforces this and returns 403 otherwise.
 *
 * All requests go through the same HttpClient the rest of the app uses,
 * so they inherit Tor transport in production and SOCKS routing in dev.
 */
class AdminApi(private val http: HttpClient) {

    // ============================================================
    // Enrollment tokens
    // ============================================================

    data class CreateTokenRequest(
        val role: String,           // owner | admin | user | auditor
        val boundPublicKey: String, // base64url 32B, from the scanned device QR
        val ttlSeconds: Int = 86400,
        val labelHint: String? = null,
    )

    data class CreatedToken(
        val tokenId: String,
        val token: String,          // only present in create response
        val expiresAt: String,
    )

    suspend fun createEnrollmentToken(
        req: CreateTokenRequest,
        sessionToken: String,
    ): CreatedToken {
        val body = JSONObject().apply {
            put("role", req.role)
            put("bound_public_key", req.boundPublicKey)
            put("ttl_seconds", req.ttlSeconds)
            if (req.labelHint != null) put("label_hint", req.labelHint)
        }.toString()

        val result = try {
            http.postJson("/admin/enrollment-tokens", body, bearer = sessionToken)
        } catch (e: HttpException) {
            throw AdminApiException("network_error", e)
        }
        if (result.code != 201) {
            throw AdminApiException(errorCodeFrom(result), null, result.code)
        }
        return try {
            val json = JSONObject(result.body)
            CreatedToken(
                tokenId = json.getString("token_id"),
                token = json.getString("token"),
                expiresAt = json.getString("expires_at"),
            )
        } catch (e: Exception) {
            throw AdminApiException("invalid_response", e)
        }
    }

    // ============================================================
    // Devices
    // ============================================================

    data class DeviceEntry(
        val deviceId: String,
        val label: String,
        val role: String,
        val status: String,
        val enrolledAt: String,
        val lastSeenAt: String?,
        val revokedAt: String?,
    )

    suspend fun listDevices(sessionToken: String): List<DeviceEntry> {
        val result = try {
            http.get("/admin/devices", bearer = sessionToken)
        } catch (e: HttpException) {
            throw AdminApiException("network_error", e)
        }
        if (result.code != 200) {
            throw AdminApiException(errorCodeFrom(result), null, result.code)
        }
        return try {
            val arr = JSONObject(result.body).getJSONArray("devices")
            (0 until arr.length()).map { i ->
                val d = arr.getJSONObject(i)
                DeviceEntry(
                    deviceId = d.getString("device_id"),
                    label = d.getString("label"),
                    role = d.getString("role"),
                    status = d.getString("status"),
                    enrolledAt = d.getString("enrolled_at"),
                    lastSeenAt = if (d.isNull("last_seen_at")) null else d.getString("last_seen_at"),
                    revokedAt = if (d.isNull("revoked_at")) null else d.getString("revoked_at"),
                )
            }
        } catch (e: Exception) {
            throw AdminApiException("invalid_response", e)
        }
    }

    suspend fun revokeDevice(deviceId: String, reason: String, sessionToken: String) {
        val body = JSONObject().put("reason", reason).toString()
        val result = try {
            http.postJson("/admin/devices/$deviceId/revoke", body, bearer = sessionToken)
        } catch (e: HttpException) {
            throw AdminApiException("network_error", e)
        }
        if (result.code != 204) {
            throw AdminApiException(errorCodeFrom(result), null, result.code)
        }
    }

    // ============================================================
    // Contacts
    // ============================================================

    data class ContactEntry(
        val ownerDeviceId: String,
        val contactDeviceId: String,
        val ownerLabel: String,
        val contactLabel: String,
        val status: String,
        val verificationLevel: String,
        val authorizedAt: String,
        val revokedAt: String?,
    )

    suspend fun listContacts(sessionToken: String): List<ContactEntry> {
        val result = try {
            http.get("/admin/contacts", bearer = sessionToken)
        } catch (e: HttpException) {
            throw AdminApiException("network_error", e)
        }
        if (result.code != 200) {
            throw AdminApiException(errorCodeFrom(result), null, result.code)
        }
        return try {
            val arr = JSONObject(result.body).getJSONArray("contacts")
            (0 until arr.length()).map { i ->
                val c = arr.getJSONObject(i)
                ContactEntry(
                    ownerDeviceId = c.getString("owner_device_id"),
                    contactDeviceId = c.getString("contact_device_id"),
                    ownerLabel = c.getString("owner_label"),
                    contactLabel = c.getString("contact_label"),
                    status = c.getString("status"),
                    verificationLevel = c.getString("verification_level"),
                    authorizedAt = c.getString("authorized_at"),
                    revokedAt = if (c.isNull("revoked_at")) null else c.getString("revoked_at"),
                )
            }
        } catch (e: Exception) {
            throw AdminApiException("invalid_response", e)
        }
    }

    suspend fun authorizeContact(
        ownerDeviceId: String,
        contactDeviceId: String,
        sessionToken: String,
        verificationLevel: String = "directory",
    ) {
        val body = JSONObject().apply {
            put("owner_device_id", ownerDeviceId)
            put("contact_device_id", contactDeviceId)
            put("verification_level", verificationLevel)
        }.toString()
        val result = try {
            http.postJson("/admin/contacts", body, bearer = sessionToken)
        } catch (e: HttpException) {
            throw AdminApiException("network_error", e)
        }
        if (result.code != 204) {
            throw AdminApiException(errorCodeFrom(result), null, result.code)
        }
    }

    suspend fun revokeContact(
        ownerDeviceId: String,
        contactDeviceId: String,
        reason: String,
        sessionToken: String,
    ) {
        val body = JSONObject().put("reason", reason).toString()
        val result = try {
            http.postJson(
                "/admin/contacts/$ownerDeviceId/$contactDeviceId/revoke",
                body,
                bearer = sessionToken,
            )
        } catch (e: HttpException) {
            throw AdminApiException("network_error", e)
        }
        if (result.code != 204) {
            throw AdminApiException(errorCodeFrom(result), null, result.code)
        }
    }

    // ============================================================
    // Helpers
    // ============================================================

    private fun errorCodeFrom(result: HttpResult): String = try {
        JSONObject(result.body).optString("error", "unknown_error")
    } catch (_: Exception) {
        "unknown_error"
    }
}

class AdminApiException(
    val code: String,
    cause: Throwable? = null,
    val httpCode: Int? = null,
) : Exception("admin api failed: $code", cause)
