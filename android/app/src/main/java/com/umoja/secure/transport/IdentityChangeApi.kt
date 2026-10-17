package com.umoja.secure.transport

import org.json.JSONObject

/**
 * Identity-change API client.
 *
 * Wraps the peer-facing identity-change endpoints. All requests go
 * through the same HttpClient the rest of the app uses, so they
 * inherit Tor transport in production and SOCKS routing in dev.
 *
 * Error taxonomy mirrors [AdminApi] and [ContactsApi]:
 *   - `network_error` — transport failure (DNS, SOCKS, timeout)
 *   - `{error_code_from_json}` — the server's `error` field, verbatim
 *   - `invalid_response` — 2xx but the body did not parse as expected
 *
 * Caller is responsible for the session token being valid; the backend
 * enforces role and org scoping.
 *
 * Scope note — this client does not call `POST /identity-change-notices`
 * (admin-side only, no consumer in 030e-c) or `GET /identity-change-acks/
 * :notice_hash` (peer-ack visibility lands with the 030e-d UI). Adding
 * those before a consumer exists would be speculative surface.
 *
 * Task: TASK-P1-030 030e-c 3b
 * ADR: ADR-IDENTITY-CHANGE-001 §7
 */
class IdentityChangeApi(private val http: HttpClient) {

    data class RemoteNotice(
        val noticeHash: String,
        val canonicalUtf8: String,
        val signatureBase64url: String,
        val fromDeviceId: String,
        val toDeviceId: String,
        val createdAt: String,
    )

    data class AckResponse(
        val ackHash: String,
        val createdAt: String,
    )

    /**
     * GET /identity-change-notices.
     *
     * Returns up to 500 most recent notices in the caller's org.
     * Backend does not filter by `permitted_contacts` (ADR §5 Option C);
     * the caller filters locally by its accepted matrix.
     */
    fun getNotices(sessionToken: String): List<RemoteNotice> {
        val result = try {
            http.get("/identity-change-notices", bearer = sessionToken)
        } catch (e: HttpException) {
            throw IdentityChangeApiException("network_error", e)
        }
        if (result.code != 200) {
            throw IdentityChangeApiException(errorCodeFrom(result), null, result.code)
        }
        return try {
            val arr = JSONObject(result.body).getJSONArray("notices")
            (0 until arr.length()).map { i ->
                val n = arr.getJSONObject(i)
                RemoteNotice(
                    noticeHash = n.getString("notice_hash"),
                    canonicalUtf8 = n.getString("canonical_utf8"),
                    signatureBase64url = n.getString("signature_base64url"),
                    fromDeviceId = n.getString("from_device_id"),
                    toDeviceId = n.getString("to_device_id"),
                    createdAt = n.getString("created_at"),
                )
            }
        } catch (e: Exception) {
            throw IdentityChangeApiException("invalid_response", e)
        }
    }

    /**
     * POST /identity-change-acks.
     *
     * Body: `{canonical_utf8, signature_base64url}` — the signed ack
     * wrapper and its signature. Backend verifies the signature against
     * the acking device's auth key before storing (ADR §4); a bad
     * signature returns 400 `invalid_signature`.
     *
     * Response 201: `{ack_hash, created_at}`.
     */
    fun postAck(
        canonicalUtf8: String,
        signatureBase64url: String,
        sessionToken: String,
    ): AckResponse {
        val body = JSONObject().apply {
            put("canonical_utf8", canonicalUtf8)
            put("signature_base64url", signatureBase64url)
        }.toString()

        val result = try {
            http.postJson("/identity-change-acks", body, bearer = sessionToken)
        } catch (e: HttpException) {
            throw IdentityChangeApiException("network_error", e)
        }
        if (result.code != 201) {
            throw IdentityChangeApiException(errorCodeFrom(result), null, result.code)
        }
        return try {
            val json = JSONObject(result.body)
            AckResponse(
                ackHash = json.getString("ack_hash"),
                createdAt = json.getString("created_at"),
            )
        } catch (e: Exception) {
            throw IdentityChangeApiException("invalid_response", e)
        }
    }

    private fun errorCodeFrom(result: HttpResult): String = try {
        JSONObject(result.body).optString("error", "unknown_error")
    } catch (_: Exception) {
        "unknown_error"
    }
}

class IdentityChangeApiException(
    val code: String,
    cause: Throwable? = null,
    val httpCode: Int? = null,
) : Exception("identity-change api failed: $code", cause)
