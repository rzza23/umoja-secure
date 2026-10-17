package com.umoja.secure.transport

import org.json.JSONObject

/**
 * Matrix transport client.
 *
 * Fetches the current signed authorization matrix for the caller's
 * device from GET /me/matrix. Backend relays the bytes verbatim (no
 * provisioning-signature verification, server-blind per
 * ADR-PROVISIONING-001 §2 Q3); the caller verifies on receipt against
 * the pinned provisioning key before calling MatrixStore.accept.
 *
 * **Lambda injection over interface extraction.** Takes
 * `fetchFn: (String) -> HttpResult` instead of HttpClient directly.
 * Same pattern as IdentityChangeController (dde60f2's KDoc "API
 * injected as two lambdas, not a concrete IdentityChangeApi...
 * avoids extracting an interface from a just-shipped final class for
 * testability"). HttpClient is final; introducing MatrixTransport
 * would be the codebase diverging from itself. If a future refactor
 * consolidates the seam, both sites move together.
 *
 * **404 → null, not exception.** The backend returns 404
 * `matrix_not_found` when no matrix has been seeded for the caller's
 * device. That is not an error state — it is "no matrix yet". Caller
 * treats null as no-op (registry §B TASK-P1-037: verification
 * failure on fetch does NOT crash; logs and continues). The existing
 * MatrixStore contents are preserved.
 *
 * **Error taxonomy** mirrors IdentityChangeApi and ContactsApi:
 *   - `network_error` — transport failure (DNS, SOCKS, timeout)
 *   - `{error_code_from_json}` — the server's `error` field, verbatim
 *   - `invalid_response` — 2xx but body did not parse as expected
 *
 * **Scope note.** Only GET /me/matrix. POST /me/matrix is P1-033's
 * write path (admin attaches signature and pushes) — no consumer
 * here. Adding it before the task would be speculative surface.
 *
 * Task: TASK-P1-037 (O-2)
 * ADR: ADR-HARDENING-001 §6
 */
class MatrixApi(
    private val fetchFn: (sessionToken: String) -> HttpResult,
) {
    data class RemoteMatrix(
        val canonicalUtf8: String,
        val signatureBase64url: String,
    )

    /**
     * Fetch the caller's matrix. Returns null on 404 (no matrix
     * seeded), throws [MatrixApiException] on 401, other non-200
     * statuses, network failure, or malformed response body.
     */
    fun fetch(sessionToken: String): RemoteMatrix? {
        val result = try {
            fetchFn(sessionToken)
        } catch (e: HttpException) {
            throw MatrixApiException("network_error", e)
        }
        if (result.code == 404) return null
        if (result.code != 200) {
            throw MatrixApiException(errorCodeFrom(result), null, result.code)
        }
        return try {
            val json = JSONObject(result.body)
            RemoteMatrix(
                canonicalUtf8 = json.getString("canonical_utf8"),
                signatureBase64url = json.getString("signature_base64url"),
            )
        } catch (e: Exception) {
            throw MatrixApiException("invalid_response", e)
        }
    }

    private fun errorCodeFrom(result: HttpResult): String = try {
        JSONObject(result.body).optString("error", "unknown_error")
    } catch (_: Exception) {
        "unknown_error"
    }
}

class MatrixApiException(
    val code: String,
    cause: Throwable? = null,
    val httpCode: Int? = null,
) : Exception("matrix api failed: $code", cause)
