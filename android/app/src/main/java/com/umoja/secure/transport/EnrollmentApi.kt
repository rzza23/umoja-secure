package com.umoja.secure.transport

import org.json.JSONObject

data class EnrollmentRequest(
    val token: String,
    val deviceId: String,
    val devicePublicKey: String,
    val label: String,
)

data class EnrollmentResponse(
    val deviceId: String,
    val orgId: String,
    val role: String,
    val enrollmentMatrixVersionFloor: Int?,
)

class EnrollmentApi(private val http: HttpClient) {

    /**
     * Submit an enrollment request. On success, returns the server-assigned
     * device_id and organization. On any error, throws EnrollmentException
     * with a stable error code.
     */
    fun enroll(request: EnrollmentRequest): EnrollmentResponse {
        val body = JSONObject().apply {
            put("token", request.token)
            put("device_id", request.deviceId)
            put("device_public_key", request.devicePublicKey)
            put("label", request.label)
        }.toString()

        val result = try {
            http.postJson("/enrollment", body)
        } catch (e: HttpException) {
            throw EnrollmentException("network_error", e)
        }

        if (result.code == 201) {
            return try {
                val json = JSONObject(result.body)
                EnrollmentResponse(
                    deviceId = json.getString("device_id"),
                    orgId = json.getString("org_id"),
                    role = json.getString("role"),
                    enrollmentMatrixVersionFloor =
                        if (json.isNull("enrollment_matrix_version_floor")) null
                        else json.getInt("enrollment_matrix_version_floor"),
                )
            } catch (e: Exception) {
                throw EnrollmentException("invalid_response", e)
            }
        }

        val errorCode = try {
            JSONObject(result.body).optString("error", "unknown_error")
        } catch (_: Exception) {
            "unknown_error"
        }
        throw EnrollmentException(errorCode, null, result.code)
    }
}

class EnrollmentException(
    val code: String,
    cause: Throwable? = null,
    val httpCode: Int? = null,
) : Exception("enrollment failed: $code", cause)
