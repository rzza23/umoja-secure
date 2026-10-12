package com.umoja.secure.auth

/**
 * A challenge issued by the backend for device authentication.
 * Field names and types mirror the backend Challenge interface exactly.
 */
data class Challenge(
    val v: Int,
    val purpose: String,
    val challengeId: String,
    val nonce: String,
    val deviceId: String,
    val sessionContext: String?,
    val issuedAt: String,
    val expiresAt: String,
    val serverId: String,
)
