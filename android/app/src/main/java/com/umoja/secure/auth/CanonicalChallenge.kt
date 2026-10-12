package com.umoja.secure.auth

/**
 * Deterministic canonical encoding for challenge signing.
 *
 * MUST produce byte-identical output to the backend's
 * src/auth/canonical.ts `canonicalizeChallenge`.
 *
 * Rules (matched to backend):
 *   - Prefix "v1:" (ASCII).
 *   - Then JSON object with keys sorted ascending (UTF-16 code unit order).
 *   - No whitespace between tokens.
 *   - v is emitted as a JSON number (no quotes).
 *   - session_context is emitted as empty string when null.
 *   - Strings escaped the same way Node's JSON.stringify escapes them
 *     (quotes, backslash, control characters).
 */
object CanonicalChallenge {

    fun encode(c: Challenge): ByteArray {
        val sb = StringBuilder(256)
        sb.append('{')
        appendStringField(sb, "challenge_id", c.challengeId)
        sb.append(',')
        appendStringField(sb, "device_id", c.deviceId)
        sb.append(',')
        appendStringField(sb, "expires_at", c.expiresAt)
        sb.append(',')
        appendStringField(sb, "issued_at", c.issuedAt)
        sb.append(',')
        appendStringField(sb, "nonce", c.nonce)
        sb.append(',')
        appendStringField(sb, "purpose", c.purpose)
        sb.append(',')
        appendStringField(sb, "server_id", c.serverId)
        sb.append(',')
        appendStringField(sb, "session_context", c.sessionContext ?: "")
        sb.append(',')
        sb.append("\"v\":").append(c.v)
        sb.append('}')
        return ("v1:" + sb.toString()).toByteArray(Charsets.UTF_8)
    }

    private fun appendStringField(sb: StringBuilder, key: String, value: String) {
        sb.append('"').append(key).append("\":\"")
        appendEscaped(sb, value)
        sb.append('"')
    }

    private fun appendEscaped(sb: StringBuilder, s: String) {
        for (ch in s) {
            when {
                ch == '\\' -> sb.append("\\\\")
                ch == '"' -> sb.append("\\\"")
                ch == '\n' -> sb.append("\\n")
                ch == '\r' -> sb.append("\\r")
                ch == '\t' -> sb.append("\\t")
                ch == '\b' -> sb.append("\\b")
                ch == '\u000C' -> sb.append("\\f")
                ch < ' ' -> sb.append("\\u").append("%04x".format(ch.code))
                else -> sb.append(ch)
            }
        }
    }
}
