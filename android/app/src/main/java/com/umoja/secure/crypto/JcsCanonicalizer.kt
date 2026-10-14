package com.umoja.secure.crypto

/**
 * RFC 8785 JSON Canonicalization Scheme (JCS).
 *
 * This is the Umoja authorization-matrix signing canonicalizer. It is
 * DISTINCT from:
 *   - CanonicalChallenge.encode  (challenge-response protocol, no prehash)
 *   - canonicalJson in backend   (audit hash chain, no prehash)
 *
 * The matrix protocol REQUIRES SHA-256 prehash of the canonical bytes
 * (Build Master §3.8). Do not unify the three encoders.
 *
 * Input model: pure Kotlin types.
 *   null, Boolean, Number, String, List<*>, Map<String, *> (nested)
 *
 * Callers that have an org.json.JSONObject / JSONArray from the wire
 * must convert to this shape before calling. Keeping the canonicalizer
 * dependency-free means it runs on the JVM test classpath and can be
 * cross-validated byte-for-byte against backend/src/crypto/jcs.ts.
 *
 * Spec:         https://www.rfc-editor.org/rfc/rfc8785.txt
 * Conformance:  docs/reference/jcs-conformance/
 *               docs/reference/rfc8785-number-samples.json
 * Build Master: §3.8
 * Task:         TASK-P1-026
 */
class JcsException(message: String) : IllegalArgumentException(message)

/**
 * Canonicalize a JSON value per RFC 8785. Returns the canonical UTF-8 bytes.
 *
 * @throws JcsException if the value contains anything JCS does not permit
 *   (NaN, Infinity, non-String map keys, or unsupported Kotlin types).
 */
fun jcsCanonicalize(value: Any?): ByteArray =
    jcsCanonicalizeString(value).toByteArray(Charsets.UTF_8)

/**
 * Canonicalize a JSON value per RFC 8785, returning the canonical string.
 */
fun jcsCanonicalizeString(value: Any?): String = serialize(value)

private fun serialize(value: Any?): String {
    if (value == null) return "null"

    return when (value) {
        is Boolean -> if (value) "true" else "false"
        is Number -> serializeNumber(value)
        is String -> escapeString(value)

        is List<*> -> buildString {
            append('[')
            for (i in value.indices) {
                if (i > 0) append(',')
                append(serialize(value[i]))
            }
            append(']')
        }

        is Map<*, *> -> serializeObject(value)

        else -> throw JcsException(
            "JCS does not permit values of type ${value::class.qualifiedName}"
        )
    }
}

private fun serializeNumber(n: Number): String {
    // Every Number reaches the formatter as a Double, matching JSON.parse
    // semantics in ECMAScript (one number type, IEEE 754 double). For
    // Long values above 2^53 this is lossy — same loss as JS.
    val d = n.toDouble()
    if (!d.isFinite()) {
        throw JcsException("JCS does not permit NaN, Infinity, or -Infinity")
    }
    return JcsNumberFormatter.format(d)
}

private fun serializeObject(map: Map<*, *>): String {
    // Every key must be a String. Reject anything else rather than
    // coercing — silent coercion is a signing-boundary hazard.
    val entries = ArrayList<Pair<String, Any?>>(map.size)
    for ((k, v) in map) {
        if (k !is String) {
            throw JcsException(
                "JCS requires String keys; got ${k?.let { it::class.qualifiedName } ?: "null"}"
            )
        }
        entries.add(k to v)
    }
    entries.sortWith { a, b -> utf16Compare(a.first, b.first) }

    return buildString {
        append('{')
        for (i in entries.indices) {
            if (i > 0) append(',')
            append(escapeString(entries[i].first))
            append(':')
            append(serialize(entries[i].second))
        }
        append('}')
    }
}

private val HEX = "0123456789abcdef"

private fun escapeString(s: String): String = buildString(s.length + 2) {
    append('"')
    var i = 0
    while (i < s.length) {
        val c = s[i]
        when (c) {
            '"' -> append("\\\"")
            '\\' -> append("\\\\")
            '\b' -> append("\\b")
            '\u000C' -> append("\\f")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> when {
                c < ' ' -> appendUnicodeEscape(this, c.code)
                Character.isHighSurrogate(c) -> {
                    if (i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) {
                        append(c)
                        append(s[i + 1])
                        i++
                    } else {
                        appendUnicodeEscape(this, c.code)
                    }
                }
                Character.isLowSurrogate(c) -> appendUnicodeEscape(this, c.code)
                else -> append(c)
            }
        }
        i++
    }
    append('"')
}

private fun appendUnicodeEscape(sb: StringBuilder, code: Int) {
    sb.append("\\u")
    sb.append(HEX[(code ushr 12) and 0xF])
    sb.append(HEX[(code ushr 8) and 0xF])
    sb.append(HEX[(code ushr 4) and 0xF])
    sb.append(HEX[code and 0xF])
}

/**
 * UTF-16 code unit order comparison. RFC 8785 §3.2.3. Not locale-aware,
 * not Unicode-collation.
 */
private fun utf16Compare(a: String, b: String): Int {
    val n = minOf(a.length, b.length)
    for (i in 0 until n) {
        val ca = a[i].code
        val cb = b[i].code
        if (ca != cb) return ca - cb
    }
    return a.length - b.length
}
