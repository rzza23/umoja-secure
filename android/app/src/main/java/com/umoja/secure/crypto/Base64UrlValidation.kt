package com.umoja.secure.crypto

import java.util.Base64

/**
 * Shared validation helpers for crypto payload fields.
 *
 * Session U-1 KI-016 extraction: [requireString] and
 * [requireBase64Url32] were byte-identical private copies in
 * [ProvisioningBundle] and [AuthorizationMatrix]. Extracting them
 * eliminates the drift risk (a future change to one file's helper but
 * not the other would produce inconsistent validation between
 * enrollment payload parsing and matrix parsing).
 *
 * **Scope deliberately limited:**
 * - [ProvisioningBundle] additionally keeps its `PRINTABLE_ASCII_RE`
 *   and `requirePrintableAscii` local (not duplicated elsewhere).
 * - [AuthorizationMatrix] additionally keeps its `requireStringList`
 *   local (not duplicated elsewhere). Its `ISO8601_UTC_RE` and
 *   `requirePositiveInt` were extracted to this file on 2026-10-21
 *   when [RecoveryNotice] became the third consumer of the ISO
 *   regex (see continuation note below).
 * - [EnrollmentQrPayload] keeps its own variant — different regex
 *   shape (exact-43 `{43}` vs one-or-more `+`) and String-typed
 *   input, not the `Any?` duck-typing shape the shared helper uses.
 *   That's a genuine different validation, not a stylistic copy.
 *
 * **Session F's `RN_` prefix note is superseded.** That discipline
 * existed because [ReplacementNotice] had file-private copies of
 * `requireString` / `requireBase64Url32` / `RN_BASE64URL_RE` that
 * could be silently confused with the same-named copies in
 * [ProvisioningBundle] and [AuthorizationMatrix]. Session U-1
 * extracted a single shared definition; there is nothing left to
 * confuse. One name, one location, three consumers. Keeping the
 * RN_ prefix would recreate the duplication the extraction
 * eliminates. Session F's note was correct for the state it
 * addressed; this extraction supersedes it.
 *
 * **Visibility: `internal`.** Module-scoped — callable from anywhere
 * in the app module, not from outside. Kotlin's `internal` maps to
 * module-private visibility, which is exactly the scope these need.
 * All consumers are in `com.umoja.secure.crypto`.
 *
 * **2026-10-21 continuation (Session Z-22, P1-035b pre-condition).**
 * The ISO 8601 UTC regex reached its **fourth** file-private copy:
 * `ISO8601_UTC_RE` (AuthorizationMatrix), `RN_ISO8601_UTC_RE`
 * (ReplacementNotice), `IC_ISO8601_UTC_RE` (IdentityChangeAck), and
 * the imminent `RecoveryNotice` (this session). `requirePositiveInt`
 * had 2 copies. Both extracted here. Same rationale as U-1's
 * extraction: byte-identical private helpers across files are a
 * drift hazard, and extraction supersedes the prefix discipline.
 *
 * **Known remaining duplication (backlog item, not this session):**
 * [IdentityChangeAck] still has `IC_REQUIRE_STRING`,
 * `IC_REQUIRE_BASE64URL32`, and `IC_BASE64URL32_RE` — three
 * file-private copies of helpers this file already provides. They
 * predate U-1's extraction to this file (U-1 did not touch
 * IdentityChangeAck). Filed separately for a future doc-hygiene
 * pass; this session does not fold them in, to keep the 035b
 * pre-condition refactor bounded.
 */
internal val BASE64URL_RE = Regex("^[A-Za-z0-9_-]+$")

internal fun requireString(value: Any?, field: String): String {
    val s = value as? String
        ?: throw IllegalArgumentException(
            "$field: expected string, got ${value?.let { it::class.simpleName } ?: "null"}",
        )
    if (s.isEmpty()) {
        throw IllegalArgumentException("$field: empty string not permitted")
    }
    return s
}

internal fun requireBase64Url32(value: Any?, field: String): String {
    val s = requireString(value, field)
    if (!BASE64URL_RE.matches(s)) {
        throw IllegalArgumentException("$field: not base64url (no padding, [A-Za-z0-9_-] only)")
    }
    if (s.length != 43) {
        throw IllegalArgumentException(
            "$field: expected 43 base64url chars for 32 bytes, got ${s.length}",
        )
    }
    val decoded = Base64.getUrlDecoder().decode(s)
    if (decoded.size != 32) {
        throw IllegalArgumentException("$field: decodes to ${decoded.size} bytes, expected 32")
    }
    return s
}


internal val ISO8601_UTC_RE = Regex("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?Z$")

internal fun requirePositiveInt(value: Any?, field: String): Int {
    val n = when (value) {
        is Int -> value
        is Long -> {
            require(value in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong()) {
                "$field: out of Int range"
            }
            value.toInt()
        }
        else -> throw IllegalArgumentException(
            "$field: expected positive integer, got ${value?.let { it::class.simpleName } ?: "null"}",
        )
    }
    if (n < 1) {
        throw IllegalArgumentException("$field: expected positive integer, got $n")
    }
    return n
}
