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
 * - [AuthorizationMatrix] additionally keeps its `ISO8601_UTC_RE`,
 *   `requirePositiveInt`, and `requireStringList` local (not
 *   duplicated elsewhere).
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
 * The three consumers are all in `com.umoja.secure.crypto`.
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
