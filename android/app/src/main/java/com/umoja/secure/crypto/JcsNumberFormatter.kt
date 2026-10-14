package com.umoja.secure.crypto

import java.math.BigDecimal
import java.math.BigInteger
import java.math.MathContext
import java.math.RoundingMode
import kotlin.math.abs

/**
 * Formats a Double per ECMAScript Number.prototype.toString().
 *
 * This is the number-serialization rule that RFC 8785 JCS mandates for
 * JSON numbers. Java's Double.toString() does NOT follow it: it differs
 * at the exponential-notation thresholds, in exponent sign, and for
 * certain subnormals (Java pre-19 emits "4.9E-324" for the minimum
 * subnormal where ES6 emits "5e-324").
 *
 * Deliberately separate from JcsCanonicalizer so it can be validated in
 * isolation against docs/reference/rfc8785-number-samples.json before
 * anything else is built on top of it. See handoff KI-007.
 *
 * Spec:         https://tc39.es/ecma262/#sec-number.prototype.tostring
 * Build Master: §3.8
 * Task:         TASK-P1-026
 */
internal object JcsNumberFormatter {

    /**
     * Format a finite Double per ECMAScript Number.prototype.toString().
     *
     * @throws IllegalArgumentException if [d] is NaN or infinite. RFC 8785
     *   §3.2.2.3 does not permit those values in JSON. The check lives
     *   here as a defensive second line — the canonicalizer also rejects
     *   them at the JSON-value boundary.
     */
    fun format(d: Double): String {
        require(d.isFinite()) {
            "JCS does not permit NaN, Infinity, or -Infinity"
        }
        if (d == 0.0) return "0"

        val negative = d < 0.0
        val absD = if (negative) -d else d

        val (sig, exp) = shortestRoundTripping(absD)
        val sigStr = sig.toString()
        val k = sigStr.length
        val n = exp + k

        val body: String = when {
            n in k..21 ->
                sigStr + "0".repeat(n - k)

            n in 1 until k ->
                sigStr.substring(0, n) + "." + sigStr.substring(n)

            n in -5..0 ->
                "0." + "0".repeat(-n) + sigStr

            else -> {
                val mantissa =
                    if (k == 1) sigStr
                    else sigStr[0] + "." + sigStr.substring(1)
                val e = n - 1
                val sign = if (e >= 0) "+" else "-"
                mantissa + "e" + sign + abs(e)
            }
        }

        return if (negative) "-$body" else body
    }

    private fun shortestRoundTripping(absD: Double): Pair<BigInteger, Int> {
        require(absD > 0.0 && absD.isFinite())
        val exact = BigDecimal(absD)
        for (precision in 1..17) {
            val rounded = exact.round(MathContext(precision, RoundingMode.HALF_EVEN))
            if (rounded.toDouble() == absD) {
                val stripped = rounded.stripTrailingZeros()
                return Pair(stripped.unscaledValue(), -stripped.scale())
            }
        }
        error("no shortest round-tripping representation for $absD")
    }
}
