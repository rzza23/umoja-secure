package com.umoja.secure.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * Conformance tests for JcsNumberFormatter against RFC 8785 Appendix B.
 *
 * Ground truth: docs/reference/rfc8785-number-samples.json (24 samples).
 * The hex values below are transcribed verbatim from that file's
 * ieee754_hex fields, so this test is self-contained and does not need
 * JSON parsing at JVM-unit-test time.
 *
 * If a test fails, the formatter is wrong — do not edit the sample.
 *
 * Task: TASK-P1-026
 * Build Master: §3.8
 * Handoff: KI-007
 */
class JcsNumberFormatterTest {

    private data class Sample(val hex: String, val expected: String, val comment: String)

    private val samples = listOf(
        Sample("0000000000000000", "0", "Zero"),
        Sample("8000000000000000", "0", "Minus zero"),
        Sample("0000000000000001", "5e-324", "Min pos number"),
        Sample("8000000000000001", "-5e-324", "Min neg number"),
        Sample("7fefffffffffffff", "1.7976931348623157e+308", "Max pos number"),
        Sample("ffefffffffffffff", "-1.7976931348623157e+308", "Max neg number"),
        Sample("4340000000000000", "9007199254740992", "Max pos int"),
        Sample("c340000000000000", "-9007199254740992", "Max neg int"),
        Sample("4430000000000000", "295147905179352830000", "~2**68"),
        Sample("44b52d02c7e14af5", "9.999999999999997e+22", ""),
        Sample("44b52d02c7e14af6", "1e+23", ""),
        Sample("44b52d02c7e14af7", "1.0000000000000001e+23", ""),
        Sample("444b1ae4d6e2ef4e", "999999999999999700000", ""),
        Sample("444b1ae4d6e2ef4f", "999999999999999900000", ""),
        Sample("444b1ae4d6e2ef50", "1e+21", ""),
        Sample("3eb0c6f7a0b5ed8c", "9.999999999999997e-7", ""),
        Sample("3eb0c6f7a0b5ed8d", "0.000001", ""),
        Sample("41b3de4355555553", "333333333.3333332", ""),
        Sample("41b3de4355555554", "333333333.33333325", ""),
        Sample("41b3de4355555555", "333333333.3333333", ""),
        Sample("41b3de4355555556", "333333333.3333334", ""),
        Sample("41b3de4355555557", "333333333.33333343", ""),
        Sample("becbf647612f3696", "-0.0000033333333333333333", ""),
        Sample("43143ff3c1cb0959", "1424953923781206.2", "Round to even"),
    )

    @Test
    fun `all 24 RFC 8785 Appendix B samples`() {
        assertEquals(24, samples.size)
        for (s in samples) {
            val bits = java.lang.Long.parseUnsignedLong(s.hex, 16)
            val d = Double.fromBits(bits)
            val label = if (s.comment.isEmpty()) s.hex else "${s.hex} (${s.comment})"
            assertEquals(label, s.expected, JcsNumberFormatter.format(d))
        }
    }

    @Test
    fun `rejects NaN`() {
        assertThrows(IllegalArgumentException::class.java) {
            JcsNumberFormatter.format(Double.NaN)
        }
    }

    @Test
    fun `rejects Infinity`() {
        assertThrows(IllegalArgumentException::class.java) {
            JcsNumberFormatter.format(Double.POSITIVE_INFINITY)
        }
    }

    @Test
    fun `rejects -Infinity`() {
        assertThrows(IllegalArgumentException::class.java) {
            JcsNumberFormatter.format(Double.NEGATIVE_INFINITY)
        }
    }
}
