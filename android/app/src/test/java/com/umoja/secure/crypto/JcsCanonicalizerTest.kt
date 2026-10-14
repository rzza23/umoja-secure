package com.umoja.secure.crypto

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.File

/**
 * Conformance tests for JcsCanonicalizer against:
 *   1. The cyberphone JCS corpus (6 input/output pairs).
 *   2. Behavior spot checks mirroring the TS suite.
 *
 * Ground truth lives in docs/reference/. Do not edit those files to make
 * a test pass — fix the canonicalizer.
 *
 * The TS counterpart is backend/src/crypto/jcs.test.ts. Both must produce
 * byte-identical output for every input.
 *
 * Task: TASK-P1-026
 * Build Master: §3.8
 */
class JcsCanonicalizerTest {

    private fun repoRoot(): File {
        var dir = File(System.getProperty("user.dir"))
        for (i in 0 until 10) {
            if (File(dir, "UMOJA-SECURE-BUILD-MASTER.md").exists()) return dir
            dir = dir.parentFile ?: break
        }
        error("could not find repo root from ${System.getProperty("user.dir")}")
    }

    /**
     * Convert org.json values into the pure-Kotlin shape that
     * jcsCanonicalize consumes.
     */
    private fun fromOrgJson(value: Any?): Any? = when (value) {
        null, JSONObject.NULL -> null
        is Boolean -> value
        is Int -> value
        is Long -> value
        is Double -> value
        is java.math.BigDecimal -> value.toDouble()
        is java.math.BigInteger -> value.toDouble()
        is String -> value
        is JSONArray -> (0 until value.length()).map { fromOrgJson(value.get(it)) }
        is JSONObject -> {
            val out = LinkedHashMap<String, Any?>()
            val keys = value.keys()
            while (keys.hasNext()) {
                val k = keys.next()
                out[k] = fromOrgJson(value.get(k))
            }
            out
        }
        else -> error("unexpected org.json type: ${value::class.qualifiedName}")
    }

    @Test
    fun `all 6 cyberphone corpus pairs`() {
        val corpus = File(repoRoot(), "docs/reference/jcs-conformance")
        val inputDir = File(corpus, "input")
        val outputDir = File(corpus, "output")
        val names = inputDir.listFiles { f -> f.name.endsWith(".json") }!!
            .map { it.name }.sorted()
        assertEquals(6, names.size)
        for (name in names) {
            val inputRaw = File(inputDir, name).readText()
            val expected = File(outputDir, name).readText()
            val parsed = when (val v: Any = org.json.JSONTokener(inputRaw).nextValue()) {
                is JSONObject -> fromOrgJson(v)
                is JSONArray -> fromOrgJson(v)
                else -> v
            }
            val got = jcsCanonicalizeString(parsed)
            assertEquals("corpus pair $name", expected, got)
        }
    }

    @Test
    fun `sorts object keys by UTF-16 code unit order`() {
        assertEquals("""{"a":2,"b":1}""", jcsCanonicalizeString(mapOf("b" to 1, "a" to 2)))
    }

    @Test
    fun `preserves array order`() {
        assertEquals("[3,1,2]", jcsCanonicalizeString(listOf(3, 1, 2)))
    }

    @Test
    fun `collapses -0 to 0`() {
        assertEquals("0", jcsCanonicalizeString(-0.0))
    }

    @Test
    fun `emits 1e21 with a plus sign in the exponent`() {
        assertEquals("1e+21", jcsCanonicalizeString(1e21))
    }

    @Test
    fun `escapes double quote and backslash`() {
        assertEquals("\"\\\"\\\\\"", jcsCanonicalizeString("\"\\"))
    }

    @Test
    fun `escapes control characters as lowercase unicode escapes`() {
        assertEquals("\"\\u0000\\u001f\"", jcsCanonicalizeString("\u0000\u001f"))
    }

    @Test
    fun `emits printable non-ASCII as raw UTF-8`() {
        assertEquals("\"café\"", jcsCanonicalizeString("café"))
    }

    @Test
    fun `rejects NaN`() {
        assertThrows(JcsException::class.java) { jcsCanonicalizeString(Double.NaN) }
    }

    @Test
    fun `rejects Infinity`() {
        assertThrows(JcsException::class.java) { jcsCanonicalizeString(Double.POSITIVE_INFINITY) }
    }

    @Test
    fun `rejects non-String map keys`() {
        assertThrows(JcsException::class.java) {
            jcsCanonicalizeString(mapOf(1 to "x"))
        }
    }
}
