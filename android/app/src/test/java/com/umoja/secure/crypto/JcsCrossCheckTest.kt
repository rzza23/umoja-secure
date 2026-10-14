package com.umoja.secure.crypto

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Test
import java.io.File
import java.util.Base64

/**
 * Produces canonical output for the cross-check corpora and writes it to
 * android/app/build/jcs-cross-check/kotlin.tsv.
 *
 * The TS side produces the same shape (backend/src/crypto/jcs-dump.ts).
 * scripts/jcs-cross-check.sh runs both and diffs.
 *
 * Format: {id}\t{base64(canonical_bytes)} per line, sorted by id.
 * Rejections emit "REJECT:<message>" in place of the base64 field.
 *
 * This test asserts nothing. It is a producer, not a validator. The
 * diff is the assertion, and it happens in the shell script.
 *
 * Task: TASK-P1-026
 * Closes: KI-012
 */
class JcsCrossCheckTest {

    private fun repoRoot(): File {
        var dir = File(System.getProperty("user.dir"))
        for (i in 0 until 10) {
            if (File(dir, "UMOJA-SECURE-BUILD-MASTER.md").exists()) return dir
            dir = dir.parentFile ?: break
        }
        error("could not find repo root from ${System.getProperty("user.dir")}")
    }

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

    private fun parseJson(text: String): Any? =
        fromOrgJson(org.json.JSONTokener(text).nextValue())

    private data class Entry(val id: String, val value: Any?)

    private fun loadCyberphone(root: File): List<Entry> {
        val dir = File(root, "docs/reference/jcs-conformance/input")
        val files = dir.listFiles { f -> f.name.endsWith(".json") }
            ?: error("no corpus input directory at $dir")
        return files.sortedBy { it.name }.map { f ->
            Entry("cyberphone:${f.name.removeSuffix(".json")}", parseJson(f.readText()))
        }
    }

    private fun loadUmojaWrappers(root: File): List<Entry> {
        val path = File(root, "docs/reference/canonical-matrix-test-vectors.json")
        val doc = JSONObject(path.readText())
        val vectors = doc.getJSONArray("vectors")
        val out = ArrayList<Entry>()
        for (i in 0 until vectors.length()) {
            val v = vectors.getJSONObject(i)
            if (v.has("input_wrapper") && !v.isNull("input_wrapper")) {
                out.add(Entry("umoja:${v.getString("id")}", fromOrgJson(v.get("input_wrapper"))))
            }
        }
        return out
    }

    private fun loadRfcNumbers(root: File): List<Entry> {
        val path = File(root, "docs/reference/rfc8785-number-samples.json")
        val doc = JSONObject(path.readText())
        val samples = doc.getJSONArray("samples")
        val out = ArrayList<Entry>()
        for (i in 0 until samples.length()) {
            val s = samples.getJSONObject(i)
            val hex = s.getString("ieee754_hex")
            val bits = java.lang.Long.parseUnsignedLong(hex, 16)
            out.add(Entry("rfc:$hex", java.lang.Double.longBitsToDouble(bits)))
        }
        return out
    }

    @Test
    fun `produce cross-check output file`() {
        val root = repoRoot()
        val entries = loadCyberphone(root) + loadUmojaWrappers(root) + loadRfcNumbers(root)

        val lines = entries.map { e ->
            val field: String = try {
                Base64.getEncoder().encodeToString(jcsCanonicalize(e.value))
            } catch (ex: JcsException) {
                "REJECT:${ex.message}"
            }
            "${e.id}\t$field"
        }.sorted()

        val outFile = File(System.getProperty("user.dir"), "build/jcs-cross-check/kotlin.tsv")
        outFile.parentFile.mkdirs()
        outFile.writeText(lines.joinToString("\n", postfix = "\n"))
        println("JcsCrossCheck: wrote ${lines.size} entries to ${outFile.absolutePath}")
    }
}
