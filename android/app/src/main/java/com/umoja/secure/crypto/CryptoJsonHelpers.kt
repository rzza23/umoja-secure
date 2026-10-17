package com.umoja.secure.crypto

import org.json.JSONArray
import org.json.JSONObject

/**
 * Shared JSON → pure-Kotlin map conversion for JCS canonicalization.
 *
 * [jcsCanonicalize] / [jcsCanonicalizeString] consume pure Kotlin types
 * (String, Int, Long, Boolean, List, Map, null). `JSONObject` and
 * `JSONArray` are not those — they need to be walked into `Map` /
 * `List` first. This is that walk.
 *
 * Extracted from four sites (MatrixStore, MatrixStoreTest,
 * ReplacementNoticeTest, IdentityChangeAckSignerTest) that each had a
 * private copy. The store about to be written would have been the
 * fifth. Extracted per the three-file threshold rule so the count
 * does not keep growing.
 *
 * No number-format handling here — `JSONObject.get` returns `Int`,
 * `Long`, or `Double` depending on parse, and `jcsCanonicalize`
 * handles number formatting per RFC 8785. This helper is a structural
 * translation only.
 */
fun jsonObjectToPlainMap(jo: JSONObject): Map<String, Any?> {
    val out = linkedMapOf<String, Any?>()
    for (key in jo.keys()) {
        out[key] = jsonValueToPlain(jo.get(key))
    }
    return out
}

fun jsonValueToPlain(v: Any?): Any? = when (v) {
    null, JSONObject.NULL -> null
    is JSONObject -> jsonObjectToPlainMap(v)
    is JSONArray -> (0 until v.length()).map { jsonValueToPlain(v.get(it)) }
    else -> v
}
