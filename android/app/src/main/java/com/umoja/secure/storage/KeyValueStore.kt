package com.umoja.secure.storage

/**
 * Minimal encrypted-or-plain key-value storage contract.
 *
 * Exists so crypto-adjacent classes (currently [MatrixStore]) can be
 * tested on the JVM without an [android.content.Context]. The production
 * implementation is [SecureStorage]; tests use an in-memory map.
 *
 * Four methods by design. `clear()` and `allKeys()` exist on
 * [SecureStorage] but are not part of this contract — they are
 * conveniences, not a general shape. Add them here only when a second
 * caller needs them.
 */
interface KeyValueStore {
    fun put(key: String, value: String)
    fun get(key: String): String?
    fun remove(key: String)
    fun has(key: String): Boolean
}
