package com.umoja.secure.crypto

/**
 * Thrown when a cryptographic operation fails in a way that the caller
 * must handle. Never wraps a key material leak; message strings are safe
 * to log.
 */
class CryptoException(message: String, cause: Throwable? = null) :
    Exception(message, cause)
