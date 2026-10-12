package com.umoja.secure.auth

import android.content.Context
import android.util.Base64
import android.util.Log
import com.umoja.secure.crypto.SignalIdentityStore
import com.umoja.secure.crypto.SignalPreKeyStore
import com.umoja.secure.storage.SecureStorage
import com.umoja.secure.transport.HttpClient
import com.umoja.secure.transport.OneTimePreKeyEntry
import com.umoja.secure.transport.PreKeyApi
import com.umoja.secure.transport.PreKeyApiException
import com.umoja.secure.transport.PreKeyUploadRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Generates libsignal prekey material, uploads the public half to the
 * backend, and keeps the private half in encrypted storage.
 *
 * Uses libsignal's own Curve25519 types (IdentityKeyPair, SignedPreKeyRecord,
 * PreKeyRecord) rather than a separate crypto library. This ensures the
 * material is directly usable by SessionBuilder/SessionCipher in 20b.
 */
class PreKeyUploader(private val context: Context) {

    companion object {
        private const val TAG = "UmojaPreKeys"
    }

    sealed class UploadOutcome {
        data class Success(val stored: Int, val total: Int) : UploadOutcome()
        data class Failure(val code: String) : UploadOutcome()
        object NotAuthenticated : UploadOutcome()
    }

    suspend fun uploadPreKeys(): UploadOutcome = withContext(Dispatchers.IO) {
        val storage = SecureStorage(context)
        val sessionToken = storage.get("session_token")
            ?: return@withContext UploadOutcome.NotAuthenticated

        try {
            val identityStore = SignalIdentityStore(context)
            val identityKeyPair = identityStore.getOrGenerate()

            val preKeyStore = SignalPreKeyStore(context)
            val generated = preKeyStore.generateFresh(identityKeyPair)

            val identityKeyB64 = encodeRaw(identityKeyPair.publicKey.publicKey.publicKeyBytes)
            val spkPublicB64 = encodeRaw(generated.signedPreKey.keyPair.publicKey.publicKeyBytes)
            val spkSignatureB64 = encodeRaw(generated.signedPreKey.signature)

            val kyberPublicB64 = encodeRaw(generated.kyberPreKey.keyPair.publicKey.serialize())
            val kyberSignatureB64 = encodeRaw(generated.kyberPreKey.signature)

            val otpEntries = generated.oneTimePreKeys.map { record ->
                OneTimePreKeyEntry(
                    id = record.id,
                    publicKeyB64 = encodeRaw(record.keyPair.publicKey.publicKeyBytes),
                )
            }

            val kyberOtpEntries = generated.oneTimeKyberPreKeys.map { record ->
                OneTimePreKeyEntry(
                    id = record.id,
                    publicKeyB64 = encodeRaw(record.keyPair.publicKey.serialize()),
                )
            }

            val request = PreKeyUploadRequest(
                identityKeyB64 = identityKeyB64,
                signedPreKeyId = generated.signedPreKey.id,
                signedPreKeyPublicB64 = spkPublicB64,
                signedPreKeySignatureB64 = spkSignatureB64,
                registrationId = generated.registrationId,
                kyberPreKeyId = generated.kyberPreKey.id,
                kyberPreKeyPublicB64 = kyberPublicB64,
                kyberPreKeySignatureB64 = kyberSignatureB64,
                oneTimePreKeys = otpEntries,
                oneTimeKyberPreKeys = kyberOtpEntries,
            )

            val http = HttpClient(HttpClient.DEV_BASE_URL)
            val api = PreKeyApi(http)
            val response = api.upload(request, sessionToken)

            Log.i(
                TAG,
                "uploaded prekeys: stored=${response.storedPrekeys} total=${response.totalUnconsumed}",
            )

            UploadOutcome.Success(response.storedPrekeys, response.totalUnconsumed)
        } catch (e: PreKeyApiException) {
            Log.e(TAG, "PreKeyApiException: ${e.code}", e)
            UploadOutcome.Failure(e.code)
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected exception during prekey upload", e)
            UploadOutcome.Failure("unexpected_error")
        }
    }

    private fun encodeRaw(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
}
