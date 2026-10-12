package com.umoja.secure.auth

import android.content.Context
import android.util.Base64
import android.util.Log
import com.umoja.secure.crypto.PersistentSignalProtocolStore
import com.umoja.secure.storage.SecureStorage
import com.umoja.secure.transport.HttpClient
import com.umoja.secure.transport.OneTimePreKeyEntry
import com.umoja.secure.transport.PreKeyApi
import com.umoja.secure.transport.PreKeyApiException
import com.umoja.secure.transport.PreKeyUploadRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class PreKeyUploader(private val context: Context) {

    companion object {
        private const val TAG = "UmojaPreKeys"
        private const val ONE_TIME_EC_COUNT = 100
        private const val ONE_TIME_KYBER_COUNT = 100
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
            val store = PersistentSignalProtocolStore(context)
            val generated = store.generateAndStorePreKeys(
                oneTimeEcCount = ONE_TIME_EC_COUNT,
                oneTimeKyberCount = ONE_TIME_KYBER_COUNT,
            )

            val identityKeyB64 = encodeRaw(generated.identityKey.publicKey.publicKeyBytes)
            val spkPublicB64 = encodeRaw(generated.signedPreKey.keyPair.publicKey.publicKeyBytes)
            val spkSignatureB64 = encodeRaw(generated.signedPreKey.signature)
            val kyberPublicB64 = encodeRaw(generated.kyberPreKey.keyPair.publicKey.serialize())
            val kyberSignatureB64 = encodeRaw(generated.kyberPreKey.signature)

            val otpEntries = generated.oneTimeEcPreKeys.map { record ->
                OneTimePreKeyEntry(
                    id = record.id,
                    publicKeyB64 = encodeRaw(record.keyPair.publicKey.publicKeyBytes),
                )
            }
            val kyberOtpEntries = generated.oneTimeKyberPreKeys.map { record ->
                OneTimePreKeyEntry(
                    id = record.id,
                    // KEMPublicKey uses serialize(); publicKeyBytes is EC-only.
                    publicKeyB64 = encodeRaw(record.keyPair.publicKey.serialize()),
                )
            }

            val request = PreKeyUploadRequest(
                identityKeyB64 = identityKeyB64,
                signedPreKeyId = generated.signedPreKeyId,
                signedPreKeyPublicB64 = spkPublicB64,
                signedPreKeySignatureB64 = spkSignatureB64,
                registrationId = generated.registrationId,
                kyberPreKeyId = generated.kyberPreKeyId,
                kyberPreKeyPublicB64 = kyberPublicB64,
                kyberPreKeySignatureB64 = kyberSignatureB64,
                oneTimePreKeys = otpEntries,
                oneTimeKyberPreKeys = kyberOtpEntries,
            )

            val http = HttpClient(HttpClient.DEV_BASE_URL)
            val api = PreKeyApi(http)
            val response = api.upload(request, sessionToken)

            Log.i(TAG, "uploaded: ec=${response.storedPrekeys} kyber=${response.storedKyberPrekeys}")
            UploadOutcome.Success(response.storedPrekeys, response.totalUnconsumed)
        } catch (e: PreKeyApiException) {
            Log.e(TAG, "PreKeyApiException: ${e.code}", e)
            UploadOutcome.Failure(e.code)
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected exception", e)
            UploadOutcome.Failure("unexpected_error")
        }
    }

    private fun encodeRaw(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
}
