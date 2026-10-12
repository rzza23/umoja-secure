package com.umoja.secure.auth

import android.content.Context
import android.util.Log
import com.umoja.secure.crypto.DeviceIdentity
import com.umoja.secure.crypto.DeviceKeyManager
import com.umoja.secure.crypto.PreKeyGenerator
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
        const val STORED_SIGNED_PREKEY_ID = "prekey.signed.id"
        const val STORED_REGISTRATION_ID = "prekey.registration.id"
    }

    sealed class UploadOutcome {
        data class Success(val stored: Int, val total: Int) : UploadOutcome()
        data class Failure(val code: String) : UploadOutcome()
        object NotAuthenticated : UploadOutcome()
    }

    suspend fun uploadPreKeys(): UploadOutcome = withContext(Dispatchers.IO) {
        val storage = SecureStorage(context)
        val sessionToken = storage.get("session_token") ?: return@withContext UploadOutcome.NotAuthenticated

        try {
            val keyManager = DeviceKeyManager(context = context)
            if (!keyManager.hasKey()) {
                return@withContext UploadOutcome.Failure("device_key_missing")
            }
            val keyInfo = keyManager.ensureKeyPair()
            val identityKeyB64 = DeviceIdentity.encodePublicKey(keyInfo.spkiEncoded)

            // Signed prekey id is deterministic per device, stored for reuse.
            val signedPreKeyId = storage.get(STORED_SIGNED_PREKEY_ID)?.toIntOrNull() ?: 1
            val registrationId = storage.get(STORED_REGISTRATION_ID)?.toIntOrNull()
                ?: generateRegistrationId()

            // Generate signed prekey — signature is over the raw public key
            // using the device identity key.
            val signedPreKey = PreKeyGenerator.generateSignedPreKey(signedPreKeyId) { rawPub ->
                keyManager.sign(rawPub)
            }

            // Generate a fresh batch of one-time prekeys.
            val oneTimePreKeys = PreKeyGenerator.generateOneTimePreKeys(100)

            val request = PreKeyUploadRequest(
                identityKeyB64 = identityKeyB64,
                signedPreKeyId = signedPreKey.id,
                signedPreKeyPublicB64 = PreKeyGenerator.toB64Url(signedPreKey.publicKey),
                signedPreKeySignatureB64 = PreKeyGenerator.toB64Url(signedPreKey.signature),
                registrationId = registrationId,
                oneTimePreKeys = oneTimePreKeys.map { otp ->
                    OneTimePreKeyEntry(
                        id = otp.id,
                        publicKeyB64 = PreKeyGenerator.toB64Url(otp.publicKey),
                    )
                },
            )

            val http = HttpClient(HttpClient.DEV_BASE_URL)
            val api = PreKeyApi(http)
            val response = api.upload(request, sessionToken)

            storage.put(STORED_SIGNED_PREKEY_ID, signedPreKeyId.toString())
            storage.put(STORED_REGISTRATION_ID, registrationId.toString())

            UploadOutcome.Success(response.storedPrekeys, response.totalUnconsumed)
        } catch (e: PreKeyApiException) {
            Log.e(TAG, "PreKeyApiException: ${e.code}", e)
            UploadOutcome.Failure(e.code)
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected exception during prekey upload", e)
            UploadOutcome.Failure("unexpected_error")
        }
    }

    private fun generateRegistrationId(): Int =
        (1..16383).random()
}
