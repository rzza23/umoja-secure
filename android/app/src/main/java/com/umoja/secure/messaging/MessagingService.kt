package com.umoja.secure.messaging

import android.content.Context
import android.util.Base64
import android.util.Log
import org.json.JSONObject
import com.umoja.secure.crypto.MatrixStore
import com.umoja.secure.crypto.PersistentSignalProtocolStore
import com.umoja.secure.crypto.SendGate
import com.umoja.secure.storage.SecureStorage
import com.umoja.secure.storage.local.MessageStatus
import com.umoja.secure.storage.local.MessageStore
import com.umoja.secure.transport.EnvelopeApi
import com.umoja.secure.transport.EnvelopeApiException
import com.umoja.secure.transport.HttpClient
import com.umoja.secure.transport.PreKeyApi
import com.umoja.secure.transport.PreKeyApiException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.kem.KEMPublicKey
import org.signal.libsignal.protocol.message.CiphertextMessage
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.PreKeyBundle

/**
 * Orchestrates the encrypted messaging flow:
 *
 * Send:
 *   1. Fetch peer's prekey bundle from the backend.
 *   2. Establish an X3DH session via SessionBuilder.
 *   3. Encrypt the plaintext.
 *   4. Submit the ciphertext as an envelope.
 *
 * Receive:
 *   1. List pending envelopes.
 *   2. Fetch each one's ciphertext body.
 *   3. Decrypt via SessionCipher.
 *   4. Acknowledge the envelope.
 *
 * The backend never sees plaintext.
 */
class MessagingService(private val context: Context) {

    companion object {
        private const val TAG = "UmojaMessaging"

        /**
         * Process-wide counter incremented whenever a message is persisted
         * (outgoing or incoming). Compose screens collect this to trigger
         * a re-query of the local message store.
         */
        private val _messagesVersion = MutableStateFlow(0L)
        val messagesVersion: StateFlow<Long> = _messagesVersion.asStateFlow()

        fun notifyMessagesChanged() {
            _messagesVersion.value = _messagesVersion.value + 1
        }
    }

    sealed class SendOutcome {
        data class Success(val envelopeId: String, val wasPreKey: Boolean) : SendOutcome()
        data class Failure(val code: String) : SendOutcome()
        /**
         * Policy denial: the peer is not in the accepted authorization
         * matrix's `permitted_contacts`, or no matrix is stored. Distinct
         * from [Failure] (transient/transport) because no retry helps —
         * the fix is a new matrix from the admin.
         *
         * TASK-P1-038, ADR-HARDENING-001 §4.
         */
        data class NotAuthorized(val peerDeviceId: String) : SendOutcome()
    }

    data class ReceivedMessage(
        val envelopeId: String,
        val senderDeviceId: String,
        val plaintext: String,
    )

    sealed class ReceiveOutcome {
        data class Success(val messages: List<ReceivedMessage>) : ReceiveOutcome()
        data class Failure(val code: String) : ReceiveOutcome()
    }

    /**
     * Send an encrypted message to a peer device.
     *
     * The peer must have uploaded a valid prekey bundle to the backend
     * (which they do on first launch after authentication).
     */
    suspend fun sendMessage(
        peerDeviceId: String,
        plaintext: String,
    ): SendOutcome = withContext(Dispatchers.IO) {
        // 0. Send gate: fail-closed on the accepted authorization matrix.
        //    Null (no matrix stored) and empty (matrix with zero contacts)
        //    both reject — "matrix not loaded" is not a policy to send
        //    under. See ADR-HARDENING-001 §4, TASK-P1-038.
        val storage = SecureStorage(context)
        val matrixStore = MatrixStore(storage)
        if (!SendGate.authorized(matrixStore.permittedContacts(), peerDeviceId)) {
            Log.w(TAG, "sendMessage blocked by SendGate for peer ${peerDeviceId.take(8)}")
            return@withContext SendOutcome.NotAuthorized(peerDeviceId)
        }

        val sessionToken = storage.get("session_token")
            ?: return@withContext SendOutcome.Failure("not_authenticated")

        val myDeviceId = storage.get("device_id")
            ?: return@withContext SendOutcome.Failure("not_enrolled")

        try {
            val http = HttpClient(HttpClient.DEV_BASE_URL)
            val prekeyApi = PreKeyApi(http)

            // 1. Fetch peer's bundle
            val bundleResponse = try {
                prekeyApi.fetchBundle(peerDeviceId, sessionToken)
            } catch (e: PreKeyApiException) {
                Log.e(TAG, "fetchBundle failed: ${e.code}", e)
                return@withContext SendOutcome.Failure("bundle_${e.code}")
            }

            // 2. Reconstruct a libsignal PreKeyBundle from the bytes
            val bundle = bundleFromResponse(bundleResponse)

            val peerAddress = SignalProtocolAddress(peerDeviceId, 1)

            // 3. Establish session if needed
            val store = PersistentSignalProtocolStore(context)
            val hadSession = store.containsSession(peerAddress)
            Log.d(TAG, "sendMessage: containsSession=$hadSession for peer ${peerDeviceId.take(8)}")
            if (!hadSession) {
                SessionBuilder(store, peerAddress).process(bundle)
                Log.d(TAG, "sendMessage: established NEW session")
            } else {
                Log.d(TAG, "sendMessage: REUSING existing session")
            }

            // 4. Encrypt
            val cipher = SessionCipher(store, peerAddress)
            val ciphertext = cipher.encrypt(plaintext.toByteArray(Charsets.UTF_8))

            if (ciphertext.type == CiphertextMessage.PREKEY_TYPE) {
                try {
                    val pkm = PreKeySignalMessage(ciphertext.serialize())
                    val pkId = if (pkm.preKeyId.isPresent) pkm.preKeyId.get() else -1
                    Log.d(TAG, "sendMessage: outgoing PreKeySignalMessage " +
                        "preKeyId=$pkId signedPreKeyId=${pkm.signedPreKeyId}")
                } catch (e: Exception) {
                    Log.w(TAG, "could not parse outgoing PreKeySignalMessage", e)
                }
            }

            val ciphertextB64 = encode(ciphertext.serialize())

            // 5. Submit envelope
            val envelopeApi = EnvelopeApi(http)
            val submitResponse = try {
                envelopeApi.submit(
                    recipientDeviceId = peerDeviceId,
                    ciphertextB64 = ciphertextB64,
                    sessionToken = sessionToken,
                )
            } catch (e: EnvelopeApiException) {
                Log.e(TAG, "submit envelope failed: ${e.code}", e)
                return@withContext SendOutcome.Failure("submit_${e.code}")
            }

            val wasPreKey = ciphertext.type == CiphertextMessage.PREKEY_TYPE
            Log.d(TAG, "sent envelope ${submitResponse.envelopeId} (prekey=$wasPreKey) to $peerDeviceId")

            try {
                MessageStore(context).insertOutgoing(
                    peerDeviceId = peerDeviceId,
                    plaintext = plaintext,
                    envelopeId = submitResponse.envelopeId,
                    status = MessageStatus.SENT,
                )
                notifyMessagesChanged()
            } catch (e: Exception) {
                Log.w(TAG, "failed to persist outgoing message", e)
            }

            SendOutcome.Success(submitResponse.envelopeId, wasPreKey)
        } catch (e: Exception) {
            Log.e(TAG, "sendMessage unexpected", e)
            SendOutcome.Failure("unexpected_error")
        }
    }

    /**
     * Poll for and decrypt pending envelopes.
     */
    suspend fun receiveMessages(): ReceiveOutcome = withContext(Dispatchers.IO) {
        val storage = SecureStorage(context)
        val sessionToken = storage.get("session_token")
            ?: return@withContext ReceiveOutcome.Failure("not_authenticated")

        val http = HttpClient(HttpClient.DEV_BASE_URL)
        val envelopeApi = EnvelopeApi(http)

        try {
            val pending = try {
                envelopeApi.listPending(sessionToken)
            } catch (e: EnvelopeApiException) {
                Log.e(TAG, "listPending failed: ${e.code}", e)
                return@withContext ReceiveOutcome.Failure("list_${e.code}")
            }

            val messages = mutableListOf<ReceivedMessage>()
            val store = PersistentSignalProtocolStore(context)

            for (item in pending) {
                try {
                    val body = envelopeApi.fetch(item.envelopeId, sessionToken)
                    val ciphertextBytes = decode(body.ciphertext)

                    val peerAddress = SignalProtocolAddress(item.senderDeviceId, 1)
                    val cipher = SessionCipher(store, peerAddress)

                    val plaintext = decrypt(cipher, ciphertextBytes)
                    if (plaintext == null) {
                        Log.w(TAG, "could not decrypt envelope ${item.envelopeId}")
                        continue
                    }

                    envelopeApi.ack(item.envelopeId, sessionToken)

                    val text = String(plaintext, Charsets.UTF_8)
                    try {
                        val store = MessageStore(context)
                        if (!store.hasEnvelope(item.envelopeId)) {
                            store.insertIncoming(
                                peerDeviceId = item.senderDeviceId,
                                plaintext = text,
                                envelopeId = item.envelopeId,
                            )
                            notifyMessagesChanged()
                        }
                    } catch (e: Exception) {
                        Log.w(TAG, "failed to persist polled message", e)
                    }

                    messages.add(
                        ReceivedMessage(
                            envelopeId = item.envelopeId,
                            senderDeviceId = item.senderDeviceId,
                            plaintext = text,
                        ),
                    )
                } catch (e: Exception) {
                    Log.e(TAG, "failed to process envelope ${item.envelopeId}", e)
                }
            }

            ReceiveOutcome.Success(messages)
        } catch (e: Exception) {
            Log.e(TAG, "receiveMessages unexpected", e)
            ReceiveOutcome.Failure("unexpected_error")
        }
    }

    /**
     * Decrypt an envelope delivered over WebSocket.
     * The frame contains: type, envelope_id, sender_device_id,
     * envelope_type, ciphertext (base64url), created_at.
     * Acks the envelope via HTTP on successful decrypt.
     */
    suspend fun decryptWebSocketFrame(frame: JSONObject): ReceivedMessage? =
        withContext(Dispatchers.IO) {
            try {
                val envelopeId = frame.getString("envelope_id")
                val senderDeviceId = frame.getString("sender_device_id")
                val ciphertextB64 = frame.getString("ciphertext")

                val store = PersistentSignalProtocolStore(context)
                val peerAddress = SignalProtocolAddress(senderDeviceId, 1)
                val cipher = SessionCipher(store, peerAddress)

                val bytes = decode(ciphertextB64)
                val plaintext = decrypt(cipher, bytes) ?: return@withContext null

                // Ack via HTTP so the backend marks retrieved
                val storage = SecureStorage(context)
                val token = storage.get("session_token")
                if (token != null) {
                    try {
                        val http = HttpClient(HttpClient.DEV_BASE_URL)
                        EnvelopeApi(http).ack(envelopeId, token)
                    } catch (_: Exception) {
                        // best-effort; envelope will be re-delivered on next poll
                    }
                }

                val text = String(plaintext, Charsets.UTF_8)
                try {
                    val store = MessageStore(context)
                    if (!store.hasEnvelope(envelopeId)) {
                        store.insertIncoming(
                            peerDeviceId = senderDeviceId,
                            plaintext = text,
                            envelopeId = envelopeId,
                        )
                        notifyMessagesChanged()
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "failed to persist incoming message", e)
                }

                ReceivedMessage(
                    envelopeId = envelopeId,
                    senderDeviceId = senderDeviceId,
                    plaintext = text,
                )
            } catch (e: Exception) {
                Log.e(TAG, "decryptWebSocketFrame failed", e)
                null
            }
        }

    // ============================================================
    // Internal helpers
    // ============================================================

    private fun bundleFromResponse(r: com.umoja.secure.transport.PeerPreKeyBundle): PreKeyBundle {
        val preKeyId = r.oneTimePreKeyId ?: PreKeyBundle.NULL_PRE_KEY_ID
        val preKey = r.oneTimePreKeyPublicB64?.let {
            ECPublicKey.fromPublicKeyBytes(decode(it))
        } ?: ECPublicKey.fromPublicKeyBytes(decode(r.signedPreKeyPublicB64))

        // libsignal's PreKeyBundle has a single Kyber slot. Signal Protocol
        // uses it for the SIGNED Kyber prekey (verified by the signature).
        // One-time Kyber prekeys are not exposed through PreKeyBundle in
        // libsignal 0.86.x; we always use the signed Kyber prekey here.
        val kyberId = r.kyberPreKeyId
        val kyberBytes = r.kyberPreKeyPublicB64

        Log.d(
            TAG,
            "bundleFromResponse: peer=${r.deviceId.take(8)} regId=${r.registrationId} " +
                "spkId=${r.signedPreKeyId} preKeyId=$preKeyId kyberId=$kyberId " +
                "ikLen=${decode(r.identityKeyB64).size} " +
                "spkPubLen=${decode(r.signedPreKeyPublicB64).size} " +
                "spkSigLen=${decode(r.signedPreKeySignatureB64).size} " +
                "kyberPubLen=${decode(kyberBytes).size} " +
                "kyberSigLen=${decode(r.kyberPreKeySignatureB64).size}",
        )

        return PreKeyBundle(
            r.registrationId,
            1, // deviceId: 1 in our model (per SignalProtocolAddress above)
            preKeyId,
            preKey,
            r.signedPreKeyId,
            ECPublicKey.fromPublicKeyBytes(decode(r.signedPreKeyPublicB64)),
            decode(r.signedPreKeySignatureB64),
            // Backend stores 32 raw bytes; build ECPublicKey then IdentityKey.
            // IdentityKey(byte[]) would expect a 33-byte prefixed form and throw.
            IdentityKey(ECPublicKey.fromPublicKeyBytes(decode(r.identityKeyB64))),
            kyberId,
            KEMPublicKey(decode(kyberBytes)),
            decode(r.kyberPreKeySignatureB64),
        )
    }

    private fun decrypt(cipher: SessionCipher, bytes: ByteArray): ByteArray? {
        // Try SignalMessage (established session) first
        try {
            return cipher.decrypt(SignalMessage(bytes))
        } catch (_: Exception) {
            // Fall through to PreKeySignalMessage
        }
        try {
            return cipher.decrypt(PreKeySignalMessage(bytes))
        } catch (e: Exception) {
            Log.w(TAG, "decrypt failed for both message types", e)
            return null
        }
    }

    private fun encode(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    private fun decode(b64: String): ByteArray =
        Base64.decode(b64, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
}
