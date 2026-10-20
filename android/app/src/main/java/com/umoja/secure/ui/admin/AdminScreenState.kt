package com.umoja.secure.ui.admin

import com.umoja.secure.crypto.MatrixBuilder
import com.umoja.secure.crypto.ProvisioningBundle
import com.umoja.secure.crypto.jcsCanonicalizeString
import com.umoja.secure.transport.AdminApi
import com.umoja.secure.transport.MatrixApi
import com.umoja.secure.transport.AdminApiException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import java.util.Base64

/**
 * State and logic for AdminScreen (TASK-P1-025 / admin flows).
 *
 * Extracted from the composable so the load / token / authorize /
 * build-matrix logic is JVM-testable with injected lambdas -- no
 * Compose runtime, no Android context, no real backend. Behavior is
 * preserved exactly; the extraction is structural.
 *
 * Follows ChatViewModel's precedent: plain Kotlin class, MutableStateFlow
 * backing, internal CoroutineScope semantics provided by the caller's
 * scope.launch, no androidx ViewModel, no lifecycle awareness. Callers
 * (MainActivity) construct one instance per deviceId via `remember`.
 *
 * Form-input state (ownerDeviceId, contactDeviceId, provisionClearance,
 * provisionVersion, provisionContacts, debugPasteText) stays in the
 * composable -- it is UI input, not server/action state, and is
 * exercised by Compose tests, not JVM tests.
 *
 * Five injected lambdas give tests control over every backend call:
 *   listDevicesFn      -> api.listDevices(token)
 *   listContactsFn     -> api.listContacts(token)
 *   createTokenFn      -> api.createEnrollmentToken(req, token)
 *   authorizeContactFn -> api.authorizeContact(owner, contact, token)
 *   sessionToken       -> SecureStorage.get("session_token") at construct time
 */
class AdminScreenState(
    private val sessionToken: String?,
    private val listDevicesFn: suspend (String) -> List<AdminApi.DeviceEntry>,
    private val listContactsFn: suspend (String) -> List<AdminApi.ContactEntry>,
    private val createTokenFn: suspend (AdminApi.CreateTokenRequest, String) -> AdminApi.CreatedToken,
    private val authorizeContactFn: suspend (String, String, String) -> Unit,
    private val pushFn: suspend (String, MatrixApi.RemoteMatrix, String) -> MatrixApi.PushResult =
        { _, _, _ -> error("AdminScreenState.pushSignedMatrix: pushFn not provided") },
) {
    private val _loading = MutableStateFlow(true)
    val loading: StateFlow<Boolean> = _loading.asStateFlow()

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    private val _statusMessage = MutableStateFlow<String?>(null)
    val statusMessage: StateFlow<String?> = _statusMessage.asStateFlow()

    private val _devices = MutableStateFlow<List<AdminApi.DeviceEntry>>(emptyList())
    val devices: StateFlow<List<AdminApi.DeviceEntry>> = _devices.asStateFlow()

    private val _contacts = MutableStateFlow<List<AdminApi.ContactEntry>>(emptyList())
    val contacts: StateFlow<List<AdminApi.ContactEntry>> = _contacts.asStateFlow()

    private val _scannedBundle = MutableStateFlow<ProvisioningBundle?>(null)
    val scannedBundle: StateFlow<ProvisioningBundle?> = _scannedBundle.asStateFlow()

    private val _createdToken = MutableStateFlow<AdminApi.CreatedToken?>(null)
    val createdToken: StateFlow<AdminApi.CreatedToken?> = _createdToken.asStateFlow()

    private val _builtWrapperJson = MutableStateFlow<String?>(null)
    val builtWrapperJson: StateFlow<String?> = _builtWrapperJson.asStateFlow()

    private val _builtHash = MutableStateFlow<String?>(null)
    val builtHash: StateFlow<String?> = _builtHash.asStateFlow()

    private val _importedSignature = MutableStateFlow<String?>(null)
    val importedSignature: StateFlow<String?> = _importedSignature.asStateFlow()

    private val _pushedMatrix = MutableStateFlow<MatrixApi.PushResult?>(null)
    val pushedMatrix: StateFlow<MatrixApi.PushResult?> = _pushedMatrix.asStateFlow()

    suspend fun load() {
        if (sessionToken == null) {
            _error.value = "Not authenticated"
            _loading.value = false
            return
        }
        _loading.value = true
        _error.value = null
        try {
            val d = withContext(Dispatchers.IO) { listDevicesFn(sessionToken) }
            val c = withContext(Dispatchers.IO) { listContactsFn(sessionToken) }
            _devices.value = d
            _contacts.value = c.filter { it.status == "active" }
        } catch (e: AdminApiException) {
            _error.value = e.code
        } finally {
            _loading.value = false
        }
    }

    fun loadBundle(json: String) {
        try {
            _scannedBundle.value = ProvisioningBundle.parse(json)
            _createdToken.value = null
            _error.value = null
        } catch (e: IllegalArgumentException) {
            _error.value = "QR parse failed: ${e.message}"
        }
    }

    suspend fun createTokenForScannedDevice() {
        val tok = sessionToken
        if (tok == null) {
            _error.value = "Not authenticated"
            return
        }
        val bundle = _scannedBundle.value
        if (bundle == null) {
            _error.value = "No scanned device"
            return
        }
        _error.value = null
        _statusMessage.value = null
        try {
            val t = withContext(Dispatchers.IO) {
                createTokenFn(
                    AdminApi.CreateTokenRequest(
                        role = "user",
                        boundPublicKey = bundle.pubDeviceAuthKey,
                    ),
                    tok,
                )
            }
            _createdToken.value = t
            _statusMessage.value = "Token created"
        } catch (e: AdminApiException) {
            _error.value = e.code
        }
    }

    suspend fun authorize(ownerDeviceId: String, contactDeviceId: String) {
        val tok = sessionToken
        if (tok == null) {
            _error.value = "Not authenticated"
            return
        }
        _error.value = null
        _statusMessage.value = null
        try {
            withContext(Dispatchers.IO) {
                authorizeContactFn(ownerDeviceId.trim(), contactDeviceId.trim(), tok)
            }
            _statusMessage.value = "Contact authorized"
            load()
        } catch (e: AdminApiException) {
            _error.value = e.code
        }
    }

    fun buildMatrix(clearance: String, versionStr: String, permittedContacts: List<String>) {
        _error.value = null
        _statusMessage.value = null
        val v = versionStr.toIntOrNull()
        if (v == null || v < 1) {
            _error.value = "version must be a positive integer"
            return
        }
        val bundle = _scannedBundle.value
        if (bundle == null) {
            _error.value = "No scanned device"
            return
        }
        try {
            val signed = MatrixBuilder.build(
                bundle = bundle,
                clearance = clearance.trim(),
                permittedContacts = permittedContacts,
                version = v,
            )
            val wrapperStr = jcsCanonicalizeString(signed.toJsonMap())
            val digest = MessageDigest.getInstance("SHA-256")
                .digest(wrapperStr.toByteArray(Charsets.UTF_8))
            val hashB64 = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(digest)
            _builtWrapperJson.value = wrapperStr
            _builtHash.value = hashB64
            _pushedMatrix.value = null
            _statusMessage.value = "Matrix built - review hash and content"
        } catch (e: IllegalArgumentException) {
            _error.value = "Build failed: ${e.message}"
        }
    }

    /**
     * Import the signature produced by the offline signer for the
     * currently-built matrix. Validates 86-char base64url (64-byte
     * Ed25519 no-pad). Clearing the prior pushedMatrix is deliberate:
     * a new signature invalidates any previously-pushed state.
     *
     * Task: TASK-P1-033b
     */
    fun importSignature(base64url: String) {
        _error.value = null
        _statusMessage.value = null
        if (!base64url.matches(Regex("^[A-Za-z0-9_-]{86}$"))) {
            _error.value = "signature must be 86-char base64url (64 bytes)"
            return
        }
        _importedSignature.value = base64url
        _pushedMatrix.value = null
        _statusMessage.value = "Signature imported - review and push"
    }

    /**
     * Clear imported signature and pushed state. Built wrapper/hash
     * (from [buildMatrix]) are preserved -- they are the pre-signing
     * artifact, orthogonal to the signature.
     *
     * Task: TASK-P1-033b
     */
    fun clearSignature() {
        _importedSignature.value = null
        _pushedMatrix.value = null
        _error.value = null
        _statusMessage.value = null
    }

    /**
     * Push the built matrix + imported signature to the backend via
     * POST /admin/matrices/:device_id (TASK-P1-033a's route).
     *
     * Requires: sessionToken (admin's), scannedBundle (target
     * device_id), builtWrapperJson (canonical to push), and
     * importedSignature (signature to attach). All four are checked
     * before the network call -- missing inputs surface as specific
     * error strings, not network failures.
     *
     * On success: poppedMatrix echoes the server's stored
     * {device_id, version} (client can assert version matches what
     * it built). On MatrixApiException: error code recorded.
     *
     * Task: TASK-P1-033b
     */
    suspend fun pushSignedMatrix() {
        val tok = sessionToken
        if (tok == null) {
            _error.value = "Not authenticated"
            return
        }
        val bundle = _scannedBundle.value
        if (bundle == null) {
            _error.value = "No scanned device"
            return
        }
        val wrapper = _builtWrapperJson.value
        if (wrapper == null) {
            _error.value = "No built matrix to push"
            return
        }
        val sig = _importedSignature.value
        if (sig == null) {
            _error.value = "No signature imported"
            return
        }
        _error.value = null
        _statusMessage.value = null
        try {
            val result = withContext(Dispatchers.IO) {
                pushFn(
                    bundle.deviceId,
                    MatrixApi.RemoteMatrix(
                        canonicalUtf8 = wrapper,
                        signatureBase64url = sig,
                    ),
                    tok,
                )
            }
            _pushedMatrix.value = result
            _statusMessage.value =
                "Matrix pushed (v${result.version})"
        } catch (e: AdminApiException) {
            _error.value = e.code
        }
    }

    fun setStatusMessage(msg: String) {
        _statusMessage.value = msg
    }
}
