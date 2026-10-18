package com.umoja.secure.ui.admin

import com.umoja.secure.crypto.MatrixBuilder
import com.umoja.secure.crypto.ProvisioningBundle
import com.umoja.secure.crypto.jcsCanonicalizeString
import com.umoja.secure.transport.AdminApi
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
            _statusMessage.value = "Matrix built - review hash and content"
        } catch (e: IllegalArgumentException) {
            _error.value = "Build failed: ${e.message}"
        }
    }

    fun setStatusMessage(msg: String) {
        _statusMessage.value = msg
    }
}
