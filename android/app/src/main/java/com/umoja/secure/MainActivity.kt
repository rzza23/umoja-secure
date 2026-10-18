package com.umoja.secure

import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.umoja.secure.auth.SessionManager
import com.umoja.secure.messaging.MessagingService
import com.umoja.secure.storage.SecureStorage
import com.umoja.secure.transport.EnrollmentApi
import com.umoja.secure.transport.EnrollmentException
import com.umoja.secure.transport.EnrollmentRequest
import com.umoja.secure.transport.HttpClient
import com.umoja.secure.ui.admin.AdminScreen
import com.umoja.secure.ui.diagnostics.DiagnosticsScreen
import com.umoja.secure.ui.navigation.MainNavigation
import com.umoja.secure.ui.navigation.Tab
import com.umoja.secure.ui.provisioning.EnrollmentQrScreen
import com.umoja.secure.ui.theme.UmojaSecureTheme
import com.umoja.secure.crypto.DeviceIdStore
import com.umoja.secure.crypto.DeviceIdentity
import com.umoja.secure.crypto.DeviceKeyManager
import com.umoja.secure.crypto.MatrixStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.umoja.secure.crypto.IdentityChangeController
import com.umoja.secure.crypto.ProvisioningKeys
import com.umoja.secure.crypto.ReplacementNoticeStore
import com.umoja.secure.transport.IdentityChangeApi
import com.umoja.secure.transport.MatrixApi
import com.umoja.secure.transport.MatrixApiException
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            UmojaSecureTheme {
                AppRoot(lifecycle = lifecycle)
            }
        }
    }
}

private sealed class AppScreen {
    object Enrollment : AppScreen()
    object Authenticated : AppScreen()
    object Admin : AppScreen()
    object Diagnostics : AppScreen()
}

@Composable
fun AppRoot(lifecycle: Lifecycle) {
    val context = LocalContext.current
    val app = context.applicationContext as UmojaApplication

    var deviceId by remember { mutableStateOf<String?>(null) }
    var sessionExpiresAt by remember { mutableStateOf<String?>(null) }
    var role by remember { mutableStateOf<String?>(null) }
    var screen by remember { mutableStateOf<AppScreen>(AppScreen.Enrollment) }
    var selectedTab by remember { mutableStateOf(Tab.Conversations) }
    var envelopesReceived by remember { mutableStateOf(0) }
    var openEnrollmentQr by remember { mutableStateOf(false) }

    // MatrixStore (TASK-P1-026 authority). Remembered per deviceId to
    // mirror identityChangeController's shape. The store is stateless
    // from a Compose perspective (reads SecureStorage on each call), so
    // multiple MatrixStore(SecureStorage(context)) instances are
    // equivalent. Hoisting one instance here gives the ChatScreen gate
    // a single reference and a natural seam for future reactivity
    // (MatrixStore.version StateFlow) if P1-036 rotation ever needs it.
    val matrixStore = remember(deviceId) { MatrixStore(SecureStorage(context)) }

    val wsState by app.webSocketClient.state.collectAsState()
    val coroutineScope = rememberCoroutineScope()

    // Identity-change controller. Constructed once per deviceId;
    // null pre-enrollment, non-null after. One HttpClient per
    // controller lifetime — polling reuses the connection, does not
    // rebuild the SOCKS stack on each refresh. The Authenticated
    // branch reaches this only when deviceId is non-null (routing
    // rule), so the error() guard is a programming-error check that
    // should never fire.
    val identityChangeController = remember(deviceId) {
        deviceId?.let { id ->
            val keyManager = DeviceKeyManager(context = context)
            val api = IdentityChangeApi(HttpClient(HttpClient.DEV_BASE_URL))
            IdentityChangeController(
                listNotices = api::getNotices,
                postAck = api::postAck,
                store = ReplacementNoticeStore(
                    store = SecureStorage(context),
                    signingFn = { digest -> keyManager.sign(digest) },
                    ackingDeviceId = id,
                ),
                sessionTokenProvider = {
                    SessionManager(context).currentSession()?.sessionToken
                },
                trustedKeys = setOf(provisioningPublicKey()),
            )
        }
    }

    // Foreground lifecycle polling: refresh notices whenever the app
    // becomes visible. ON_START fires on screen-on, return-from-other-
    // app, and activity restart. ChatScreen's LaunchedEffect covers
    // the chat-open case; this covers "the app is open, a notice
    // arrived while I was elsewhere."
    //
    // Keyed on identityChangeController so the effect re-runs when
    // deviceId transitions null -> non-null (post-enrollment). The
    // observer must capture the current controller, not the null one
    // present at first composition. The immediate refresh covers the
    // window where ON_START has already fired before the controller
    // existed -- a fresh observer registration does not replay past
    // events.
    DisposableEffect(lifecycle, identityChangeController) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_START) {
                identityChangeController?.let { ctrl ->
                    coroutineScope.launch { ctrl.refresh() }
                }
            }
        }
        lifecycle.addObserver(observer)
        identityChangeController?.let { ctrl ->
            coroutineScope.launch { ctrl.refresh() }
        }
        onDispose { lifecycle.removeObserver(observer) }
    }

    // Matrix transport fetch on Authenticated entry (TASK-P1-037 O-2).
    // Pulls the caller's signed matrix from GET /me/matrix, verifies
    // against the pinned provisioning key, and feeds MatrixStore.accept.
    //
    // Fires on:
    //   - Enrollment -> Authenticated (first session entry)
    //   - Admin/Diagnostics -> Authenticated (returning from a
    //     sub-screen; accepted trade-off per O-2 reviewer note)
    //   - Session re-auth that lands back on Authenticated
    //
    // Does NOT poll. Matrix changes are rare; P1-036 (rotation) will
    // handle notice-driven updates separately. The trade-off is that
    // Admin<->Authenticated navigation re-fetches — cheap, matrix
    // payload is small, and idempotent on the store side (accept
    // rejects same-version, silent).
    //
    // Failure handling per registry §B TASK-P1-037:
    //   - 404 matrix_not_found -> MatrixApi returns null -> no-op
    //   - MatrixApiException (network / 401 / invalid_response) ->
    //     caught silently, MatrixStore unchanged
    //   - AcceptResult.Rejected (bad signature, rollback, below_floor)
    //     -> silent per registry §B; logging is P1-041's territory,
    //     no log surface available pre-041
    //
    // A rejected matrix leaves MatrixStore unchanged. The fetch-then-
    // accept path is idempotent — a later fetch of a valid matrix
    // recovers automatically.
    LaunchedEffect(screen, deviceId) {
        if (screen is AppScreen.Authenticated && deviceId != null) {
            // LaunchedEffect body runs on Dispatchers.Main by default.
            // MatrixApi.fetch -> HttpClient.get is a blocking OkHttp call;
            // must run on IO. Same pattern as enrollDevice's
            // = withContext(Dispatchers.IO) { ... }. See ADR-HARDENING-001
            // §9 v0.2 / TASK-P1-037 O-2 acceptance notes.
            withContext(Dispatchers.IO) {
                val token = SessionManager(context).currentSession()?.sessionToken
                if (token != null) {
                    try {
                        val api = MatrixApi { t ->
                            HttpClient(HttpClient.DEV_BASE_URL)
                                .get("/me/matrix", bearer = t)
                        }
                        val remote = api.fetch(token)
                        if (remote != null) {
                            MatrixStore(SecureStorage(context)).accept(
                                canonical = remote.canonicalUtf8.toByteArray(Charsets.UTF_8),
                                signatureBase64url = remote.signatureBase64url,
                                trustedKeys = setOf(provisioningPublicKey()),
                            )
                        }
                    } catch (_: MatrixApiException) {
                        // Silent per registry §B — see KDoc above
                    }
                }
            }
        }
    }

    // Initial state load
    LaunchedEffect(Unit) {
        val s = SecureStorage(context)
        deviceId = s.get("device_id")
        sessionExpiresAt = s.get("session_expires_at")
        role = s.get("session_role")
        screen = when {
            deviceId == null -> AppScreen.Enrollment
            sessionExpiresAt == null -> AppScreen.Enrollment
            else -> AppScreen.Authenticated
        }
    }

    // Re-evaluate when the session changes
    LaunchedEffect(sessionExpiresAt, deviceId) {
        val s = SecureStorage(context)
        role = s.get("session_role")
        if (sessionExpiresAt != null && deviceId != null &&
            screen !is AppScreen.Admin && screen !is AppScreen.Diagnostics
        ) {
            screen = AppScreen.Authenticated
        }
        if (sessionExpiresAt == null && screen is AppScreen.Authenticated) {
            screen = AppScreen.Enrollment
        }
    }

    // Decrypt incoming envelopes
    LaunchedEffect(Unit) {
        app.webSocketClient.envelopes.collect { frame ->
            envelopesReceived += 1
            MessagingService(context).decryptWebSocketFrame(frame)
        }
    }

    // KI-020: enrollment QR overlay. Renders full-screen over the
    // current screen and returns to it on Back. Mirrors the overlay
    // pattern in MainNavigation. Placed after the LaunchedEffect
    // blocks so the early return does not dispose them.
    if (openEnrollmentQr) {
        EnrollmentQrScreen(onBack = { openEnrollmentQr = false })
        return
    }

    when (val s = screen) {
        AppScreen.Enrollment -> EnrollmentScreen(
            deviceId = deviceId,
            onEnrolled = { newDeviceId ->
                deviceId = newDeviceId
                screen = AppScreen.Enrollment  // will re-route to auth on next state read
            },
            onAuthenticated = {
                val store = SecureStorage(context)
                sessionExpiresAt = store.get("session_expires_at")
                role = store.get("session_role")
                screen = AppScreen.Authenticated
            },
            onOpenEnrollmentQr = { openEnrollmentQr = true },
        )

        AppScreen.Authenticated -> MainNavigation(
            onLogout = {
                val scope = kotlinx.coroutines.CoroutineScope(Dispatchers.IO)
                scope.launch {
                    SessionManager(context).clearSession()
                }
                sessionExpiresAt = null
                role = null
                screen = AppScreen.Enrollment
            },
            onOpenAdmin = if (role == "admin" || role == "owner") {
                {
                    selectedTab = Tab.Settings
                    screen = AppScreen.Admin
                }
            } else null,
            onOpenDiagnostics = { screen = AppScreen.Diagnostics },
            selectedTab = selectedTab,
            onSelectTab = { selectedTab = it },
            identityChangeController = identityChangeController
                ?: error("Authenticated without identityChangeController"),
            matrixStore = matrixStore,
        )

        AppScreen.Admin -> AdminScreen(
            onBack = {
                android.util.Log.d("UmojaNavigation", "Admin Back callback invoked")
                screen = AppScreen.Authenticated
            },
        )

        AppScreen.Diagnostics -> DiagnosticsScreen(
            wsState = wsState,
            envelopesReceived = envelopesReceived,
            onConnectWs = {
                val token = SecureStorage(context).get("session_token")
                if (token != null) app.webSocketClient.connect(token)
            },
            onDisconnectWs = { app.webSocketClient.disconnect() },
            onBack = { screen = AppScreen.Authenticated },
        )
    }
}

@Composable
fun EnrollmentScreen(
    deviceId: String?,
    onEnrolled: (String) -> Unit,
    onAuthenticated: () -> Unit,
    onOpenEnrollmentQr: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var tokenInput by remember { mutableStateOf("") }
    var labelInput by remember { mutableStateOf("Android device") }
    var status by remember { mutableStateOf<String?>(null) }
    var isBusy by remember { mutableStateOf(false) }

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Text("Umoja Secure", style = MaterialTheme.typography.headlineMedium)
            Spacer(Modifier.height(8.dp))
            Text(
                "Your conversations. Your control.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )

            Spacer(Modifier.height(40.dp))

            if (deviceId == null) {
                OutlinedTextField(
                    value = tokenInput,
                    onValueChange = { tokenInput = it },
                    label = { Text("Enrollment token") },
                    enabled = !isBusy,
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = labelInput,
                    onValueChange = { labelInput = it },
                    label = { Text("Device label") },
                    enabled = !isBusy,
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(20.dp))
                Button(
                    onClick = {
                        isBusy = true
                        status = null
                        scope.launch {
                            val outcome = enrollDevice(context, tokenInput, labelInput)
                            withContext(Dispatchers.Main) {
                                isBusy = false
                                when (outcome) {
                                    is EnrollUiOutcome.Success -> onEnrolled(outcome.deviceId)
                                    is EnrollUiOutcome.Failure -> status = "Error: ${outcome.code}"
                                }
                            }
                        }
                    },
                    enabled = !isBusy && tokenInput.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(if (isBusy) "Enrolling..." else "Enroll device")
                }
                Spacer(Modifier.height(8.dp))
                TextButton(
                    onClick = onOpenEnrollmentQr,
                    enabled = !isBusy,
                ) {
                    Text("Show enrollment QR")
                }
            } else {
                Text("Device enrolled", color = MaterialTheme.colorScheme.primary,
                    style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(16.dp))
                Button(
                    onClick = {
                        isBusy = true
                        status = null
                        scope.launch {
                            val manager = SessionManager(context)
                            val outcome = manager.authenticate()
                            withContext(Dispatchers.Main) {
                                isBusy = false
                                when (outcome) {
                                    is SessionManager.AuthOutcome.Success -> onAuthenticated()
                                    is SessionManager.AuthOutcome.Failure ->
                                        status = "Auth error: ${outcome.code}"
                                    SessionManager.AuthOutcome.NotEnrolled ->
                                        status = "Device not enrolled"
                                }
                            }
                        }
                    },
                    enabled = !isBusy,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(if (isBusy) "Authenticating..." else "Authenticate")
                }
            }

            status?.let {
                Spacer(Modifier.height(16.dp))
                Text(it, style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error)
            }
        }
    }
}

private sealed class EnrollUiOutcome {
    data class Success(val deviceId: String) : EnrollUiOutcome()
    data class Failure(val code: String) : EnrollUiOutcome()
}

private suspend fun enrollDevice(
    context: Context,
    token: String,
    label: String,
): EnrollUiOutcome = withContext(Dispatchers.IO) {
    try {
        val keyManager = DeviceKeyManager(context = context)
        val keyInfo = keyManager.ensureKeyPair()
        val publicKeyB64 = DeviceIdentity.encodePublicKey(keyInfo.spkiEncoded)

        val storage = SecureStorage(context)
        val deviceId = DeviceIdStore(storage).getOrCreate()

        val http = HttpClient(HttpClient.DEV_BASE_URL)
        val api = EnrollmentApi(http)
        val response = api.enroll(
            EnrollmentRequest(
                token = token,
                deviceId = deviceId,
                devicePublicKey = publicKeyB64,
                label = label,
            ),
        )

        storage.put("device_id", response.deviceId)
        storage.put("org_id", response.orgId)
        storage.put("role", response.role)
        MatrixStore(storage).setEnrollmentFloor(response.enrollmentMatrixVersionFloor)

        EnrollUiOutcome.Success(response.deviceId)
    } catch (e: EnrollmentException) {
        EnrollUiOutcome.Failure(e.code)
    } catch (e: Exception) {
        EnrollUiOutcome.Failure("unexpected_error")
    }
}

// Ed25519 SubjectPublicKeyInfo prefix per RFC 8410 §4. Wraps a raw
// 32-byte Ed25519 public key into the DER form KeyFactory expects.
// Duplicated from MatrixSigner.SPKI_PREFIX; consolidated later if a
// fourth consumer appears (three-file threshold rule).
private val ED25519_SPKI_PREFIX = byteArrayOf(
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
)

private fun provisioningPublicKey(): PublicKey {
    val raw = Base64.getUrlDecoder()
        .decode(ProvisioningKeys.CURRENT_PROVISIONING_PUBKEY_B64U)
    require(raw.size == 32) {
        "expected 32-byte provisioning pubkey, got ${raw.size}"
    }
    val spki = ED25519_SPKI_PREFIX + raw
    return KeyFactory.getInstance("Ed25519")
        .generatePublic(X509EncodedKeySpec(spki))
}
