package com.umoja.secure.signing

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.journeyapps.barcodescanner.BarcodeEncoder
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.launch

/**
 * Compose UI for the offline signing app (TASK-P1-033c).
 *
 * Two visual modes, driven by [SigningState.mode]:
 *
 *   CEREMONY  — shows the provisioning public key as QR + copyable
 *               text. One-shot: after this screen the pubkey goes in
 *               the ceremony log and the device is turned off.
 *
 *   OPERATING — canonical-matrix input (QR scan or paste), JCS
 *               validation, SHA-256 preview, sign on button press,
 *               signature QR + copyable text output.
 *
 * No transport calls, no branding, no navigation. This screen is
 * reachable only via `adb shell am start`; the physical ceremony's
 * isolation comes from the workstation USB policy (KEY-CUSTODY §4.3).
 *
 * Task: TASK-P1-033c
 */
@Composable
fun SigningScreen(
    state: SigningState,
    initialMode: SigningMode?,
    modifier: Modifier = Modifier,
) {
    val mode by state.mode.collectAsState()
    val hasKey by state.hasKey.collectAsState()
    val publicKeyB64u by state.publicKeyB64u.collectAsState()
    val canonicalUtf8 by state.canonicalUtf8.collectAsState()
    val canonicalHashB64u by state.canonicalHashB64u.collectAsState()
    val signatureB64u by state.signatureB64u.collectAsState()
    val error by state.error.collectAsState()
    val statusMessage by state.statusMessage.collectAsState()

    val scope = rememberCoroutineScope()

    LaunchedEffect(initialMode) {
        when (initialMode) {
            SigningMode.CEREMONY -> state.enterCeremonyMode()
            SigningMode.OPERATING -> state.enterOperatingMode()
            null -> {}
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
    ) {
        if (initialMode == null) {
            Text("Invalid invocation.", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            Text(
                "Launch with an explicit mode:\n" +
                    "  adb shell am start -n com.umoja.secure.signing/" +
                    "com.umoja.secure.signing.SigningActivity \\\n" +
                    "    --es mode ceremony|operating",
                style = MaterialTheme.typography.bodySmall,
            )
            return
        }

        // Header
        when (mode) {
            SigningMode.CEREMONY -> Text(
                "Provisioning Ceremony",
                style = MaterialTheme.typography.headlineSmall,
            )
            SigningMode.OPERATING -> Text(
                "Sign Authorization Matrix",
                style = MaterialTheme.typography.headlineSmall,
            )
            null -> Text(
                "Loading…",
                style = MaterialTheme.typography.headlineSmall,
            )
        }

        statusMessage?.let { msg ->
            Spacer(Modifier.height(8.dp))
            Text(msg, style = MaterialTheme.typography.bodyMedium)
        }
        error?.let { e ->
            Spacer(Modifier.height(8.dp))
            Card {
                Text(
                    e,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(12.dp),
                )
            }
        }

        Spacer(Modifier.height(16.dp))

        when (mode) {
            SigningMode.CEREMONY -> CeremonyBody(publicKeyB64u)
            SigningMode.OPERATING -> OperatingBody(
                hasKey = hasKey,
                canonicalUtf8 = canonicalUtf8,
                canonicalHashB64u = canonicalHashB64u,
                signatureB64u = signatureB64u,
                scope = scope,
                state = state,
            )
            null -> Unit
        }
    }
}

@Composable
private fun CeremonyBody(publicKeyB64u: String?) {
    val clipboard = LocalClipboardManager.current
    if (publicKeyB64u == null) {
        Text(
            "Waiting for key generation…",
            style = MaterialTheme.typography.bodyMedium,
        )
        return
    }
    Text(
        "Provisioning public key (record in the ceremony log):",
        style = MaterialTheme.typography.titleSmall,
    )
    Spacer(Modifier.height(8.dp))
    val qrBitmap = remember(publicKeyB64u) {
        try {
            BarcodeEncoder().encodeBitmap(publicKeyB64u, BarcodeFormat.QR_CODE, 640, 640)
        } catch (_: Exception) {
            null
        }
    }
    qrBitmap?.let { bmp ->
        Image(
            bitmap = bmp.asImageBitmap(),
            contentDescription = "Provisioning public key QR",
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(8.dp))
    }
    Card {
        Text(
            publicKeyB64u,
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(12.dp),
        )
    }
    Spacer(Modifier.height(8.dp))
    Button(onClick = { clipboard.setText(AnnotatedString(publicKeyB64u)) }) {
        Text("Copy public key")
    }
    Spacer(Modifier.height(16.dp))
    Text(
        "Ceremony complete. Record the public key in the paper log, " +
            "verify it matches the build's PRODUCTION_PROVISIONING_PUBKEY_B64U, " +
            "then power off the device.",
        style = MaterialTheme.typography.bodySmall,
    )
}

@Composable
private fun OperatingBody(
    hasKey: Boolean,
    canonicalUtf8: String?,
    canonicalHashB64u: String?,
    signatureB64u: String?,
    scope: kotlinx.coroutines.CoroutineScope,
    state: SigningState,
) {
    val clipboard = LocalClipboardManager.current
    if (!hasKey) {
        Text(
            "No provisioning key present. Refusing to sign. " +
                "Run the ceremony first (KEY-CUSTODY §2).",
            style = MaterialTheme.typography.bodyMedium,
        )
        return
    }

    if (signatureB64u != null) {
        SignatureBody(signatureB64u, clipboard, state, scope)
        return
    }

    if (canonicalUtf8 == null) {
        CanonicalInputBody(state, scope)
        return
    }

    CanonicalReviewBody(canonicalUtf8, canonicalHashB64u, clipboard, state, scope)
}

@Composable
private fun CanonicalInputBody(
    state: SigningState,
    scope: kotlinx.coroutines.CoroutineScope,
) {
    var pasteText by remember { mutableStateOf("") }

    val scanLauncher = rememberLauncherForActivityResult(
        contract = ScanContract(),
    ) { result ->
        val contents = result.contents
        if (contents != null) {
            pasteText = contents
            state.setCanonical(contents)
        }
    }

    Text(
        "Load a canonical matrix from the admin app's output.",
        style = MaterialTheme.typography.bodyMedium,
    )
    Spacer(Modifier.height(12.dp))

    Button(onClick = {
        scanLauncher.launch(
            ScanOptions().apply {
                setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                setPrompt("Scan matrix QR")
                setBeepEnabled(false)
                setOrientationLocked(false)
            },
        )
    }) { Text("Scan matrix QR") }

    Spacer(Modifier.height(12.dp))

    OutlinedTextField(
        value = pasteText,
        onValueChange = { pasteText = it },
        label = { Text("Paste canonical matrix") },
        modifier = Modifier.fillMaxWidth(),
    )
    Spacer(Modifier.height(8.dp))
    Button(onClick = { state.setCanonical(pasteText.trim()) }) {
        Text("Load canonical")
    }
}

@Composable
private fun CanonicalReviewBody(
    canonicalUtf8: String,
    canonicalHashB64u: String?,
    clipboard: androidx.compose.ui.platform.ClipboardManager,
    state: SigningState,
    scope: kotlinx.coroutines.CoroutineScope,
) {
    Text("Canonical matrix loaded.", style = MaterialTheme.typography.titleSmall)
    Spacer(Modifier.height(8.dp))
    canonicalHashB64u?.let { h ->
        Text("SHA-256 (base64url):", style = MaterialTheme.typography.labelSmall)
        Text(h, style = MaterialTheme.typography.bodySmall)
        Spacer(Modifier.height(8.dp))
    }
    Text("Canonical bytes:", style = MaterialTheme.typography.labelSmall)
    Card {
        Text(
            canonicalUtf8,
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(12.dp),
        )
    }
    Spacer(Modifier.height(8.dp))
    Row {
        Button(onClick = { scope.launch { state.sign() } }) {
            Text("Sign")
        }
        Spacer(Modifier.width(8.dp))
        Button(onClick = {
            clipboard.setText(AnnotatedString(canonicalUtf8))
        }) { Text("Copy canonical") }
    }
    Spacer(Modifier.height(8.dp))
    Button(onClick = { state.clearSignature() }) {
        Text("Discard and load another")
    }
}

@Composable
private fun SignatureBody(
    signatureB64u: String,
    clipboard: androidx.compose.ui.platform.ClipboardManager,
    state: SigningState,
    scope: kotlinx.coroutines.CoroutineScope,
) {
    Text("Signature ready.", style = MaterialTheme.typography.titleSmall)
    Spacer(Modifier.height(8.dp))
    val qrBitmap = remember(signatureB64u) {
        try {
            BarcodeEncoder().encodeBitmap(signatureB64u, BarcodeFormat.QR_CODE, 640, 640)
        } catch (_: Exception) {
            null
        }
    }
    qrBitmap?.let { bmp ->
        Image(
            bitmap = bmp.asImageBitmap(),
            contentDescription = "Signature QR",
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(8.dp))
    }
    Card {
        Text(
            signatureB64u,
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(12.dp),
        )
    }
    Spacer(Modifier.height(8.dp))
    Button(onClick = { clipboard.setText(AnnotatedString(signatureB64u)) }) {
        Text("Copy signature")
    }
    Spacer(Modifier.height(8.dp))
    Button(onClick = { state.clearSignature() }) {
        Text("Sign another matrix")
    }
}
