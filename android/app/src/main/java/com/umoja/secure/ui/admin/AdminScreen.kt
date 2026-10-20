package com.umoja.secure.ui.admin

import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.Image
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import androidx.compose.ui.graphics.asImageBitmap
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.journeyapps.barcodescanner.BarcodeEncoder
import com.google.zxing.BarcodeFormat
import com.umoja.secure.crypto.ProvisioningBundle
import com.umoja.secure.transport.AdminApi
import com.umoja.secure.ui.common.SecureScreen
import kotlinx.coroutines.launch

@Composable
fun AdminScreen(
    onBack: () -> Unit,
    state: AdminScreenState,
    modifier: Modifier = Modifier,
) {
    SecureScreen()
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    BackHandler { onBack() }

    val loading by state.loading.collectAsState()
    val error by state.error.collectAsState()
    val statusMessage by state.statusMessage.collectAsState()
    val devices by state.devices.collectAsState()
    val contacts by state.contacts.collectAsState()
    val scannedBundle by state.scannedBundle.collectAsState()
    val createdToken by state.createdToken.collectAsState()
    val builtWrapperJson by state.builtWrapperJson.collectAsState()
    val builtHash by state.builtHash.collectAsState()
    val importedSignature by state.importedSignature.collectAsState()
    val pushedMatrix by state.pushedMatrix.collectAsState()

    var ownerDeviceId by remember { mutableStateOf("") }
    var contactDeviceId by remember { mutableStateOf("") }
    var provisionClearance by remember { mutableStateOf("") }
    var provisionVersion by remember { mutableStateOf("1") }
    var provisionContacts by remember { mutableStateOf<Set<String>>(emptySet()) }

    val clipboard = LocalClipboardManager.current
    val scanLauncher = rememberLauncherForActivityResult(contract = ScanContract()) { result ->
        val contents = result.contents
        if (contents != null) {
            state.loadBundle(contents)
        }
    }

    val pushScope = rememberCoroutineScope()
    var importedSigText by remember { mutableStateOf("") }
    val sigScanLauncher = rememberLauncherForActivityResult(contract = ScanContract()) { result ->
        val contents = result.contents
        if (contents != null) {
            importedSigText = contents
            state.importSignature(contents)
        }
    }

    LaunchedEffect(Unit) { state.load() }

    Column(modifier.fillMaxSize().padding(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = {
                android.util.Log.d("UmojaNavigation", "Admin Back button tapped")
                onBack()
            }) { Text("Back") }
            Spacer(Modifier.width(8.dp))
            Text("Admin", style = MaterialTheme.typography.headlineSmall)
        }
        Spacer(Modifier.height(12.dp))

        if (loading) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
            return@Column
        }

        LazyColumn(
            verticalArrangement = Arrangement.spacedBy(12.dp),
            modifier = Modifier.fillMaxSize(),
        ) {
            error?.let {
                item { Text("Error: $it", color = MaterialTheme.colorScheme.error) }
            }
            statusMessage?.let {
                item { Text(it, color = MaterialTheme.colorScheme.primary) }
            }

            item { Text("Devices (${devices.size})", style = MaterialTheme.typography.titleMedium) }
            items(devices.size) { i ->
                val d = devices[i]
                Card { Column(Modifier.fillMaxWidth().padding(12.dp)) {
                    Text(d.label, style = MaterialTheme.typography.titleSmall)
                    Text(d.deviceId, style = MaterialTheme.typography.bodySmall)
                    Text("${d.role} / ${d.status}", style = MaterialTheme.typography.bodySmall)
                } }
            }

            item {
                Spacer(Modifier.height(8.dp))
                Text("Provision new device", style = MaterialTheme.typography.titleMedium)
            }
            item {
                Column {
                    var debugPasteText by remember { mutableStateOf("") }
                    val isDebug = (context.applicationInfo.flags and
                        android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0

                    Button(onClick = {
                        val options = ScanOptions().apply {
                            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                            setPrompt("Scan device enrollment QR")
                            setBeepEnabled(false)
                            setOrientationLocked(false)
                        }
                        scanLauncher.launch(options)
                    }) { Text("Scan device QR") }

                    if (isDebug) {
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "Debug: paste QR payload",
                            style = MaterialTheme.typography.labelSmall,
                        )
                        OutlinedTextField(
                            value = debugPasteText,
                            onValueChange = { debugPasteText = it },
                            label = { Text("Enrollment JSON") },
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Spacer(Modifier.height(4.dp))
                        Row {
                            Button(onClick = {
                                state.loadBundle(debugPasteText)
                            }) { Text("Load JSON") }
                            Spacer(Modifier.width(8.dp))
                            TextButton(onClick = { debugPasteText = "" }) { Text("Clear") }
                        }
                    }

                    scannedBundle?.let { b ->
                        Spacer(Modifier.height(8.dp))
                        Card { Column(Modifier.fillMaxWidth().padding(12.dp)) {
                            Text("Scanned device", style = MaterialTheme.typography.titleSmall)
                            Text("device_id: ${b.deviceId}", style = MaterialTheme.typography.bodySmall)
                            Text("auth: ${b.pubDeviceAuthKey.take(12)}...", style = MaterialTheme.typography.bodySmall)
                            Text("msg: ${b.pubMessagingIdentityKey.take(12)}...", style = MaterialTheme.typography.bodySmall)
                            Text("wipe: ${b.pubWipeConfirmationKey.take(12)}...", style = MaterialTheme.typography.bodySmall)
                            Spacer(Modifier.height(8.dp))
                            Button(onClick = {
                                scope.launch { state.createTokenForScannedDevice() }
                            }) { Text("Create enrollment token for this device") }
                            createdToken?.let { t ->
                                Spacer(Modifier.height(8.dp))
                                Text("Token (shown once)", style = MaterialTheme.typography.labelSmall)
                                Text(t.token, style = MaterialTheme.typography.bodySmall)
                                Text("Expires: ${t.expiresAt}", style = MaterialTheme.typography.bodySmall)
                                Spacer(Modifier.height(8.dp))
                                Button(onClick = {
                                    clipboard.setText(AnnotatedString(t.token))
                                    state.setStatusMessage("Token copied")
                                }) { Text("Copy token") }
                            }
                        } }
                    }
                }
            }
            scannedBundle?.let { b ->
                item {
                    Column {
                        OutlinedTextField(
                            value = provisionClearance,
                            onValueChange = { provisionClearance = it },
                            label = { Text("Clearance") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Spacer(Modifier.height(8.dp))
                        OutlinedTextField(
                            value = provisionVersion,
                            onValueChange = { s -> provisionVersion = s.filter { it.isDigit() } },
                            label = { Text("Matrix version") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Text(
                            "Matrix version. Must be higher than any previously issued matrix. " +
                                "Devices reject matrices with version <= their stored version. " +
                                "Use 1 for the first matrix.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
                item {
                    Column {
                        Text(
                            "Permitted contacts (${provisionContacts.size})",
                            style = MaterialTheme.typography.titleSmall,
                        )
                        devices.filter { it.status == "active" && it.deviceId != b.deviceId }.forEach { d ->
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Checkbox(
                                    checked = provisionContacts.contains(d.deviceId),
                                    onCheckedChange = { checked ->
                                        provisionContacts = if (checked) {
                                            provisionContacts + d.deviceId
                                        } else {
                                            provisionContacts - d.deviceId
                                        }
                                    },
                                )
                                Text(
                                    "${d.label} (${d.deviceId.take(8)})",
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                        }
                    }
                }
                item {
                    Button(onClick = {
                        state.buildMatrix(
                            provisionClearance,
                            provisionVersion,
                            provisionContacts.toList(),
                        )
                    }) { Text("Build matrix") }
                }
                builtWrapperJson?.let { w ->
                    item {
                        Card { Column(Modifier.fillMaxWidth().padding(12.dp)) {
                            Text("Unsigned wrapper (JCS-canonical)", style = MaterialTheme.typography.labelSmall)
                            Text(w, style = MaterialTheme.typography.bodySmall)
                        } }
                    }
                }
                builtHash?.let { h ->
                    item {
                        Card { Column(Modifier.fillMaxWidth().padding(12.dp)) {
                            Text("SHA-256 (base64url, no pad)", style = MaterialTheme.typography.labelSmall)
                            Text(h, style = MaterialTheme.typography.bodySmall)
                            Spacer(Modifier.height(8.dp))
                            Row {
                                Button(onClick = {
                                    clipboard.setText(AnnotatedString(builtWrapperJson ?: ""))
                                    state.setStatusMessage("Wrapper copied")
                                }) { Text("Copy wrapper") }
                                Spacer(Modifier.width(8.dp))
                                Button(onClick = {
                                    clipboard.setText(AnnotatedString(h))
                                    state.setStatusMessage("Hash copied")
                                }) { Text("Copy hash") }
                            }
                        } }
                    }
                }
                builtHash?.let { _ ->
                    item {
                        Card { Column(Modifier.fillMaxWidth().padding(12.dp)) {
                            Text("Push signed matrix (TASK-P1-033b)", style = MaterialTheme.typography.titleSmall)
                            Spacer(Modifier.height(8.dp))
                            builtWrapperJson?.let { w ->
                                val qrBitmap = remember(w) {
                                    try {
                                        BarcodeEncoder().encodeBitmap(w, BarcodeFormat.QR_CODE, 640, 640)
                                    } catch (_: Exception) { null }
                                }
                                if (qrBitmap != null) {
                                    Image(
                                        bitmap = qrBitmap.asImageBitmap(),
                                        contentDescription = "Signed matrix QR",
                                        modifier = Modifier.fillMaxWidth(),
                                    )
                                    Spacer(Modifier.height(8.dp))
                                }
                            }
                            OutlinedTextField(
                                value = importedSigText,
                                onValueChange = { importedSigText = it },
                                label = { Text("Signature (86-char base64url)") },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth(),
                            )
                            Spacer(Modifier.height(8.dp))
                            Row {
                                Button(onClick = {
                                    sigScanLauncher.launch(ScanOptions().apply {
                                        setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                                        setPrompt("Scan signature QR")
                                        setBeepEnabled(false)
                                        setOrientationLocked(false)
                                    })
                                }) { Text("Scan signature") }
                                Spacer(Modifier.width(8.dp))
                                Button(onClick = {
                                    state.importSignature(importedSigText.trim())
                                }) { Text("Import signature") }
                            }
                            importedSignature?.let { sig ->
                                Spacer(Modifier.height(8.dp))
                                Text(
                                    "Signature imported: ${sig.take(12)}…",
                                    style = MaterialTheme.typography.bodySmall,
                                )
                                Spacer(Modifier.height(8.dp))
                                Button(
                                    onClick = { pushScope.launch { state.pushSignedMatrix() } },
                                    enabled = pushedMatrix == null,
                                ) {
                                    Text(if (pushedMatrix == null) "Push signed matrix" else "Pushed")
                                }
                                pushedMatrix?.let { pr ->
                                    Spacer(Modifier.height(4.dp))
                                    Text(
                                        "Pushed: ${pr.deviceId.take(8)}… at v${pr.version}",
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                }
                            }
                        } }
                    }
                }
            }

            item {
                Spacer(Modifier.height(8.dp))
                Text("Authorize a contact pair", style = MaterialTheme.typography.titleMedium)
            }
            item {
                Column {
                    OutlinedTextField(
                        value = ownerDeviceId,
                        onValueChange = { ownerDeviceId = it },
                        label = { Text("Owner device ID") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = contactDeviceId,
                        onValueChange = { contactDeviceId = it },
                        label = { Text("Contact device ID") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(8.dp))
                    Button(onClick = {
                        scope.launch { state.authorize(ownerDeviceId, contactDeviceId) }
                    }) { Text("Authorize") }
                }
            }

            item {
                Spacer(Modifier.height(8.dp))
                Text("Active contacts (${contacts.size})", style = MaterialTheme.typography.titleMedium)
            }
            items(contacts.size) { i ->
                val c = contacts[i]
                Card { Column(Modifier.fillMaxWidth().padding(12.dp)) {
                    Text("${c.ownerLabel} -> ${c.contactLabel}", style = MaterialTheme.typography.titleSmall)
                    Text(
                        "${c.ownerDeviceId.take(8)} -> ${c.contactDeviceId.take(8)}",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Text(c.verificationLevel, style = MaterialTheme.typography.bodySmall)
                } }
            }
        }
    }
}