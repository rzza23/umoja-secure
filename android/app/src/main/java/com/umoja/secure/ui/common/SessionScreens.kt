package com.umoja.secure.ui.common

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

/**
 * Loading spinner for [com.umoja.secure.auth.SessionStateManager.State.Authenticating]
 * and [com.umoja.secure.auth.SessionStateManager.State.Reauthenticating].
 *
 * Both states are transient — the state machine single-flights reauth,
 * so this screen appears at most once per reauth cycle, for as long as
 * the challenge-response round-trip takes. The default message is
 * generic because the user-facing distinction between first-auth and
 * reauth is not actionable; the ADR §2 ruling is "no intermediate
 * state visible" on success.
 */
@Composable
fun LoadingScreen(message: String = "Connecting...") {
    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier.fillMaxSize(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            CircularProgressIndicator()
            Spacer(Modifier.height(16.dp))
            Text(
                message,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/**
 * Terminal-state screen for [com.umoja.secure.auth.SessionStateManager.State.Revoked],
 * [com.umoja.secure.auth.SessionStateManager.State.EnrollmentRequired],
 * and [com.umoja.secure.auth.SessionStateManager.State.NetworkFailure].
 *
 * ADR-HARDENING-001 §1's invariant: every terminal and retryable state
 * must give the user "a clear next step." The primary action is always
 * a way forward; the optional secondary is a way out (log out). No
 * "error occurred" without a next step.
 *
 * Deliberately not reusing EnrollmentScreen: enrollment is a form with
 * required fields, whereas terminal states are a message with a single
 * decision. Composing one over the other would either force
 * EnrollmentScreen to grow an "error mode" (confusing) or hide the form
 * behind a transparent overlay (worse).
 */
@Composable
fun TerminalMessageScreen(
    title: String,
    message: String,
    primaryLabel: String,
    onPrimary: () -> Unit,
    secondaryLabel: String? = null,
    onSecondary: (() -> Unit)? = null,
) {
    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Text(title, style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.height(16.dp))
            Text(
                message,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(32.dp))
            Button(onClick = onPrimary, modifier = Modifier.fillMaxWidth()) {
                Text(primaryLabel)
            }
            if (secondaryLabel != null && onSecondary != null) {
                Spacer(Modifier.height(8.dp))
                TextButton(onClick = onSecondary, modifier = Modifier.fillMaxWidth()) {
                    Text(secondaryLabel)
                }
            }
        }
    }
}
