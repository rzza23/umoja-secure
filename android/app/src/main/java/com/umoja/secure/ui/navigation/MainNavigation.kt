package com.umoja.secure.ui.navigation

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Email
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import com.umoja.secure.ui.contacts.ContactsScreen
import com.umoja.secure.ui.conversations.ConversationsScreen
import com.umoja.secure.ui.settings.SettingsScreen

enum class Tab(val label: String, val icon: ImageVector) {
    Conversations("Conversations", Icons.Filled.Email),
    Contacts("Contacts", Icons.Filled.Person),
    Settings("Settings", Icons.Filled.Settings),
}

@Composable
fun MainNavigation(
    onLogout: () -> Unit,
    onOpenAdmin: (() -> Unit)?,
    onOpenDiagnostics: () -> Unit,
) {
    var selected by remember { mutableStateOf(Tab.Conversations) }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        bottomBar = {
            NavigationBar {
                Tab.entries.forEach { tab ->
                    NavigationBarItem(
                        selected = selected == tab,
                        onClick = { selected = tab },
                        icon = { Icon(tab.icon, contentDescription = tab.label) },
                        label = { Text(tab.label) },
                    )
                }
            }
        },
    ) { innerPadding ->
        val contentModifier = Modifier.padding(innerPadding)
        when (selected) {
            Tab.Conversations -> ConversationsScreen(contentModifier)
            Tab.Contacts -> ContactsScreen(contentModifier)
            Tab.Settings -> SettingsScreen(
                onLogout = onLogout,
                onOpenAdmin = onOpenAdmin,
                onOpenDiagnostics = onOpenDiagnostics,
                modifier = contentModifier,
            )
        }
    }
}
