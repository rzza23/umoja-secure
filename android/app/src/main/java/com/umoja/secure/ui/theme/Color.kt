package com.umoja.secure.ui.theme

import androidx.compose.ui.graphics.Color

// ============================================================
// Brand palette — fixed, not dynamic.
//
// Material You is deliberately NOT used. Dynamic color would derive
// the accent from the user's wallpaper, which (a) makes every install
// visually distinct and (b) creates a wallpaper-based fingerprint that
// could correlate users. For a privacy app, the palette must be
// identical on every device regardless of system theme.
// ============================================================

// Dark theme (default)
val BackgroundDark      = Color(0xFF0A0E14)
val SurfaceDark         = Color(0xFF131820)
val SurfaceVariantDark  = Color(0xFF1C222C)
val OutlineDark         = Color(0xFF2A323F)
val OnBackgroundDark    = Color(0xFFE6EAF0)
val OnSurfaceVariantDark= Color(0xFFA8B0BD)

// Signature accent
val Primary             = Color(0xFF00D9C0)
val PrimaryVariant      = Color(0xFF00A896)
val OnPrimary           = Color(0xFF0A0E14)
val PrimaryContainerDark= Color(0xFF00382F)
val OnPrimaryContainer  = Color(0xFF7DFEE8)

// Semantic
val Success             = Color(0xFF4ADE80)
val Warning             = Color(0xFFFBBF24)
val Danger              = Color(0xFFF87171)
val Info                = Color(0xFF60A5FA)

// Cryptographic / special
val Cipher              = Color(0xFF7DD3FC)

// Light theme (mirror)
val BackgroundLight     = Color(0xFFF6F8FB)
val SurfaceLight        = Color(0xFFFFFFFF)
val SurfaceVariantLight = Color(0xFFECF0F5)
val OutlineLight        = Color(0xFFD2D8E0)
val OnBackgroundLight   = Color(0xFF0A0E14)
val OnSurfaceVariantLight = Color(0xFF4A5461)
val PrimaryContainerLight = Color(0xFFCCFBF1)
val OnPrimaryContainerLight = Color(0xFF00221C)
