package com.umoja.secure

import android.app.Application

/**
 * Umoja Secure application entry point.
 *
 * Phase 1: minimal. Will host service locator / dependency graph in later tasks.
 */
class UmojaApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        // Reserved for service locator initialization (later tasks)
    }
}