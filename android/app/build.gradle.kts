plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.umoja.secure"
    compileSdk {
        version = release(36) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        applicationId = "com.umoja.secure"
        minSdk = 30
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // P1-033c: signing flavor split.
    //
    // Two build flavors:
    //   - client:  the ordinary Umoja app. Full transport, WebSocket,
    //              matrix verification. SIGNING_ONLY=false.
    //   - signing: the offline ceremony device. NO transport code
    //              reachable (TransportConfig throws), NO WebSocket
    //              (UmojaApplication short-circuits), NO matrix
    //              verification (ProvisioningKeys routing does not
    //              apply), NO MainActivity (removed via src/signing/
    //              AndroidManifest.xml). Only SigningActivity, only
    //              reachable via ADB. SIGNING_ONLY=true.
    //
    // Workflow cost: gradle task names gain the flavor prefix.
    //   installDebug            -> installClientDebug
    //   testDebugUnitTest       -> testClientDebugUnitTest
    //   connectedAndroidTest    -> connectedClientAndroidTest
    // Session entries before Z-17 used the pre-flavor names; they
    // are historical, not corrected.
    flavorDimensions += "mode"
    productFlavors {
        create("client") {
            dimension = "mode"
            buildConfigField("boolean", "SIGNING_ONLY", "false")
        }
        create("signing") {
            dimension = "mode"
            applicationIdSuffix = ".signing"
            versionNameSuffix = "-signing"
            buildConfigField("boolean", "SIGNING_ONLY", "true")
        }
    }

    buildTypes {
        release {
            optimization {
                enable = true
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
        isCoreLibraryDesugaringEnabled = true
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
}

dependencies {
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation(libs.libsignal.android)
    implementation(libs.libsignal.client)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.material3)
    implementation("androidx.compose.material:material-icons-extended:1.7.0")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation("org.bouncycastle:bcprov-jdk18on:1.79")
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.5")
    testImplementation(libs.junit)
    testImplementation("org.json:json:20240303")
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    debugImplementation(libs.androidx.compose.ui.tooling)
}