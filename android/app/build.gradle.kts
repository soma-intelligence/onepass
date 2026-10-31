plugins {
    alias(libs.plugins.android.application)
}

// The NDK pinned for the core (android/scripts/versions.env): AGP strips
// the debug symbols of libonepass_ffi.so with it when packaging.
val pinnedNdk: String =
    providers.fileContents(rootProject.layout.projectDirectory.file("scripts/versions.env"))
        .asText.get().lineSequence()
        .first { it.startsWith("ANDROID_NDK_VERSION=") }
        .substringAfter("=").trim()

android {
    namespace = "me.somalabs.onepass"
    compileSdk = libs.versions.compileSdk.get().toInt()
    ndkVersion = pinnedNdk

    defaultConfig {
        applicationId = "me.somalabs.onepass"
        minSdk = libs.versions.minSdk.get().toInt()
        targetSdk = libs.versions.targetSdk.get().toInt()
        versionCode = 1
        versionName = "0.1.0"

        // armv7 is left out until the founder asks for it (spec 3.1).
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    // Play Store (FCM) and F-Droid (UnifiedPush) builds.
    flavorDimensions += "distribution"
    productFlavors {
        create("play") { dimension = "distribution" }
        create("fdroid") { dimension = "distribution" }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(project(":vaultkit-android"))
}
