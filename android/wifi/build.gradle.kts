plugins {
    alias(libs.plugins.android.library)
}

// Automatic Wi-Fi: the router items of the vault become Android network
// suggestions. No dependency on the Rust core, so its unit tests run on the
// JVM alone; :app feeds it the router items it reads from the vault.
android {
    namespace = "me.somalabs.onepass.wifi"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
    }

    // The same two distributions as :app (Play Store, F-Droid).
    flavorDimensions += "distribution"
    productFlavors {
        create("play") { dimension = "distribution" }
        create("fdroid") { dimension = "distribution" }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests.all {
            it.useJUnitPlatform()
        }
    }
}

dependencies {
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}
