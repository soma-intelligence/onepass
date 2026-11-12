import me.somalabs.onepass.gradle.GenerateUniffiBindings

plugins {
    alias(libs.plugins.android.library)
}

// The Rust workspace and the host library of cargo's debug build. The
// providers only capture locals of `run`: top-level values are members of
// the build script, which the configuration cache refuses to serialize.
val androidRoot: Directory = rootProject.layout.projectDirectory
val coreRoot: Directory = androidRoot.dir("../core")
val hostLibDir: Provider<Directory> = run {
    val root = androidRoot
    val defaultTarget = coreRoot.dir("target")
    providers.environmentVariable("CARGO_TARGET_DIR")
        .map { root.dir(it) }
        .orElse(defaultTarget)
        .map { it.dir("debug") }
}
val hostLib: Provider<RegularFile> = run {
    val os = System.getProperty("os.name")
    val name = when {
        os.startsWith("Mac") -> "libonepass_ffi.dylib"
        // cargo names a cdylib without the lib prefix on Windows.
        os.startsWith("Windows") -> "onepass_ffi.dll"
        else -> "libonepass_ffi.so"
    }
    hostLibDir.map { it.file(name) }
}

// One feature set for the host library and the bindgen binary: cargo then
// builds onepass-ffi once, and `cargo run` below does not relink the host
// library without dev-fast-kdf (the JVM tests need the dev KDF floor).
// RUSTFLAGS is left alone (android/scripts/common.sh refuses it).
val hostFeatures = "bindgen,dev-fast-kdf"

// The host build of onepass-ffi: the JVM unit tests load it through JNA, and
// the Kotlin bindings are generated from its metadata.
val buildHostCore = tasks.register<Exec>("buildHostCore") {
    group = "onepass"
    description = "Builds the host libonepass_ffi (dev-fast-kdf) and uniffi-bindgen."
    workingDir = coreRoot.asFile
    commandLine(
        "cargo", "build", "-p", "onepass-ffi", "--features", hostFeatures,
        "--lib", "--bin", "uniffi-bindgen",
    )
}

val generateUniffiBindings = tasks.register<GenerateUniffiBindings>("generateUniffiBindings") {
    group = "onepass"
    description = "Generates the Kotlin bindings of onepass-ffi into build/generated/uniffi."
    dependsOn(buildHostCore)
    library.set(hostLib)
    config.set(coreRoot.file("onepass-ffi/uniffi.toml"))
    coreDir.set(coreRoot)
    features.set(hostFeatures)
    outputDir.set(layout.buildDirectory.dir("generated/uniffi"))
}

// libonepass_ffi.so for arm64-v8a and x86_64 into src/main/jniLibs, checked
// for 16 KiB pages. Debug by default; `-Ponepass.coreProfile=release` for a
// release build of the core.
val coreProfile: String = providers.gradleProperty("onepass.coreProfile").getOrElse("debug")
// On Windows a bare `bash` can resolve to WSL's System32\bash.exe, which has
// neither the Windows NDK nor cargo: use Git Bash, or ONEPASS_BASH.
val bash: String = run {
    val explicit = providers.environmentVariable("ONEPASS_BASH").orNull
    when {
        explicit != null -> explicit
        System.getProperty("os.name").startsWith("Windows") ->
            listOf("ProgramFiles", "ProgramW6432")
                .mapNotNull { System.getenv(it) }
                .map { File(it, "Git/bin/bash.exe") }
                .firstOrNull { it.isFile }?.absolutePath
                ?: error("Git Bash not found: install Git for Windows or set ONEPASS_BASH")
        else -> "bash"
    }
}
val buildCore = tasks.register<Exec>("buildCore") {
    group = "onepass"
    description = "Builds libonepass_ffi.so for the Android ABIs (android/scripts/build-core.sh)."
    workingDir = androidRoot.asFile
    commandLine(bash, "scripts/build-core.sh", coreProfile)
}

tasks.named("preBuild") {
    dependsOn(buildCore)
}

android {
    namespace = "me.somalabs.onepass.vaultkit"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        consumerProguardFiles("consumer-rules.pro")
    }

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

androidComponents {
    onVariants { variant ->
        variant.sources.kotlin?.addGeneratedSourceDirectory(
            generateUniffiBindings,
            GenerateUniffiBindings::getOutputDir,
        )
    }
}

tasks.withType<Test>().configureEach {
    dependsOn(buildHostCore)
    // JNA finds the host libonepass_ffi here (the jar's own natives load
    // libjnidispatch).
    systemProperty("jna.library.path", hostLibDir.get().asFile.absolutePath)
}

dependencies {
    // The Android build of JNA (libjnidispatch for each ABI); the JVM tests
    // use the plain jar, which carries the desktop natives.
    implementation("${libs.jna.get()}@aar")
    testImplementation(libs.jna)
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}
