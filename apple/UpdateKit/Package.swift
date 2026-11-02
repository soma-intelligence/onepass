// swift-tools-version: 6.2
import PackageDescription

// Updates of the Developer ID Mac app through Sparkle (spec
// docs/superpowers/specs/2026-11-02-mac-updater-design.md). Mac only: the
// OnePass target links it for its macOS destination; iOS, watchOS and visionOS
// update through the App Store.
let package = Package(
    name: "UpdateKit",
    defaultLocalization: "fr",
    platforms: [.macOS("26.0")],
    products: [
        .library(name: "UpdateKit", targets: ["UpdateKit"])
    ],
    dependencies: [
        // Exact version: SwiftPM checks the binary's checksum from Package.resolved.
        .package(url: "https://github.com/sparkle-project/Sparkle", exact: "2.10.1")
    ],
    targets: [
        .target(
            name: "UpdateKit",
            dependencies: [.product(name: "Sparkle", package: "Sparkle")],
            resources: [.process("Resources")]
        ),
        .testTarget(
            name: "UpdateKitTests",
            dependencies: ["UpdateKit"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
