// swift-tools-version: 6.2
import PackageDescription

// GlanceKit is pure Swift (widgets and watch glances link it without the Rust
// core). CompanionLink pulls OnePassCore from VaultKit, whose manifest reads
// ONEPASS_FFI_XCFRAMEWORK (path relative to the VaultKit directory), so
// `make test` passes the same variable here.
let package = Package(
    name: "CompanionKit",
    platforms: [.iOS("26.0"), .macOS("26.0"), .watchOS("26.0"), .visionOS("26.0")],
    products: [
        .library(name: "GlanceKit", targets: ["GlanceKit"]),
        .library(name: "CompanionLink", targets: ["CompanionLink"]),
    ],
    dependencies: [
        .package(path: "../VaultKit")
    ],
    targets: [
        .target(name: "GlanceKit"),
        .target(
            name: "CompanionLink",
            dependencies: [.product(name: "OnePassCore", package: "VaultKit")]
        ),
        .testTarget(
            name: "GlanceKitTests",
            dependencies: ["GlanceKit"]
        ),
        .testTarget(
            name: "CompanionLinkTests",
            dependencies: ["CompanionLink", .product(name: "OnePassCore", package: "VaultKit")]
        ),
    ],
    swiftLanguageModes: [.v6]
)
