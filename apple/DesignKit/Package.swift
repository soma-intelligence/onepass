// swift-tools-version: 6.2
import PackageDescription

// DesignKit pulls VaultKit for FfiItemType and itemTypes(). VaultKit's manifest
// reads ONEPASS_FFI_XCFRAMEWORK (path relative to the VaultKit directory), so
// `make test` passes the same variable to both packages.
let package = Package(
    name: "DesignKit",
    defaultLocalization: "fr",
    platforms: [.iOS("26.0"), .macOS("26.0"), .visionOS("26.0")],
    products: [
        .library(name: "DesignKit", targets: ["DesignKit"])
    ],
    dependencies: [
        .package(path: "../VaultKit")
    ],
    targets: [
        .target(
            name: "DesignKit",
            dependencies: [.product(name: "VaultKit", package: "VaultKit")],
            resources: [.process("Resources")]
        ),
        .testTarget(
            name: "DesignKitTests",
            dependencies: ["DesignKit"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
