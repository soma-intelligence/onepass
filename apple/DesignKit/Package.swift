// swift-tools-version: 6.2
import PackageDescription

// DesignKit pulls OnePassCore (VaultKit's bindings product) for FfiItemType and itemTypes(),
// not the VaultKit product, which does not build on watchOS. VaultKit's manifest
// reads ONEPASS_FFI_XCFRAMEWORK (path relative to the VaultKit directory), so
// `make test` passes the same variable to both packages.
let package = Package(
    name: "DesignKit",
    defaultLocalization: "fr",
    platforms: [.iOS("26.0"), .macOS("26.0"), .visionOS("26.0"), .watchOS("26.0")],
    products: [
        .library(name: "DesignKit", targets: ["DesignKit"])
    ],
    dependencies: [
        .package(path: "../VaultKit")
    ],
    targets: [
        .target(
            name: "DesignKit",
            dependencies: [.product(name: "OnePassCore", package: "VaultKit")],
            resources: [.process("Resources")]
        ),
        .testTarget(
            name: "DesignKitTests",
            dependencies: ["DesignKit", .product(name: "VaultKit", package: "VaultKit")]
        ),
    ],
    swiftLanguageModes: [.v6]
)
