// swift-tools-version: 6.2
import Foundation
import PackageDescription

// The Rust core as an XCFramework. `make core` builds the shipped one
// (release, three slices); `make test` builds a macOS-only debug one with the
// dev-fast-kdf floor and points ONEPASS_FFI_XCFRAMEWORK at it (path relative
// to this package directory: SwiftPM rejects absolute binary target paths).
// An empty value counts as unset.
let ffiPath: String = {
    let value = ProcessInfo.processInfo.environment["ONEPASS_FFI_XCFRAMEWORK"] ?? ""
    return value.isEmpty ? "../build/OnePassFFI.xcframework" : value
}()

let package = Package(
    name: "VaultKit",
    defaultLocalization: "fr",
    platforms: [.iOS("26.0"), .macOS("26.0"), .watchOS("26.0"), .visionOS("26.0")],
    products: [
        .library(name: "VaultKit", targets: ["VaultKit"]),
        .library(name: "OnePassCore", targets: ["OnePassCore"]),
    ],
    targets: [
        .binaryTarget(name: "OnePassFFI", path: ffiPath),
        // Generated UniFFI bindings only (see apple/scripts/build-core.sh).
        .target(
            name: "OnePassCore",
            dependencies: ["OnePassFFI"],
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedFramework("CoreFoundation"),
                .linkedLibrary("c++"),
            ]
        ),
        .target(
            name: "VaultKit",
            dependencies: ["OnePassCore"],
            resources: [.process("Resources")]
        ),
        .testTarget(
            name: "VaultKitTests",
            dependencies: ["VaultKit"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
