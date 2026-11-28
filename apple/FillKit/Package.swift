// swift-tools-version: 6.2
import PackageDescription

// Pure logic for filling logins anywhere on the Mac (spec
// docs/superpowers/specs/2026-11-23-mac-fill-anywhere-design.md): field kind, match target,
// fill steps and focus guard, all over snapshots. No AppKit, no Accessibility calls.
let package = Package(
    name: "FillKit",
    platforms: [.macOS("26.0")],
    products: [
        .library(name: "FillKit", targets: ["FillKit"])
    ],
    targets: [
        .target(name: "FillKit"),
        .testTarget(
            name: "FillKitTests",
            dependencies: ["FillKit"],
            resources: [.copy("Fixtures")]
        ),
    ],
    swiftLanguageModes: [.v6]
)
