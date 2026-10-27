// swift-tools-version: 6.2
import PackageDescription

// SafariRelay: the transport between the Safari Web Extension handler and the
// OnePass bridge host. Pure Swift (Foundation only), so `swift test` runs it
// without the Rust core or a signed app.
let package = Package(
    name: "SafariRelay",
    platforms: [.macOS("26.0")],
    products: [
        .library(name: "SafariRelay", targets: ["SafariRelay"])
    ],
    targets: [
        .target(name: "SafariRelay"),
        .testTarget(name: "SafariRelayTests", dependencies: ["SafariRelay"]),
    ],
    swiftLanguageModes: [.v6]
)
