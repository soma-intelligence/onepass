// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "DesignBridgeKit",
    defaultLocalization: "en",
    platforms: [.iOS(.v26), .macOS(.v26), .watchOS(.v26), .visionOS(.v26)],
    products: [
        .library(name: "DesignBridgeKit", targets: ["DesignBridgeKit"]),
    ],
    targets: [
        .target(name: "DesignBridgeKit", resources: [.process("Resources")]),
        .testTarget(name: "DesignBridgeKitTests", dependencies: ["DesignBridgeKit"]),
    ]
)
