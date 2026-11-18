// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "DesignBridgeTesting",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        // Snapshot matrix on swift-snapshot-testing plus the locale model and pseudo-locale.
        .library(name: "DesignBridgeSnapshots", targets: ["DesignBridgeSnapshots"]),
        // XCUITest base class. Compiles to an empty module outside iOS.
        .library(name: "DesignBridgeUITesting", targets: ["DesignBridgeUITesting"]),
        // SSIM, offset search, diff images and the HTML report.
        .library(name: "DBDiff", targets: ["DBDiff"]),
        .executable(name: "dbdiff", targets: ["DBDiffCLI"]),
    ],
    dependencies: [
        .package(url: "https://github.com/pointfreeco/swift-snapshot-testing", .upToNextMinor(from: "1.19.0")),
    ],
    targets: [
        .target(name: "DBDiff"),
        // The folder is DBDiffCLI because DBDiff and dbdiff collide on case-insensitive file systems.
        .executableTarget(name: "DBDiffCLI", dependencies: ["DBDiff"]),
        .target(
            name: "DesignBridgeSnapshots",
            dependencies: [
                .product(name: "SnapshotTesting", package: "swift-snapshot-testing"),
            ]
        ),
        .target(name: "DesignBridgeUITesting"),
        .testTarget(name: "DBDiffTests", dependencies: ["DBDiff"]),
        .testTarget(name: "DesignBridgeSnapshotsTests", dependencies: ["DesignBridgeSnapshots"]),
        .testTarget(name: "DesignBridgeUITestingTests", dependencies: ["DesignBridgeUITesting"]),
    ]
)
