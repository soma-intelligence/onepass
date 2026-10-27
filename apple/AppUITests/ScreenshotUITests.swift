import XCTest

/// iPhone and iPad captures for the visual review, run by `scripts/screenshots.sh` only: skipped
/// unless `ONEPASS_SCREENSHOT_DIR` is set (xcodebuild passes `TEST_RUNNER_ONEPASS_SCREENSHOT_DIR`).
/// Demonstration data only (Debug `-OnePassDemoData`, fictional values), the onboarding on an
/// emptied store. `ONEPASS_SCREENSHOT_DEVICE` names the files (`iphone`, `ipad`),
/// `ONEPASS_SCREENSHOT_LANDSCAPE=1` turns the device first (the simulator has no rotate command).
@MainActor
final class ScreenshotUITests: XCTestCase {
    private struct Screen {
        let name: String
        let arguments: [String]
        /// Shown once the screen is ready.
        let ready: String
    }

    /// The list waits for its first row by title (a lazy list only exposes the rows on screen).
    private static let screens: [Screen] = [
        Screen(name: "welcome", arguments: isolated + ["-OnePassUITestReset", "YES"], ready: "onboarding.create"),
        Screen(name: "locked", arguments: demo + ["-OnePassDemoLocked", "YES"], ready: "lock.password"),
        Screen(name: "list", arguments: demo + ["-OnePassDemoTab", "search"], ready: "list.row.API Cartes Atlas"),
        Screen(name: "detail", arguments: demo + ["-OnePassDemoItem", "Forge Atlas"], ready: "item.title"),
        Screen(
            name: "edit", arguments: demo + ["-OnePassDemoItem", "Forge Atlas", "-OnePassDebugEdit", "YES"],
            ready: "editor.save"),
        Screen(name: "settings", arguments: demo + ["-OnePassDemoSettings", "YES"], ready: "settings.done"),
    ]

    private static let demo = ["-OnePassDemoData", "YES"]
    /// Debug: the app's own test store, defaults suite and keychain service (never the real ones).
    private static let isolated = ["-OnePassTestIsolation", "YES"]

    override func setUp() async throws {
        continueAfterFailure = false
    }

    func testCaptureScreens() throws {
        let environment = ProcessInfo.processInfo.environment
        guard let folder = environment["ONEPASS_SCREENSHOT_DIR"], !folder.isEmpty else {
            throw XCTSkip("captures only: run apple/scripts/screenshots.sh")
        }
        let device = environment["ONEPASS_SCREENSHOT_DEVICE"] ?? "iphone"
        let directory = URL(fileURLWithPath: folder, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let landscape = environment["ONEPASS_SCREENSHOT_LANDSCAPE"] == "1"
        XCUIDevice.shared.orientation = landscape ? .landscapeLeft : .portrait
        let orientation = landscape ? "-landscape" : ""
        defer {
            XCUIDevice.shared.orientation = .portrait
            XCUIDevice.shared.appearance = .light
            // Empties the isolated test store, defaults suite and keychain service.
            let cleanup = XCUIApplication()
            cleanup.launchArguments += Self.isolated + ["-OnePassUITestReset", "YES"]
            cleanup.launch()
            cleanup.terminate()
        }

        for (suffix, appearance) in [("light", XCUIDevice.Appearance.light), ("dark", .dark)] {
            XCUIDevice.shared.appearance = appearance
            for screen in Self.screens {
                let app = XCUIApplication()
                app.launchArguments += screen.arguments
                app.launch()
                // The demo account is created with the real Argon2id cost.
                let ready = app.descendants(matching: .any)[screen.ready].firstMatch
                XCTAssertTrue(ready.waitForExistence(timeout: 90), "\(screen.name) not shown")
                // Let transitions and the keyboard settle.
                Thread.sleep(forTimeInterval: 1.5)
                let png = XCUIScreen.main.screenshot().pngRepresentation
                let name = "\(device)\(orientation)-\(screen.name)-\(suffix).png"
                try png.write(to: directory.appendingPathComponent(name))
                app.terminate()
            }
        }
    }
}
