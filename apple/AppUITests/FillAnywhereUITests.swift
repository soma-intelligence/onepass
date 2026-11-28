#if os(macOS)
import AppKit
import XCTest

/// End to end, fill anywhere on the Mac (spec 2026-11-23-mac-fill-anywhere-design, Testing): the
/// Debug OnePass app on demo data, the "OnePass Fill" helper it embeds, and FillLab's hostile
/// fields. For each field the test presses ⌥⌘\, picks "Forge Atlas", then checks the field's
/// value length and the strategy the helper logged. Target `OnePassMacUITests`.
///
/// The helper writes its Debug test log (`-OnePassFillTestLog <path>`, `Fill/FillTestLog.swift`):
/// `trusted=`, `bridge=`, `pill=` and `strategy=` lines. The test skips, and never touches TCC,
/// when the helper has no Accessibility grant or when the bridge refuses it (`appClosed`, which an
/// ad hoc Debug helper always gets: `unsigned_helper`). A team-signed build with the grant runs it.
@MainActor
final class FillAnywhereUITests: XCTestCase {
    private static let seedTimeout: TimeInterval = 600
    private static let uiTimeout: TimeInterval = 15
    private static let fillTimeout: TimeInterval = 30
    /// The demo login and the length of its password (`DemoData`, "tj7N-qe4L-wPz9-Kc2m").
    private static let login = "Forge Atlas"
    private static let passwordLength = 19

    private var app: XCUIApplication!
    private var lab: XCUIApplication!
    private var helperUI: XCUIApplication!
    private var helper: NSRunningApplication?
    private var logURL: URL!
    /// Log lines already looked at: each wait reads only what came after.
    private var seen = 0

    func testFillsEveryLabField() async throws {
        continueAfterFailure = false
        let products = Self.productsDirectory()
        let appURL = products.appendingPathComponent("OnePass.app")
        let helperURL = appURL.appendingPathComponent("Contents/Library/LoginItems/OnePass Fill.app")
        let labURL = products.appendingPathComponent("FillLab.app")
        for url in [appURL, helperURL, labURL] {
            XCTAssertTrue(FileManager.default.fileExists(atPath: url.path), "missing \(url.lastPathComponent)")
        }
        let helperID = try XCTUnwrap(Bundle(url: helperURL)?.bundleIdentifier, "helper has no bundle id")
        guard NSRunningApplication.runningApplications(withBundleIdentifier: helperID).isEmpty else {
            throw XCTSkip("another OnePass Fill (\(helperID)) is running: quit it, then run the test again")
        }

        logURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("onepass-fill-test-\(UUID().uuidString).log")
        addTeardownBlock { @MainActor [weak self] in self?.stopEverything() }

        // 1. The Mac app on the demo vault.
        app = XCUIApplication()
        app.launchArguments += [
            "-OnePassDemoData", "YES", "-OnePassRX", "YES",
            "-OnePassDemoBiometrics", "NO", "-OnePassDemoCrypto", "NO",
        ]
        app.launch()
        let seeded = app.descendants(matching: .any).matching(
            NSPredicate(format: "label CONTAINS %@ OR identifier CONTAINS %@", Self.login, Self.login)
        ).firstMatch
        XCTAssertTrue(seeded.waitForExistence(timeout: Self.seedTimeout), "demo vault not shown")

        // 2. The helper, launched by LaunchServices so that it is its own responsible process for
        // Accessibility (a child of the runner would be judged by the runner's grant).
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.arguments = ["-OnePassFillTestLog", logURL.path]
        configuration.activates = false
        configuration.createsNewApplicationInstance = true
        configuration.addsToRecentItems = false
        helper = try await NSWorkspace.shared.openApplication(at: helperURL, configuration: configuration)
        helperUI = XCUIApplication(bundleIdentifier: helperID)

        let trusted = try await nextLine("trusted=", timeout: Self.uiTimeout)
        guard trusted == "trusted=true" else {
            throw XCTSkip(
                "OnePass Fill is not trusted for Accessibility. Grant it in System Settings > Privacy & "
                    + "Security > Accessibility by hand, then run again (the test never changes TCC).")
        }
        let bridge = try await nextLine("bridge=", timeout: Self.uiTimeout)
        guard bridge != "bridge=appClosed" else {
            throw XCTSkip(
                "The bridge refused OnePass Fill (appClosed). An ad hoc Debug helper is refused as "
                    + "unsigned_helper and the Debug app does not listen: run on a team-signed build.")
        }
        XCTAssertEqual(bridge, "bridge=unlocked", "demo vault not unlocked for the helper")

        // 3. FillLab. Its window title is the login's: native fields find it through the picker's
        // first search, the window title.
        lab = XCUIApplication(url: labURL)
        lab.launchArguments += ["-FillLabWindowTitle", Self.login]
        lab.launch()
        XCTAssertTrue(window.waitForExistence(timeout: Self.uiTimeout), "FillLab window not shown")

        // 4. One fill per hostile field, then the field that must be left alone.
        try await fill(labField("filllab.secure"), expect: "accessibility")
        try await fill(labField("filllab.custom"), expect: "typing")
        try await fill(labField("filllab.labelled"), expect: "accessibility")
        try await fill(labField("filllab.clearing"), expect: "typing")
        let web = lab.webViews.firstMatch.secureTextFields.firstMatch
        XCTAssertTrue(web.waitForExistence(timeout: Self.uiTimeout), "web view password field not shown")
        try await fill(web, expect: "accessibility")
        try await leftAlone(labField("filllab.hint"))
    }

    // MARK: Steps

    /// Clicks `field`, waits for the pill, presses ⌥⌘\, picks the login and checks the result.
    private func fill(_ field: XCUIElement, expect strategy: String) async throws {
        XCTAssertTrue(field.waitForExistence(timeout: Self.uiTimeout), "\(field) not shown")
        // Lines left by the previous field (a pill shown again after its fill) do not count.
        _ = newLines()
        field.click()
        let pill = try await nextLine("pill=", timeout: Self.uiTimeout)
        XCTAssertEqual(pill, "pill=password", "the pill did not show as a password field's")

        lab.typeKey("\\", modifierFlags: [.command, .option])
        let row = helperUI.descendants(matching: .any).matching(
            NSPredicate(format: "label BEGINSWITH %@", Self.login)
        ).firstMatch
        XCTAssertTrue(row.waitForExistence(timeout: Self.uiTimeout), "\(Self.login) not offered in the picker")
        // A click at the row's screen point, through FillLab: the picker is a non-activating panel,
        // and activating the helper would move the focus the fill is guarded on.
        click(at: row.frame)

        let used = try await nextLine("strategy=", timeout: Self.fillTimeout)
        XCTAssertEqual(used, "strategy=\(strategy)", "wrong strategy for \(field)")
        XCTAssertEqual((field.value as? String)?.count, Self.passwordLength, "wrong value length in \(field)")
    }

    /// A plain field titled "Password hint": no pill, nothing filled.
    private func leftAlone(_ field: XCUIElement) async throws {
        XCTAssertTrue(field.waitForExistence(timeout: Self.uiTimeout), "\(field) not shown")
        // Lines left by the previous field (a pill shown again after its fill) do not count.
        _ = newLines()
        field.click()
        try await Task.sleep(for: .seconds(2))
        XCTAssertNil(newLines().first { $0.hasPrefix("pill=") }, "a pill showed next to the hint field")
        XCTAssertFalse(helperUI.descendants(matching: .any)["fill.pill"].exists, "pill shown for the hint field")
        XCTAssertEqual((field.value as? String) ?? "", "", "the hint field was filled")
    }

    // MARK: Helpers

    private var window: XCUIElement { lab.windows["filllab.window"].firstMatch }

    private func labField(_ id: String) -> XCUIElement {
        lab.descendants(matching: .any)[id].firstMatch
    }

    /// Clicks the screen point at the centre of `frame` (screen coordinates, top left).
    private func click(at frame: CGRect) {
        let origin = window.frame.origin
        window.coordinate(withNormalizedOffset: .zero)
            .withOffset(CGVector(dx: frame.midX - origin.x, dy: frame.midY - origin.y))
            .click()
    }

    /// Every line of the helper's test log so far.
    private func logLines() -> [String] {
        let text = (try? String(contentsOf: logURL, encoding: .utf8)) ?? ""
        return text.split(separator: "\n").map(String.init)
    }

    /// The log lines written since the last look, marked as seen.
    private func newLines() -> [String] {
        let lines = logLines()
        guard lines.count > seen else { return [] }
        defer { seen = lines.count }
        return Array(lines[seen...])
    }

    /// The first unseen line that starts with `prefix`. It and the lines before it are marked as
    /// seen; the lines after it stay for the next wait.
    private func nextLine(_ prefix: String, timeout: TimeInterval) async throws -> String {
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            let lines = logLines()
            if lines.count > seen, let index = lines[seen...].firstIndex(where: { $0.hasPrefix(prefix) }) {
                seen = index + 1
                return lines[index]
            }
            try await Task.sleep(for: .milliseconds(200))
        } while Date() < deadline
        throw MissingLine(prefix: prefix, timeout: timeout)
    }

    private struct MissingLine: Error, CustomStringConvertible {
        let prefix: String
        let timeout: TimeInterval
        var description: String { "no \(prefix) line in the helper's test log within \(Int(timeout)) s" }
    }

    private func stopEverything() {
        lab?.terminate()
        if let helper, !helper.isTerminated {
            helper.terminate()
        }
        app?.terminate()
        if let logURL { try? FileManager.default.removeItem(at: logURL) }
    }

    /// `Build/Products/Debug`: four levels above this bundle
    /// (`OnePassMacUITests-Runner.app/Contents/PlugIns/OnePassMacUITests.xctest`).
    private static func productsDirectory() -> URL {
        var url = Bundle(for: FillAnywhereUITests.self).bundleURL
        for _ in 0..<4 { url.deleteLastPathComponent() }
        return url
    }
}
#endif
