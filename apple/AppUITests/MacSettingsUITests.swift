#if os(macOS)
import XCTest

/// Réglages on the Mac, on the demo account (Debug demo data only, fictional items). Target
/// `OnePassMacUITests`, scheme `OnePassMacUITests` (the iPhone `SettingsUITests` live in
/// `SettingsUITests.swift`, iOS only).
@MainActor
final class SettingsUITests: XCTestCase {
    private static let seedTimeout: TimeInterval = 600
    private static let uiTimeout: TimeInterval = 15

    private var app: XCUIApplication!

    override func setUp() async throws {
        continueAfterFailure = false
        app = XCUIApplication()
        app.launchArguments += [
            "-OnePassDemoData", "YES", "-OnePassRX", "NO", "-OnePassDemoBiometrics", "NO", "-OnePassDemoCrypto", "NO",
            // French, the source language: the labels below are the French ones.
            "-AppleLanguages", "(fr)", "-AppleLocale", "fr_FR",
        ]
        app.launch()
    }

    private func element(_ id: String) -> XCUIElement {
        app.descendants(matching: .any)[id].firstMatch
    }

    /// Remplissage automatique > Remplir partout, opened by the helper's link
    /// (`onepass://settings/fill-anywhere`): the page shows the Accessibility row and, with no
    /// grant reported by OnePass Fill (it is not running in a test), "Ouvrir les réglages".
    /// Nothing is toggled: the login item is never registered from a test.
    func testFillAnywherePageShowsAccessibilityStep() throws {
        let window = app.windows.firstMatch
        XCTAssertTrue(window.waitForExistence(timeout: Self.seedTimeout), "main window not shown")
        // The demo account unlocks once its items are seeded.
        let seeded = app.descendants(matching: .any).matching(
            NSPredicate(format: "label CONTAINS 'Forge Atlas' OR identifier CONTAINS 'Forge Atlas'")
        ).firstMatch
        XCTAssertTrue(seeded.waitForExistence(timeout: Self.seedTimeout), "demo vault not shown")

        app.open(URL(string: "onepass://settings/fill-anywhere")!)

        let accessibility = element("fillAnywhere.accessibility")
        XCTAssertTrue(accessibility.waitForExistence(timeout: Self.uiTimeout), "Remplir partout did not open")
        let open = element("fillAnywhere.accessibility.open")
        XCTAssertTrue(open.waitForExistence(timeout: Self.uiTimeout), "no Ouvrir les réglages without the grant")
        XCTAssertEqual(open.label, "Ouvrir les réglages")
        XCTAssertTrue(element("fillAnywhere.enabled").exists, "no Remplir partout toggle")

        let shot = XCTAttachment(screenshot: app.screenshot())
        shot.name = "fill-anywhere"
        shot.lifetime = .keepAlways
        add(shot)
    }
}
#endif
