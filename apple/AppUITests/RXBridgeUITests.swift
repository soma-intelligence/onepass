import DesignBridgeUITesting
import XCTest

/// The RX look ("Nouveau design") on the DesignBridge rules, on the demo account (Debug
/// `-OnePassDemoData`, fictional values only): a copy and an error each show a toast, the last
/// row of every page clears the tab bar, no screen shows the same action twice, and the
/// accessibility audit passes. With `DB_SCREENSHOT_DIR` set on the runner, it also writes the
/// captures `dbdiff` compares with the Penpot boards (home, watchtower, settings, password).
@MainActor
final class RXBridgeUITests: DBUITestCase {
    /// The demo account uses a real Argon2id: seeding takes a while on a busy Mac.
    private static let seedTimeout: TimeInterval = 600
    private static let uiTimeout: TimeInterval = 15

    /// English, so the captures read like the Penpot boards. `DB_THEME` picks the appearance.
    override var launchConfiguration: DBLaunchConfiguration {
        configurationOverride ?? .fromEnvironment(defaults: DBLaunchConfiguration(locale: "en_US"))
    }

    private static let demo = [
        "-OnePassDemoData", "YES", "-OnePassRX", "YES", "-OnePassDemoBiometrics", "NO",
        "-OnePassDemoCrypto", "NO",
    ]

    /// Launches the demo account in the RX look with `extra` arguments, then waits for `ready`.
    @discardableResult
    private func launch(_ extra: [String] = [], ready: String) -> XCUIElement {
        var config = launchConfiguration
        config.extraArguments += Self.demo + extra
        launchApp(config)
        let marker = element(ready)
        XCTAssertTrue(marker.waitForExistence(timeout: Self.seedTimeout), "\(ready) not shown")
        return marker
    }

    private func element(_ id: String) -> XCUIElement {
        app.descendants(matching: .any)[id].firstMatch
    }

    /// The capture name of a screen, the same as the Penpot export it pairs with in `dbdiff`
    /// (`iphone-home-light@3x.png`).
    private func captureName(_ screen: String) -> String {
        "iphone-\(screen)-\(launchConfiguration.theme == .dark ? "dark" : "light")"
    }

    // MARK: Toasts

    /// Copying the one-time code from the code card shows the success toast, which then goes.
    func testCopyShowsToast() {
        launch(["-OnePassDemoItem", "Forge Atlas"], ready: "item.title")
        let copy = app.buttons.matching(NSPredicate(format: "identifier BEGINSWITH 'field.copy.'")).firstMatch
        XCTAssertTrue(copy.waitForExistence(timeout: Self.uiTimeout), "no copy button on the item")
        copy.tap()
        assertToast("Copied", disappearsWithin: 10)
    }

    /// A broken invitation link shows the error toast (the same words as the classic look).
    func testErrorShowsToast() throws {
        launch(ready: "rx.home.score")
        let link = try XCTUnwrap(URL(string: "onepass://org/join?invite=not-a-real-invite"))
        // The first open can relaunch the app before it handles the link; the second reaches the
        // running, unlocked vault.
        openLink(link)
        XCTAssertTrue(element("rx.home.score").waitForExistence(timeout: Self.seedTimeout))
        openLink(link)
        assertToast("isn't valid", timeout: 8)
    }

    // MARK: Last row and duplicate actions

    func testHome() throws {
        launch(ready: "rx.home.score")
        assertNoDuplicateActions()
        saveScreenshot(named: captureName("home"))
        assertLastRowReachable()
    }

    func testWatchtower() throws {
        launch(["-OnePassDemoTab", "watchtower"], ready: "rx.watchtower.stat.weak")
        assertNoDuplicateActions()
        saveScreenshot(named: captureName("watchtower"))
        assertLastRowReachable()
    }

    func testSettings() throws {
        launch(["-OnePassDemoSettings", "YES"], ready: "settings.general")
        assertNoDuplicateActions()
        saveScreenshot(named: captureName("settings"))
        assertLastRowReachable()
    }

    func testItem() throws {
        launch(["-OnePassDemoItem", "Forge Atlas"], ready: "item.title")
        // The back button and the tab are both "Items": the system's navigation, not two actions.
        assertNoDuplicateActions(ignoring: ["Items"])
        saveScreenshot(named: captureName("password"))
        assertLastRowReachable()
    }

    // MARK: Accessibility

    func testHomeAccessibilityAudit() throws {
        launch(ready: "rx.home.score")
        settle()
        try assertAccessibilityAudit()
    }

    func testItemAccessibilityAudit() throws {
        launch(["-OnePassDemoItem", "Forge Atlas"], ready: "item.title")
        settle()
        try assertAccessibilityAudit()
    }

    // MARK: Private

    /// Opens `url` in the app, accepting the system's "Open in Kelid?" prompt when it shows.
    private func openLink(_ url: URL) {
        app.open(url)
        let open = XCUIApplication(bundleIdentifier: "com.apple.springboard").buttons["Open"]
        if open.waitForExistence(timeout: 3) { open.tap() }
    }

    /// Lets transitions and the hero fade settle, so the audit measures the resting screen.
    private func settle() {
        RunLoop.current.run(until: Date().addingTimeInterval(2))
    }

    /// Accepted audit issues of the RX screens, each with its reason.
    override var auditAllowlist: [DBAuditAllowance] {
        [
            DBAuditAllowance(.dynamicType, label: "CD",
                             reason: "account initials inside a fixed avatar disc; the name next to it scales"),
            DBAuditAllowance(.hitRegion, label: "Password Strength",
                             reason: "the strength meter is a read-only value, not a control"),
            DBAuditAllowance(.sufficientElementDescription, identifier: "item.url.open.0",
                             reason: "the website address is the content of the row"),
            DBAuditAllowance(.contrast, label: "Carte Visa Exemple",
                             reason: "at rest it sits under the tab bar glass; it scrolls clear of it"),
            DBAuditAllowance(.contrast, label: "Forge Atlas",
                             reason: "at rest it sits under the tab bar glass; it scrolls clear of it"),
            DBAuditAllowance(.contrast, label: "Messagerie Exemple",
                             reason: "at rest it sits under the tab bar glass; it scrolls clear of it"),
            DBAuditAllowance(.contrast, label: "Wi-Fi Maison",
                             reason: "at rest it sits under the tab bar glass; it scrolls clear of it"),
            DBAuditAllowance(.contrast, label: "Tags",
                             reason: "at rest it sits under the tab bar glass; it scrolls clear of it"),
            DBAuditAllowance(.contrast, label: "Travail",
                             reason: "at rest it sits under the tab bar glass; it scrolls clear of it"),
            DBAuditAllowance(.contrast, label: "Excellent",
                             reason: "at rest it sits under the tab bar glass; it scrolls clear of it"),
            DBAuditAllowance(.contrast, label: "LOGIN",
                             reason: "at rest it sits under the tab bar glass; it scrolls clear of it"),
            DBAuditAllowance(.contrast, label: "Camille Durand",
                             reason: "at rest it sits under the tab bar glass; it scrolls clear of it"),
            DBAuditAllowance(.contrast, label: "Vaults",
                             reason: "at rest it sits under the tab bar glass; it scrolls clear of it"),
            DBAuditAllowance(.contrast, label: "1",
                             reason: "at rest it sits under the tab bar glass; it scrolls clear of it"),
            DBAuditAllowance(.contrast, identifier: "item.notes",
                             reason: "at rest the Forge Atlas notes card sits under the tab bar glass; it scrolls clear of it"),
            DBAuditAllowance(.contrast, label: "Notes",
                             reason: "the notes card's title, under the tab bar glass at rest; it scrolls clear of it"),
        ]
    }

    /// Scrolls to the end of the page, then checks its lowest button is hittable and above the
    /// tab bar (UX-SAFE-02).
    private func assertLastRowReachable(file: StaticString = #filePath, line: UInt = #line) {
        let scroller = app.scrollViews.firstMatch
        for _ in 0..<8 { scroller.exists ? scroller.swipeUp() : app.swipeUp() }
        let window = app.windows.firstMatch.frame
        let buttons = scroller.exists ? scroller.buttons.allElementsBoundByIndex : app.buttons.allElementsBoundByIndex
        let last = buttons
            .filter { $0.exists && window.intersects($0.frame) && !$0.frame.isEmpty }
            .max { $0.frame.maxY < $1.frame.maxY }
        guard let last else {
            XCTFail("no button on the page", file: file, line: line)
            return
        }
        assertReachable(lastElement: last, in: scroller.exists ? scroller : nil, maxSwipes: 2, file: file, line: line)
    }
}
