import XCTest

/// The unfolded iPhone layout (list and detail side by side) on a window at least 600 pt wide, the
/// tabs below that. On the iPhone Duo simulator the unfolded inner screen is 669 pt wide in
/// portrait and the cover screen 466 pt, so this checks whichever screen the test runs on.
/// Demonstration data only (Debug `-OnePassDemoData`, fictional values, a temporary database).
@MainActor
final class FoldLayoutUITests: XCTestCase {
    override func setUp() {
        continueAfterFailure = false
    }

    func testLayoutFollowsWindowWidth() throws {
        let app = XCUIApplication()
        guard UIDevice.current.userInterfaceIdiom == .phone else {
            throw XCTSkip("The unfolded layout is iPhone only.")
        }
        app.launchArguments += ["-OnePassDemoData", "YES", "-OnePassDemoBiometrics", "NO"]
        app.launch()

        let fold = app.descendants(matching: .any)["fold.split"].firstMatch
        let tabs = app.descendants(matching: .any)["tab.items"].firstMatch
        // One of the two layouts once the demo vault is open; the width is read only then, since
        // the window settles on its screen while the app launches.
        let shown = NSPredicate { _, _ in fold.exists || tabs.exists }
        let ready = XCTNSPredicateExpectation(predicate: shown, object: nil)
        XCTAssertEqual(XCTWaiter().wait(for: [ready], timeout: 90), .completed, "no layout shown")

        let width = app.windows.firstMatch.frame.width
        if FoldLayoutUITests.isUnfolded(width) {
            XCTAssertTrue(fold.exists, "unfolded layout not shown at \(width) pt")
            XCTAssertFalse(tabs.exists, "tabs shown on an unfolded iPhone at \(width) pt")
        } else {
            XCTAssertTrue(tabs.exists, "tabs not shown at \(width) pt")
            XCTAssertFalse(fold.exists, "unfolded layout shown on a folded iPhone at \(width) pt")
        }
    }

    /// `FoldLayout.minWidth` in DesignKit, which the UI test target does not link.
    private static func isUnfolded(_ width: CGFloat) -> Bool {
        width >= 600
    }
}
