#if canImport(XCTest) && os(iOS)
import XCTest

/// One allowed accessibility audit issue. Matching is always scoped to an element (identifier or
/// label) and an audit type, never global, so a known false positive cannot hide a new one.
public struct DBAuditAllowance: Sendable, CustomStringConvertible {
    public var auditType: XCUIAccessibilityAuditType
    public var identifier: String?
    public var label: String?
    /// Why the issue is accepted. Required so the allowlist stays reviewable.
    public var reason: String

    public init(_ auditType: XCUIAccessibilityAuditType, identifier: String, reason: String) {
        self.auditType = auditType
        self.identifier = identifier
        self.label = nil
        self.reason = reason
    }

    public init(_ auditType: XCUIAccessibilityAuditType, label: String, reason: String) {
        self.auditType = auditType
        self.identifier = nil
        self.label = label
        self.reason = reason
    }

    @MainActor
    func matches(_ issue: XCUIAccessibilityAuditIssue) -> Bool {
        guard auditType.contains(issue.auditType), let element = issue.element else { return false }
        if let identifier { return element.identifier == identifier }
        if let label { return element.label == label }
        return false
    }

    public var description: String {
        "\(identifier.map { "id \($0)" } ?? label.map { "label \($0)" } ?? "?"): \(reason)"
    }
}

/// Base class for DesignBridge UI flows.
///
/// Subclasses set `launchConfiguration` (or override it) and call `launchApp()` in a test or in
/// `setUp`. Every helper fails the test at the caller's line.
///
/// ```swift
/// final class SettingsFlow: DBUITestCase {
///     override var launchConfiguration: DBLaunchConfiguration { .init(theme: .dark, contentSize: .accessibility5) }
///
///     func testCopyShowsToast() throws {
///         launchApp()
///         app.buttons["copy-password"].tap()
///         assertToast("Copied")
///         try assertAccessibilityAudit()
///     }
/// }
/// ```
@MainActor
open class DBUITestCase: XCTestCase {
    /// The app under test, created by `launchApp()`.
    public private(set) var app = XCUIApplication()

    /// Launch settings. Override in a subclass, or set `configurationOverride` in a test.
    /// The default reads `DB_THEME`, `DB_CONTENT_SIZE`, `DB_REDUCE_MOTION` and `DB_LOCALE` from
    /// the runner environment (see `DBLaunchConfiguration.fromEnvironment`).
    open var launchConfiguration: DBLaunchConfiguration { configurationOverride ?? .fromEnvironment() }
    public var configurationOverride: DBLaunchConfiguration?

    /// Known, documented audit issues for this test case.
    open var auditAllowlist: [DBAuditAllowance] { [] }

    /// Accessibility identifier DBToast sets on its container.
    open var toastIdentifier: String { "db.toast" }

    private var previousAppearance: XCUIDevice.Appearance?

    override open func setUp() async throws {
        try await super.setUp()
        continueAfterFailure = false
    }

    override open func tearDown() async throws {
        if let previousAppearance { XCUIDevice.shared.appearance = previousAppearance }
        try await super.tearDown()
    }

    /// Launches the app with the theme, content size, Reduce Motion and locale arguments.
    /// Pass `bundleIdentifier` to drive an app other than the test target's host.
    @discardableResult
    public func launchApp(bundleIdentifier: String? = nil, _ configuration: DBLaunchConfiguration? = nil) -> XCUIApplication {
        let config = configuration ?? launchConfiguration
        app = bundleIdentifier.map(XCUIApplication.init(bundleIdentifier:)) ?? XCUIApplication()
        app.launchArguments += config.launchArguments
        app.launchEnvironment.merge(config.launchEnvironment) { _, new in new }

        // The device appearance also drives system chrome (tab bar glass, sheets), which an
        // in-app preferredColorScheme does not reach.
        if previousAppearance == nil { previousAppearance = XCUIDevice.shared.appearance }
        switch config.theme {
        case .light: XCUIDevice.shared.appearance = .light
        case .dark: XCUIDevice.shared.appearance = .dark
        case .system: break
        }

        app.launch()
        return app
    }

    // MARK: Accessibility audit

    /// Runs `performAccessibilityAudit` and fails on every issue not in `allowlist` (merged with
    /// `auditAllowlist`). Accepted issues are attached to the test so they stay visible.
    public func assertAccessibilityAudit(
        _ types: XCUIAccessibilityAuditType = .all,
        allowlist: [DBAuditAllowance] = [],
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let allowed = auditAllowlist + allowlist
        var accepted: [String] = []
        var rejected: [String] = []
        try app.performAccessibilityAudit(for: types) { issue in
            let element = issue.element.map { "\($0.elementType) id=\"\($0.identifier)\" label=\"\($0.label)\"" } ?? "no element"
            let line = "\(issue.compactDescription) [\(element)]"
            if let rule = allowed.first(where: { $0.matches(issue) }) {
                accepted.append("\(line) allowed: \(rule.reason)")
                return true
            }
            rejected.append(line)
            // Returning true marks it handled; this helper reports rejected issues itself so
            // the message lists all of them at once.
            return true
        }
        if !accepted.isEmpty {
            let attachment = XCTAttachment(string: accepted.joined(separator: "\n"))
            attachment.name = "Accepted accessibility issues"
            attachment.lifetime = .keepAlways
            add(attachment)
        }
        if !rejected.isEmpty {
            XCTFail("Accessibility audit found \(rejected.count) issue(s):\n" + rejected.joined(separator: "\n"), file: file, line: line)
        }
    }

    /// Fails when any text is clipped, using the audit's `textClipped` check (UX-TEXT-01).
    public func assertNotTruncated(
        allowlist: [DBAuditAllowance] = [],
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        try assertAccessibilityAudit(.textClipped, allowlist: allowlist, file: file, line: line)
    }

    // MARK: Screen rules

    /// Fails when two hittable buttons on screen share a label or an identifier (UX-ACT-02).
    /// `ignoring` lists labels or identifiers that may repeat (for example a list of "Edit" rows
    /// is better given distinct identifiers than ignored).
    public func assertNoDuplicateActions(
        in container: XCUIElement? = nil,
        ignoring: Set<String> = [],
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let root = container ?? app
        let screen = app.windows.firstMatch.frame
        var byLabel: [String: Int] = [:]
        var byIdentifier: [String: Int] = [:]
        for button in root.descendants(matching: .button).allElementsBoundByIndex {
            // Frame first: `isHittable` fails the test on an element scrolled out of a carousel
            // ("Activation point invalid"), so only buttons fully on screen are asked.
            guard button.exists else { continue }
            let frame = button.frame
            guard !frame.isEmpty, screen.contains(frame), button.isHittable else { continue }
            let label = button.label.trimmingCharacters(in: .whitespacesAndNewlines)
            if !label.isEmpty, !ignoring.contains(label) { byLabel[label, default: 0] += 1 }
            let id = button.identifier
            if !id.isEmpty, !ignoring.contains(id) { byIdentifier[id, default: 0] += 1 }
        }
        let dupLabels = byLabel.filter { $0.value > 1 }.map { "label \"\($0.key)\" x\($0.value)" }
        let dupIds = byIdentifier.filter { $0.value > 1 }.map { "identifier \"\($0.key)\" x\($0.value)" }
        let all = (dupLabels + dupIds).sorted()
        if !all.isEmpty {
            attachScreenshot(named: "Duplicate actions")
            XCTFail("Duplicate actions on screen: " + all.joined(separator: ", "), file: file, line: line)
        }
    }

    /// Scrolls until `lastElement` is visible, then checks it is hittable and fully above the tab
    /// bar and any `bottomObstructions` such as a floating button (UX-SAFE-02).
    public func assertReachable(
        lastElement: XCUIElement,
        in scrollView: XCUIElement? = nil,
        bottomObstructions: [XCUIElement] = [],
        maxSwipes: Int = 12,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let scroller: XCUIElement
        if let scrollView {
            scroller = scrollView
        } else if app.collectionViews.firstMatch.exists {
            scroller = app.collectionViews.firstMatch
        } else {
            scroller = app.scrollViews.firstMatch
        }
        var swipes = 0
        while !(lastElement.exists && lastElement.isHittable && isAboveObstructions(lastElement, bottomObstructions)) && swipes < maxSwipes {
            if scroller.exists { scroller.swipeUp() } else { app.swipeUp() }
            swipes += 1
        }
        // One more swipe settles bounce so the final frame is the resting one.
        if scroller.exists { scroller.swipeUp() } else { app.swipeUp() }

        guard lastElement.waitForExistence(timeout: 2) else {
            XCTFail("Last element \(lastElement) never appeared after \(swipes) swipes", file: file, line: line)
            return
        }
        guard lastElement.isHittable else {
            attachScreenshot(named: "Unreachable last element")
            XCTFail("Last element \(lastElement.identifier) is not hittable after scrolling to the end", file: file, line: line)
            return
        }
        let frame = lastElement.frame
        for obstruction in obstructions(bottomObstructions) where obstruction.exists {
            let top = obstruction.frame.minY
            if frame.maxY > top + 0.5 {
                attachScreenshot(named: "Last element under a bottom bar")
                XCTFail(
                    "Last element \(lastElement.identifier) ends at y=\(frame.maxY), under \(obstruction.elementType) starting at y=\(top)",
                    file: file, line: line
                )
            }
        }
    }

    /// Waits for a toast whose label contains `text`, then checks it stays clear of the tab bar
    /// (UX-TOAST-01 and 03). With `disappearsWithin`, also checks it goes away (UX-TOAST-02).
    @discardableResult
    public func assertToast(
        _ text: String,
        timeout: TimeInterval = 3,
        disappearsWithin: TimeInterval? = nil,
        file: StaticString = #filePath,
        line: UInt = #line
    ) -> XCUIElement {
        let predicate = NSPredicate(format: "label CONTAINS %@", text)
        let scoped = app.descendants(matching: .any).matching(identifier: toastIdentifier)
        let byIdentifier = scoped.matching(predicate).firstMatch
        let anywhere = app.descendants(matching: .any).matching(predicate).firstMatch

        let deadline = Date().addingTimeInterval(timeout)
        var toast: XCUIElement?
        while Date() < deadline {
            if byIdentifier.exists { toast = byIdentifier; break }
            if scoped.firstMatch.exists, scoped.firstMatch.descendants(matching: .any).matching(predicate).firstMatch.exists {
                toast = scoped.firstMatch; break
            }
            if anywhere.exists { toast = anywhere; break }
            RunLoop.current.run(until: Date().addingTimeInterval(0.1))
        }
        guard let toast else {
            attachScreenshot(named: "Missing toast")
            XCTFail("No toast with text \"\(text)\" within \(timeout) s", file: file, line: line)
            return anywhere
        }

        let tabBar = app.tabBars.firstMatch
        if tabBar.exists, toast.frame.intersects(tabBar.frame) {
            attachScreenshot(named: "Toast over tab bar")
            XCTFail("Toast \"\(text)\" overlaps the tab bar", file: file, line: line)
        }

        if let disappearsWithin {
            let gone = XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: toast)
            if XCTWaiter.wait(for: [gone], timeout: disappearsWithin) != .completed {
                XCTFail("Toast \"\(text)\" still visible after \(disappearsWithin) s", file: file, line: line)
            }
        }
        return toast
    }

    // MARK: Screenshots

    /// Attaches a screenshot to the test result.
    public func attachScreenshot(named name: String) {
        let attachment = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    /// Writes a PNG screenshot for `dbdiff`. The folder comes from the `DB_SCREENSHOT_DIR`
    /// environment variable of the test runner (set it in the scheme or with
    /// `TEST_RUNNER_DB_SCREENSHOT_DIR` on the `xcodebuild` command line). Returns nil when unset.
    @discardableResult
    public func saveScreenshot(named name: String, element: XCUIElement? = nil) -> URL? {
        guard let dir = ProcessInfo.processInfo.environment["DB_SCREENSHOT_DIR"], !dir.isEmpty else { return nil }
        let folder = URL(fileURLWithPath: dir, isDirectory: true)
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let shot = element?.screenshot() ?? XCUIScreen.main.screenshot()
        let url = folder.appendingPathComponent("\(name).png")
        do {
            try shot.pngRepresentation.write(to: url, options: .atomic)
            return url
        } catch {
            XCTFail("Cannot write screenshot \(url.path): \(error)")
            return nil
        }
    }

    // MARK: Private

    private func obstructions(_ extra: [XCUIElement]) -> [XCUIElement] {
        [app.tabBars.firstMatch] + extra
    }

    private func isAboveObstructions(_ element: XCUIElement, _ extra: [XCUIElement]) -> Bool {
        let maxY = element.frame.maxY
        return obstructions(extra).allSatisfy { !$0.exists || maxY <= $0.frame.minY + 0.5 }
    }
}
#endif
