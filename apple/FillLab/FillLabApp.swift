import AppKit
import WebKit

/// FillLab, the Debug-only test app of "OnePass Fill" (spec 2026-11-23-mac-fill-anywhere-design,
/// Testing). One window with hostile login fields, each with a stable accessibility identifier for
/// `FillAnywhereUITests`. Never embedded in OnePass.app, never built in a Release configuration
/// (its target fails the build there) and never in the App Store project.
///
/// The sections and the strategy the helper should log for each:
/// 1. `filllab.secure`: a standard `NSSecureTextField`, `accessibility`.
/// 2. `filllab.custom`: a custom view that refuses an Accessibility value set but takes typed keys,
///    `typing`.
/// 3. `filllab.hint`: a plain text field titled "Password hint", no label. Not a password: no pill
///    and nothing offered.
/// 4. `filllab.labelled`: a plain text field whose Accessibility label is exactly "Password". A
///    password for the classifier, `accessibility`.
/// 5. `filllab.web`: a `WKWebView` login page from the bundled `login.html`, `accessibility`.
/// 6. `filllab.clearing`: a secure field that clears itself when its value is set through
///    Accessibility, so the helper falls back to `typing`.
///
/// `-FillLabWindowTitle <title>` sets the window title, which the helper's picker searches first
/// when no login names this app.
@main
@MainActor
final class FillLabApp: NSObject, NSApplicationDelegate {
    private static var delegate: FillLabApp?
    private var window: NSWindow?

    static func main() {
        let app = NSApplication.shared
        let delegate = FillLabApp()
        Self.delegate = delegate
        app.delegate = delegate
        app.setActivationPolicy(.regular)
        app.run()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let window = NSWindow(
            contentRect: CGRect(x: 0, y: 0, width: 820, height: 560),
            styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        window.title = UserDefaults.standard.string(forKey: "FillLabWindowTitle") ?? "FillLab"
        window.setAccessibilityIdentifier("filllab.window")
        window.contentView = Self.content()
        window.center()
        window.makeKeyAndOrderFront(nil)
        self.window = window
        NSApp.activate()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    // MARK: Layout

    /// Two columns. The plain "Password hint" field sits alone at the bottom of the right column:
    /// with a password field right below it, the helper would read it as a username.
    private static func content() -> NSView {
        let secure = NSSecureTextField()
        secure.placeholderString = "Secure field"
        let custom = RefusingField()
        let hint = NSTextField()
        hint.setAccessibilityTitle("Password hint")
        let labelled = NSTextField()
        labelled.setAccessibilityLabel("Password")
        let clearing = ClearingSecureField()
        clearing.placeholderString = "Clears itself on set"
        let web = WebLogin()

        let ids: [(NSView, String)] = [
            (secure, "filllab.secure"), (custom, "filllab.custom"), (hint, "filllab.hint"),
            (labelled, "filllab.labelled"), (clearing, "filllab.clearing"), (web, "filllab.web"),
        ]
        for (view, id) in ids {
            view.setAccessibilityIdentifier(id)
            view.translatesAutoresizingMaskIntoConstraints = false
        }
        for field in [secure, hint, labelled, clearing] as [NSTextField] {
            field.widthAnchor.constraint(equalToConstant: 300).isActive = true
        }
        NSLayoutConstraint.activate([
            custom.widthAnchor.constraint(equalToConstant: 300),
            custom.heightAnchor.constraint(equalToConstant: 24),
            web.widthAnchor.constraint(equalToConstant: 340),
            web.heightAnchor.constraint(equalToConstant: 230),
        ])

        let left = column([
            section("1. NSSecureTextField (accessibility)", secure),
            section("2. Custom view, no value set (typing)", custom),
            section("4. Plain field, AX label (accessibility)", labelled),
            section("6. Clears itself on set (typing)", clearing),
        ])
        let right = column([
            section("5. Web view login page (accessibility)", web),
            section("3. Plain field, title only (none offered)", hint),
        ])
        let row = NSStackView(views: [left, right])
        row.orientation = .horizontal
        row.alignment = .top
        row.spacing = 40
        row.edgeInsets = NSEdgeInsets(top: 24, left: 24, bottom: 24, right: 24)
        return row
    }

    private static func column(_ views: [NSView]) -> NSStackView {
        let stack = NSStackView(views: views)
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 28
        return stack
    }

    /// A caption and its field. The caption is not the field's title element, so the helper
    /// never reads it as a label.
    private static func section(_ caption: String, _ field: NSView) -> NSView {
        let label = NSTextField(labelWithString: caption)
        label.font = .systemFont(ofSize: NSFont.smallSystemFontSize, weight: .semibold)
        label.textColor = .secondaryLabelColor
        let stack = NSStackView(views: [label, field])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 6
        return stack
    }
}

// MARK: 2. A custom field that refuses an Accessibility value set

/// A hand-drawn password field: it takes typed keys, shows bullets, and says through
/// Accessibility that its value cannot be set, as many custom and cross-platform fields do.
final class RefusingField: NSView {
    private var text = ""

    override var acceptsFirstResponder: Bool { true }
    override var isFlipped: Bool { true }

    override func becomeFirstResponder() -> Bool {
        needsDisplay = true
        NSAccessibility.post(element: self, notification: .focusedUIElementChanged)
        return true
    }

    override func resignFirstResponder() -> Bool {
        needsDisplay = true
        return true
    }

    override func mouseDown(with event: NSEvent) {
        window?.makeFirstResponder(self)
    }

    override func keyDown(with event: NSEvent) {
        guard let characters = event.characters, !characters.isEmpty else { return }
        if event.keyCode == 51 {
            // Delete: the last character goes.
            if !text.isEmpty { text.removeLast() }
        } else if event.modifierFlags.contains(.command) {
            super.keyDown(with: event)
            return
        } else {
            // Control characters and the function keys' private-use characters are not text.
            let typed = characters.unicodeScalars.filter {
                $0.value >= 0x20 && $0.value != 0x7F && !(0xF700...0xF8FF).contains($0.value)
            }
            text.unicodeScalars.append(contentsOf: typed)
        }
        changed()
    }

    private func changed() {
        needsDisplay = true
        NSAccessibility.post(element: self, notification: .valueChanged)
    }

    override func draw(_ dirtyRect: NSRect) {
        let focused = window?.firstResponder === self
        let box = bounds.insetBy(dx: 0.5, dy: 0.5)
        NSColor.textBackgroundColor.setFill()
        box.fill()
        (focused ? NSColor.keyboardFocusIndicatorColor : NSColor.separatorColor).setStroke()
        let path = NSBezierPath(rect: box)
        path.lineWidth = focused ? 2 : 1
        path.stroke()
        let bullets = String(repeating: "\u{2022}", count: text.count) as NSString
        bullets.draw(
            at: CGPoint(x: 6, y: 4),
            withAttributes: [.font: NSFont.systemFont(ofSize: NSFont.systemFontSize), .foregroundColor: NSColor.labelColor])
    }

    // Accessibility: a secure text field whose value reads as bullets and cannot be set.

    override func isAccessibilityElement() -> Bool { true }
    override func accessibilityRole() -> NSAccessibility.Role? { .textField }
    override func accessibilitySubrole() -> NSAccessibility.Subrole? { .secureTextField }
    override func accessibilityValue() -> Any? { String(repeating: "\u{2022}", count: text.count) }
    override func accessibilityNumberOfCharacters() -> Int { text.count }
    override func isAccessibilityFocused() -> Bool { window?.firstResponder === self }
    override func isAccessibilityEnabled() -> Bool { true }

    override func setAccessibilityValue(_ accessibilityValue: Any?) {
        // Refused: the value only changes through typed keys.
    }

    override func setAccessibilityFocused(_ accessibilityFocused: Bool) {
        if accessibilityFocused { window?.makeFirstResponder(self) }
    }

    override func isAccessibilitySelectorAllowed(_ selector: Selector) -> Bool {
        if selector == #selector(NSView.setAccessibilityValue(_:)) { return false }
        return super.isAccessibilitySelectorAllowed(selector)
    }
}

// MARK: 6. A secure field that clears itself on set

/// Takes an Accessibility value set and drops it at once, so the length read back is 0. Typed
/// keys go through the field editor as usual.
final class ClearingSecureField: NSSecureTextField {
    override func setAccessibilityValue(_ accessibilityValue: Any?) {
        stringValue = ""
        currentEditor()?.string = ""
    }
}

// MARK: 5. A web view login page

/// `login.html` from the bundle. Its base URL is the demo login's site, so the helper matches the
/// page by URL (`AXURL` of the web area). Nothing is fetched: the page is self-contained.
final class WebLogin: WKWebView {
    init() {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        super.init(frame: .zero, configuration: configuration)
        if let url = Bundle.main.url(forResource: "login", withExtension: "html"),
            let html = try? String(contentsOf: url, encoding: .utf8)
        {
            loadHTMLString(html, baseURL: URL(string: "https://github.com/login"))
        }
    }

    required init?(coder: NSCoder) { nil }
}
