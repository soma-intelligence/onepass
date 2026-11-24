import AppKit
import ApplicationServices
import FillKit
import os

/// A focused field the helper may fill: its attributes, its kind, and the elements the flow needs.
struct FieldContext {
    let snapshot: FieldSnapshot
    let kind: FieldKind
    /// The focused element (nil when the app exposes none: the shortcut still opens the picker).
    let element: AXUIElement?
    let pid: pid_t
    /// The password field right below a username field, when found.
    let passwordBelow: AXUIElement?

    var hasPasswordBelow: Bool { passwordBelow != nil }

    /// The focus guard for this field: this process and this element.
    var focusGuard: FocusGuard { FocusGuard(pid: pid, elementID: ElementID(element, pid: pid)) }
}

/// An element as the focus guard compares it: `CFEqual` on the element (two reads of the same
/// field give equal elements), or the process alone when no element was exposed.
struct ElementID: Hashable {
    private let element: AXUIElement?
    private let pid: pid_t

    init(_ element: AXUIElement?, pid: pid_t) {
        self.element = element
        self.pid = pid
    }

    static func == (a: ElementID, b: ElementID) -> Bool {
        guard a.pid == b.pid else { return false }
        switch (a.element, b.element) {
        case (nil, nil): return true
        case (let x?, let y?): return CFEqual(x, y)
        default: return false
        }
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(pid)
        if let element { hasher.combine(CFHash(element)) }
    }
}

/// Follows the focused element of the frontmost app (spec, FocusWatcher): one `AXObserver` for
/// that app, rebuilt on every activation and released on deactivation, on the main run loop.
/// Reports a `FieldContext` when the focus lands on a password field or the username right above
/// one, and nil when it leaves. The helper's own process is never watched.
@MainActor
final class FocusWatcher {
    /// Called on the main actor with the new field, or nil when the focus left a fillable field.
    var onChange: ((FieldContext?) -> Void)?

    private var observer: AXObserver?
    private var observedApp: AXUIElement?
    private var observedPID: pid_t?
    private var tokens: [NSObjectProtocol] = []
    private let ownPID = ProcessInfo.processInfo.processIdentifier
    private static let log = Logger(
        subsystem: Bundle.main.bundleIdentifier ?? "me.somalabs.onepass.fill", category: "focus")

    func start() {
        guard tokens.isEmpty else { return }
        let center = NSWorkspace.shared.notificationCenter
        tokens.append(
            center.addObserver(
                forName: NSWorkspace.didActivateApplicationNotification, object: nil, queue: .main
            ) { [weak self] note in
                let pid = (note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication)?
                    .processIdentifier
                MainActor.assumeIsolated { self?.attach(pid: pid) }
            })
        tokens.append(
            center.addObserver(
                forName: NSWorkspace.didDeactivateApplicationNotification, object: nil, queue: .main
            ) { [weak self] note in
                let pid = (note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication)?
                    .processIdentifier
                MainActor.assumeIsolated {
                    guard let self, pid == self.observedPID else { return }
                    self.release()
                    self.onChange?(nil)
                }
            })
        attach(pid: NSWorkspace.shared.frontmostApplication?.processIdentifier)
    }

    func stop() {
        tokens.forEach { NSWorkspace.shared.notificationCenter.removeObserver($0) }
        tokens.removeAll()
        release()
    }

    /// A new observer for `pid` (the app that just came forward), the old one released first.
    private func attach(pid: pid_t?) {
        release()
        guard let pid, pid != ownPID, AXIsProcessTrusted() else {
            onChange?(nil)
            return
        }
        var made: AXObserver?
        let status = AXObserverCreate(
            pid,
            { _, element, notification, refcon in
                guard let refcon else { return }
                let watcher = Unmanaged<FocusWatcher>.fromOpaque(refcon).takeUnretainedValue()
                let name = notification as String
                // Delivered on the main run loop, where the source was added.
                MainActor.assumeIsolated { watcher.received(name, element: element) }
            }, &made)
        guard status == .success, let made else {
            Self.log.debug("no observer for pid \(pid, privacy: .public): \(status.rawValue, privacy: .public)")
            onChange?(nil)
            return
        }
        let app = AXUIElementCreateApplication(pid)
        AX.limitTimeout(app)
        let me = Unmanaged.passUnretained(self).toOpaque()
        let added = AXObserverAddNotification(made, app, kAXFocusedUIElementChangedNotification as CFString, me)
        guard added == .success else {
            // An app with no accessibility tree (some games, some Qt builds): nothing to follow.
            Self.log.debug("focus not observable in pid \(pid, privacy: .public): \(added.rawValue, privacy: .public)")
            onChange?(nil)
            return
        }
        CFRunLoopAddSource(CFRunLoopGetMain(), AXObserverGetRunLoopSource(made), .commonModes)
        observer = made
        observedApp = app
        observedPID = pid
        onChange?(evaluate(pid: pid))
    }

    /// Removes the observer from the run loop and drops it.
    private func release() {
        if let observer, let observedApp {
            AXObserverRemoveNotification(observer, observedApp, kAXFocusedUIElementChangedNotification as CFString)
            CFRunLoopRemoveSource(CFRunLoopGetMain(), AXObserverGetRunLoopSource(observer), .commonModes)
        }
        observer = nil
        observedApp = nil
        observedPID = nil
    }

    private func received(_ notification: String, element: AXUIElement) {
        guard let pid = observedPID, notification == kAXFocusedUIElementChangedNotification as String else { return }
        onChange?(evaluate(pid: pid))
    }

    /// The fillable field focused in `pid` now, if any.
    private func evaluate(pid: pid_t) -> FieldContext? {
        guard let context = Self.context(pid: pid), context.element != nil else { return nil }
        switch context.kind {
        case .password, .username: return context
        case .oneTimeCode, .other: return nil
        }
    }

    // MARK: Reading the focus

    /// The frontmost app's pid, never the helper's.
    static func frontmostPID() -> pid_t? {
        guard let app = NSWorkspace.shared.frontmostApplication,
            app.processIdentifier != ProcessInfo.processInfo.processIdentifier
        else { return nil }
        return app.processIdentifier
    }

    /// The element focused in `pid`.
    static func focusedElement(pid: pid_t) -> AXUIElement? {
        let app = AXUIElementCreateApplication(pid)
        AX.limitTimeout(app)
        return AX.element(app, kAXFocusedUIElementAttribute)
    }

    /// The focused field of `pid`, classified; with no focused element, a context for the app alone
    /// (kind `.other`, window title only), so the shortcut can still offer a search.
    static func context(pid: pid_t) -> FieldContext? {
        guard let bundleID = NSRunningApplication(processIdentifier: pid)?.bundleIdentifier else { return nil }
        let app = AXUIElementCreateApplication(pid)
        AX.limitTimeout(app)
        let window = AX.element(app, kAXFocusedWindowAttribute)
        let windowTitle = window.flatMap { AX.string($0, kAXTitleAttribute) }
        guard let element = AX.element(app, kAXFocusedUIElementAttribute), AX.isTextInput(element) else {
            let snapshot = FieldSnapshot(pid: pid, bundleID: bundleID, windowTitle: windowTitle,
                url: window.flatMap(AX.documentURL))
            return FieldContext(snapshot: snapshot, kind: .other, element: nil, pid: pid, passwordBelow: nil)
        }
        let snapshot = AX.snapshot(element, pid: pid, bundleID: bundleID, window: window, windowTitle: windowTitle)
        var kind = FieldClassifier.kind(snapshot, above: nil)
        var passwordBelow: AXUIElement?
        if kind == .other, snapshot.role == kAXTextFieldRole as String,
            let below = AX.fieldBelow(element, frame: snapshot.frame, within: AX.scanRoot(element, window: window))
        {
            let belowSnapshot = AX.snapshot(below, pid: pid, bundleID: bundleID, window: window, windowTitle: windowTitle)
            kind = FieldClassifier.kind(snapshot, above: nil, below: belowSnapshot)
            if kind == .username { passwordBelow = below }
        }
        return FieldContext(snapshot: snapshot, kind: kind, element: element, pid: pid, passwordBelow: passwordBelow)
    }
}

/// Small Accessibility readers. Every call is bounded by the messaging timeout of the app element.
enum AX {
    /// A hung app answers no faster than this, instead of the default 6 s.
    static func limitTimeout(_ element: AXUIElement) {
        AXUIElementSetMessagingTimeout(element, 0.5)
    }

    static func value(_ element: AXUIElement, _ attribute: String) -> CFTypeRef? {
        var out: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, attribute as CFString, &out) == .success else { return nil }
        return out
    }

    static func string(_ element: AXUIElement, _ attribute: String) -> String? {
        guard let s = value(element, attribute) as? String, !s.isEmpty else { return nil }
        return s
    }

    static func element(_ element: AXUIElement, _ attribute: String) -> AXUIElement? {
        guard let raw = value(element, attribute), CFGetTypeID(raw) == AXUIElementGetTypeID() else { return nil }
        return (raw as! AXUIElement)
    }

    static func elements(_ element: AXUIElement, _ attribute: String) -> [AXUIElement] {
        guard let raw = value(element, attribute) as? [AnyObject] else { return [] }
        return raw.compactMap { item in
            CFGetTypeID(item) == AXUIElementGetTypeID() ? (item as! AXUIElement) : nil
        }
    }

    /// The element's frame in Accessibility coordinates (top left of the main screen, y down).
    static func frame(_ element: AXUIElement) -> CGRect? {
        if let raw = value(element, "AXFrame"), CFGetTypeID(raw) == AXValueGetTypeID() {
            var rect = CGRect.zero
            if AXValueGetValue(raw as! AXValue, .cgRect, &rect) { return rect }
        }
        guard let p = value(element, kAXPositionAttribute), let s = value(element, kAXSizeAttribute),
            CFGetTypeID(p) == AXValueGetTypeID(), CFGetTypeID(s) == AXValueGetTypeID()
        else { return nil }
        var origin = CGPoint.zero
        var size = CGSize.zero
        guard AXValueGetValue(p as! AXValue, .cgPoint, &origin), AXValueGetValue(s as! AXValue, .cgSize, &size)
        else { return nil }
        return CGRect(origin: origin, size: size)
    }

    static let textRoles: Set<String> = [kAXTextFieldRole as String, kAXComboBoxRole as String, "AXSecureTextField"]

    static func isTextInput(_ element: AXUIElement) -> Bool {
        if let role = string(element, kAXRoleAttribute), textRoles.contains(role) { return true }
        return string(element, kAXSubroleAttribute) == kAXSecureTextFieldSubrole as String
    }

    /// The attributes `FieldClassifier` and `TargetResolver` read. Never the field's value.
    static func snapshot(
        _ element: AXUIElement, pid: pid_t, bundleID: String, window: AXUIElement?, windowTitle: String?
    ) -> FieldSnapshot {
        let label =
            self.element(element, kAXTitleUIElementAttribute).flatMap {
                string($0, kAXValueAttribute) ?? string($0, kAXTitleAttribute)
            } ?? string(element, kAXDescriptionAttribute)
        let classes = (value(element, "AXDOMClassList") as? [String]) ?? []
        return FieldSnapshot(
            role: string(element, kAXRoleAttribute), subrole: string(element, kAXSubroleAttribute),
            title: string(element, kAXTitleAttribute), placeholder: string(element, kAXPlaceholderValueAttribute),
            label: label, domIdentifier: string(element, "AXDOMIdentifier"), domClasses: classes,
            frame: frame(element) ?? .zero, pid: pid, bundleID: bundleID, windowTitle: windowTitle,
            url: pageURL(element) ?? window.flatMap(documentURL))
    }

    /// The URL of the web area holding `element` (browsers and web views expose `AXURL` there).
    static func pageURL(_ element: AXUIElement) -> URL? {
        var current: AXUIElement? = element
        for _ in 0..<40 {
            guard let node = current else { return nil }
            if string(node, kAXRoleAttribute) == "AXWebArea" {
                if let raw = value(node, kAXURLAttribute) {
                    if let url = raw as? URL { return url }
                    if let s = raw as? String { return URL(string: s) }
                }
                return nil
            }
            current = self.element(node, kAXParentAttribute)
        }
        return nil
    }

    /// The window's document (`AXDocument`), when it is a URL.
    static func documentURL(_ window: AXUIElement) -> URL? {
        string(window, kAXDocumentAttribute).flatMap(URL.init(string:))
    }

    /// Where to look for the next field: the web area holding `element`, else its window.
    static func scanRoot(_ element: AXUIElement, window: AXUIElement?) -> AXUIElement? {
        var current: AXUIElement? = element
        for _ in 0..<40 {
            guard let node = current else { break }
            if string(node, kAXRoleAttribute) == "AXWebArea" { return node }
            current = self.element(node, kAXParentAttribute)
        }
        return window
    }

    /// The text input right below `frame` (AX coordinates) inside `root`, overlapping it
    /// horizontally: the password under a username, the code under a password. A bounded walk
    /// (600 nodes, 30 levels), so a huge page costs little.
    static func fieldBelow(_ element: AXUIElement, frame: CGRect, within root: AXUIElement?) -> AXUIElement? {
        guard let root, frame != .zero else { return nil }
        var queue: [(AXUIElement, Int)] = [(root, 0)]
        var visited = 0
        var best: (AXUIElement, CGFloat)?
        while !queue.isEmpty, visited < 600 {
            let (node, depth) = queue.removeFirst()
            visited += 1
            if isTextInput(node), !CFEqual(node, element), let f = self.frame(node),
                f.minY >= frame.maxY - 2, f.maxX > frame.minX, f.minX < frame.maxX, f.height > 0
            {
                let gap = f.minY - frame.maxY
                if gap < (best?.1 ?? .infinity) { best = (node, gap) }
                continue
            }
            if depth < 30 { queue.append(contentsOf: elements(node, kAXChildrenAttribute).map { ($0, depth + 1) }) }
        }
        return best?.0
    }
}
