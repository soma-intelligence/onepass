import AppKit
import ApplicationServices
import FillKit
import os

/// A focused field the helper may fill: its attributes, its kind, and the elements the flow needs.
struct FieldContext {
    let snapshot: FieldSnapshot
    var kind: FieldKind
    /// The focused element, a text input or not (a remote desktop canvas, a custom view: the
    /// guard and the typed keys follow it). Nil only when the app exposes no focused element.
    let element: AXUIElement?
    /// The app's focused window when the field was picked: part of the guard, so a fill never
    /// goes into another window of the same app.
    let window: AXUIElement?
    let pid: pid_t
    /// Whether `element` is a text input (the pill and the Accessibility set need one).
    let isTextInput: Bool
    /// The password field right below a username field, once `AX.resolveBelow` found it.
    var passwordBelow: AXUIElement?

    var hasPasswordBelow: Bool { passwordBelow != nil }

    /// What the guard compares in this process: the element and its window.
    var target: ElementID { ElementID.of(element: element, window: window) }

    /// The focus guard for this field: this process, this element, this window.
    var focusGuard: FocusGuard { FocusGuard(pid: pid, elementID: target) }
}

/// An Accessibility element as the guard compares it: `CFEqual` (two reads of the same field or
/// window give equal elements) and `CFHash`.
struct AXRef: Hashable {
    let element: AXUIElement

    static func == (a: AXRef, b: AXRef) -> Bool { CFEqual(a.element, b.element) }
    func hash(into hasher: inout Hasher) { hasher.combine(CFHash(element)) }
}

/// The focused element and window, compared together (FillKit `FocusTarget`).
typealias ElementID = FocusTarget<AXRef>

extension FocusTarget where Element == AXRef {
    static func of(element: AXUIElement?, window: AXUIElement?) -> ElementID {
        ElementID(element: element.map(AXRef.init), window: window.map(AXRef.init))
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
    /// Bumped on every focus change: a field-below walk that finishes late is dropped.
    private var generation = 0
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

    /// The fillable field focused in `pid` now, if any. A password field answers at once. A plain
    /// text field may be the username above one: the walk that finds the field below runs off
    /// the main thread, and its answer is reported only if the focus has not moved meanwhile.
    private func evaluate(pid: pid_t) -> FieldContext? {
        generation &+= 1
        guard let context = Self.context(pid: pid), context.isTextInput, context.element != nil else { return nil }
        switch context.kind {
        case .password:
            return context
        case .other where context.snapshot.role == kAXTextFieldRole as String:
            let asked = generation
            Task { [weak self] in
                let resolved = await AX.resolveBelow(context)
                guard let self, asked == self.generation, self.observedPID == pid, resolved.kind == .username,
                    let now = FocusWatcher.focusedElement(pid: pid), let element = resolved.element,
                    CFEqual(now, element)
                else { return }
                self.onChange?(resolved)
            }
            return nil
        default:
            return nil
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

    /// The window focused in `pid`.
    static func focusedWindow(pid: pid_t) -> AXUIElement? {
        let app = AXUIElementCreateApplication(pid)
        AX.limitTimeout(app)
        return AX.element(app, kAXFocusedWindowAttribute)
    }

    /// The focused element of `pid`, classified on its own attributes (cheap: no walk of the
    /// tree; `AX.resolveBelow` adds the field below when needed). A focused element that is not a
    /// text input is kept, for the guard and the typed keys; with none at all, the context names
    /// the app alone (window title only), so the shortcut can still offer a search.
    static func context(pid: pid_t) -> FieldContext? {
        guard let bundleID = NSRunningApplication(processIdentifier: pid)?.bundleIdentifier else { return nil }
        let app = AXUIElementCreateApplication(pid)
        AX.limitTimeout(app)
        let window = AX.element(app, kAXFocusedWindowAttribute)
        let windowTitle = window.flatMap { AX.string($0, kAXTitleAttribute) }
        guard let element = AX.element(app, kAXFocusedUIElementAttribute) else {
            let snapshot = FieldSnapshot(pid: pid, bundleID: bundleID, windowTitle: windowTitle,
                url: window.flatMap(AX.documentURL))
            return FieldContext(
                snapshot: snapshot, kind: .other, element: nil, window: window, pid: pid, isTextInput: false)
        }
        let snapshot = AX.snapshot(element, pid: pid, bundleID: bundleID, window: window, windowTitle: windowTitle)
        guard AX.isTextInput(element) else {
            return FieldContext(
                snapshot: snapshot, kind: .other, element: element, window: window, pid: pid, isTextInput: false)
        }
        return FieldContext(
            snapshot: snapshot, kind: FieldClassifier.kind(snapshot, above: nil), element: element, window: window,
            pid: pid, isTextInput: true)
    }
}

/// A value that crosses to the background queue and back. Accessibility reads are thread safe;
/// the elements inside are only read there, never mutated.
struct Unchecked<T>: @unchecked Sendable {
    let value: T
}

/// Small Accessibility readers. Every call is bounded by the messaging timeout: the system-wide
/// one set at launch (`limitSystemWideTimeout`), and the app element's own.
enum AX {
    static let timeout: Float = 0.5

    /// A hung app answers no faster than this, instead of the default 6 s.
    static func limitTimeout(_ element: AXUIElement) {
        AXUIElementSetMessagingTimeout(element, timeout)
    }

    /// The default for every element the helper reads, set once at launch.
    static func limitSystemWideTimeout() {
        AXUIElementSetMessagingTimeout(AXUIElementCreateSystemWide(), timeout)
    }

    private static let walkQueue = DispatchQueue(label: "me.somalabs.onepass.fill.ax", qos: .userInitiated)

    /// Runs `work` (Accessibility reads only) on a background queue.
    static func offMain<T>(_ work: @escaping @Sendable () -> T) async -> Unchecked<T> {
        await withCheckedContinuation { continuation in
            walkQueue.async { continuation.resume(returning: Unchecked(value: work())) }
        }
    }

    /// `context` with its username role settled: a plain text field with a password right below
    /// it becomes `.username` and keeps that password element. The tree walk runs off main.
    @MainActor static func resolveBelow(_ context: FieldContext) async -> FieldContext {
        guard context.isTextInput, context.kind == .other, context.passwordBelow == nil,
            context.snapshot.role == kAXTextFieldRole as String, let element = context.element
        else { return context }
        let input = Unchecked(value: (element, context.snapshot))
        let found = await offMain { () -> (AXUIElement, FieldSnapshot)? in
            let (element, snapshot) = input.value
            let window = AX.element(element, kAXWindowAttribute)
            guard let below = fieldBelow(element, frame: snapshot.frame, within: scanRoot(element, window: window))
            else { return nil }
            return (
                below,
                AX.snapshot(below, pid: snapshot.pid, bundleID: snapshot.bundleID, window: window,
                    windowTitle: snapshot.windowTitle)
            )
        }.value
        guard let found else { return context }
        var resolved = context
        resolved.kind = FieldClassifier.kind(context.snapshot, above: nil, below: found.1)
        if resolved.kind == .username { resolved.passwordBelow = found.0 }
        return resolved
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

    /// FillKit's one list of text input roles (`FillDecision.textInputRoles`).
    static func isTextInput(_ element: AXUIElement) -> Bool {
        FillDecision.isTextInput(role: string(element, kAXRoleAttribute), subrole: string(element, kAXSubroleAttribute))
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
