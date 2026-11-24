import AppKit
import ApplicationServices
import FillKit
import OnePassCore
import os

/// "OnePass Fill", the login item that fills logins outside the browsers (spec
/// 2026-11-23-mac-fill-anywhere-design). An agent app (`LSUIElement`): no Dock icon and no menu;
/// its only windows are the pill and the picker. It reaches the Mac app through `BridgeLink`.
@main
@MainActor
final class OnePassFillApp: NSObject, NSApplicationDelegate {
    /// `NSApplication.delegate` is weak: the delegate lives here.
    private static var delegate: OnePassFillApp?

    private let link = BridgeLink()
    private let watcher = FocusWatcher()
    private let pill = Pill()
    private let picker = Picker()
    private let clipboard = Clipboard()
    private var hotKey: HotKey?
    private var settings = FillSettings.current()
    private var trusted = false
    private var housekeeping: Timer?
    private var follow: Timer?
    /// The element the pill follows (read by `follow`).
    private var followed: AXUIElement?
    /// The field the pill stands next to.
    private var pillContext: FieldContext?
    /// The picker's field, target and pick, from opening to the end of the fill.
    private var session: Session?
    private let log = Logger(subsystem: Bundle.main.bundleIdentifier ?? "me.somalabs.onepass.fill", category: "app")

    /// Opens the main app's "Fill anywhere" settings page. The app has no such route yet (Task 9
    /// adds it): today the link only brings the app forward.
    static let settingsLink = URL(string: "onepass://settings/fill-anywhere")!
    /// Brings the app forward on its lock screen (`BrowserBridge.isUnlockLink` in the app).
    static let unlockLink = URL(string: "onepass://unlock")!
    /// Browsers that may run without the extension: matched by URL when the page gives one.
    static let browsers: Set<String> = [
        "company.thebrowser.Browser", "com.kagi.kagimacOS", "org.torproject.torbrowser",
        "com.duckduckgo.macos.browser",
    ]

    private struct Session {
        let context: FieldContext
        let target: FillTarget
        let kind: FieldKind
        var picked: FfiFillCandidate?
        var copyKind: FieldKind?
    }

    static func main() {
        let app = NSApplication.shared
        let delegate = OnePassFillApp()
        Self.delegate = delegate
        app.delegate = delegate
        app.setActivationPolicy(.accessory)
        app.run()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        watcher.onChange = { [weak self] context in self?.focusChanged(context) }
        pill.onClick = { [weak self] in
            guard let self, let context = self.pillContext else { return }
            self.openPicker(for: context)
        }
        picker.onPick = { [weak self] candidate, remember in self?.picked(candidate, remember: remember) }
        picker.onSearch = { [weak self] query in self?.search(query) }
        picker.onAction = { [weak self] action in self?.perform(action) }
        picker.onClose = { [weak self] in self?.session = nil }
        refresh()
        // Accessibility and the settings can change at any time in the app or System Settings.
        housekeeping = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.refresh() }
        }
        Task {
            let status = await link.status()
            log.notice("bridge status: \(String(describing: status), privacy: .public)")
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        clipboard.clearNow()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    /// Applies the Accessibility grant and the settings: watcher, pill and shortcut.
    private func refresh() {
        settings = FillSettings.current()
        let nowTrusted = AXIsProcessTrusted()
        if nowTrusted != trusted {
            trusted = nowTrusted
            log.notice("accessibility granted: \(nowTrusted, privacy: .public)")
            if nowTrusted { watcher.start() } else { watcher.stop(); focusChanged(nil) }
        }
        if settings.shortcutEnabled, hotKey == nil {
            hotKey = HotKey { [weak self] in self?.shortcutPressed() }
        } else if !settings.shortcutEnabled, let hotKey {
            hotKey.invalidate()
            self.hotKey = nil
        }
        if let pillContext, !pillAllowed(for: pillContext) { focusChanged(nil) }
    }

    // MARK: Pill

    private func pillAllowed(for context: FieldContext) -> Bool {
        trusted && settings.pillEnabled && !settings.isExcluded(context.snapshot.bundleID)
            && context.snapshot.frame != .zero
    }

    private func focusChanged(_ context: FieldContext?) {
        follow?.invalidate()
        follow = nil
        followed = nil
        guard let context, pillAllowed(for: context), let element = context.element else {
            pillContext = nil
            pill.hide()
            return
        }
        pillContext = context
        followed = element
        pill.show(at: context.snapshot.frame)
        // Moves and scrolls give no focus notification: the frame is read again while shown.
        follow = Timer.scheduledTimer(withTimeInterval: 0.2, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, let element = self.followed else { return }
                if let frame = AX.frame(element), frame != .zero {
                    self.pill.move(to: frame)
                } else {
                    self.focusChanged(nil)
                }
            }
        }
    }

    // MARK: Picker

    private func shortcutPressed() {
        guard AXIsProcessTrusted() else {
            // No Accessibility: the setup screen in the app's settings.
            openApp(Self.settingsLink)
            return
        }
        guard let pid = FocusWatcher.frontmostPID(), let context = FocusWatcher.context(pid: pid) else { return }
        openPicker(for: context)
    }

    private func openPicker(for context: FieldContext) {
        let target = TargetResolver.target(for: context.snapshot)
        // The shortcut on a field nothing names (a remote desktop, a custom field): the password.
        let kind: FieldKind = context.kind == .other ? .password : context.kind
        session = Session(context: context, target: target, kind: kind)
        pill.hide()
        let isApp = if case .app = target { true } else { false }
        picker.open(near: context.element == nil ? nil : context.snapshot.frame, rememberShown: isApp, query: nil)
        Task { await load() }
    }

    /// The bridge's state, then the candidates; no match opens on a search with the window title.
    private func load() async {
        guard let session else { return }
        switch await link.status() {
        case .appClosed:
            picker.show(.message(String(localized: "fill.picker.appClosed"), action: .openApp))
            return
        case .locked:
            picker.show(.message(String(localized: "fill.picker.locked"), action: .unlock))
            return
        case .unlocked:
            break
        }
        do {
            let found = try await link.candidates(for: session.target)
            guard self.session != nil else { return }
            if !found.isEmpty {
                picker.show(.list(found, note: urlNote(session)))
                return
            }
            let title = session.context.snapshot.windowTitle ?? ""
            let results = title.isEmpty ? [] : try await searchResults(title)
            guard self.session != nil else { return }
            picker.show(.list(results, note: urlNote(session) ?? String(localized: "fill.picker.noMatch")))
            if !title.isEmpty { picker.setQuery(title) }
        } catch {
            picker.show(Self.state(for: error))
        }
    }

    /// A browser without the extension whose page gave no URL: say why the list is a search.
    private func urlNote(_ session: Session) -> String? {
        guard case .app(let bundleID, _) = session.target, Self.browsers.contains(bundleID) else { return nil }
        return String(localized: "fill.picker.urlUnreadable")
    }

    private func search(_ query: String) {
        guard session != nil else { return }
        let text = query.trimmingCharacters(in: .whitespacesAndNewlines)
        Task {
            if text.isEmpty {
                await load()
                return
            }
            do {
                let results = try await searchResults(text)
                guard session != nil else { return }
                picker.show(.list(results, note: nil))
            } catch {
                picker.show(Self.state(for: error))
            }
        }
    }

    /// Free search over login titles. The client has no search request: `list_for_app` with an
    /// app id no login carries (the helper's own, never remembered) matches the words of the
    /// title it is given against every login's title.
    private func searchResults(_ text: String) async throws -> [FfiFillCandidate] {
        let own = Bundle.main.bundleIdentifier ?? "me.somalabs.onepass.fill"
        return try await link.candidates(for: .app(bundleID: own, windowTitle: String(text.prefix(200))))
    }

    private func picked(_ candidate: FfiFillCandidate, remember: Bool) {
        guard var session else { return }
        session.picked = candidate
        self.session = session
        Task { await fill(session, candidate: candidate, remember: remember) }
    }

    /// The flow for the picked login: the values are asked for one at a time, by the filler.
    private func fill(_ session: Session, candidate: FfiFillCandidate, remember: Bool) async {
        let context = session.context
        var elements: [FieldKind: AXUIElement] = [:]
        if candidate.hasTotp, let code = codeField(after: context) { elements[.oneTimeCode] = code }
        let steps: [FillStep] =
            session.kind == .oneTimeCode
            ? [.value(.oneTimeCode)]
            : FillFlow.steps(
                focused: session.kind, hasPasswordBelow: context.hasPasswordBelow,
                hasTotp: elements[.oneTimeCode] != nil)
        let appName = BridgeLink.appName(pid: context.pid)
        let filler = Filler(clipboard: clipboard, typingDelayMs: settings.typingDelayMs)
        var rememberNext = remember
        let link = self.link
        let outcome = await filler.fill(
            steps: steps,
            values: { kind in
                // Remembered once, with the first value.
                defer { rememberNext = false }
                return try await link.value(
                    target: session.target, itemID: candidate.itemId, field: kind, remember: rememberNext,
                    appName: appName)
            },
            guard: context.focusGuard, elements: elements)
        log.notice("fill ended: \(String(describing: outcome), privacy: .public)")
        let frame = context.element == nil ? nil : context.snapshot.frame
        switch outcome {
        case .done(.clipboard):
            self.session = nil
            pill.flash(String(localized: "fill.pill.copied"), near: frame)
        case .done:
            self.session = nil
        case .stoppedFocusChanged:
            self.session = nil
            pill.flash(String(localized: "fill.pill.focusChanged"), near: frame)
        case .secureInputElsewhere:
            reopen(session, copy: filler.lastKind, .message(String(localized: "fill.picker.secureInput"), action: .copy))
        case .failed:
            if let error = filler.lastError {
                reopen(session, copy: nil, Self.state(for: error))
            } else {
                reopen(session, copy: filler.lastKind, .message(String(localized: "fill.picker.failed"), action: .copy))
            }
        }
    }

    /// The one-time code field right below the password (the focused one, or the one below the
    /// username), when it asks for a code.
    private func codeField(after context: FieldContext) -> AXUIElement? {
        guard let password = context.kind == .username ? context.passwordBelow : context.element,
            let frame = AX.frame(password)
        else { return nil }
        let window = AX.element(password, kAXWindowAttribute)
        guard let below = AX.fieldBelow(password, frame: frame, within: AX.scanRoot(password, window: window))
        else { return nil }
        let snapshot = AX.snapshot(
            below, pid: context.pid, bundleID: context.snapshot.bundleID, window: window,
            windowTitle: context.snapshot.windowTitle)
        return FieldClassifier.kind(snapshot, above: nil) == .oneTimeCode ? below : nil
    }

    private func reopen(_ session: Session, copy kind: FieldKind?, _ state: PickerState) {
        var next = session
        next.copyKind = kind
        self.session = next
        picker.open(near: session.context.element == nil ? nil : session.context.snapshot.frame, rememberShown: false, query: nil)
        picker.show(state)
    }

    private func perform(_ action: PickerAction) {
        switch action {
        case .openApp:
            picker.close()
            session = nil
            openApp(Self.unlockLink)
        case .unlock:
            picker.show(.loading)
            Task { await unlockAndWait() }
        case .copy:
            Task { await copyValue() }
        }
    }

    /// Asks the app to come forward and unlock, then loads the list once it is unlocked (for two
    /// minutes at most, while the picker is open).
    private func unlockAndWait() async {
        var status = await link.unlock()
        if status == .appClosed {
            openApp(Self.unlockLink)
        }
        for _ in 0..<120 where status != .unlocked {
            try? await Task.sleep(for: .seconds(1))
            guard session != nil else { return }
            status = await link.status()
        }
        if status == .unlocked { await load() }
    }

    /// "Copier": the value of the field that could not be filled, on the clipboard.
    private func copyValue() async {
        guard let session, let candidate = session.picked else { return }
        let kind = session.copyKind ?? session.kind
        do {
            let secret = try await link.value(
                target: session.target, itemID: candidate.itemId, field: kind, remember: false,
                appName: BridgeLink.appName(pid: session.context.pid))
            guard clipboard.copy(secret) else {
                picker.show(.message(String(localized: "fill.picker.failed"), action: nil))
                return
            }
            picker.close()
            self.session = nil
            pill.flash(String(localized: "fill.pill.copied"), near: nil)
        } catch {
            picker.show(Self.state(for: error))
        }
    }

    /// The picker's message for a bridge error (spec, Errors).
    static func state(for error: any Error) -> PickerState {
        guard let error = error as? OnePassError else {
            return .message(String(localized: "fill.picker.error"), action: nil)
        }
        switch error {
        case .AppClosed:
            return .message(String(localized: "fill.picker.appClosed"), action: .openApp)
        case .Locked:
            return .message(String(localized: "fill.picker.locked"), action: .unlock)
        case .NotFound:
            return .message(String(localized: "fill.picker.notFound"), action: nil)
        case .Validation(field: "bridge", reason: let reason):
            switch reason {
            case "timeout": return .message(String(localized: "fill.picker.timeout"), action: nil)
            case "origin_mismatch": return .message(String(localized: "fill.picker.originMismatch"), action: nil)
            case "not_allowed": return .message(String(localized: "fill.picker.notAllowed"), action: nil)
            default: return .message(String(localized: "fill.picker.error"), action: nil)
            }
        default:
            return .message(String(localized: "fill.picker.error"), action: nil)
        }
    }

    // MARK: The main app

    /// Opens `url` in the Mac app this helper ships in (its own copy, not another build that
    /// claims `onepass://`), launching it when needed.
    private func openApp(_ url: URL) {
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = true
        guard let app = Self.mainAppURL(appBundleID: settings.appBundleID) else {
            NSWorkspace.shared.open(url)
            return
        }
        NSWorkspace.shared.open([url], withApplicationAt: app, configuration: configuration) { _, error in
            if let error {
                Logger(subsystem: Bundle.main.bundleIdentifier ?? "me.somalabs.onepass.fill", category: "app")
                    .error("main app not opened: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    /// `OnePass.app`, four levels above `Contents/Library/LoginItems/OnePass Fill.app`, when its
    /// bundle id is the expected one; else the app LaunchServices knows by that id.
    static func mainAppURL(appBundleID: String?) -> URL? {
        var url = Bundle.main.bundleURL
        for _ in 0..<4 { url.deleteLastPathComponent() }
        if let id = Bundle(url: url)?.bundleIdentifier, id == appBundleID { return url }
        return appBundleID.flatMap { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0) }
    }
}
