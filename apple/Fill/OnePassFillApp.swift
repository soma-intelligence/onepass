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
    /// The key code and Carbon modifiers `hotKey` was registered with.
    private var hotKeyCombo: (keyCode: Int, modifiers: Int)?
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
    private var nextSessionID: UInt64 = 0
    /// A fill is under way: the shortcut and the pill wait for it to end.
    private var filling = false
    private let log = Logger(subsystem: Bundle.main.bundleIdentifier ?? "me.somalabs.onepass.fill", category: "app")

    /// Opens the main app's "Remplir partout" settings page (the app's `FillAnywhereLink`).
    static let settingsLink = URL(string: "onepass://settings/fill-anywhere")!
    /// Brings the app forward on its lock screen (`BrowserBridge.isUnlockLink` in the app).
    static let unlockLink = URL(string: "onepass://unlock")!
    /// Browsers that may run without the extension: matched by URL when the page gives one.
    static let browsers: Set<String> = [
        "company.thebrowser.Browser", "com.kagi.kagimacOS", "org.torproject.torbrowser",
        "com.duckduckgo.macos.browser",
    ]

    private struct Session {
        /// Identity of this picker and fill: late answers for an older session are dropped.
        let id: UInt64
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
        // Every element read is bounded, not only the app elements (a hung app answers in 0.5 s).
        AX.limitSystemWideTimeout()
        promptForAccessibilityOnFirstRun()
        refresh()
        // The app posts this after it writes a setting: no wait for the next tick.
        if let app = settings.appBundleID {
            DistributedNotificationCenter.default().addObserver(
                forName: FillDefaults.changedNotification(appBundleID: app), object: nil, queue: .main
            ) { [weak self] _ in
                MainActor.assumeIsolated { self?.refresh() }
            }
        }
        // Posted when any app's Accessibility grant changes. The new value is not readable at
        // once, so the check runs a moment later (the 3 s tick catches it anyway).
        DistributedNotificationCenter.default().addObserver(
            forName: Notification.Name("com.apple.accessibility.api"), object: nil, queue: .main
        ) { [weak self] _ in
            Timer.scheduledTimer(withTimeInterval: 0.5, repeats: false) { _ in
                MainActor.assumeIsolated { self?.refresh() }
            }
        }
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

    /// Applies the Accessibility grant and the settings: watcher, pill and shortcut. Also tells
    /// the app's settings page whether Accessibility is granted (`fill.trusted`).
    private func refresh() {
        settings = FillSettings.current()
        if settings.enabled == false {
            // Turned off in the app: the login item is unregistered, which normally ends this
            // process already. Nothing keeps running behind the user's back. A fill under way
            // ends first (`picked` calls `refresh` when it does).
            guard !filling else { return }
            log.notice("turned off in the app: quitting")
            NSApp.terminate(nil)
            return
        }
        let nowTrusted = AXIsProcessTrusted()
        publishTrusted(nowTrusted)
        if nowTrusted != trusted {
            trusted = nowTrusted
            log.notice("accessibility granted: \(nowTrusted, privacy: .public)")
            if nowTrusted { watcher.start() } else { watcher.stop(); focusChanged(nil) }
        }
        let combo = (keyCode: settings.hotkeyKeyCode, modifiers: settings.hotkeyModifiers)
        if let hotKey, !settings.shortcutEnabled || hotKeyCombo.map({ $0 != combo }) ?? true {
            // Off, or new keys: the old registration goes first.
            hotKey.invalidate()
            self.hotKey = nil
            hotKeyCombo = nil
        }
        if settings.shortcutEnabled, hotKey == nil {
            hotKey = HotKey(keyCode: UInt32(combo.keyCode), modifiers: UInt32(combo.modifiers)) { [weak self] in
                self?.shortcutPressed()
            }
            hotKeyCombo = combo
        }
        if let pillContext, !pillAllowed(for: pillContext) { focusChanged(nil) }
    }

    /// Writes `fill.trusted` when it differs from the grant (cheap: once per change).
    private func publishTrusted(_ granted: Bool) {
        guard let defaults = FillSettings.sharedDefaults(bundle: .main) else { return }
        if defaults.object(forKey: FillDefaults.Key.trusted) as? Bool != granted {
            defaults.set(granted, forKey: FillDefaults.Key.trusted)
        }
    }

    /// The first launch with no grant asks the system once, which also lists "OnePass Fill" in
    /// Privacy & Security > Accessibility, where the app's settings page sends the user. Later
    /// launches never prompt: the page's "Ouvrir les réglages" is the way back.
    private func promptForAccessibilityOnFirstRun() {
        guard !AXIsProcessTrusted() else { return }
        // Turned off in the app: no prompt, `refresh` quits right after.
        guard FillSettings.current().enabled != false else { return }
        let defaults = FillSettings.sharedDefaults(bundle: .main)
        guard defaults?.object(forKey: FillDefaults.Key.trusted) == nil else { return }
        // The value of `kAXTrustedCheckOptionPrompt` (a C global Swift 6 will not read here).
        let options = ["AXTrustedCheckOptionPrompt": true] as CFDictionary
        _ = AXIsProcessTrustedWithOptions(options)
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
        // A fill under way keeps the keyboard: a second press is ignored.
        guard !filling else { return }
        guard let pid = FocusWatcher.frontmostPID(), let context = FocusWatcher.context(pid: pid) else { return }
        openPicker(for: context)
    }

    private func openPicker(for context: FieldContext) {
        guard !filling else { return }
        let target = TargetResolver.target(for: context.snapshot)
        // The shortcut on a field nothing names (a remote desktop canvas, a custom view): the
        // password, typed into the focused element.
        let kind: FieldKind = context.kind == .other ? .password : context.kind
        nextSessionID &+= 1
        session = Session(id: nextSessionID, context: context, target: target, kind: kind)
        pill.hide()
        let isApp = if case .app = target { true } else { false }
        picker.open(near: anchor(of: context), rememberShown: isApp, query: nil)
        let id = nextSessionID
        Task { await load(id) }
    }

    /// The frame to open the picker or a message at: the text field's, else none (screen centre).
    private func anchor(of context: FieldContext) -> CGRect? {
        context.isTextInput && context.element != nil ? context.snapshot.frame : nil
    }

    /// Whether `id` is still the open session. An old fill, unlock or search never touches a
    /// newer one.
    private func isCurrent(_ id: UInt64) -> Bool {
        session?.id == id
    }

    /// The bridge's state, then the candidates; no match opens on a search with the window title.
    private func load(_ id: UInt64) async {
        guard let session, session.id == id else { return }
        let status = await link.status()
        guard isCurrent(id) else { return }
        switch status {
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
            guard isCurrent(id) else { return }
            if !found.isEmpty {
                picker.show(.list(found, note: urlNote(session)))
                return
            }
            let title = session.context.snapshot.windowTitle?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let results = title.isEmpty ? [] : try await link.search(String(title.prefix(200)))
            guard isCurrent(id) else { return }
            picker.show(.list(results, note: urlNote(session) ?? String(localized: "fill.picker.noMatch")))
            if !title.isEmpty { picker.setQuery(title) }
        } catch {
            guard isCurrent(id) else { return }
            picker.show(Self.state(for: error))
        }
    }

    /// A browser without the extension whose page gave no URL: say why the list is a search.
    private func urlNote(_ session: Session) -> String? {
        guard case .app(let bundleID, _) = session.target, Self.browsers.contains(bundleID) else { return nil }
        return String(localized: "fill.picker.urlUnreadable")
    }

    private func search(_ query: String) {
        guard let id = session?.id else { return }
        let text = query.trimmingCharacters(in: .whitespacesAndNewlines)
        Task {
            if text.isEmpty {
                await load(id)
                return
            }
            do {
                let results = try await link.search(String(text.prefix(200)))
                guard isCurrent(id) else { return }
                picker.show(.list(results, note: nil))
            } catch {
                guard isCurrent(id) else { return }
                picker.show(Self.state(for: error))
            }
        }
    }

    private func picked(_ candidate: FfiFillCandidate, remember: Bool) {
        guard var session, !filling else { return }
        session.picked = candidate
        self.session = session
        filling = true
        Task {
            await fill(session, candidate: candidate, remember: remember)
            filling = false
            // A change held back during the fill (turned off in the app) applies now.
            refresh()
        }
    }

    /// The flow for the picked login: the values are asked for one at a time, by the filler.
    private func fill(_ session: Session, candidate: FfiFillCandidate, remember: Bool) async {
        // The tree walks (password below, code below) run now, off the main thread.
        let context = await AX.resolveBelow(session.context)
        // A plain field the walk found a password below is the username after all.
        let kind: FieldKind = context.kind == .username ? .username : session.kind
        var elements: [FieldKind: AXUIElement] = [:]
        if let password = context.passwordBelow { elements[.password] = password }
        if candidate.hasTotp, let code = await codeField(after: context) { elements[.oneTimeCode] = code }
        guard isCurrent(session.id) else { return }
        let steps: [FillStep] =
            kind == .oneTimeCode
            ? [.value(.oneTimeCode)]
            : FillFlow.steps(
                focused: kind, hasPasswordBelow: context.hasPasswordBelow,
                hasTotp: elements[.oneTimeCode] != nil, passwordKnown: elements[.password] != nil)
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
        // A newer session (the picker opened again meanwhile) owns the screen now.
        guard isCurrent(session.id) else { return }
        let frame = anchor(of: context)
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
    /// username), when it asks for a code. The walk runs off the main thread.
    private func codeField(after context: FieldContext) async -> AXUIElement? {
        guard let password = context.kind == .username ? context.passwordBelow : context.element else { return nil }
        let input = Unchecked(value: (password, context.snapshot))
        return await AX.offMain { () -> AXUIElement? in
            let (password, snapshot) = input.value
            guard let frame = AX.frame(password) else { return nil }
            let window = AX.element(password, kAXWindowAttribute)
            guard let below = AX.fieldBelow(password, frame: frame, within: AX.scanRoot(password, window: window))
            else { return nil }
            let belowSnapshot = AX.snapshot(
                below, pid: snapshot.pid, bundleID: snapshot.bundleID, window: window,
                windowTitle: snapshot.windowTitle)
            return FieldClassifier.kind(belowSnapshot, above: nil) == .oneTimeCode ? below : nil
        }.value
    }

    private func reopen(_ session: Session, copy kind: FieldKind?, _ state: PickerState) {
        var next = session
        next.copyKind = kind
        self.session = next
        picker.open(near: anchor(of: session.context), rememberShown: false, query: nil)
        picker.show(state)
    }

    private func perform(_ action: PickerAction) {
        guard let id = session?.id else { return }
        switch action {
        case .openApp:
            picker.close()
            session = nil
            openApp(Self.unlockLink)
        case .unlock:
            picker.show(.loading)
            Task { await unlockAndWait(id) }
        case .copy:
            Task { await copyValue(id) }
        }
    }

    /// Asks the app to come forward and unlock, then loads the list once it is unlocked (for two
    /// minutes at most, while this session's picker is open).
    private func unlockAndWait(_ id: UInt64) async {
        var status = await link.unlock()
        guard isCurrent(id) else { return }
        if status == .appClosed {
            openApp(Self.unlockLink)
        }
        for _ in 0..<120 where status != .unlocked {
            try? await Task.sleep(for: .seconds(1))
            guard isCurrent(id) else { return }
            status = await link.status()
        }
        if status == .unlocked, isCurrent(id) { await load(id) }
    }

    /// "Copier": the value of the field that could not be filled, on the clipboard.
    private func copyValue(_ id: UInt64) async {
        guard let session, session.id == id, let candidate = session.picked else { return }
        let kind = session.copyKind ?? session.kind
        do {
            let secret = try await link.value(
                target: session.target, itemID: candidate.itemId, field: kind, remember: false,
                appName: BridgeLink.appName(pid: session.context.pid))
            guard isCurrent(id) else { return }
            guard clipboard.copy(secret) else {
                picker.show(.message(String(localized: "fill.picker.failed"), action: nil))
                return
            }
            picker.close()
            self.session = nil
            pill.flash(String(localized: "fill.pill.copied"), near: nil)
        } catch {
            guard isCurrent(id) else { return }
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
