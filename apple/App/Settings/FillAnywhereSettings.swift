#if os(macOS) && !ONEPASS_APP_STORE
import AppKit
import Carbon.HIToolbox
import GlanceKit
import ServiceManagement
import SwiftUI
import VaultKit
import os

/// `onepass://settings/fill-anywhere`, opened by OnePass Fill when the shortcut is pressed without
/// the Accessibility grant: Remplissage automatique, pushed to Remplir partout.
enum FillAnywhereLink {
    /// The `AppModel.settingsFocusRequest` the Remplissage automatique page takes.
    static let focus = "fillAnywhere"

    static func handles(_ url: URL) -> Bool {
        guard url.scheme == "onepass",
            let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
            components.host == "settings", components.path == "/fill-anywhere",
            components.query == nil, components.fragment == nil,
            components.user == nil, components.password == nil, components.port == nil
        else { return false }
        return true
    }
}

/// The OnePass Fill login item (spec 2026-11-23-mac-fill-anywhere): where it is, its id, and
/// whether this run may register it.
enum FillAnywhereHelper {
    static let log = Logger(subsystem: "me.somalabs.onepass", category: "fill-anywhere")

    /// `Contents/Library/LoginItems/OnePass Fill.app` inside this app.
    static var bundleURL: URL {
        Bundle.main.bundleURL.appending(path: "Contents/Library/LoginItems/OnePass Fill.app", directoryHint: .isDirectory)
    }

    /// The page and its link show only when this build carries the helper.
    static var isPresent: Bool {
        FileManager.default.fileExists(atPath: bundleURL.path(percentEncoded: false))
    }

    /// `<app bundle id>.fill`, the helper's bundle id in every configuration.
    static var identifier: String? {
        Bundle.main.bundleIdentifier.map { "\($0).fill" }
    }

    static var service: SMAppService? {
        identifier.map { SMAppService.loginItem(identifier: $0) }
    }

    /// Never registered from previews, unit tests, UI tests or a demo run: only the user's own tap
    /// in a normal run turns the helper on.
    static var mayRegister: Bool {
        let environment = ProcessInfo.processInfo.environment
        if environment["XCODE_RUNNING_FOR_PREVIEWS"] == "1" || environment["XCTestConfigurationFilePath"] != nil {
            return false
        }
        if NSClassFromString("XCTestCase") != nil { return false }
        return !TestIsolation.isActive && !UserDefaults.standard.bool(forKey: "OnePassDemoData")
    }
}

/// The state of the Remplir partout page: the login item, the Accessibility grant the helper
/// reports, and the helper's settings in the App Group defaults (`FillDefaults`).
@MainActor @Observable
final class FillAnywhereSettingsModel {
    typealias Key = FillDefaults.Key

    private(set) var status: SMAppService.Status = .notRegistered
    private(set) var trusted = false
    private(set) var pill = FillDefaults.pill
    private(set) var hotkey = FillDefaults.hotkey
    private(set) var keyCode = FillDefaults.hotkeyKeyCode
    private(set) var modifiers = FillDefaults.hotkeyModifiers
    private(set) var excluded: [String] = []
    private(set) var typingDelayMs = FillDefaults.typingDelayMs
    private(set) var busy = false
    var errorMessage: String?

    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private let appBundleID = Bundle.main.bundleIdentifier

    init() {
        // A test run never touches the user's settings.
        defaults = TestIsolation.isActive
            ? TestIsolation.defaults : (UserDefaults(suiteName: AppGroup.identifier) ?? .standard)
        reload()
    }

    /// On while registered, including while the system waits for the user's approval.
    var isOn: Bool { status == .enabled || status == .requiresApproval }

    var hotkeyIsDefault: Bool {
        keyCode == FillDefaults.hotkeyKeyCode && modifiers == FillDefaults.hotkeyModifiers
    }

    /// Reads everything again: the page polls while shown (the helper and System Settings change
    /// things behind it).
    func reload() {
        status = FillAnywhereHelper.service?.status ?? .notFound
        trusted = defaults.object(forKey: Key.trusted) as? Bool ?? false
        pill = defaults.object(forKey: Key.pill) as? Bool ?? FillDefaults.pill
        hotkey = defaults.object(forKey: Key.hotkey) as? Bool ?? FillDefaults.hotkey
        if let code = defaults.object(forKey: Key.hotkeyKeyCode) as? Int,
            let mods = defaults.object(forKey: Key.hotkeyModifiers) as? Int,
            (0...127).contains(code), FillDefaults.isValidHotkey(modifiers: mods)
        {
            keyCode = code
            modifiers = FillDefaults.cleanModifiers(mods)
        } else {
            keyCode = FillDefaults.hotkeyKeyCode
            modifiers = FillDefaults.hotkeyModifiers
        }
        excluded = defaults.array(forKey: Key.excluded) as? [String] ?? FillDefaults.excluded(appBundleID: appBundleID)
        if let ms = defaults.object(forKey: Key.typingDelayMs) as? Int {
            typingDelayMs = min(max(ms, FillDefaults.typingDelayRange.lowerBound), FillDefaults.typingDelayRange.upperBound)
        } else {
            typingDelayMs = FillDefaults.typingDelayMs
        }
    }

    // MARK: The login item

    /// On: the helper may pair again (a forgotten one is on the bridge's block list), then the
    /// login item is registered. Off: unregistered, which ends the helper.
    func setOn(_ on: Bool, bridge: BrowserBridge?) async {
        guard !busy, let service = FillAnywhereHelper.service else { return }
        guard FillAnywhereHelper.mayRegister else {
            FillAnywhereHelper.log.notice("login item untouched in a test or demo run")
            return
        }
        busy = true
        defer {
            busy = false
            reload()
        }
        errorMessage = nil
        if on {
            write(true, Key.enabled)
            do {
                try service.register()
            } catch {
                // The system may still have taken it: waiting for the user's approval in System
                // Settings (or already on). Then the helper must find `fill.enabled` true when it
                // starts, and the approval row says what to do; no error.
                let status = service.status
                FillAnywhereHelper.log.error(
                    "register failed (status \(status.rawValue, privacy: .public)): \(error.localizedDescription, privacy: .public)")
                if status != .requiresApproval && status != .enabled {
                    write(false, Key.enabled)
                    errorMessage = String(localized: "fillAnywhere.error.register \(error.localizedDescription)")
                }
            }
            // Turning it on is the user's choice to let it in again (Task 5 ruling), once the
            // system has it.
            if service.status == .enabled || service.status == .requiresApproval {
                bridge?.allowAgain("fill")
            }
        } else {
            write(false, Key.enabled)
            do {
                try await service.unregister()
            } catch {
                FillAnywhereHelper.log.error("unregister failed: \(error.localizedDescription, privacy: .public)")
                errorMessage = String(localized: "fillAnywhere.error.unregister \(error.localizedDescription)")
            }
        }
    }

    // MARK: The helper's settings

    func setPill(_ on: Bool) {
        write(on, Key.pill)
        reload()
    }

    func setHotkey(_ on: Bool) {
        write(on, Key.hotkey)
        reload()
    }

    func setShortcut(keyCode: Int, modifiers: Int) {
        guard (0...127).contains(keyCode), FillDefaults.isValidHotkey(modifiers: modifiers) else { return }
        defaults.set(keyCode, forKey: Key.hotkeyKeyCode)
        write(FillDefaults.cleanModifiers(modifiers), Key.hotkeyModifiers)
        reload()
    }

    func resetShortcut() {
        setShortcut(keyCode: FillDefaults.hotkeyKeyCode, modifiers: FillDefaults.hotkeyModifiers)
    }

    func setTypingDelay(_ ms: Int) {
        let clamped = min(max(ms, FillDefaults.typingDelayRange.lowerBound), FillDefaults.typingDelayRange.upperBound)
        write(clamped, Key.typingDelayMs)
        reload()
    }

    /// The OnePass app itself is always excluded by the helper: shown, never removable.
    func isAlwaysExcluded(_ bundleID: String) -> Bool { bundleID == appBundleID }

    func addExcluded(_ bundleID: String) {
        guard !excluded.contains(bundleID) else { return }
        write(excluded + [bundleID], Key.excluded)
        reload()
    }

    func removeExcluded(_ bundleID: String) {
        guard !isAlwaysExcluded(bundleID) else { return }
        write(excluded.filter { $0 != bundleID }, Key.excluded)
        reload()
    }

    /// Writes one setting and tells the helper at once.
    private func write(_ value: Any, _ key: String) {
        defaults.set(value, forKey: key)
        guard let appBundleID else { return }
        DistributedNotificationCenter.default().postNotificationName(
            FillDefaults.changedNotification(appBundleID: appBundleID), object: nil, userInfo: nil,
            deliverImmediately: true)
    }
}

/// Remplissage automatique > Remplir partout: turns OnePass Fill on or off, shows the
/// Accessibility grant it needs, and holds its settings (pill, shortcut and its keys, excluded
/// apps, typing delay). Only in builds that carry the helper (`FillAnywhereHelper.isPresent`).
struct FillAnywhereSettings: View {
    /// Made once the page shows: `AutoFillSettings` builds this view on every evaluation of its
    /// row, and the model reads the login item and the defaults when made.
    @State private var state: FillAnywhereSettingsModel?

    var body: some View {
        Group {
            if let state {
                FillAnywhereForm(state: state)
            } else {
                ProgressView()
            }
        }
        .task {
            let state = state ?? FillAnywhereSettingsModel()
            self.state = state
            // The helper writes the grant, System Settings approves the login item: read again
            // while the page shows.
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(2))
                state.reload()
            }
        }
    }
}

/// The page's form, on a model made by `FillAnywhereSettings`.
private struct FillAnywhereForm: View {
    @Environment(AppModel.self) private var model
    let state: FillAnywhereSettingsModel

    var body: some View {
        Form {
            Group {
                mainSection
                accessibilitySection
                Section {
                    Toggle("fillAnywhere.pill", isOn: Binding(get: { state.pill }, set: { state.setPill($0) }))
                        .accessibilityIdentifier("fillAnywhere.pill")
                } footer: {
                    SettingsFootnote("fillAnywhere.pill.footer")
                }
                shortcutSection
                excludedSection
                Section {
                    Stepper(
                        value: Binding(get: { state.typingDelayMs }, set: { state.setTypingDelay($0) }),
                        in: FillDefaults.typingDelayRange, step: 2
                    ) {
                        Text("fillAnywhere.delay \(state.typingDelayMs)")
                    }
                    .accessibilityIdentifier("fillAnywhere.delay")
                } footer: {
                    SettingsFootnote("fillAnywhere.delay.footer")
                }
            }
            .rxSettingsRows()
        }
        .rxSettingsSkin()
        .settingsPage("fillAnywhere.title")
        .accessibilityIdentifier("fillAnywhere.page")
    }

    private var mainSection: some View {
        Section {
            Toggle("fillAnywhere.toggle", isOn: Binding(
                get: { state.isOn },
                set: { on in Task { await state.setOn(on, bridge: model.browserBridge) } }
            ))
            .disabled(state.busy)
            .accessibilityIdentifier("fillAnywhere.enabled")
            if state.status == .requiresApproval {
                LabeledContent("fillAnywhere.status") {
                    Text("fillAnywhere.status.approval").foregroundStyle(.orange)
                }
                .accessibilityIdentifier("fillAnywhere.status")
                Button("fillAnywhere.approve", systemImage: "gear") {
                    SMAppService.openSystemSettingsLoginItems()
                }
                .accessibilityIdentifier("fillAnywhere.approve")
            }
            if let message = state.errorMessage {
                Label(message, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .accessibilityIdentifier("fillAnywhere.error")
            }
        } footer: {
            SettingsFootnote("fillAnywhere.footer")
        }
    }

    private var accessibilitySection: some View {
        Section {
            LabeledContent("fillAnywhere.accessibility") {
                if state.trusted {
                    Label("fillAnywhere.accessibility.granted", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                } else {
                    Text("fillAnywhere.accessibility.missing")
                }
            }
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("fillAnywhere.accessibility")
            if !state.trusted {
                Button("fillAnywhere.accessibility.open", systemImage: "hand.raised") {
                    if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility") {
                        NSWorkspace.shared.open(url)
                    }
                }
                .accessibilityIdentifier("fillAnywhere.accessibility.open")
            }
        } footer: {
            SettingsFootnote("fillAnywhere.accessibility.footer")
        }
    }

    private var shortcutSection: some View {
        Section {
            Toggle("fillAnywhere.hotkey", isOn: Binding(get: { state.hotkey }, set: { state.setHotkey($0) }))
                .accessibilityIdentifier("fillAnywhere.hotkey")
            if state.hotkey {
                LabeledContent("fillAnywhere.hotkey.keys") {
                    HStack(spacing: 8) {
                        if !state.hotkeyIsDefault {
                            Button("fillAnywhere.hotkey.reset") { state.resetShortcut() }
                                .accessibilityIdentifier("fillAnywhere.hotkey.reset")
                        }
                        HotkeyRecorder(keyCode: state.keyCode, modifiers: state.modifiers) { code, mods in
                            state.setShortcut(keyCode: code, modifiers: mods)
                        }
                    }
                }
            }
        } footer: {
            SettingsFootnote("fillAnywhere.hotkey.footer")
        }
    }

    private var excludedSection: some View {
        Section {
            ForEach(state.excluded, id: \.self) { bundleID in
                LabeledContent {
                    if state.isAlwaysExcluded(bundleID) {
                        Text("fillAnywhere.excluded.always").foregroundStyle(.secondary)
                    } else {
                        Button("fillAnywhere.excluded.remove", role: .destructive) { state.removeExcluded(bundleID) }
                            .accessibilityLabel(Text("fillAnywhere.excluded.remove.label \(Self.appName(bundleID))"))
                            .accessibilityIdentifier("fillAnywhere.excluded.remove")
                    }
                } label: {
                    Text(verbatim: Self.appName(bundleID)).lineLimit(1)
                }
            }
            Button("fillAnywhere.excluded.add", systemImage: "plus") { chooseApp() }
                .accessibilityIdentifier("fillAnywhere.excluded.add")
        } header: {
            Text("fillAnywhere.excluded.header")
        } footer: {
            SettingsFootnote("fillAnywhere.excluded.footer")
        }
    }

    /// The app's name for a bundle id, else the id itself (an app no longer installed).
    static func appName(_ bundleID: String) -> String {
        if bundleID == Bundle.main.bundleIdentifier { return "OnePass" }
        guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID) else { return bundleID }
        let name = FileManager.default.displayName(atPath: url.path(percentEncoded: false))
        return name.hasSuffix(".app") ? String(name.dropLast(4)) : name
    }

    /// An app picked in /Applications joins the list by its bundle id.
    private func chooseApp() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.applicationBundle]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.directoryURL = URL(filePath: "/Applications", directoryHint: .isDirectory)
        panel.prompt = String(localized: "fillAnywhere.excluded.panel.prompt")
        guard panel.runModal() == .OK, let url = panel.url,
            let bundleID = Bundle(url: url)?.bundleIdentifier
        else { return }
        state.addExcluded(bundleID)
    }
}

/// The shortcut's keys: a click starts recording, the next combination with ⌘, ⌥ or ⌃ is saved,
/// Escape cancels. The keys are read by a local monitor while recording only.
private struct HotkeyRecorder: View {
    let keyCode: Int
    let modifiers: Int
    let save: (Int, Int) -> Void
    @State private var recording = false
    @State private var invalid = false
    @State private var monitor: Any?

    var body: some View {
        VStack(alignment: .trailing, spacing: 4) {
            Button {
                recording ? stop() : start()
            } label: {
                if recording {
                    Text("fillAnywhere.hotkey.recording")
                } else {
                    Text(verbatim: Self.display(keyCode: keyCode, modifiers: modifiers))
                        .monospaced()
                }
            }
            .accessibilityValue(Text(verbatim: Self.display(keyCode: keyCode, modifiers: modifiers)))
            .accessibilityIdentifier("fillAnywhere.hotkey.record")
            if invalid {
                Text("fillAnywhere.hotkey.invalid")
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .accessibilityIdentifier("fillAnywhere.hotkey.invalid")
            }
        }
        .onDisappear(perform: stop)
    }

    private func start() {
        recording = true
        invalid = false
        monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
            MainActor.assumeIsolated { handle(event) }
            return nil
        }
    }

    private func stop() {
        recording = false
        if let monitor { NSEvent.removeMonitor(monitor) }
        monitor = nil
    }

    private func handle(_ event: NSEvent) {
        let code = Int(event.keyCode)
        let mods = Self.carbonModifiers(event.modifierFlags)
        if code == kVK_Escape, mods == 0 {
            stop()
            return
        }
        guard FillDefaults.isValidHotkey(modifiers: mods), code < 128 else {
            invalid = true
            return
        }
        invalid = false
        stop()
        save(code, mods)
    }

    static func carbonModifiers(_ flags: NSEvent.ModifierFlags) -> Int {
        var mods = 0
        if flags.contains(.command) { mods |= FillDefaults.cmdKey }
        if flags.contains(.option) { mods |= FillDefaults.optionKey }
        if flags.contains(.control) { mods |= FillDefaults.controlKey }
        if flags.contains(.shift) { mods |= FillDefaults.shiftKey }
        return mods
    }

    /// "⌃⌥⇧⌘\" in the system's order, the key as the current layout prints it.
    static func display(keyCode: Int, modifiers: Int) -> String {
        var text = ""
        if modifiers & FillDefaults.controlKey != 0 { text += "⌃" }
        if modifiers & FillDefaults.optionKey != 0 { text += "⌥" }
        if modifiers & FillDefaults.shiftKey != 0 { text += "⇧" }
        if modifiers & FillDefaults.cmdKey != 0 { text += "⌘" }
        return text + keyName(keyCode)
    }

    private static let specialKeys: [Int: String] = [
        kVK_Space: "␣", kVK_Return: "↩", kVK_Tab: "⇥", kVK_Delete: "⌫", kVK_ForwardDelete: "⌦",
        kVK_LeftArrow: "←", kVK_RightArrow: "→", kVK_UpArrow: "↑", kVK_DownArrow: "↓",
        kVK_Home: "↖", kVK_End: "↘", kVK_PageUp: "⇞", kVK_PageDown: "⇟",
        kVK_F1: "F1", kVK_F2: "F2", kVK_F3: "F3", kVK_F4: "F4", kVK_F5: "F5", kVK_F6: "F6",
        kVK_F7: "F7", kVK_F8: "F8", kVK_F9: "F9", kVK_F10: "F10", kVK_F11: "F11", kVK_F12: "F12",
    ]

    /// The character the key gives with no modifier on the current layout (`UCKeyTranslate`).
    static func keyName(_ keyCode: Int) -> String {
        if let special = specialKeys[keyCode] { return special }
        guard let source = TISCopyCurrentKeyboardLayoutInputSource()?.takeRetainedValue(),
            let raw = TISGetInputSourceProperty(source, kTISPropertyUnicodeKeyLayoutData)
        else { return "#\(keyCode)" }
        let data = Unmanaged<CFData>.fromOpaque(raw).takeUnretainedValue() as Data
        var dead: UInt32 = 0
        var chars = [UniChar](repeating: 0, count: 4)
        var length = 0
        let status = data.withUnsafeBytes { bytes -> OSStatus in
            guard let layout = bytes.baseAddress?.assumingMemoryBound(to: UCKeyboardLayout.self) else { return -1 }
            return UCKeyTranslate(
                layout, UInt16(keyCode), UInt16(kUCKeyActionDisplay), 0, UInt32(LMGetKbdType()),
                OptionBits(kUCKeyTranslateNoDeadKeysMask), &dead, chars.count, &length, &chars)
        }
        guard status == noErr, length > 0 else { return "#\(keyCode)" }
        let name = String(utf16CodeUnits: chars, count: length).trimmingCharacters(in: .whitespacesAndNewlines)
        return name.isEmpty ? "#\(keyCode)" : name.uppercased()
    }
}
#endif
