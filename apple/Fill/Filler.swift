import AppKit
import ApplicationServices
import Carbon.HIToolbox
import FillKit
import os

/// How a fill ended.
enum FillOutcome: Equatable {
    /// Every step ran; the strategy of the last value. `.clipboard` ends the flow at that value:
    /// the user pastes it, and the steps after it are not run.
    case done(FillStrategy)
    /// The frontmost app or the focused element changed: nothing more was typed.
    case stoppedFocusChanged
    /// Accessibility could not set the value and a secure input session of another process
    /// blocks typing: the picker offers the clipboard.
    case secureInputElsewhere
    /// No strategy worked, typing broke off midway, the field after Tab is not the one the value
    /// is for, or the value could not be had (`Filler.lastError`). The picker offers Copy for
    /// `Filler.lastKind` unless `lastError` says why.
    case failed
}

/// Fills the steps of `FillFlow` into the focused field (spec, Fill strategies and Focus guard):
/// for each value, Accessibility set, then typed key events, then the clipboard. The value is
/// asked for only when its step comes, and dropped right after it.
@MainActor
final class Filler {
    /// The value kind of the step that failed or was stopped, for the picker's Copy button.
    private(set) var lastKind: FieldKind?
    /// The error of the value request that failed the fill, if any.
    private(set) var lastError: (any Error)?

    private let clipboard: Clipboard
    private let typingDelay: Duration
    private static let log = Logger(
        subsystem: Bundle.main.bundleIdentifier ?? "me.somalabs.onepass.fill", category: "filler")

    init(clipboard: Clipboard, typingDelayMs: Int) {
        self.clipboard = clipboard
        typingDelay = .milliseconds(typingDelayMs)
    }

    /// Runs `steps` against the element `guard` names. `values` gives one value per call, only
    /// for the step being filled. `elements` holds fields the flow knows by kind: `.password` for
    /// `.focusPassword`, `.oneTimeCode` for the code that follows the password.
    func fill(
        steps: [FillStep], values: (FieldKind) async throws -> SecretBuffer, guard focusGuard: FocusGuard,
        elements: [FieldKind: AXUIElement] = [:]
    ) async -> FillOutcome {
        lastKind = nil
        lastError = nil
        // Neither an element nor a window to pin the fill to: nothing is typed, Copy is offered.
        if let focus = Self.currentFocus(), focusGuard.holds(pid: focus.pid, elementID: focus.id),
            !focus.id.isGuardable
        {
            lastKind = steps.lazy.compactMap { step -> FieldKind? in
                if case .value(let kind) = step { return kind }
                return nil
            }.first
            return .failed
        }
        var guardNow = focusGuard
        var last: FillStrategy?
        var previousWasValue = false
        for (index, step) in steps.enumerated() {
            guard let focus = Self.currentFocus(), guardNow.holds(pid: focus.pid, elementID: focus.id) else {
                return .stoppedFocusChanged
            }
            let nextKind = steps[(index + 1)...].lazy.compactMap { step -> FieldKind? in
                if case .value(let kind) = step { return kind }
                return nil
            }.first
            switch step {
            case .focusPassword:
                lastKind = .password
                guard let password = elements[.password], let moved = await moveFocus(from: focus, to: password)
                else { return .failed }
                guardNow = moved
                previousWasValue = false
            case .tab:
                lastKind = nextKind
                switch await tab(from: focus, for: nextKind) {
                case .moved(let moved): guardNow = moved
                case .wrongField: return .failed
                case .lost: return .stoppedFocusChanged
                }
                previousWasValue = false
            case .value(let kind):
                lastKind = kind
                var target = focus
                if previousWasValue {
                    // Two values in a row (the code after the password): the known field, never
                    // the one just filled.
                    guard let next = elements[kind], let moved = await moveFocus(from: focus, to: next),
                        let now = Self.currentFocus()
                    else { return last.map(FillOutcome.done) ?? .failed }
                    guardNow = moved
                    target = now
                }
                let outcome = await fillValue(kind: kind, at: target, values: values, guard: guardNow)
                switch outcome {
                case .done(.clipboard):
                    return outcome
                case .done(let strategy):
                    last = strategy
                default:
                    return outcome
                }
                previousWasValue = true
            }
        }
        lastKind = nil
        return last.map(FillOutcome.done) ?? .failed
    }

    /// One value, strategy after strategy, the guard checked before each.
    private func fillValue(
        kind: FieldKind, at focus: Focus, values: (FieldKind) async throws -> SecretBuffer, guard focusGuard: FocusGuard
    ) async -> FillOutcome {
        let secret: SecretBuffer
        do {
            secret = try await values(kind)
        } catch {
            lastError = error
            return .failed
        }
        // Touch ID may have run meanwhile: the focus is checked again before anything is written.
        let typingBlocked = FillDecision.secureInputBlocksTyping(Self.secureInput(), targetPID: focus.pid)
        let canSet = focus.element.map {
            FillDecision.allowsAccessibilitySet(
                role: AX.string($0, kAXRoleAttribute), subrole: AX.string($0, kAXSubroleAttribute))
        } ?? false
        var result = StrategyResult.start
        var typingStarted = false
        while let strategy = FillDecision.next(after: result, typingBlocked: typingBlocked, typingStarted: typingStarted) {
            guard holds(focusGuard) else { return .stoppedFocusChanged }
            let worked: Bool
            switch strategy {
            case .accessibility:
                // Not on a canvas or a custom view: those get typed keys only.
                worked = canSet && focus.element.map { Self.setByAccessibility(secret, on: $0) } == true
            case .typing:
                switch await type(secret, pid: focus.pid, element: canSet ? focus.element : nil, guard: focusGuard) {
                case .typed: worked = true
                case .failed(let started):
                    worked = false
                    typingStarted = started
                case .focusChanged: return .stoppedFocusChanged
                }
            case .clipboard:
                // Typing skipped for another process's secure input: the user chooses to copy.
                if typingBlocked { return .secureInputElsewhere }
                worked = clipboard.copy(secret)
            }
            Self.log.notice("fill \(String(describing: kind), privacy: .public): \(strategy.rawValue, privacy: .public) \(worked ? "worked" : "failed", privacy: .public)")
            result = worked ? .worked(strategy) : .failed(strategy)
        }
        if case .worked(let strategy) = result {
#if DEBUG
            FillTestLog.append("strategy=\(strategy.rawValue)")
#endif
            return .done(strategy)
        }
        return .failed
    }

    private func holds(_ focusGuard: FocusGuard) -> Bool {
        guard let focus = Self.currentFocus() else { return false }
        return focusGuard.holds(pid: focus.pid, elementID: focus.id)
    }

    // MARK: Focus

    struct Focus {
        let pid: pid_t
        let element: AXUIElement?
        let window: AXUIElement?
        var id: ElementID { ElementID.of(element: element, window: window) }
    }

    /// The frontmost app (never the helper) and its focused element now.
    static func currentFocus() -> Focus? {
        guard let pid = FocusWatcher.frontmostPID() else { return nil }
        return Focus(
            pid: pid, element: FocusWatcher.focusedElement(pid: pid), window: FocusWatcher.focusedWindow(pid: pid))
    }

    /// Moves the focus to `element` by Accessibility, in the same process. The guard that follows
    /// names that element; nil when the focus did not land on it.
    private func moveFocus(from focus: Focus, to element: AXUIElement) async -> FocusGuard? {
        guard AXUIElementSetAttributeValue(element, kAXFocusedAttribute as CFString, kCFBooleanTrue) == .success
        else { return nil }
        try? await Task.sleep(for: .milliseconds(80))
        guard let now = Self.currentFocus(), now.pid == focus.pid, let reached = now.element, CFEqual(reached, element)
        else { return nil }
        return FocusGuard(pid: now.pid, elementID: now.id)
    }

    private enum TabResult {
        case moved(FocusGuard)
        /// The focus moved to a field that is not for `kind`: nothing is written there.
        case wrongField
        /// The focus left the process or vanished.
        case lost
    }

    /// Tab, then the field that took the focus must be one `kind` may go into
    /// (`FillDecision.acceptsAfterTab`: a password only into a password field).
    private func tab(from focus: Focus, for kind: FieldKind?) async -> TabResult {
        guard Self.postKey(CGKeyCode(kVK_Tab), flags: [], pid: focus.pid) else { return .wrongField }
        try? await Task.sleep(for: .milliseconds(80))
        guard let now = Self.currentFocus(), now.pid == focus.pid, let element = now.element, !(now.id == focus.id)
        else { return .lost }
        guard let kind, let bundleID = NSRunningApplication(processIdentifier: now.pid)?.bundleIdentifier else {
            return .wrongField
        }
        let snapshot = AX.snapshot(element, pid: now.pid, bundleID: bundleID, window: nil, windowTitle: nil)
        guard FillDecision.acceptsAfterTab(snapshot, for: kind) else { return .wrongField }
        return .moved(FocusGuard(pid: now.pid, elementID: now.id))
    }

    // MARK: Accessibility set

    /// `kAXValueAttribute`, confirmed by the length read back: `kAXNumberOfCharacters`, else the
    /// end of the selected range. The value itself is never read back.
    static func setByAccessibility(_ secret: SecretBuffer, on element: AXUIElement) -> Bool {
        var settable: DarwinBoolean = false
        guard AXUIElementIsAttributeSettable(element, kAXValueAttribute as CFString, &settable) == .success,
            settable.boolValue
        else { return false }
        let (status, units, characters) = secret.withValue { value in
            (AXUIElementSetAttributeValue(element, kAXValueAttribute as CFString, value as CFString),
             value.utf16.count, value.count)
        }
        guard status == .success else { return false }
        guard let length = (AX.value(element, kAXNumberOfCharactersAttribute) as? Int) ?? selectionEnd(element)
        else { return false }
        return length == units || length == characters
    }

    /// Where the selection ends (the caret sits after the value once it is set).
    private static func selectionEnd(_ element: AXUIElement) -> Int? {
        guard let raw = AX.value(element, kAXSelectedTextRangeAttribute), CFGetTypeID(raw) == AXValueGetTypeID()
        else { return nil }
        var range = CFRange()
        guard AXValueGetValue(raw as! AXValue, .cfRange, &range) else { return nil }
        return range.location + range.length
    }

    // MARK: Typing

    private enum TypingResult {
        case typed
        /// `started`: some keys went out before the failure.
        case failed(started: Bool)
        case focusChanged
    }

    /// Key events posted to `pid`, `keysPerBatch` at a time with the guard checked before each
    /// batch, `typingDelay` apart. Characters the keyboard layout types become their key; the
    /// others go as Unicode string events. A text field's content is selected first by
    /// Accessibility so the value replaces it (`element` is nil for a canvas).
    private func type(_ secret: SecretBuffer, pid: pid_t, element: AXUIElement?, guard focusGuard: FocusGuard) async
        -> TypingResult
    {
        let keys = TypedKeys(secret)
        guard !keys.isEmpty else { return .failed(started: false) }
        if let element { Self.selectAll(element) }
        let map = KeyMap.current()
        var sent = false
        for batch in FillDecision.batches(of: keys.count) {
            guard holds(focusGuard) else { return .focusChanged }
            for index in batch {
                guard keys.post(index, map: map, pid: pid) else { return .failed(started: sent) }
                sent = true
                try? await Task.sleep(for: typingDelay)
            }
        }
        return .typed
    }

    private static func selectAll(_ element: AXUIElement) {
        guard let length = AX.value(element, kAXNumberOfCharactersAttribute) as? Int, length > 0 else { return }
        var range = CFRange(location: 0, length: length)
        guard let value = AXValueCreate(.cfRange, &range) else { return }
        _ = AXUIElementSetAttributeValue(element, kAXSelectedTextRangeAttribute as CFString, value)
    }

    /// One key with `flags`, to `pid`. Shift and Option, when asked, are pressed around it with
    /// their own `flagsChanged` events, so a client that tracks modifier state (remote desktop,
    /// a VM) sees them down while the key goes and up after.
    nonisolated static func postKey(_ code: CGKeyCode, flags: CGEventFlags, pid: pid_t) -> Bool {
        let source = CGEventSource(stateID: .privateState)
        let modifiers: [(CGKeyCode, CGEventFlags)] = [
            (CGKeyCode(kVK_Shift), .maskShift), (CGKeyCode(kVK_Option), .maskAlternate),
        ].filter { flags.contains($0.1) }
        var held: CGEventFlags = []
        for (key, flag) in modifiers {
            held.insert(flag)
            guard modifierEvent(key, flags: held, source: source, pid: pid) else { return false }
        }
        guard let down = CGEvent(keyboardEventSource: source, virtualKey: code, keyDown: true),
            let up = CGEvent(keyboardEventSource: source, virtualKey: code, keyDown: false)
        else { return false }
        down.flags = flags
        up.flags = flags
        down.postToPid(pid)
        up.postToPid(pid)
        for (key, flag) in modifiers.reversed() {
            held.remove(flag)
            guard modifierEvent(key, flags: held, source: source, pid: pid) else { return false }
        }
        return true
    }

    /// A `flagsChanged` event for a modifier key, with the flags held after it.
    nonisolated private static func modifierEvent(
        _ key: CGKeyCode, flags: CGEventFlags, source: CGEventSource?, pid: pid_t
    ) -> Bool {
        guard let event = CGEvent(keyboardEventSource: source, virtualKey: key, keyDown: !flags.isEmpty) else {
            return false
        }
        event.type = .flagsChanged
        event.flags = flags
        event.postToPid(pid)
        return true
    }

    // MARK: Secure input

    /// The secure keyboard input session and its owner. `IsSecureEventInputEnabled` says whether
    /// one is on; macOS has no public API for its owner, so the owner is read from the session
    /// dictionary (`CGSessionCopyCurrentDictionary`, key `kCGSSessionSecureInputPID`: not
    /// documented, but present on current macOS and read by other text tools). No key, or a pid
    /// of 0, gives `ownerUnknown`, which counts as another process.
    static func secureInput() -> SecureInput {
        guard IsSecureEventInputEnabled() else { return .off }
        guard let session = CGSessionCopyCurrentDictionary() as? [String: Any],
            let owner = session["kCGSSessionSecureInputPID"] as? NSNumber, owner.int32Value > 0
        else { return .ownerUnknown }
        return .owned(by: owner.int32Value)
    }
}

/// The value as UTF-16 units grouped by character, in memory this object zeroes when released,
/// so typing over several batches never keeps a `String` alive across the waits.
private final class TypedKeys {
    private let units: UnsafeMutableBufferPointer<UInt16>
    /// Start of each character in `units`, plus the end.
    private let bounds: UnsafeMutableBufferPointer<Int>
    let count: Int

    init(_ secret: SecretBuffer) {
        var made: (UnsafeMutableBufferPointer<UInt16>, UnsafeMutableBufferPointer<Int>, Int)!
        secret.withValue { value in
            let units = UnsafeMutableBufferPointer<UInt16>.allocate(capacity: max(value.utf16.count, 1))
            let bounds = UnsafeMutableBufferPointer<Int>.allocate(capacity: value.count + 1)
            var at = 0
            var n = 0
            for character in value {
                bounds[n] = at
                n += 1
                for unit in character.utf16 {
                    units[at] = unit
                    at += 1
                }
            }
            bounds[n] = at
            made = (units, bounds, n)
        }
        units = made.0
        bounds = made.1
        count = made.2
    }

    var isEmpty: Bool { count == 0 }

    /// Posts character `index` to `pid`: its key when the layout has one, else a Unicode event.
    func post(_ index: Int, map: KeyMap, pid: pid_t) -> Bool {
        let start = bounds[index]
        let length = bounds[index + 1] - start
        if length == 1, let key = map.key(for: units[start]) {
            return Filler.postKey(key.code, flags: key.flags, pid: pid)
        }
        let source = CGEventSource(stateID: .privateState)
        // Virtual key 0 (kVK_ANSI_A on ANSI keyboards): macOS has no key code that maps to no
        // character on every layout, so this keeps the common choice. Apps read the Unicode
        // string; a client that reads only the key code would type "a" (Task 10 hand check).
        guard let down = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: true),
            let up = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: false),
            let base = units.baseAddress
        else { return false }
        down.flags = []
        up.flags = []
        down.keyboardSetUnicodeString(stringLength: length, unicodeString: base + start)
        up.keyboardSetUnicodeString(stringLength: length, unicodeString: base + start)
        down.postToPid(pid)
        up.postToPid(pid)
        return true
    }

    deinit {
        if let base = units.baseAddress {
            _ = memset_s(base, units.count * MemoryLayout<UInt16>.size, 0, units.count * MemoryLayout<UInt16>.size)
        }
        if let base = bounds.baseAddress {
            _ = memset_s(base, bounds.count * MemoryLayout<Int>.size, 0, bounds.count * MemoryLayout<Int>.size)
        }
        units.deallocate()
        bounds.deallocate()
    }
}

/// Which key, with which modifiers, types one UTF-16 unit on the current keyboard layout
/// (`UCKeyTranslate` over every key with none, Shift, Option and Shift-Option).
struct KeyMap {
    struct Key {
        let code: CGKeyCode
        let flags: CGEventFlags
    }

    private var keys: [UInt16: Key] = [:]

    func key(for unit: UInt16) -> Key? { keys[unit] }

    static func current() -> KeyMap {
        var map = KeyMap()
        guard let source = TISCopyCurrentKeyboardLayoutInputSource()?.takeRetainedValue(),
            let raw = TISGetInputSourceProperty(source, kTISPropertyUnicodeKeyLayoutData)
        else { return map }
        let data = Unmanaged<CFData>.fromOpaque(raw).takeUnretainedValue() as Data
        let kbType = UInt32(LMGetKbdType())
        let combos: [(UInt32, CGEventFlags)] = [
            (0, []), (UInt32(shiftKey >> 8), .maskShift), (UInt32(optionKey >> 8), .maskAlternate),
            (UInt32((shiftKey | optionKey) >> 8), [.maskShift, .maskAlternate]),
        ]
        data.withUnsafeBytes { bytes in
            guard let layout = bytes.baseAddress?.assumingMemoryBound(to: UCKeyboardLayout.self) else { return }
            for (modifiers, flags) in combos {
                for code in 0..<UInt16(128) {
                    var dead: UInt32 = 0
                    var length = 0
                    var chars = [UniChar](repeating: 0, count: 4)
                    let status = UCKeyTranslate(
                        layout, code, UInt16(kUCKeyActionDown), modifiers, kbType,
                        OptionBits(kUCKeyTranslateNoDeadKeysMask), &dead, chars.count, &length, &chars)
                    // The first combination wins: a character keeps its plainest key.
                    if status == noErr, length == 1, map.keys[chars[0]] == nil, chars[0] >= 0x20 {
                        map.keys[chars[0]] = Key(code: CGKeyCode(code), flags: flags)
                    }
                }
            }
        }
        return map
    }
}

/// The clipboard fallback: the value marked concealed and transient (`org.nspasteboard`
/// conventions, so clipboard managers skip it), cleared after 30 s if the clipboard still holds
/// it. A paste does not change `changeCount`, so it cannot be seen cheaply; `changeCount` only
/// tells that something else replaced the value, in which case nothing is cleared.
@MainActor
final class Clipboard {
    static let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
    static let transient = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")
    static let lifetime: Duration = .seconds(30)

    private let pasteboard: NSPasteboard
    private var ownedChangeCount: Int?
    private var expiry: Task<Void, Never>?

    init(pasteboard: NSPasteboard = .general) {
        self.pasteboard = pasteboard
    }

    /// Puts the value on the clipboard. The pasteboard keeps its own copy, which the helper
    /// cannot zero; it is cleared at expiry.
    func copy(_ secret: SecretBuffer) -> Bool {
        let item = NSPasteboardItem()
        let set = secret.withValue { item.setString($0, forType: .string) }
        guard set else { return false }
        item.setData(Data(), forType: Self.concealed)
        item.setData(Data(), forType: Self.transient)
        pasteboard.clearContents()
        guard pasteboard.writeObjects([item]) else { return false }
        let count = pasteboard.changeCount
        ownedChangeCount = count
        expiry?.cancel()
        expiry = Task { [weak self] in
            try? await Task.sleep(for: Self.lifetime)
            guard !Task.isCancelled else { return }
            self?.clearIfOwned(count)
        }
        return true
    }

    /// Clears the clipboard if it still holds the value written at `count`.
    func clearIfOwned(_ count: Int) {
        guard ownedChangeCount == count else { return }
        ownedChangeCount = nil
        if pasteboard.changeCount == count { pasteboard.clearContents() }
    }

    /// At quit: the value does not outlive the helper.
    func clearNow() {
        if let count = ownedChangeCount { clearIfOwned(count) }
        expiry?.cancel()
    }
}
