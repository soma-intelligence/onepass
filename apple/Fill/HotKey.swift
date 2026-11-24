import Carbon.HIToolbox
import os

/// The global shortcut, ⌥⌘\ by default, through `RegisterEventHotKey`: Carbon delivers it to this
/// process without Input Monitoring, and the helper sees no other key.
@MainActor
final class HotKey {
    private var ref: EventHotKeyRef?
    private var handler: EventHandlerRef?
    private let action: @MainActor () -> Void
    private static let signature: OSType = 0x4F_50_46_4C  // "OPFL"
    private static let log = Logger(
        subsystem: Bundle.main.bundleIdentifier ?? "me.somalabs.onepass.fill", category: "hotkey")

    /// `keyCode` is a virtual key (`kVK_*`), `modifiers` Carbon modifier flags.
    init(
        keyCode: UInt32 = UInt32(kVK_ANSI_Backslash), modifiers: UInt32 = UInt32(optionKey | cmdKey),
        action: @escaping @MainActor () -> Void
    ) {
        self.action = action
        var type = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
        let me = Unmanaged.passUnretained(self).toOpaque()
        let installed = InstallEventHandler(
            GetApplicationEventTarget(),
            { _, event, context in
                guard let event, let context else { return OSStatus(eventNotHandledErr) }
                var id = EventHotKeyID()
                let status = GetEventParameter(
                    event, EventParamName(kEventParamDirectObject), EventParamType(typeEventHotKeyID), nil,
                    MemoryLayout<EventHotKeyID>.size, nil, &id)
                guard status == noErr, id.signature == HotKey.signature else {
                    return OSStatus(eventNotHandledErr)
                }
                let hotKey = Unmanaged<HotKey>.fromOpaque(context).takeUnretainedValue()
                // Carbon calls back on the main thread (the application event target).
                MainActor.assumeIsolated { hotKey.action() }
                return noErr
            }, 1, &type, me, &handler)
        guard installed == noErr else {
            Self.log.error("hot key handler not installed, status \(installed, privacy: .public)")
            return
        }
        let status = RegisterEventHotKey(
            keyCode, modifiers, EventHotKeyID(signature: Self.signature, id: 1), GetApplicationEventTarget(), 0,
            &ref)
        if status != noErr {
            // Taken by another app: the pill still works.
            Self.log.error("hot key not registered, status \(status, privacy: .public)")
        }
    }

    /// Unregisters the shortcut. Called before the object goes (the setting turned off).
    func invalidate() {
        if let ref { UnregisterEventHotKey(ref) }
        if let handler { RemoveEventHandler(handler) }
        ref = nil
        handler = nil
    }
}
