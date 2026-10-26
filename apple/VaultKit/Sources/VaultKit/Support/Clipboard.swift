import Foundation
import Synchronization

#if canImport(UIKit)
import UIKit
import UniformTypeIdentifiers
#elseif canImport(AppKit)
import AppKit
#endif

/// The system pasteboard as seen by `Clipboard` (a test double replaces it).
public protocol PasteboardWriter: Sendable {
    /// Writes local only (no Universal Clipboard), marked concealed when asked.
    func write(_ s: String, concealed: Bool, expiresAfter: TimeInterval)
    /// Clears the pasteboard only if nothing was copied since our last `write`.
    func clearIfUnchanged()
}

/// Real pasteboard. iOS: `localOnly` + system expiration date. macOS: current host only,
/// `org.nspasteboard.ConcealedType` so clipboard managers skip it; `Clipboard` clears it.
public final class SystemPasteboard: PasteboardWriter {
    /// `changeCount` right after our last write.
    private let ownChange = Mutex<Int?>(nil)

    #if canImport(UIKit)
    public init() {}
    #elseif canImport(AppKit)
    /// Pasteboard name (tests use a private named pasteboard, never the user's one).
    private let name: NSPasteboard.Name

    public init(name: NSPasteboard.Name = .general) {
        self.name = name
    }

    private var board: NSPasteboard { NSPasteboard(name: name) }
    #endif

    public func write(_ s: String, concealed: Bool, expiresAfter: TimeInterval) {
        #if canImport(UIKit)
        let board = UIPasteboard.general
        board.setItems(
            [[UTType.utf8PlainText.identifier: s]],
            options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(expiresAfter)])
        let count = board.changeCount
        ownChange.withLock { $0 = count }
        #elseif canImport(AppKit)
        let board = self.board
        // Clears the pasteboard and sets "this Mac only" (no Universal Clipboard). No `declareTypes`
        // after it: that would clear again with the default options.
        board.prepareForNewContents(with: .currentHostOnly)
        board.setString(s, forType: .string)
        if concealed { board.setData(Data(), forType: Self.concealedType) }
        let count = board.changeCount
        ownChange.withLock { $0 = count }
        #endif
    }

    public func clearIfUnchanged() {
        #if canImport(UIKit)
        let board = UIPasteboard.general
        guard ownChange.withLock({ $0 }) == board.changeCount else { return }
        board.items = []
        ownChange.withLock { $0 = nil }
        #elseif canImport(AppKit)
        let board = self.board
        guard ownChange.withLock({ $0 }) == board.changeCount else { return }
        board.clearContents()
        ownChange.withLock { $0 = nil }
        #endif
    }

    #if canImport(AppKit) && !canImport(UIKit)
    /// nspasteboard.org convention honoured by clipboard managers.
    static let concealedType = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
    #endif
}

/// Copies a value and clears it after `clearAfter` seconds (90 s) unless something else was copied.
@MainActor
public final class Clipboard {
    public static let defaultClearAfter: TimeInterval = 90

    private let pasteboard: any PasteboardWriter
    private let clock: any BootClock
    private let clearAfter: TimeInterval
    private var expiresAt: Date?
    private var timer: Task<Void, Never>?

    public init(pasteboard: any PasteboardWriter, clock: any BootClock, clearAfter: TimeInterval = Clipboard.defaultClearAfter) {
        self.pasteboard = pasteboard
        self.clock = clock
        self.clearAfter = clearAfter
    }

    public func copy(_ value: String, concealed: Bool) {
        pasteboard.write(value, concealed: concealed, expiresAfter: clearAfter)
        expiresAt = clock.now.addingTimeInterval(clearAfter)
        timer?.cancel()
        let delay = clearAfter
        timer = Task { [weak self] in
            try? await Task.sleep(for: .seconds(delay))
            guard !Task.isCancelled else { return }
            self?.clearNow()
        }
    }

    /// Clears now if our value is still there (called on lock).
    public func clear() { clearNow() }

    /// Clears when the delay has passed on the injected clock (also call it when the app becomes active:
    /// a suspended app does not run its timer).
    public func clearIfExpired() {
        guard let expiresAt, clock.now >= expiresAt else { return }
        clearNow()
    }

    private func clearNow() {
        guard expiresAt != nil else { return }
        pasteboard.clearIfUnchanged()
        expiresAt = nil
        timer?.cancel()
        timer = nil
    }
}
