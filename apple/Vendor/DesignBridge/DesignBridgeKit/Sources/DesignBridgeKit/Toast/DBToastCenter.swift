import Foundation
import Observation
import SwiftUI
import os

/// Why the visible toast's timer is paused.
public enum DBToastPauseReason: Sendable, Hashable {
    case touch
    case voiceOver
}

/// Drives a `DBToastQueue` with real time. One per `.dbToastHost()`.
@MainActor
@Observable
public final class DBToastCenter {
    public private(set) var queue = DBToastQueue()

    public var current: DBToast? { queue.current }

    @ObservationIgnored private let origin = ContinuousClock.now
    @ObservationIgnored private var timer: Task<Void, Never>?
    @ObservationIgnored private var pauseReasons: Set<DBToastPauseReason> = []
    @ObservationIgnored private var visibleID: UUID?
    @ObservationIgnored private let announce: @MainActor (DBToast) -> Void

    public init() {
        self.announce = DBToastCenter.postAnnouncement
    }

    /// For tests: replaces the VoiceOver announcement.
    init(announce: @escaping @MainActor (DBToast) -> Void) {
        self.announce = announce
    }

    public func show(_ toast: DBToast) {
        queue.enqueue(toast, now: now)
        didChange()
    }

    public func dismiss() {
        queue.dismissCurrent(now: now)
        didChange()
    }

    public func pause(_ reason: DBToastPauseReason) {
        pauseReasons.insert(reason)
        queue.pause(now: now)
        reschedule()
    }

    public func resume(_ reason: DBToastPauseReason) {
        pauseReasons.remove(reason)
        guard pauseReasons.isEmpty else { return }
        queue.resume(now: now)
        reschedule()
    }

    private var now: TimeInterval {
        let elapsed = ContinuousClock.now - origin
        return Double(elapsed.components.seconds) + Double(elapsed.components.attoseconds) / 1e18
    }

    private func didChange() {
        if queue.current?.id != visibleID {
            visibleID = queue.current?.id
            pauseReasons.removeAll()
            if let toast = queue.current {
                announce(toast)
            }
        }
        reschedule()
    }

    private func reschedule() {
        timer?.cancel()
        guard let remaining = queue.remaining(now: now) else { return }
        timer = Task { [weak self] in
            try? await Task.sleep(for: .seconds(remaining))
            guard !Task.isCancelled else { return }
            self?.expire()
        }
    }

    private func expire() {
        // A small tolerance absorbs sleep jitter so the timer never spins.
        queue.advance(now: now + 0.02)
        didChange()
    }

    /// Announces the toast without moving VoiceOver focus (UX-TOAST-04).
    static func postAnnouncement(_ toast: DBToast) {
        var text = AttributedString(toast.message)
        if let action = toast.action {
            text += AttributedString(". \(action.title) available.")
        }
        text.accessibilitySpeechAnnouncementPriority = toast.kind == .error ? .high : .default
        AccessibilityNotification.Announcement(text).post()
    }
}

/// The environment action that shows a toast:
///
/// ```swift
/// @Environment(\.toast) private var toast
/// Button("Copy") { toast.copyToClipboard(code, label: "Code copied") }
/// ```
public struct DBToastPresenter: Sendable {
    private let present: @MainActor @Sendable (DBToast) -> Void
    private let writePasteboard: @MainActor @Sendable (String) -> Void

    public init(_ present: @escaping @MainActor @Sendable (DBToast) -> Void) {
        self.init(present: present, pasteboard: { DBPasteboard.copy($0) })
    }

    init(
        present: @escaping @MainActor @Sendable (DBToast) -> Void,
        pasteboard: @escaping @MainActor @Sendable (String) -> Void
    ) {
        self.present = present
        self.writePasteboard = pasteboard
    }

    @MainActor
    public func callAsFunction(_ toast: DBToast) {
        present(toast)
    }

    /// Copies `string` and confirms with a success toast (UX-TOAST-01).
    @MainActor
    public func copyToClipboard(_ string: String, label: String = DBStrings.copied) {
        writePasteboard(string)
        present(.success(label, systemImage: "doc.on.doc.fill"))
    }

    /// Used when no `.dbToastHost()` is above the view. Logs so the missing host is found.
    static let unhosted = DBToastPresenter { toast in
        Logger(subsystem: "DesignBridgeKit", category: "Toast")
            .error("toast(\(toast.message, privacy: .public)) without a .dbToastHost() above the view")
    }
}

extension EnvironmentValues {
    /// Shows a toast in the nearest `.dbToastHost()`.
    @Entry public var toast: DBToastPresenter = .unhosted
}

/// Writes to the system pasteboard.
@MainActor
public enum DBPasteboard {
    public static func copy(_ string: String) {
        #if os(watchOS)
        // No pasteboard on watchOS: copy actions are not offered there.
        _ = string
        #elseif canImport(UIKit)
        UIPasteboard.general.string = string
        #elseif canImport(AppKit)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(string, forType: .string)
        #endif
    }
}
