import Foundation
import GlanceKit
import WidgetKit

/// What one widget entry shows.
enum GlanceState: Sendable {
    case available(GlanceSnapshot)
    /// The file exists but cannot be read: the device is locked (data protection Complete).
    case locked
    /// Absent, expired or corrupt: the app has to publish a new snapshot.
    case stale
}

struct GlanceEntry: TimelineEntry {
    let date: Date
    let state: GlanceState
}

/// Shared by both widgets. One entry every 30 s for one hour (aligned on the TOTP 30 s steps),
/// then WidgetKit asks again. An entry past the snapshot's end shows "Ouvre OnePass pour
/// actualiser".
struct GlanceProvider: TimelineProvider {
    static let step: TimeInterval = 30
    static let span: TimeInterval = 3_600
    /// Locked or stale: nothing changes until the app publishes (which reloads the widgets).
    static let idleRetry: TimeInterval = 900

    func placeholder(in context: Context) -> GlanceEntry {
        GlanceEntry(date: .now, state: .stale)
    }

    func getSnapshot(in context: Context, completion: @escaping (GlanceEntry) -> Void) {
        let now = Date.now
        completion(GlanceEntry(date: now, state: Self.state(now: now)))
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<GlanceEntry>) -> Void) {
        completion(Self.timeline(now: .now))
    }

    static func state(now: Date) -> GlanceState {
        guard let store = GlanceStore.shared() else { return .stale }
        switch store.status(now: now) {
        case .available(let snapshot): return .available(snapshot)
        case .locked: return .locked
        case .stale: return .stale
        }
    }

    static func timeline(now: Date) -> Timeline<GlanceEntry> {
        let state = state(now: now)
        guard case .available(let snapshot) = state else {
            return Timeline(entries: [GlanceEntry(date: now, state: state)], policy: .after(now + idleRetry))
        }
        var entries = [GlanceEntry(date: now, state: state)]
        // The next 30 s boundary, then every 30 s up to one hour.
        var date = (now.timeIntervalSince1970 / step).rounded(.down) * step + step
        let end = now.timeIntervalSince1970 + span
        while date <= end {
            let at = Date(timeIntervalSince1970: date)
            entries.append(GlanceEntry(date: at, state: at < snapshot.validUntil ? state : .stale))
            date += step
        }
        return Timeline(entries: entries, policy: .after(entries[entries.count - 1].date))
    }
}
