import CompanionLink
import Foundation
import GlanceKit
import VaultKit
import os
#if os(iOS)
import WidgetKit
#endif

/// Keeps what lives outside the app up to date while the vault is unlocked: the widget snapshot
/// in the App Group (iOS) and, from Task 8, the watch payload (`phone`). Called on unlock, on
/// every data change during the session and on each return to the foreground unlocked.
@MainActor
final class CompanionCoordinator {
    /// Codes precomputed for the widgets: 12 h (spec 7, ruling W4).
    static let glanceWindow: TimeInterval = 43_200
    /// Changes come in bursts (unlock then reload, sync rounds): one publication per burst.
    static let debounce: Duration = .seconds(2)

    let session: VaultSession
    /// The watch link (Task 8). Nil until wired.
    var phone: PhoneCompanion?
    /// Nil without the App Group (unsigned builds): nothing is published.
    private let glanceStore: GlanceStore?
    private var pending: Task<Void, Never>?
    private var started = false

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "companion")

    init(session: VaultSession, glanceStore: GlanceStore?, phone: PhoneCompanion?) {
        self.session = session
        self.glanceStore = glanceStore
        self.phone = phone
    }

    /// The watch link of this device: iPhone only (macOS and visionOS have no paired watch).
    /// The payload excludes hidden vaults and is sealed to the watch key.
    static func makePhone(session: VaultSession) -> PhoneCompanion? {
        #if os(iOS)
        return PhoneCompanion(
            transport: WatchConnectivityTransport(), defaults: .standard,
            seal: { key, generation in
                try await session.companionPayload(recipientPublicKey: key, generation: generation)
            })
        #else
        return nil
        #endif
    }

    /// Called once by `AppModel.start()`.
    func start() {
        guard !started else { return }
        started = true
        phone?.start()
        sessionChanged()
    }

    /// The session state or its data changed: publishes 2 s after the last change, only while
    /// unlocked. A lock cancels a publication not yet started.
    func sessionChanged() {
        pending?.cancel()
        pending = nil
        guard session.state == .unlocked else { return }
        pending = Task { [weak self] in
            try? await Task.sleep(for: Self.debounce)
            guard !Task.isCancelled else { return }
            await self?.publishGlance()
            await self?.phone?.vaultChanged()
        }
    }

    /// Writes the widget snapshot and reloads the widgets. iOS only (no widgets elsewhere).
    func publishGlance() async {
        #if os(iOS)
        guard let glanceStore, session.state == .unlocked else { return }
        do {
            let ffi = try await session.glanceSnapshot(window: Self.glanceWindow)
            // Locked meanwhile: the result is dropped.
            guard session.state == .unlocked else { return }
            let types = Dictionary(
                session.summaries.map { ($0.id, $0.itemType) }, uniquingKeysWith: { first, _ in first })
            try glanceStore.write(GlanceMapping.snapshot(ffi, itemTypes: types))
            WidgetCenter.shared.reloadAllTimelines()
        } catch {
            Self.log.error("glance snapshot not published")
        }
        #endif
    }
}
