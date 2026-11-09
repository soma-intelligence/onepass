import CoreLocation
import os
import DesignKit
import SwiftUI
import VaultKit
#if os(macOS)
import AppKit
#else
import UIKit
#endif

/// The user's position, "when in use" only. Nothing is asked at launch: the permission prompt
/// shows the first time the user taps "Utiliser ma position" or opens "À proximité".
///
/// Privacy: the position stays on the device. It is compared with the items' places in memory
/// (`VaultSession.nearbyItems`) and is never sent anywhere, not even to Apple's geocoder.
@MainActor
final class LocationAccess: NSObject, CLLocationManagerDelegate {
    static let shared = LocationAccess()

    enum Failure: Error, Equatable {
        /// Refused, restricted (parental controls, MDM), or Location Services off.
        case denied
        /// No fix (no Wi-Fi around a Mac, airplane mode...).
        case unavailable
    }

    /// Made on first use only: creating it never prompts, but there is no reason to before.
    private var manager: CLLocationManager?
    private var authorizationWaiters: [CheckedContinuation<Void, Never>] = []
    private var locationWaiters: [CheckedContinuation<CLLocation, any Error>] = []
    /// The best fix of the updates under way, kept in case none reaches `wantedAccuracy` in time.
    private var bestFix: CLLocation?
    private var fixDeadline: Task<Void, Never>?
    /// Accuracy that ends the updates under way: the strictest asked by their waiters.
    private var wanted: CLLocationAccuracy = LocationAccess.wantedAccuracy

    /// A fix this recent and this precise is used as it is: "À proximité" opens with no wait.
    static let reuseAge: TimeInterval = 5 * 60
    static let reuseAccuracy: CLLocationAccuracy = 500
    /// The first fix this precise ends the wait: plenty for "within 2 km". (`requestLocation`
    /// waited for the most precise fix it could get, often several seconds.)
    static let wantedAccuracy: CLLocationAccuracy = 1_000
    /// Longest wait for that fix; the best one seen by then is used.
    static let fixTimeout: Duration = .seconds(6)

    /// Whether `location` can be used without asking for a new fix.
    static func isReusable(_ location: CLLocation, now: Date = Date()) -> Bool {
        location.horizontalAccuracy >= 0 && location.horizontalAccuracy <= reuseAccuracy
            && now.timeIntervalSince(location.timestamp) < reuseAge
    }

    private func makeManager() -> CLLocationManager {
        if let manager { return manager }
        let manager = CLLocationManager()
        // A street-level fix is plenty for "within 2 km" and for placing an item.
        manager.desiredAccuracy = kCLLocationAccuracyHundredMeters
        manager.delegate = self
        self.manager = manager
        return manager
    }

    /// The last fix CoreLocation holds, only when the user already allowed it: never prompts (the
    /// detail shows "à 350 m" with it when known).
    var knownLocation: CLLocation? {
        let manager = makeManager()
        switch manager.authorizationStatus {
        case .denied, .restricted, .notDetermined: return nil
        default: return manager.location
        }
    }

    /// One fix. Asks for "when in use" permission first if the user was never asked. `accuracy`
    /// ends the wait early (Wi-Fi by proximity asks for a fix that can tell 200 m apart).
    func currentLocation(accuracy: CLLocationAccuracy = LocationAccess.wantedAccuracy) async throws -> CLLocation {
        let manager = makeManager()
        if manager.authorizationStatus == .notDetermined {
            await withCheckedContinuation { continuation in
                authorizationWaiters.append(continuation)
                if authorizationWaiters.count == 1 { manager.requestWhenInUseAuthorization() }
            }
        }
        switch manager.authorizationStatus {
        case .denied, .restricted, .notDetermined: throw Failure.denied
        default: break
        }
        if let last = manager.location, Self.isReusable(last), last.horizontalAccuracy <= accuracy { return last }
        return try await withCheckedThrowingContinuation { continuation in
            wanted = locationWaiters.isEmpty ? accuracy : min(wanted, accuracy)
            locationWaiters.append(continuation)
            guard locationWaiters.count == 1 else { return }
            bestFix = nil
            manager.startUpdatingLocation()
            fixDeadline = Task { [weak self] in
                try? await Task.sleep(for: Self.fixTimeout)
                guard !Task.isCancelled, let self else { return }
                if let best = self.bestFix {
                    self.finish(.success(best))
                } else {
                    self.finish(.failure(Failure.unavailable))
                }
            }
        }
    }

    // Delegate calls arrive on the thread that made the manager: the main thread.

    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        let status = manager.authorizationStatus
        MainActor.assumeIsolated {
            // Called once as soon as the delegate is set, still undetermined: keep waiting.
            guard status != .notDetermined else { return }
            let waiters = authorizationWaiters
            authorizationWaiters = []
            waiters.forEach { $0.resume() }
        }
    }

    nonisolated func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        let fixes = locations.filter { $0.horizontalAccuracy >= 0 }
        MainActor.assumeIsolated {
            guard !locationWaiters.isEmpty else { return }
            for fix in fixes where fix.horizontalAccuracy < bestFix?.horizontalAccuracy ?? .infinity {
                bestFix = fix
            }
            if let best = bestFix, best.horizontalAccuracy <= wanted { finish(.success(best)) }
        }
    }

    nonisolated func locationManager(_ manager: CLLocationManager, didFailWithError error: any Error) {
        let code = (error as? CLError)?.code
        MainActor.assumeIsolated {
            // "Location unknown" while updating is passing: the updates go on until the deadline.
            if code == .locationUnknown { return }
            finish(.failure(code == .denied ? Failure.denied : Failure.unavailable))
        }
    }

    private func finish(_ result: Result<CLLocation, any Error>) {
        manager?.stopUpdatingLocation()
        fixDeadline?.cancel()
        fixDeadline = nil
        bestFix = nil
        wanted = Self.wantedAccuracy
        let waiters = locationWaiters
        locationWaiters = []
        waiters.forEach { $0.resume(with: result) }
    }

    /// Réglages Système > Confidentialité > Service de localisation (Mac), the app's page of
    /// Réglages (iPhone, iPad).
    static func openSettings() {
        #if os(macOS)
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices") {
            NSWorkspace.shared.open(url)
        }
        #else
        if let url = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(url) }
        #endif
    }
}

/// "À proximité" items for a list: asks the position, then the session's location index.
@MainActor
@Observable
final class NearbyLoader {
    enum Phase: Equatable {
        case idle, locating, ready
        case failed(LocationAccess.Failure)
    }

    private(set) var phase: Phase = .idle
    private(set) var items: [NearbyItem] = []
    /// Where the last search started from (the iPhone home card's map).
    private(set) var origin: CLLocationCoordinate2D?

    /// The summaries to list, the distance first in their subtitle ("à 350 m · camille@exemple.fr").
    var summaries: [FfiItemSummary] {
        items.map { nearby in
            var summary = nearby.summary
            let distance = LocationIndex.distanceLabel(nearby.distance)
            summary.subtitle = summary.subtitle.isEmpty ? distance : "\(distance) · \(summary.subtitle)"
            return summary
        }
    }

    /// Durations only (how long the fix and the index took), never a place.
    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "nearby")

    func load(_ session: VaultSession, within radius: Double = LocationIndex.nearbyRadius) async {
        if items.isEmpty { phase = .locating }
        let clock = ContinuousClock()
        let start = clock.now
        do {
            let location = try await LocationAccess.shared.currentLocation()
            let located = clock.now
            origin = location.coordinate
            let point = GeoPoint(latitude: location.coordinate.latitude, longitude: location.coordinate.longitude)
            items = try await session.nearbyItems(from: point, within: radius)
            phase = .ready
            let fix = located - start, index = clock.now - located
            Self.log.info("nearby: fix \(fix, privacy: .public), index \(index, privacy: .public), \(self.items.count) items")
        } catch let failure as LocationAccess.Failure {
            items = []
            phase = .failed(failure)
        } catch {
            // Locked during the read: the list goes away with the session.
            items = []
            phase = .idle
        }
    }
}

/// Sidebar and Éléments tile of "À proximité" (same shape as the category tiles).
struct NearbyTile: View {
    var size: CGFloat = 18

    var body: some View {
        SymbolTile(symbol: "location.fill", color: Color(red: 0x0A / 255, green: 0x84 / 255, blue: 0xFF / 255),
            size: size)
    }
}

/// What "À proximité" shows instead of rows: looking for the position, refused permission (with a
/// button to the settings), no fix, or nothing around.
struct NearbyStatusView: View {
    let phase: NearbyLoader.Phase
    let retry: () -> Void

    var body: some View {
        switch phase {
        case .idle, .locating:
            ProgressView("browse.findingLocation")
                .accessibilityIdentifier("list.nearby.locating")
        case .failed(.denied):
            ContentUnavailableView {
                Label("app.locationNotAllowed", systemImage: "location.slash")
            } description: {
                Text("browse.allowOnepassToUse")
            } actions: {
                Button("app.openSettings") { LocationAccess.openSettings() }
                    .buttonStyle(.glassProminent)
                    .accessibilityIdentifier("list.nearby.openSettings")
            }
            .accessibilityIdentifier("list.nearby.denied")
        case .failed(.unavailable):
            ContentUnavailableView {
                Label("app.locationNotFound", systemImage: "location.magnifyingglass")
            } description: {
                Text("browse.cantTellWhereRight")
            } actions: {
                Button("Réessayer", action: retry)
                    .accessibilityIdentifier("list.nearby.retry")
            }
        case .ready:
            EmptyState(
                title: String(localized: "browse.nothingNearby"), systemImage: "mappin.slash",
                message: String(localized: "browse.addPlaceToItem"))
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background { NearbyMapBackdrop() }
            .accessibilityIdentifier("list.nearby.empty")
        }
    }
}

/// Behind "Rien à proximité": a drawn city plan (streets, a river, a park) in fine lines, tinted
/// with the secondary text color and fading out towards the edges. A fixed image bundled with the
/// app, the same for everyone: it shows no real place and needs no position. Decoration only,
/// hidden from VoiceOver.
struct NearbyMapBackdrop: View {
    var body: some View {
        Image("nearby-map")
            .resizable()
            .interpolation(.high)
            // A fixed scale, whatever the window: streets keep the size of a city plan.
            .frame(width: 520, height: 520)
            .foregroundStyle(.secondary)
            .opacity(0.45)
            .mask {
                EllipticalGradient(
                    stops: [
                        .init(color: .black, location: 0),
                        .init(color: .black.opacity(0.6), location: 0.5),
                        .init(color: .clear, location: 1),
                    ],
                    center: .center, startRadiusFraction: 0, endRadiusFraction: 0.5)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .clipped()
            .allowsHitTesting(false)
            .accessibilityHidden(true)
    }
}
