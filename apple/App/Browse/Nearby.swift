import CoreLocation
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

    /// One fix. Asks for "when in use" permission first if the user was never asked.
    func currentLocation() async throws -> CLLocation {
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
        if let last = manager.location, last.timestamp.timeIntervalSinceNow > -60 { return last }
        return try await withCheckedThrowingContinuation { continuation in
            locationWaiters.append(continuation)
            if locationWaiters.count == 1 { manager.requestLocation() }
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
        guard let location = locations.last else { return }
        MainActor.assumeIsolated { finish(.success(location)) }
    }

    nonisolated func locationManager(_ manager: CLLocationManager, didFailWithError error: any Error) {
        let denied = (error as? CLError)?.code == .denied
        MainActor.assumeIsolated { finish(.failure(denied ? Failure.denied : Failure.unavailable)) }
    }

    private func finish(_ result: Result<CLLocation, any Error>) {
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

    func load(_ session: VaultSession, within radius: Double = LocationIndex.nearbyRadius) async {
        if items.isEmpty { phase = .locating }
        do {
            let location = try await LocationAccess.shared.currentLocation()
            origin = location.coordinate
            let point = GeoPoint(latitude: location.coordinate.latitude, longitude: location.coordinate.longitude)
            items = try await session.nearbyItems(from: point, within: radius)
            phase = .ready
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
        RoundedRectangle(cornerRadius: size * 5 / 18, style: .continuous)
            .fill(Color(red: 0x0A / 255, green: 0x84 / 255, blue: 0xFF / 255))
            .frame(width: size, height: size)
            .overlay {
                Image(systemName: "location.fill")
                    .font(.system(size: size * 0.5, weight: .semibold))
                    .foregroundStyle(.white)
            }
            .accessibilityHidden(true)
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
            ProgressView("Recherche de ta position…")
                .accessibilityIdentifier("list.nearby.locating")
        case .failed(.denied):
            ContentUnavailableView {
                Label("Position non autorisée", systemImage: "location.slash")
            } description: {
                Text("Autorise OnePass à utiliser ta position pour voir les éléments enregistrés autour de toi. Elle reste sur cet appareil.")
            } actions: {
                Button("Ouvrir les Réglages") { LocationAccess.openSettings() }
                    .buttonStyle(.glassProminent)
                    .accessibilityIdentifier("list.nearby.openSettings")
            }
            .accessibilityIdentifier("list.nearby.denied")
        case .failed(.unavailable):
            ContentUnavailableView {
                Label("Position introuvable", systemImage: "location.magnifyingglass")
            } description: {
                Text("Impossible de savoir où tu es pour le moment.")
            } actions: {
                Button("Réessayer", action: retry)
                    .accessibilityIdentifier("list.nearby.retry")
            }
        case .ready:
            EmptyState(
                title: String(localized: "Rien à proximité"), systemImage: "mappin.slash",
                message: String(localized: "Ajoute un lieu à un élément pour le retrouver ici quand tu es à moins de 2 km."))
            .accessibilityIdentifier("list.nearby.empty")
        }
    }
}
