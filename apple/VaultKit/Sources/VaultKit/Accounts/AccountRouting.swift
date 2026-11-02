import Foundation

/// Which account answers an AutoFill request (multi-account spec 8): the account whose work domains
/// claim the request's host, else the primary account. Only one account is opened per request, so
/// AutoFill never offers items of two accounts at once (M6).
extension AutoFillRequest {
    /// The host the request is about. A QuickType suggestion comes from the system identity store,
    /// which only the primary account publishes to (ruling P6): no host, the primary account answers.
    public var routingHost: String? {
        switch self {
        case .credentialList(let services, let passkey):
            passkey?.rpID ?? services.lazy.compactMap(Self.host(of:)).first
        case .oneTimeCodeList(let services):
            services.lazy.compactMap(Self.host(of:)).first
        case .passkeyRegistration(let registration):
            registration.rpID
        case .savePassword(let save):
            save.serviceIsApp ? nil : Self.host(of: save.service)
        case .credential, .textToInsert, .configuration:
            nil
        }
    }

    /// The host of a service as the system gives it: a URL or a bare domain.
    static func host(of service: String) -> String? {
        let trimmed = service.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }
        if trimmed.contains("://") { return URL(string: trimmed)?.host() }
        return URL(string: "https://\(trimmed)")?.host() ?? trimmed
    }
}

extension AccountDirectoryStore {
    /// The slot that answers `request`. A slot whose store does not hold its bound account (a swapped
    /// file, M4) is never opened: the primary account answers instead.
    public func slot(for request: AutoFillRequest) -> String {
        guard let host = request.routingHost else { return Self.primarySlot }
        let slot = route(host: host)
        guard slot != Self.primarySlot else { return slot }
        guard (try? checkBinding(slot: slot)) != nil,
            let url = try? databaseURL(slot: slot), FileManager.default.fileExists(atPath: url.path)
        else { return Self.primarySlot }
        return slot
    }
}

extension VaultEnvironment {
    /// The environment of the account that answers an AutoFill request: the primary account's live
    /// environment, or an added account's store and settings scope, never published to the system
    /// identity store (ruling P6).
    public static func autoFill(
        for request: AutoFillRequest, container: SharedContainer = .resolve()
    ) -> VaultEnvironment {
        let store = AccountDirectoryStore(container: container)
        let slot = store.slot(for: request)
        guard slot != AccountDirectoryStore.primarySlot, let url = try? store.databaseURL(slot: slot) else {
            return .live(sync: NoSync(), container: container)
        }
        var environment = VaultEnvironment.live(
            sync: NoSync(), container: container, databaseURL: url,
            settings: VaultSettings(defaults: container.defaults, scope: slot))
        environment.identityStore = NoIdentityStore()
        return environment
    }
}

/// The iCloud zone an account signed in on a new device comes from (multi-account ruling P8). The
/// Emergency Kit names its account (the account id in a version 2 QR code, or printed on the kit);
/// without it, a single zone this device does not have is the one. Never a guess between two.
public enum SignInZone: Equatable, Sendable {
    /// The account id whose zone to fetch.
    case zone(String)
    /// Two or more accounts are in iCloud and not on this device: the account id is asked.
    case needsAccountID
    /// The kit's account is already on this device (M5).
    case alreadyOnDevice
    /// No zone of that account (or none at all) in this iCloud.
    case notFound

    /// `zones`: the account ids with a zone in iCloud; `known`: the accounts on this device.
    public static func choose(zones: [String], known: Set<String>, kitAccountID: String?) -> SignInZone {
        if let typed = kitAccountID {
            guard let id = accountID(typed) else { return .notFound }
            if known.contains(id) { return .alreadyOnDevice }
            return zones.contains(id) ? .zone(id) : .notFound
        }
        let unknown = zones.filter { !known.contains($0) }
        switch unknown.count {
        case 0: return .notFound
        case 1: return .zone(unknown[0])
        default: return .needsAccountID
        }
    }

    /// An account id as typed or scanned: 32 hex characters, spaces and dashes ignored, lowercased.
    public static func accountID(_ text: String) -> String? {
        let cleaned = text.lowercased().filter { !$0.isWhitespace && $0 != "-" }
        guard cleaned.count == 32, cleaned.allSatisfy(\.isHexDigit) else { return nil }
        return cleaned
    }
}
