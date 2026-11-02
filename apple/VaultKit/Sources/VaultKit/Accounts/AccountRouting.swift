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
