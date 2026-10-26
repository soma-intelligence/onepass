import Foundation

/// Deep links: `onepass://item?vault=<32 lowercase hex>&item=<32 lowercase hex>`,
/// `onepass://generator`, `onepass://search`. Anything else is rejected.
public enum OnePassLink: Hashable, Sendable {
    case item(vaultID: String, itemID: String)
    case generator
    case search

    public init?(url: URL) {
        guard url.scheme == "onepass",
            let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
            let host = components.host,
            components.path.isEmpty,
            components.user == nil, components.password == nil,
            components.port == nil, components.fragment == nil
        else { return nil }
        let query = components.queryItems ?? []
        switch host {
        case "generator" where query.isEmpty:
            self = .generator
        case "search" where query.isEmpty:
            self = .search
        case "item":
            guard query.count == 2,
                let vault = Self.value("vault", in: query),
                let item = Self.value("item", in: query),
                Self.isHexID(vault), Self.isHexID(item)
            else { return nil }
            self = .item(vaultID: vault, itemID: item)
        default:
            return nil
        }
    }

    public var url: URL {
        var components = URLComponents()
        components.scheme = "onepass"
        switch self {
        case .item(let vaultID, let itemID):
            components.host = "item"
            components.queryItems = [
                URLQueryItem(name: "vault", value: vaultID),
                URLQueryItem(name: "item", value: itemID),
            ]
        case .generator:
            components.host = "generator"
        case .search:
            components.host = "search"
        }
        return components.url ?? URL(string: "onepass://search")!
    }

    private static func value(_ name: String, in query: [URLQueryItem]) -> String? {
        let matches = query.filter { $0.name == name }
        return matches.count == 1 ? matches[0].value : nil
    }

    private static func isHexID(_ s: String) -> Bool {
        s.utf8.count == 32 && s.utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }
    }
}
