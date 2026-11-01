import Foundation

/// How AutoFill builds the password it proposes on a signup field (spec G5, section 5): "Fort"
/// (default), "Lisible" or "Personnalisé". A device setting, never synced.
public enum GeneratorProfile: Codable, Equatable, Sendable {
    case strong
    case readable
    /// The user's length (8 to 64) and classes; lowercase and uppercase are always on.
    case custom(length: Int, digits: Bool, symbols: Bool)

    public static let customLengths: ClosedRange<Int> = 8...64
    /// Length proposed when the user first picks "Personnalisé".
    public static let defaultCustom = GeneratorProfile.custom(length: 20, digits: true, symbols: true)

    /// The core's profile; a custom length out of range is clamped into 8 to 64.
    public var ffi: FfiPasswordProfile {
        switch self {
        case .strong: .strong
        case .readable: .readable
        case .custom(let length, let digits, let symbols):
            .custom(
                length: UInt32(min(max(length, Self.customLengths.lowerBound), Self.customLengths.upperBound)),
                digits: digits, symbols: symbols)
        }
    }
}

/// The chosen `GeneratorProfile` in the App Group `UserDefaults`, which the app and the AutoFill
/// extension share (`SharedContainer.defaults`). Missing or unreadable reads as `.strong`.
public struct GeneratorProfileStore: @unchecked Sendable {
    static let key = "generator.profile"

    private let defaults: UserDefaults

    public init(defaults: UserDefaults) {
        self.defaults = defaults
    }

    /// The store on the shared suite of the running process.
    public static func shared() -> GeneratorProfileStore {
        GeneratorProfileStore(defaults: SharedContainer.resolve().defaults)
    }

    public var profile: GeneratorProfile {
        get {
            guard let data = defaults.data(forKey: Self.key),
                let profile = try? JSONDecoder().decode(GeneratorProfile.self, from: data)
            else { return .strong }
            return profile
        }
        nonmutating set {
            guard let data = try? JSONEncoder().encode(newValue) else { return }
            defaults.set(data, forKey: Self.key)
        }
    }
}
