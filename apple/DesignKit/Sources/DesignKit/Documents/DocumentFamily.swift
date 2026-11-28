import SwiftUI

/// The rendering family of an identity document (spec 2026-11-21 section 7.1): which cover tint and
/// which printed titles a booklet or a card takes. Evocative, never a replica (section 4): a
/// family is a tint and two lines of text, never an emblem, a seal or a security pattern. Adding a
/// country is adding a case with its tint and its titles.
public enum DocumentFamily: Sendable, Hashable, CaseIterable {
    case passportFR, passportUS, passportGeneric

    /// The family of a passport issued by `issuingCountry`: the ICAO code the chip gives ("FRA",
    /// "USA"), or the name typed by hand ("France", "United States"). Anything else is generic.
    public static func passport(issuingCountry: String) -> Self {
        let key = issuingCountry.trimmingCharacters(in: .whitespacesAndNewlines)
            .folding(options: [.caseInsensitive, .diacriticInsensitive], locale: nil)
            .uppercased()
        switch key {
        case "FRA", "FR", "FRANCE", "REPUBLIQUE FRANCAISE": return .passportFR
        case "USA", "US", "UNITED STATES", "UNITED STATES OF AMERICA", "ETATS-UNIS": return .passportUS
        default: return .passportGeneric
        }
    }

    /// The cover colour, light and dark (RX document tokens), without a vault accent.
    public var coverTint: Color { coverToken.color }

    /// The cover colour for a vault whose accent is `accent` (spec 7.1): the generic cover is the
    /// neutral graphite tinted toward the accent, the country covers keep their own tint. Mixed
    /// at 30% so the cover text keeps its contrast.
    public func coverTint(accent: Color?) -> Color {
        guard self == .passportGeneric, let accent else { return coverTint }
        return coverTint.mix(with: accent, by: Self.accentShare)
    }

    /// How much of the vault accent goes into the generic cover.
    static let accentShare = 0.3

    /// The country printed on the cover, as text. Nil for the generic family (no country is drawn).
    public var countryTitle: LocalizedStringKey? {
        countryKey.map { LocalizedStringKey($0) }
    }

    /// The document type printed on the cover ("Passeport", "Passport").
    public var documentTitle: LocalizedStringKey { LocalizedStringKey(documentKey) }

    // MARK: Internals (tests read the keys)

    var coverToken: Theme.RX.Token {
        switch self {
        case .passportFR: Theme.RX.Document.bordeaux
        case .passportUS: Theme.RX.Document.navy
        case .passportGeneric: Theme.RX.Document.neutral
        }
    }

    /// A French passport reads "Passeport" and "République française", a US one "Passport" and
    /// "United States of America", whatever the language of the app: the cover says what the
    /// object says. The generic title follows the app's language.
    var documentKey: String {
        switch self {
        case .passportFR: "document.passport.fr.title"
        case .passportUS: "document.passport.us.title"
        case .passportGeneric: "document.passport.title"
        }
    }

    var countryKey: String? {
        switch self {
        case .passportFR: "document.passport.fr.country"
        case .passportUS: "document.passport.us.country"
        case .passportGeneric: nil
        }
    }
}

extension Theme.RX {
    /// Colours of the document renderings (passport covers, data page). Code-owned: not in Penpot
    /// yet. Each pair keeps the cover text (`coverInk`) above 4.5:1.
    public enum Document {
        /// The French passport's evocative cover: a deep bordeaux.
        public static let bordeaux = Token(light: Tone(css: "#6B1E2B")!, dark: Tone(css: "#561722")!)
        /// The US passport's evocative cover: a navy blue.
        public static let navy = Token(light: Tone(css: "#1D2B4F")!, dark: Tone(css: "#17223F")!)
        /// Any other country: a neutral graphite, tinted toward the vault accent at draw time
        /// (`coverTint(accent:)`).
        public static let neutral = Token(light: Tone(css: "#434A57")!, dark: Tone(css: "#363C47")!)
        /// Text and the chip symbol on a cover.
        public static let coverInk = Token(light: Tone(css: "#EFE4CC")!, dark: Tone(css: "#E3D7BD")!)
        /// The data page: a warm paper, dimmed in dark so it does not glare.
        public static let page = Token(light: Tone(css: "#F6F3EC")!, dark: Tone(css: "#D8D3C8")!)
        /// Text on the data page (same in both, the page stays light).
        public static let pageInk = Token(light: Tone(css: "#1C1C1E")!, dark: Tone(css: "#1C1C1E")!)
        /// Labels on the data page.
        public static let pageLabel = Token(light: Tone(css: "#5E5A52")!, dark: Tone(css: "#55514A")!)
        /// The band behind the notice and the MRZ.
        public static let pageBand = Token(light: Tone(css: "#E9E4D8")!, dark: Tone(css: "#C9C3B6")!)
    }
}

// MARK: - Vault accent

private struct DocumentAccentKey: EnvironmentKey {
    static let defaultValue: Color? = nil
}

extension EnvironmentValues {
    /// The accent of the vault the document belongs to: the generic cover takes it (spec 7.1).
    public var documentAccent: Color? {
        get { self[DocumentAccentKey.self] }
        set { self[DocumentAccentKey.self] = newValue }
    }
}

extension View {
    /// Tints the generic document covers inside toward `accent` (the vault's colour).
    public func documentAccent(_ accent: Color?) -> some View {
        environment(\.documentAccent, accent)
    }
}
