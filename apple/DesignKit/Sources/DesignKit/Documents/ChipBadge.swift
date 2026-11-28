import SwiftUI

/// Where the data of a document came from, frozen at the day of the read (spec 2026-11-21 section
/// 7.3): "Authentifié par la puce le 21 nov. 2026". It never claims the document is valid today
/// (it may have been cancelled or reported lost), so a help line says what was checked.
public struct ChipBadge: View {
    public enum Status: Sendable, Hashable, CaseIterable {
        /// Passive authentication passed and DG1 matches the MRZ.
        case verified
        /// Read from the chip, but the signer is not in the master list (or expired).
        case unverifiable
        /// A hash or the signature is wrong. The item is still saved, with this status shown.
        case invalid

        /// The status the core's `chip_status` menu holds (`scan/to_item.rs`), nil for any other
        /// value (a manual entry has no badge).
        public init?(coreLabel: String) {
            switch coreLabel.trimmingCharacters(in: .whitespacesAndNewlines) {
            case "Authentifié par la puce": self = .verified
            case "Lu sur la puce, signature non vérifiable": self = .unverifiable
            case "Signature invalide": self = .invalid
            default: return nil
            }
        }

        var systemImage: String {
            switch self {
            case .verified: "checkmark.circle.fill"
            case .unverifiable: "questionmark.circle"
            case .invalid: "exclamationmark.triangle.fill"
            }
        }

        var tint: Color {
            switch self {
            case .verified: Theme.RX.Palette.positive.color
            case .unverifiable: Theme.RX.Palette.textSecondary.color
            case .invalid: Theme.RX.Palette.negative.color
            }
        }
    }

    @Environment(\.locale) private var locale
    private let status: Status
    private let readOn: Date

    /// `readOn` is the calendar day of the read, as the vault stores dates (midnight UTC): it is
    /// printed in UTC so no time zone moves it to the day before.
    public init(status: Status, readOn: Date) {
        self.status = status
        self.readOn = readOn
    }

    /// "21 nov. 2026" in `locale`.
    static func day(_ date: Date, locale: Locale) -> String {
        var style = Date.FormatStyle(locale: locale).day().month(.abbreviated).year()
        style.timeZone = TimeZone(identifier: "UTC")!
        return date.formatted(style)
    }

    private var label: Text {
        let day = Self.day(readOn, locale: locale)
        return switch status {
        case .verified: Text("chipBadge.verified \(day)", bundle: .module)
        case .unverifiable: Text("chipBadge.unverifiable \(day)", bundle: .module)
        case .invalid: Text("chipBadge.invalid \(day)", bundle: .module)
        }
    }

    private var help: Text { Text("chipBadge.help", bundle: .module) }

    public var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: Theme.RX.Space.s) {
            Image(systemName: status.systemImage)
                .foregroundStyle(status.tint)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: Theme.RX.Space.xxs) {
                label
                    .rxFont(.footnoteBold)
                    .foregroundStyle(Theme.RX.Palette.textPrimary.color)
                help
                    .rxFont(.caption)
                    .foregroundStyle(Theme.RX.Palette.textSecondary.color)
            }
            .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(label)
        .accessibilityHint(help)
        #if !os(watchOS)
        .help(help)
        #endif
        .accessibilityIdentifier("document.chipBadge")
    }
}
