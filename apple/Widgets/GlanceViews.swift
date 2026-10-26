import GlanceKit
import SwiftUI
import WidgetKit

extension GlanceTint {
    var color: Color { Color(red: red, green: green, blue: blue) }
}

/// A neutral state: no title, no code (locked device, stale or empty snapshot).
struct GlanceMessage: View {
    let symbol: String
    let text: LocalizedStringKey
    @Environment(\.widgetFamily) private var family

    var body: some View {
        if family == .accessoryRectangular {
            HStack(spacing: 6) {
                Image(systemName: symbol).accessibilityHidden(true)
                Text(text).font(.caption).lineLimit(2)
                Spacer(minLength: 0)
            }
        } else {
            VStack(spacing: 8) {
                Image(systemName: symbol)
                    .font(.title2)
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
                Text(text)
                    .font(.footnote.weight(.medium))
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    static let locked = GlanceMessage(symbol: "lock.fill", text: "Déverrouille ton iPhone")
    static let stale = GlanceMessage(symbol: "arrow.clockwise", text: "Ouvre OnePass pour actualiser")
}

/// The category tile of an item (symbol on its category color).
struct GlanceTile: View {
    let item: GlanceItem
    var size: CGFloat = 22

    var body: some View {
        Image(systemName: item.symbol)
            .font(.system(size: size * 0.5, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(item.tint.color.gradient, in: RoundedRectangle(cornerRadius: size * 0.28, style: .continuous))
            .accessibilityHidden(true)
    }
}

enum CodeFormat {
    /// "123456" reads "123 456" (even lengths of 6 and more are split in two halves).
    static func grouped(_ code: String) -> String {
        guard code.count >= 6, code.count.isMultiple(of: 2) else { return code }
        let half = code.index(code.startIndex, offsetBy: code.count / 2)
        return "\(code[..<half]) \(code[half...])"
    }
}

/// One favorite's current code and the seconds left. No code for this date (past the
/// precomputed window): a refresh is needed, no code is guessed.
struct CodeRow: View {
    let codes: GlanceCodes
    let date: Date

    var body: some View {
        HStack(spacing: 10) {
            GlanceTile(item: codes.item)
            VStack(alignment: .leading, spacing: 1) {
                Text(codes.item.title)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .privacySensitive()
                if let code = codes.code(at: date) {
                    Text(CodeFormat.grouped(code.code))
                        .font(.title3.monospacedDigit().weight(.semibold))
                        .privacySensitive()
                } else {
                    Text("Ouvre OnePass pour actualiser")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 4)
            if let code = codes.code(at: date) {
                Text(timerInterval: date...code.end, countsDown: true)
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.trailing)
                    .frame(width: 40, alignment: .trailing)
            }
        }
    }
}

/// One favorite: tile and title.
struct FavoriteRow: View {
    let item: GlanceItem

    var body: some View {
        HStack(spacing: 8) {
            GlanceTile(item: item)
            Text(item.title)
                .font(.subheadline.weight(.medium))
                .lineLimit(1)
                .privacySensitive()
            Spacer(minLength: 0)
        }
        .contentShape(Rectangle())
    }
}
