import GlanceKit
import SwiftUI
import WidgetKit

/// "Codes": the TOTP codes of the favorites, computed in advance by the app (spec 7).
struct CodesWidget: Widget {
    static let kind = "me.somalabs.onepass.widget.codes"

    var body: some WidgetConfiguration {
        StaticConfiguration(kind: Self.kind, provider: GlanceProvider()) { entry in
            CodesWidgetView(entry: entry)
                .containerBackground(.fill.tertiary, for: .widget)
        }
        .configurationDisplayName("Codes")
        .description("Les codes à usage unique de tes favoris.")
        .supportedFamilies([.systemSmall, .systemMedium, .systemLarge, .accessoryRectangular])
    }
}

struct CodesWidgetView: View {
    let entry: GlanceEntry
    @Environment(\.widgetFamily) private var family

    var body: some View {
        switch entry.state {
        case .locked:
            GlanceMessage.locked
        case .stale:
            GlanceMessage.stale
        case .available(let snapshot) where snapshot.codes.isEmpty:
            GlanceMessage(symbol: "star", text: "Ajoute un favori avec un code")
        case .available(let snapshot):
            content(snapshot.codes)
        }
    }

    private var capacity: Int {
        switch family {
        case .systemLarge: 6
        case .systemMedium: 3
        default: 1
        }
    }

    @ViewBuilder private func content(_ all: [GlanceCodes]) -> some View {
        let shown = Array(all.prefix(capacity))
        switch family {
        case .accessoryRectangular:
            if let first = shown.first { accessory(first) }
        case .systemSmall:
            if let first = shown.first { small(first, more: all.count - 1) }
        default:
            VStack(alignment: .leading, spacing: family == .systemLarge ? 10 : 6) {
                ForEach(shown) { codes in
                    Link(destination: codes.item.link.url) {
                        CodeRow(codes: codes, date: entry.date)
                    }
                }
                if family == .systemLarge { Spacer(minLength: 0) }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        }
    }

    private func small(_ codes: GlanceCodes, more: Int) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                GlanceTile(item: codes.item, size: 20)
                Text(codes.item.title)
                    .font(.caption.weight(.medium))
                    .lineLimit(1)
                    .privacySensitive()
            }
            Spacer(minLength: 0)
            if let code = codes.code(at: entry.date) {
                Text(CodeFormat.grouped(code.code))
                    .font(.title2.monospacedDigit().weight(.semibold))
                    .minimumScaleFactor(0.7)
                    .lineLimit(1)
                    .privacySensitive()
                Text(timerInterval: entry.date...code.end, countsDown: true)
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            } else {
                Text("Ouvre OnePass pour actualiser")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if more > 0 {
                Text("+ \(more) autres")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
        .widgetURL(codes.item.link.url)
    }

    private func accessory(_ codes: GlanceCodes) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(codes.item.title)
                .font(.caption)
                .lineLimit(1)
                .privacySensitive()
            if let code = codes.code(at: entry.date) {
                HStack(alignment: .firstTextBaseline) {
                    Text(CodeFormat.grouped(code.code))
                        .font(.headline.monospacedDigit())
                        .widgetAccentable()
                        .privacySensitive()
                    Spacer(minLength: 4)
                    Text(timerInterval: entry.date...code.end, countsDown: true)
                        .font(.caption.monospacedDigit())
                        .multilineTextAlignment(.trailing)
                        .frame(width: 36, alignment: .trailing)
                }
            } else {
                Text("Ouvre OnePass pour actualiser").font(.caption2)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .widgetURL(codes.item.link.url)
    }
}
