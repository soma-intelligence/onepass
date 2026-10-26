import GlanceKit
import SwiftUI
import WidgetKit

/// "Favoris": each row opens the item in the app (which asks for the unlock first) (spec 7).
struct FavoritesWidget: Widget {
    static let kind = "me.somalabs.onepass.widget.favorites"

    var body: some WidgetConfiguration {
        StaticConfiguration(kind: Self.kind, provider: GlanceProvider()) { entry in
            FavoritesWidgetView(entry: entry)
                .containerBackground(.fill.tertiary, for: .widget)
        }
        .configurationDisplayName("Favoris")
        .description("Ouvre un de tes favoris dans OnePass.")
        .supportedFamilies([.systemSmall, .systemMedium])
    }
}

struct FavoritesWidgetView: View {
    let entry: GlanceEntry
    @Environment(\.widgetFamily) private var family

    var body: some View {
        switch entry.state {
        case .locked:
            GlanceMessage.locked
        case .stale:
            GlanceMessage.stale
        case .available(let snapshot) where snapshot.favorites.isEmpty:
            GlanceMessage(symbol: "star", text: "Ajoute un favori dans OnePass")
        case .available(let snapshot):
            list(snapshot.favorites)
        }
    }

    @ViewBuilder private func list(_ favorites: [GlanceItem]) -> some View {
        let shown = Array(favorites.prefix(family == .systemMedium ? 6 : 3))
        let columns = family == .systemMedium
            ? [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)]
            : [GridItem(.flexible())]
        LazyVGrid(columns: columns, alignment: .leading, spacing: 10) {
            ForEach(shown) { item in
                Link(destination: item.link.url) {
                    FavoriteRow(item: item)
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .widgetURL(shown.first?.link.url)
    }
}
