#if os(iOS)
import DesignKit
import OSLog
import SwiftUI
import UIKit

/// One icon Réglages > Général > Icône de l'app offers: its app icon set (nil for the primary,
/// violet `AppIcon`) and its name. Every set and preview comes from docs/assets/brand/family.py.
struct AppIconChoice: Identifiable, Hashable {
    /// The slug: `AppIcon-<slug>` is the alternate icon set, `IconPreview-<slug>` its picture.
    let slug: String

    var id: String { slug }
    /// The name `UIApplication.setAlternateIconName` takes; nil for the primary icon.
    var assetName: String? { slug == Self.primarySlug ? nil : "AppIcon-\(slug)" }
    var previewName: String { "IconPreview-\(slug)" }
    /// An interpolated literal would look up "settings.appIcon.%@": the key is built as a plain String.
    var title: LocalizedStringKey {
        let key = "settings.appIcon." + slug
        return LocalizedStringKey(key)
    }

    static let primarySlug = "violet"

    /// The picker's order: the primary, Auto, then the light grounds and the dark ones.
    static let all: [AppIconChoice] = [
        "violet", "auto", "white", "paper", "grey", "lavender", "charcoal", "black", "navy", "dusk", "blueprint",
    ].map(AppIconChoice.init(slug:))

    /// The choice for the alternate icon name the system reports; the primary for nil or an unknown name.
    static func choice(for assetName: String?) -> AppIconChoice {
        all.first { $0.assetName == assetName } ?? all[0]
    }
}

/// Réglages > Général: the home screen icon, as a grid of the eleven icons. The system shows its own
/// alert once the icon changes; a refused change puts the previous selection back.
struct AppIconSection: View {
    @State private var current = AppIconChoice.choice(for: UIApplication.shared.alternateIconName)
    @State private var changing = false

    private let columns = [GridItem(.adaptive(minimum: 64, maximum: 80), spacing: 14)]

    var body: some View {
        if UIApplication.shared.supportsAlternateIcons {
            Section {
                LazyVGrid(columns: columns, spacing: 14) {
                    ForEach(AppIconChoice.all) { choice in
                        Button {
                            select(choice)
                        } label: {
                            AppIconTile(choice: choice, selected: choice == current)
                        }
                        .buttonStyle(.plain)
                        .accessibilityIdentifier("settings.appIcon.\(choice.slug)")
                        .accessibilityAddTraits(choice == current ? .isSelected : [])
                    }
                }
                .padding(.vertical, 8)
                .sensoryFeedback(.selection, trigger: current)
            } header: {
                Text("settings.appIcon")
            }
        }
    }

    private func select(_ choice: AppIconChoice) {
        guard choice != current, !changing else { return }
        let before = current
        current = choice
        changing = true
        Task {
            defer { changing = false }
            do {
                try await UIApplication.shared.setAlternateIconName(choice.assetName)
            } catch {
                current = before
                Logger(subsystem: "me.somalabs.onepass", category: "appicon")
                    .error("Changing the app icon failed: \(error.localizedDescription, privacy: .public)")
            }
        }
    }
}

/// One icon of the grid: its picture in the home screen's rounded square, its name, and the
/// accent ring when it is the one in use.
private struct AppIconTile: View {
    let choice: AppIconChoice
    let selected: Bool

    var body: some View {
        VStack(spacing: 6) {
            Image(choice.previewName)
                .resizable()
                .aspectRatio(1, contentMode: .fit)
                .clipShape(.rect(cornerRadius: 14, style: .continuous))
                .overlay {
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .strokeBorder(Color.primary.opacity(0.1), lineWidth: 1)
                }
                .padding(3)
                .overlay {
                    RoundedRectangle(cornerRadius: 17, style: .continuous)
                        .strokeBorder(selected ? Theme.accent : .clear, lineWidth: 2.5)
                }
            Text(choice.title)
                .font(.caption)
                .foregroundStyle(selected ? .primary : .secondary)
                .lineLimit(1)
                .minimumScaleFactor(0.8)
        }
        .contentShape(.rect)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(choice.title))
    }
}
#endif
