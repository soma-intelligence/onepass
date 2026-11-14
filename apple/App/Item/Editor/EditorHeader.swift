import DesignKit
import SwiftUI
import VaultKit

/// Top of the editor: the item's icon with a chevron badge that opens the icon menu, and the big
/// title field. The window title already says "Modification".
struct EditorHeader: View {
    @Environment(AppModel.self) private var model
    @Bindable var editor: ItemEditorModel
    var titleFocused: FocusState<Bool>.Binding
    /// The site's icon, as on the item's page: editing keeps the same picture.
    @State private var siteIcon: Data?

    #if os(iOS)
    private static let titleHairline = Color.primary.opacity(0.06)
    #else
    private static let titleHairline = Color.white.opacity(0.08)
    #endif

    private var item: FfiItem { editor.draft.item }
    private var primaryURL: String? { (item.urls.first(where: \.primary) ?? item.urls.first)?.url }

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Space.m) {
            HStack(alignment: .center, spacing: Theme.Space.l) {
                IconMenu(item: $editor.draft.item) {
                    ItemIcon(
                        type: item.itemType, title: item.title,
                        siteIcon: siteIcon ?? model.iconLoader.cachedIcon(for: primaryURL, title: item.title),
                        size: 64, brand: item.cardBrandName, useCategory: item.iconCategory,
                        tint: ItemTint.color(named: item.color))
                        .favoriteBadge(item.favorite, iconSize: 64)
                }
                // Follows the website being typed: a new address loads its icon.
                .task(id: primaryURL) {
                    guard let url = primaryURL else {
                        siteIcon = nil
                        return
                    }
                    siteIcon = await model.iconLoader.icon(for: url, title: item.title)
                }
                titleField
            }
            if let message = editor.titleMessage {
                Label(message, systemImage: "exclamationmark.circle.fill")
                    .font(.footnote)
                    .foregroundStyle(.red)
                    // Under the title field: the 64 pt icon and the spacing.
                    .padding(.leading, 64 + Theme.Space.l)
                    .accessibilityIdentifier("editor.error")
            }
        }
        .padding(.bottom, Theme.Space.s)
        .id(ItemEditorModel.titleAnchor)
    }

    private var titleField: some View {
        let focused = titleFocused.wrappedValue
        return TextField("app.title", text: $editor.draft.item.title, prompt: Text(ItemCategory.of(item.itemType).singular))
            .textFieldStyle(.plain)
            .font(.system(size: 26, weight: .bold))
            .focused(titleFocused)
            .onChange(of: item.title) { editor.clearError(for: "title") }
            .padding(.horizontal, Theme.Space.l)
            .padding(.vertical, Theme.Space.m)
            #if os(iOS)
            .background(Color(uiColor: .secondarySystemGroupedBackground), in: .rect(cornerRadius: Theme.Radius.control, style: .continuous))
            #else
            .background(.fill.quaternary, in: .rect(cornerRadius: Theme.Radius.control, style: .continuous))
            #endif
            .overlay {
                RoundedRectangle(cornerRadius: Theme.Radius.control, style: .continuous)
                    .strokeBorder(focused ? AnyShapeStyle(Theme.accent.opacity(0.9)) : AnyShapeStyle(Self.titleHairline),
                        lineWidth: focused ? 1.5 : 1)
            }
            .animation(.easeOut(duration: 0.15), value: focused)
            .accessibilityIdentifier("editor.title")
    }
}
