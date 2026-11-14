import DesignKit
import SwiftUI
import VaultKit

/// The icon's chevron: site icon or category artwork, and a badge color (the account colors, or
/// none) drawn as the category tile's background. A site icon is never tinted.
struct IconMenu<Label: View>: View {
    @Binding var item: FfiItem
    @ViewBuilder let label: Label

    var body: some View {
        Menu {
            Picker("editor.icon", selection: $item.iconCategory) {
                Text("editor.icon.site").tag(false)
                Text("editor.icon.category").tag(true)
            }
            .pickerStyle(.inline)
            .accessibilityIdentifier("editor.icon.category")
            Picker("editor.icon.color", selection: $item.color) {
                Text("editor.icon.noColor").tag(String?.none)
                ForEach(ItemTint.names, id: \.self) { name in
                    Text(LocalizedStringKey("accounts.color.\(name)")).tag(String?.some(name))
                }
            }
            .pickerStyle(.menu)
        } label: {
            label
                .overlay(alignment: .bottomTrailing) {
                    Image(systemName: "chevron.down")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundStyle(.secondary)
                        .frame(width: 20, height: 20)
                        .background(.background, in: Circle())
                        .overlay { Circle().strokeBorder(.separator, lineWidth: 0.5) }
                        .offset(x: 4, y: 4)
                }
                .contentShape(.rect)
        }
        .menuStyle(.button)
        .buttonStyle(.plain)
        .menuIndicator(.hidden)
        .fixedSize()
        .accessibilityLabel(Text("editor.icon"))
        .accessibilityIdentifier("editor.icon")
    }
}
