import SwiftUI
import VaultKit

/// Menu field: the core's options for this type and field (`menuOptions`), or free text when the
/// core has none. A stored value missing from the list stays selectable.
struct MenuFieldEditor: View {
    let field: FfiField
    let itemType: FfiItemType
    @Binding var value: FfiFieldValue

    private var options: [String] { menuOptions(itemType: itemType, fieldId: field.id) }

    private var selection: Binding<String> {
        Binding(get: { value.text }, set: { value = .fromText($0, kind: .menu) })
    }

    var body: some View {
        let options = options
        if options.isEmpty {
            TextField(field.label, text: selection)
                .accessibilityIdentifier("editor.field.\(field.id)")
        } else {
            Picker(field.label, selection: selection) {
                Text("Aucun").tag("")
                ForEach(options, id: \.self) { Text($0).tag($0) }
                if !value.text.isEmpty, !options.contains(value.text) {
                    Text(value.text).tag(value.text)
                }
            }
            .labelsHidden()
            .pickerStyle(.menu)
            .accessibilityIdentifier("editor.field.\(field.id)")
        }
    }
}
