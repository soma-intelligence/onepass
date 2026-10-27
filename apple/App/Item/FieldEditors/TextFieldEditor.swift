import DesignKit
import SwiftUI
import VaultKit

/// Label above the control, in the accent color as in edit mode; the validation message goes below.
struct EditorRow<Content: View>: View {
    /// The field label from the core template (French data, not a UI string).
    let label: String
    var message: String?
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            EditorLabel(label)
            // The label is shown once, above: the control's own label is hidden and its text
            // starts on the left.
            content
                .labelsHidden()
                .multilineTextAlignment(.leading)
                .frame(maxWidth: .infinity, alignment: .leading)
            if let message {
                Label(message, systemImage: "exclamationmark.circle.fill")
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .accessibilityIdentifier("editor.error")
            }
        }
    }
}

/// A field or block label of the editor: small, in the accent color.
struct EditorLabel: View {
    let text: String

    init(_ text: String) { self.text = text }

    var body: some View {
        // Lightened accent: 4.5:1 or better on the dark glass, still reads as "editable".
        Text(text).font(.subheadline.weight(.medium)).foregroundStyle(Theme.readableAccent)
    }
}

/// A rounded block of rows (the editor's cards): rows are separated by `CardDivider`.
struct EditorCard<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 0) { content }
            .frame(maxWidth: .infinity, alignment: .leading)
            #if os(iOS)
            // iPhone and iPad: the grouped cell color over the grouped background (`groupedScreen`),
            // so a card reads the same in the lists, the detail and the editor.
            .background(Color(uiColor: .secondarySystemGroupedBackground), in: .rect(cornerRadius: 14))
            .overlay { RoundedRectangle(cornerRadius: 14).strokeBorder(Color.primary.opacity(0.06)) }
            #else
            // See-through over the window material, with a hairline to hold the edge.
            .background(.fill.quaternary, in: .rect(cornerRadius: 14))
            .overlay { RoundedRectangle(cornerRadius: 14).strokeBorder(.white.opacity(0.07)) }
            #endif
    }
}

extension View {
    /// iPhone and iPad: the grouped background behind the cards of the detail and the editor.
    /// Mac and Vision Pro: unchanged (the window glass).
    @ViewBuilder func groupedScreen() -> some View {
        #if os(iOS)
        background(Color(uiColor: .systemGroupedBackground).ignoresSafeArea())
        #else
        self
        #endif
    }
}

struct CardDivider: View {
    var body: some View { Divider().padding(.leading, 16) }
}

/// "+ ajouter ..." inside a card.
struct AddRowButton: View {
    let title: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Label(title, systemImage: "plus")
                .font(.body.weight(.medium))
                .foregroundStyle(Theme.accent)
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .editorRowPadding()
    }
}

/// The red "−" at the end of a removable row.
struct RemoveRowButton: View {
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: "minus.circle").font(.title3).foregroundStyle(.red)
        }
        .buttonStyle(.borderless)
    }
}

extension View {
    /// Inner padding of a card row.
    func editorRowPadding() -> some View {
        padding(.horizontal, 16).padding(.vertical, 10)
    }
}

/// Text, email, phone and URL fields: a text field with the right keyboard.
struct TextFieldEditor: View {
    let field: FfiField
    @Binding var value: FfiFieldValue

    private var text: Binding<String> {
        Binding(get: { value.text }, set: { value = .fromText($0, kind: field.kind) })
    }

    var body: some View {
        TextField(field.displayLabel, text: text, prompt: Text(placeholder))
            .fieldInput(field.kind)
            .accessibilityIdentifier("editor.field.\(field.id)")
    }

    private var placeholder: String {
        switch field.kind {
        // What to type, never an example value: a prompt that looks like data reads as a filled field.
        case .url: "https://"
        case .email: String(localized: "adresse email")
        case .phone: String(localized: "numéro de téléphone")
        default: field.id == "username" ? String(localized: "nom d'utilisateur ou email") : ""
        }
    }
}

extension View {
    /// Keyboard, content type and autocorrection for a field kind (iOS; the Mac has none of these).
    func fieldInput(_ kind: FfiFieldType) -> some View {
        #if os(iOS) || os(visionOS)
        let keyboard: UIKeyboardType =
            switch kind {
            case .url: .URL
            case .email: .emailAddress
            case .phone: .phonePad
            case .number: .numberPad
            case .money: .decimalPad
            // Coordinates need the minus sign and both separators.
            case .location: .numbersAndPunctuation
            default: .default
            }
        let plain = kind != .text
        return self
            .keyboardType(keyboard)
            .textInputAutocapitalization(plain ? .never : .sentences)
            .autocorrectionDisabled(plain)
            .textContentType(contentType(kind))
        #else
        return self.autocorrectionDisabled(kind != .text)
        #endif
    }
}

#if os(iOS) || os(visionOS)
/// No `.password` or `.oneTimeCode`: the editor holds vault secrets, and those content types make
/// iOS offer to save the value in the system password manager (outside the vault's encryption)
/// or fill in a code received by SMS.
private func contentType(_ kind: FfiFieldType) -> UITextContentType? {
    switch kind {
    case .url: .URL
    case .email: .emailAddress
    case .phone: .telephoneNumber
    default: nil
    }
}
#endif
