import SwiftUI
import VaultKit

/// Label above the control, as in the mockup's edit mode; the validation message goes below.
struct EditorRow<Content: View>: View {
    /// The field label from the core template (French data, not a UI string).
    let label: String
    var message: String?
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.footnote).foregroundStyle(.secondary)
            // The label is shown once, above: the control's own label is hidden (a grouped Form
            // would repeat it on the left on Mac) and its text starts on the left.
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
        .padding(.vertical, 2)
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
        TextField(field.label, text: text, prompt: Text(placeholder))
            .fieldInput(field.kind)
            .accessibilityIdentifier("editor.field.\(field.id)")
    }

    private var placeholder: String {
        switch field.kind {
        case .url: "https://"
        case .email: "nom@exemple.fr"
        case .phone: "+33 6 12 34 56 78"
        default: field.label
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
