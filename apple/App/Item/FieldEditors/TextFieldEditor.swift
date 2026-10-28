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
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        VStack(alignment: .leading, spacing: 0) { content }
            .frame(maxWidth: .infinity, alignment: .leading)
            #if os(iOS)
            // iPhone and iPad: the grouped cell color over the grouped background (`groupedScreen`),
            // so a card reads the same in the lists, the detail and the editor.
            .background(Color(uiColor: .secondarySystemGroupedBackground), in: .rect(cornerRadius: 14))
            .overlay { RoundedRectangle(cornerRadius: 14).strokeBorder(Color.primary.opacity(0.06)) }
            #else
            // Dark: see-through over the window, a hairline to hold the edge. Light: white cards
            // lifted off a soft gray page (`groupedScreen`) by a hairline and a faint shadow.
            .background(scheme == .dark ? AnyShapeStyle(.fill.quaternary) : AnyShapeStyle(Color.white),
                in: .rect(cornerRadius: 14))
            .overlay {
                RoundedRectangle(cornerRadius: 14)
                    .strokeBorder(scheme == .dark ? Color.white.opacity(0.07) : Color.black.opacity(0.07))
            }
            .shadow(color: .black.opacity(scheme == .dark ? 0 : 0.04), radius: 3, y: 1)
            #endif
    }
}

extension View {
    /// iPhone and iPad: the grouped background behind the cards of the detail and the editor.
    /// Mac and Vision Pro: unchanged (the window glass).
    @ViewBuilder func groupedScreen() -> some View {
        #if os(iOS)
        background(Color(uiColor: .systemGroupedBackground).ignoresSafeArea())
        #elseif os(macOS)
        modifier(MacGroupedScreen())
        #else
        self
        #endif
    }
}

#if os(macOS)
/// Mac, light appearance: a soft gray page under the white cards. Dark keeps the window as is.
private struct MacGroupedScreen: ViewModifier {
    @Environment(\.colorScheme) private var scheme

    func body(content: Content) -> some View {
        content.background(scheme == .dark ? Color.clear : Color(white: 0.965))
    }
}
#endif

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

/// Text, email, phone and URL fields: a text field with the right keyboard. Email and username
/// fields suggest the addresses already saved in the vault, most used first, as chips under the
/// field while it is being typed in.
struct TextFieldEditor: View {
    @Environment(AppModel.self) private var model
    let field: FfiField
    @Binding var value: FfiFieldValue
    @FocusState private var focused: Bool

    private var text: Binding<String> {
        Binding(get: { value.text }, set: { value = .fromText($0, kind: field.kind) })
    }

    private var suggestsAccounts: Bool { field.kind == .email || field.id == "username" }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            TextField(field.displayLabel, text: text, prompt: Text(placeholder))
                .fieldInput(field.kind)
                .focused($focused)
                .onSubmit { if let first = suggestions.first { text.wrappedValue = first } }
                .accessibilityIdentifier("editor.field.\(field.id)")
            if suggestsAccounts, focused, !suggestions.isEmpty {
                suggestionChips
                    .transition(.opacity.combined(with: .offset(y: -4)))
            }
        }
        .animation(.easeOut(duration: 0.15), value: focused)
        .animation(.easeOut(duration: 0.15), value: suggestions)
    }

    /// Up to three saved addresses that start with what is typed (all of them when empty), most
    /// used first; an exact match hides the list.
    private var suggestions: [String] {
        guard suggestsAccounts else { return [] }
        let typed = value.text.trimmingCharacters(in: .whitespaces).lowercased()
        let known = AccountSuggestions.ranked(model.session.summaries.filter { $0.trashedAt == nil }.map(\.subtitle),
            emailsOnly: field.kind == .email)
        if known.contains(where: { $0.lowercased() == typed }) { return [] }
        return Array(known.filter { typed.isEmpty || $0.lowercased().hasPrefix(typed) }.prefix(3))
    }

    private var suggestionChips: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 6) {
                ForEach(suggestions, id: \.self) { suggestion in
                    Button {
                        text.wrappedValue = suggestion
                        focused = false
                    } label: {
                        Label(suggestion, systemImage: suggestion.contains("@") ? "envelope" : "person")
                            .font(.callout)
                            .lineLimit(1)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 5)
                            .background(Theme.accent.opacity(0.14), in: Capsule())
                            .foregroundStyle(Theme.readableAccent)
                            .contentShape(Capsule())
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(Text("Utiliser \(suggestion)"))
                    .accessibilityIdentifier("editor.field.\(field.id).suggestion")
                }
            }
        }
        .scrollClipDisabled()
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

/// The usernames and addresses already saved in the vault (the items' subtitles), most used first.
enum AccountSuggestions {
    static func ranked(_ subtitles: [String], emailsOnly: Bool) -> [String] {
        var counts: [String: Int] = [:]
        var firstSeen: [String: Int] = [:]
        for (index, raw) in subtitles.enumerated() {
            let value = raw.trimmingCharacters(in: .whitespaces)
            // Card numbers and other masked subtitles are not accounts.
            guard !value.isEmpty, !value.contains("•"), !value.contains(" "),
                !emailsOnly || isEmail(value)
            else { continue }
            counts[value, default: 0] += 1
            if firstSeen[value] == nil { firstSeen[value] = index }
        }
        return counts.keys.sorted {
            counts[$0]! != counts[$1]! ? counts[$0]! > counts[$1]! : firstSeen[$0]! < firstSeen[$1]!
        }
    }

    static func isEmail(_ value: String) -> Bool {
        let parts = value.split(separator: "@")
        return parts.count == 2 && !parts[0].isEmpty && parts[1].contains(".")
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
