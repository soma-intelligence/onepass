import SwiftUI

/// The one masked input of the app for a secret typed by the user: the master password (lock
/// screen, onboarding, reprompt, settings checks) and the concealed fields of the item editor.
///
/// iOS and visionOS: a real secure text field (`isSecureTextEntry`: system keyboard only, no
/// keyboard learning, hidden from screen capture) that empties its displayed text as it leaves the
/// window, whatever takes it away (save, cancel, sheet dismissed, lock, navigation). The bound value
/// is not touched. iOS offers "Save Password?" when a filled secure field leaves the screen, whatever
/// the AutoFill provider and with no content type set; a field that is empty by then is never
/// offered (ruling X24 of the milestone 3 spec). `revealed` swaps in a plain text field, which iOS
/// never offers to save. macOS: SwiftUI's `SecureField` (no such sheet on the Mac).
struct SecretInputField: View {
    let title: String
    @Binding var text: String
    var revealed = false
    /// The keyboard focus, both ways (`@FocusState` does not reach a UIKit field).
    var focused: Binding<Bool>?
    /// Return key "Go" (unlock) instead of "Done".
    var submitGo = false
    var onSubmit: () -> Void = {}
    var monospaced = false
    var fontSize: CGFloat?
    var bordered = false
    var identifier: String

    @Environment(\.isEnabled) private var isEnabled
    @FocusState private var plainFocused: Bool

    var body: some View {
        if revealed {
            plainField
        } else {
            #if os(iOS) || os(visionOS)
            ConcealingSecureField(
                title: title, text: $text, focused: focused, returnKey: returnKey, onSubmit: onSubmit,
                font: uiFont, bordered: bordered, isEnabled: isEnabled, identifier: identifier)
            #else
            styled(SecureField(title, text: $text))
            #endif
        }
    }

    private var plainField: some View {
        styled(
            TextField(title, text: $text)
                .autocorrectionDisabled()
                #if os(iOS) || os(visionOS)
                .textInputAutocapitalization(.never)
                #endif
        )
    }

    /// SwiftUI fields: font, border, submit, focus kept in step with `focused`.
    @ViewBuilder private func styled(_ field: some View) -> some View {
        let base = field
            .font(swiftUIFont)
            .submitLabel(submitGo ? .go : .done)
            .onSubmit(onSubmit)
            .focused($plainFocused)
            .onChange(of: focused?.wrappedValue, initial: true) { _, wanted in
                if let wanted, wanted != plainFocused { plainFocused = wanted }
            }
            .onChange(of: plainFocused) { _, now in
                if let focused, focused.wrappedValue != now { focused.wrappedValue = now }
            }
            .accessibilityIdentifier(identifier)
        if bordered {
            base.textFieldStyle(.roundedBorder)
        } else {
            base
        }
    }

    private var swiftUIFont: Font {
        let size = fontSize.map { Font.system(size: $0) } ?? .body
        return monospaced ? size.monospaced() : size
    }

    #if os(iOS) || os(visionOS)
    private var uiFont: UIFont {
        let base = fontSize.map { UIFont.systemFont(ofSize: $0) } ?? .preferredFont(forTextStyle: .body)
        guard monospaced else { return base }
        return .monospacedSystemFont(ofSize: base.pointSize, weight: .regular)
    }

    private var returnKey: UIReturnKeyType { submitGo ? .go : .done }
    #endif
}

#if os(iOS) || os(visionOS)
import UIKit

/// The UIKit side of `SecretInputField`.
private struct ConcealingSecureField: UIViewRepresentable {
    let title: String
    @Binding var text: String
    let focused: Binding<Bool>?
    let returnKey: UIReturnKeyType
    let onSubmit: () -> Void
    let font: UIFont
    let bordered: Bool
    let isEnabled: Bool
    let identifier: String

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeUIView(context: Context) -> ConcealingTextField {
        let field = ConcealingTextField()
        field.isSecureTextEntry = true
        // No content type: `.password` would make the field a login form for AutoFill, and
        // `.oneTimeCode` would offer codes received by SMS.
        field.textContentType = nil
        field.autocorrectionType = .no
        field.autocapitalizationType = .none
        field.spellCheckingType = .no
        field.smartQuotesType = .no
        field.smartDashesType = .no
        field.smartInsertDeleteType = .no
        field.inlinePredictionType = .no
        field.adjustsFontForContentSizeCategory = true
        field.setContentHuggingPriority(.defaultLow, for: .horizontal)
        field.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        field.delegate = context.coordinator
        field.addTarget(context.coordinator, action: #selector(Coordinator.changed(_:)), for: .editingChanged)
        return field
    }

    func updateUIView(_ field: ConcealingTextField, context: Context) {
        context.coordinator.parent = self
        field.placeholder = title
        field.accessibilityIdentifier = identifier
        field.font = font
        field.borderStyle = bordered ? .roundedRect : .none
        field.returnKeyType = returnKey
        field.isEnabled = isEnabled
        field.modelText = text
        if field.window != nil, field.text != text { field.text = text }
        guard let wanted = focused?.wrappedValue, wanted != field.isFirstResponder else { return }
        // Not during the view update: the field may not be in its window yet.
        DispatchQueue.main.async {
            guard field.window != nil, field.isEnabled else { return }
            if wanted { field.becomeFirstResponder() } else { field.resignFirstResponder() }
        }
    }

    func sizeThatFits(_ proposal: ProposedViewSize, uiView field: ConcealingTextField, context: Context) -> CGSize? {
        let height = field.intrinsicContentSize.height
        return CGSize(width: proposal.width ?? field.intrinsicContentSize.width, height: height)
    }

    @MainActor final class Coordinator: NSObject, UITextFieldDelegate {
        var parent: ConcealingSecureField

        init(_ parent: ConcealingSecureField) { self.parent = parent }

        @objc func changed(_ field: UITextField) {
            let value = field.text ?? ""
            (field as? ConcealingTextField)?.modelText = value
            if parent.text != value { parent.text = value }
        }

        func textFieldDidBeginEditing(_ textField: UITextField) {
            if let focused = parent.focused, !focused.wrappedValue { focused.wrappedValue = true }
        }

        func textFieldDidEndEditing(_ textField: UITextField) {
            if let focused = parent.focused, focused.wrappedValue { focused.wrappedValue = false }
        }

        func textFieldShouldReturn(_ textField: UITextField) -> Bool {
            parent.onSubmit()
            return false
        }
    }
}

/// Empties its displayed text before it leaves the window, so no filled secure field ever goes
/// away (the system's save heuristic reads the field as it leaves). The value comes back from
/// `modelText` when the field is shown again (a tab or a navigation level revisited).
private final class ConcealingTextField: UITextField {
    var modelText = ""

    override func willMove(toWindow newWindow: UIWindow?) {
        if newWindow == nil, !(text ?? "").isEmpty { text = "" }
        super.willMove(toWindow: newWindow)
    }

    override func didMoveToWindow() {
        super.didMoveToWindow()
        if window != nil, text != modelText { text = modelText }
    }
}
#endif
