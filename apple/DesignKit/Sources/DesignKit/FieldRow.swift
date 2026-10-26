import SwiftUI

/// Label, value and a menu (Copier, Révéler, Afficher en grand). A secret
/// value is drawn as bullets and announced as "masqué" until revealed.
public struct FieldRow: View {
    private let label: String
    private let value: String
    private let isSecret: Bool
    private let monospaced: Bool
    private let onCopy: () -> Void
    private let onReveal: ((Bool) -> Void)?

    @State private var revealed = false
    @State private var large = false

    public init(
        label: String, value: String, isSecret: Bool, monospaced: Bool,
        onCopy: @escaping () -> Void, onReveal: ((Bool) -> Void)?
    ) {
        self.label = label
        self.value = value
        self.isSecret = isSecret
        self.monospaced = monospaced
        self.onCopy = onCopy
        self.onReveal = onReveal
    }

    private var hidden: Bool { isSecret && !revealed }

    public var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(label).font(.footnote).foregroundStyle(.secondary)
                Text(hidden ? "••••••••" : value)
                    .font(monospaced || isSecret && revealed ? .body.monospaced() : .body)
                    .textSelection(.disabled)
                    .accessibilityLabel(Text(label))
                    .accessibilityValue(Text(hidden ? "masqué" : value))
            }
            Spacer(minLength: 0)
            Menu {
                Button("Copier", systemImage: "doc.on.doc", action: onCopy)
                if isSecret {
                    Button(
                        revealed ? "Masquer" : "Révéler",
                        systemImage: revealed ? "eye.slash" : "eye"
                    ) { setRevealed(!revealed) }
                }
                Button("Afficher en grand", systemImage: "arrow.up.left.and.arrow.down.right") {
                    large = true
                }
            } label: {
                Image(systemName: "ellipsis.circle")
                    .accessibilityLabel(Text(verbatim: "Actions pour \(label)"))
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
        }
        .accessibilityElement(children: .contain)
        .sheet(isPresented: $large) {
            VStack(spacing: 16) {
                Text(label).font(.headline)
                Text(value)
                    .font(.system(.largeTitle, design: .monospaced))
                    .multilineTextAlignment(.center)
                    .minimumScaleFactor(0.4)
                Button("Fermer") { large = false }.keyboardShortcut(.cancelAction)
            }
            .padding(32)
            .presentationDetents([.medium])
        }
    }

    private func setRevealed(_ on: Bool) {
        revealed = on
        onReveal?(on)
    }
}

#Preview("FieldRow") {
    VStack(alignment: .leading, spacing: 12) {
        FieldRow(
            label: "Identifiant", value: "camille.durand@exemple.fr", isSecret: false,
            monospaced: false, onCopy: {}, onReveal: nil)
        FieldRow(
            label: "Mot de passe", value: "correct-cheval-pile-agrafe", isSecret: true,
            monospaced: true, onCopy: {}, onReveal: { _ in })
    }
    .padding()
    .frame(width: 360)
}
