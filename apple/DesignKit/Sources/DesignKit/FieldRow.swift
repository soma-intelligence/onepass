import Foundation
import SwiftUI

/// Label, value and a menu (Copier, Révéler, Afficher en grand). A secret
/// value is drawn as bullets and announced as "masqué" until revealed. A revealed secret is masked
/// again after `autoHideAfter`, when the row leaves the screen, and whenever `concealToken` changes
/// (the session bumps it on lock and when the scene leaves the foreground). While `captured` (screen
/// recording, mirroring, AirPlay) a secret is drawn as bullets, and a revealed one is masked again.
public struct FieldRow: View {
    private let label: String
    private let value: String
    private let isSecret: Bool
    private let monospaced: Bool
    private let autoHideAfter: TimeInterval
    private let onCopy: () -> Void
    private let onReveal: ((Bool) -> Void)?
    private let copyIdentifier: String?
    private let allowsLarge: Bool
    private let concealToken: Int
    private let captured: Bool

    /// What a masked value shows (spec: the mockup's eleven bullets).
    public static let mask = "•••••••••••"

    @State private var disclosure = FieldDisclosure()

    public init(
        label: String, value: String, isSecret: Bool, monospaced: Bool,
        autoHideAfter: TimeInterval = 30,
        copyIdentifier: String? = nil, allowsLarge: Bool = true,
        concealToken: Int = 0, captured: Bool = false,
        onCopy: @escaping () -> Void, onReveal: ((Bool) -> Void)?
    ) {
        self.label = label
        self.value = value
        self.isSecret = isSecret
        self.monospaced = monospaced
        self.autoHideAfter = autoHideAfter
        self.onCopy = onCopy
        self.onReveal = onReveal
        self.copyIdentifier = copyIdentifier
        self.allowsLarge = allowsLarge
        self.concealToken = concealToken
        self.captured = captured
    }

    private var revealed: Bool { disclosure.revealed }
    private var hidden: Bool { isSecret && (!revealed || captured) }
    private var largeBinding: Binding<Bool> {
        Binding(get: { disclosure.large && !hidden }, set: { disclosure.large = $0 })
    }

    public var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(label).font(.footnote).foregroundStyle(.secondary)
                Text(hidden ? Self.mask : value)
                    .font(monospaced ? .body.monospaced() : .body)
                    .textSelection(.disabled)
                    .accessibilityLabel(Text(label))
                    .accessibilityValue(Text(hidden ? "masqué" : value))
            }
            Spacer(minLength: 0)
            Menu {
                Button("Copier", systemImage: "doc.on.doc", action: onCopy)
                    .accessibilityIdentifier(copyIdentifier ?? "")
                if isSecret {
                    Button(
                        revealed ? "Masquer" : "Révéler",
                        systemImage: revealed ? "eye.slash" : "eye"
                    ) { setRevealed(!revealed) }
                }
                if allowsLarge {
                    Button("Afficher en grand", systemImage: "arrow.up.left.and.arrow.down.right") {
                        showLarge()
                    }
                }
            } label: {
                Image(systemName: "ellipsis.circle")
                    .accessibilityLabel(Text(verbatim: "Actions pour \(label)"))
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
        }
        .accessibilityElement(children: .contain)
        .task(id: disclosure.revealedAt) {
            guard disclosure.revealedAt != nil else { return }
            try? await Task.sleep(for: .seconds(autoHideAfter))
            if !Task.isCancelled, disclosure.shouldRemask(now: Date(), after: autoHideAfter) {
                setRevealed(false)
            }
        }
        .onDisappear { if disclosure.revealed { setRevealed(false) } }
        .onChange(of: concealToken) { if disclosure.revealed { setRevealed(false) } }
        // Captured: masked now, and still masked once the capture ends.
        .onChange(of: captured) { _, now in if now, disclosure.revealed { setRevealed(false) } }
        .sheet(isPresented: largeBinding) {
            VStack(spacing: 16) {
                Text(label).font(.headline)
                Text(value)
                    .font(.system(.largeTitle, design: .monospaced))
                    .multilineTextAlignment(.center)
                    .minimumScaleFactor(0.4)
                Button("Fermer") { disclosure.large = false }.keyboardShortcut(.cancelAction)
            }
            .padding(32)
            .presentationDetents([.medium])
        }
    }

    private func setRevealed(_ on: Bool) {
        if disclosure.reveal(on, isSecret: isSecret, now: Date()) { onReveal?(on) }
    }

    /// A secret goes through the same reveal path before it is shown large.
    private func showLarge() {
        if disclosure.showLarge(isSecret: isSecret) { onReveal?(true) }
    }
}

/// Reveal and large-display decisions of a field row, kept pure for tests.
struct FieldDisclosure: Equatable {
    var revealed = false
    var large = false
    /// When the value was last revealed; nil while masked.
    var revealedAt: Date?

    /// Returns true when the host must be told (`onReveal`). Masking again
    /// also closes the large display.
    mutating func reveal(_ on: Bool, isSecret: Bool, now: Date = Date()) -> Bool {
        guard isSecret else { return false }
        revealed = on
        revealedAt = on ? now : nil
        if !on { large = false }
        return true
    }

    /// True when a revealed secret has been visible for at least `delay`.
    func shouldRemask(now: Date, after delay: TimeInterval) -> Bool {
        guard revealed, let at = revealedAt else { return false }
        return now.timeIntervalSince(at) >= delay
    }

    /// Returns true when the host must be told that the value was revealed.
    mutating func showLarge(isSecret: Bool, now: Date = Date()) -> Bool {
        let notify = isSecret ? reveal(true, isSecret: true, now: now) : false
        large = true
        return notify
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
