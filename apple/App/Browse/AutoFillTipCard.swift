import DesignKit
import SwiftUI
import VaultKit

/// "Remplis tes mots de passe avec OnePass" (spec 6 and 7): on Accueil (iPhone) and at the bottom of
/// the sidebar (iPad and Mac) while OnePass is not the AutoFill provider. "Activer" shows the system
/// prompt; the close button hides the card for good (`autofillTipDismissed`). The caller shows it
/// only when `AppModel.showsAutoFillTip` is true.
struct AutoFillTipCard: View {
    @Environment(AppModel.self) private var model
    @State private var requesting = false
    /// One line for the Mac sidebar: icon, short title, "Activer", close.
    var compact = false

    var body: some View {
        if compact { compactBody } else { fullBody }
    }

    @State private var hovering = false

    /// Mac sidebar: the AutoFill tile, a title over a one-line reason, "Activer" as a small accent
    /// capsule; the close button only shows under the pointer, in the top corner.
    private var compactBody: some View {
        HStack(spacing: 10) {
            SymbolTile(symbol: "key.viewfinder", color: Theme.accent, size: 26)
            VStack(alignment: .leading, spacing: 1) {
                Text("Remplissage auto")
                    .font(.subheadline.weight(.semibold))
                    .lineLimit(1)
                Text("Désactivé")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            .layoutPriority(1)
            Spacer(minLength: 4)
            Button("Activer") { activate() }
                .buttonStyle(SmallAccentCapsuleStyle())
                .fixedSize()
                .disabled(requesting)
                .accessibilityIdentifier("autofill.tip.enable")
        }
        .overlay(alignment: .topTrailing) {
            Button {
                withAnimation(.snappy) { model.dismissAutoFillTip() }
            } label: {
                Image(systemName: "xmark")
                    .font(.system(size: 8, weight: .bold))
                    .foregroundStyle(.secondary)
                    .frame(width: 16, height: 16)
                    .background(.regularMaterial, in: Circle())
                    .overlay { Circle().strokeBorder(Color.primary.opacity(0.1)) }
                    .contentShape(Circle())
            }
            .buttonStyle(.plain)
            .offset(x: 8, y: -12)
            .opacity(hovering ? 1 : 0)
            .accessibilityLabel(Text("Fermer"))
            .accessibilityIdentifier("autofill.tip.dismiss")
        }
        .onHover { hovering = $0 }
        .animation(.easeOut(duration: 0.15), value: hovering)
        .help("Tes identifiants, codes et passkeys proposés dans les apps et Safari, sans copier-coller.")
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("autofill.tip")
    }

    private var fullBody: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Image(systemName: "key.viewfinder")
                    .foregroundStyle(.tint)
                    .accessibilityHidden(true)
                Text("Remplis tes mots de passe avec OnePass")
                    .font(.subheadline.weight(.semibold))
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
                Button {
                    withAnimation(.snappy) { model.dismissAutoFillTip() }
                } label: {
                    Image(systemName: "xmark")
                        .font(.caption.weight(.bold))
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(Text("Fermer"))
                .accessibilityIdentifier("autofill.tip.dismiss")
            }
            Text("Tes identifiants, codes et passkeys proposés dans les apps et Safari, sans copier-coller.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button {
                activate()
            } label: {
                Text("Activer OnePass")
                    .font(.footnote.weight(.semibold))
            }
            .buttonStyle(.glassProminent)
            .controlSize(.small)
            .disabled(requesting)
            .accessibilityIdentifier("autofill.tip.enable")
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("autofill.tip")
    }

    private func activate() {
        guard !requesting else { return }
        requesting = true
        Task {
            await model.requestAutoFillActivation()
            requesting = false
        }
    }
}

/// A compact accent capsule for a call to action inside a card.
private struct SmallAccentCapsuleStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.caption.weight(.semibold))
            .foregroundStyle(.white)
            .padding(.horizontal, 11)
            .padding(.vertical, 5)
            .background(Theme.accent, in: Capsule())
            .overlay { Capsule().strokeBorder(.white.opacity(0.15), lineWidth: 0.5) }
            .contentShape(Capsule())
            .opacity(configuration.isPressed ? 0.75 : 1)
    }
}
