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

    private var compactBody: some View {
        HStack(spacing: 8) {
            Image(systemName: "key.viewfinder")
                .foregroundStyle(.tint)
                .accessibilityHidden(true)
            Text("Remplissage")
                .font(.subheadline.weight(.medium))
                .lineLimit(1)
                .minimumScaleFactor(0.8)
                .layoutPriority(1)
            Spacer(minLength: 4)
            Button("Activer") { activate() }
                .buttonStyle(.glassProminent)
                .controlSize(.small)
                .fixedSize()
                .disabled(requesting)
                .accessibilityIdentifier("autofill.tip.enable")
            Button {
                withAnimation(.snappy) { model.dismissAutoFillTip() }
            } label: {
                Image(systemName: "xmark").font(.caption2.weight(.bold)).foregroundStyle(.tertiary)
            }
            .buttonStyle(.borderless)
            .accessibilityLabel(Text("Fermer"))
            .accessibilityIdentifier("autofill.tip.dismiss")
        }
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
