import SwiftUI

/// Red banner shown when the core refused tampered storage data.
public struct IntegrityBanner: View {
    private let kind: String

    public init(kind: String) { self.kind = kind }

    nonisolated static let fallback = "Le stockage a renvoyé des données altérées."

    /// French text for a core `Integrity { kind }`.
    public nonisolated static func message(for kind: String) -> String {
        switch kind {
        case "vault_missing": "Un coffre a disparu du stockage."
        case "manifest_rollback": "Une ancienne version des données a été rejouée."
        case "manifest_missing_item": "Un élément a été retenu ou supprimé du stockage."
        case "manifest_unexpected_item": "Un élément inconnu a été ajouté au stockage."
        case "manifest_item_mismatch": "Un élément ne correspond pas à la liste signée du coffre."
        case "commitment", "aead": "Des données chiffrées ont été modifiées."
        case "signature", "params_unsigned": "Une signature est invalide."
        case "params_downgrade": "Les paramètres de sécurité du compte ont été affaiblis."
        case "wrong_kind", "wrong_context": "Un enregistrement a été déplacé ou substitué."
        default: fallback
        }
    }

    public var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.shield.fill")
                .foregroundStyle(.red)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text("Données refusées").font(.headline)
                Text(Self.message(for: kind)).font(.subheadline).foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .padding(12)
        .background(Color.red.opacity(0.12), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .accessibilityElement(children: .combine)
        .accessibilityLabel(Text("Alerte d'intégrité"))
    }
}

#Preview("IntegrityBanner") {
    VStack {
        IntegrityBanner(kind: "manifest_rollback")
        IntegrityBanner(kind: "autre")
    }
    .padding()
}
