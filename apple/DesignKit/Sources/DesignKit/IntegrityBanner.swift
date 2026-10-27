import SwiftUI

/// Red banner shown when the core refused tampered storage data.
public struct IntegrityBanner: View {
    private let kind: String

    public init(kind: String) { self.kind = kind }

    nonisolated static var fallback: String {
        String(localized: "Le stockage a renvoyé des données altérées.", bundle: DesignKitStrings.bundle)
    }

    /// Text for a core `Integrity { kind }`.
    public nonisolated static func message(for kind: String) -> String {
        switch kind {
        case "account_missing": String(localized: "Le compte a disparu du stockage.", bundle: DesignKitStrings.bundle)
        case "vault_missing": String(localized: "Un coffre a disparu du stockage.", bundle: DesignKitStrings.bundle)
        case "manifest_rollback": String(localized: "Une ancienne version des données a été rejouée.", bundle: DesignKitStrings.bundle)
        case "manifest_missing_item": String(localized: "Un élément a été retenu ou supprimé du stockage.", bundle: DesignKitStrings.bundle)
        case "manifest_unexpected_item": String(localized: "Un élément inconnu a été ajouté au stockage.", bundle: DesignKitStrings.bundle)
        case "manifest_item_mismatch": String(localized: "Un élément ne correspond pas à la liste signée du coffre.", bundle: DesignKitStrings.bundle)
        case "commitment", "aead": String(localized: "Des données chiffrées ont été modifiées.", bundle: DesignKitStrings.bundle)
        case "signature", "params_unsigned": String(localized: "Une signature est invalide.", bundle: DesignKitStrings.bundle)
        case "params_downgrade": String(localized: "Les paramètres de sécurité du compte ont été affaiblis.", bundle: DesignKitStrings.bundle)
        case "wrong_kind", "wrong_context": String(localized: "Un enregistrement a été déplacé ou substitué.", bundle: DesignKitStrings.bundle)
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
