import SwiftUI

/// Red banner shown when the core refused tampered storage data.
public struct IntegrityBanner: View {
    private let kind: String

    public init(kind: String) { self.kind = kind }

    nonisolated static var fallback: String {
        String(localized: "integrityBanner.storageReturnedTamperedData", bundle: DesignKitStrings.bundle)
    }

    /// Text for a core `Integrity { kind }`.
    public nonisolated static func message(for kind: String) -> String {
        switch kind {
        case "account_missing": String(localized: "integrityBanner.accountDisappearedFromStorage", bundle: DesignKitStrings.bundle)
        case "vault_missing": String(localized: "integrityBanner.vaultDisappearedFromStorage", bundle: DesignKitStrings.bundle)
        case "manifest_rollback": String(localized: "integrityBanner.oldVersionOfData", bundle: DesignKitStrings.bundle)
        case "manifest_missing_item": String(localized: "integrityBanner.itemWasHeldBack", bundle: DesignKitStrings.bundle)
        case "manifest_unexpected_item": String(localized: "integrityBanner.unknownItemWasAdded", bundle: DesignKitStrings.bundle)
        case "manifest_item_mismatch": String(localized: "integrityBanner.itemDoesntMatchVaults", bundle: DesignKitStrings.bundle)
        case "commitment", "aead": String(localized: "integrityBanner.encryptedDataWasModified", bundle: DesignKitStrings.bundle)
        case "signature", "params_unsigned": String(localized: "integrityBanner.signatureInvalid", bundle: DesignKitStrings.bundle)
        case "params_downgrade": String(localized: "integrityBanner.accountsSecuritySettingsWere", bundle: DesignKitStrings.bundle)
        case "wrong_kind", "wrong_context": String(localized: "integrityBanner.recordWasMovedOr", bundle: DesignKitStrings.bundle)
        default: fallback
        }
    }

    private static let fill = Color.red.opacity(0.12)

    public var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.shield.fill")
                .foregroundStyle(.red)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text("integrityBanner.dataRefused", bundle: DesignKitStrings.bundle).font(.headline)
                Text(Self.message(for: kind)).font(.subheadline).foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .padding(12)
        .washBackground(
            Theme.Wash.alert(Self.fill), flat: Self.fill,
            in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .accessibilityElement(children: .combine)
        .accessibilityLabel(Text("integrityBanner.integrityAlert", bundle: DesignKitStrings.bundle))
    }
}

#Preview("IntegrityBanner") {
    VStack {
        IntegrityBanner(kind: "manifest_rollback")
        IntegrityBanner(kind: "autre")
    }
    .padding()
}
