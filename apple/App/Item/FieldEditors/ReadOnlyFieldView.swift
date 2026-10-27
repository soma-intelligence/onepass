import SwiftUI
import VaultKit

/// Passkeys (created by the AutoFill extension) and files (attachments in milestone 5) are read only.
struct ReadOnlyFieldView: View {
    let field: FfiField

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: field.kind == .passkey ? "person.badge.key.fill" : "paperclip")
                .foregroundStyle(.secondary)
            Text(Self.describe(field.value, kind: field.kind))
                .foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("editor.field.\(field.id)")
    }

    static func describe(_ value: FfiFieldValue, kind: FfiFieldType) -> String {
        switch value {
        case .passkey(let p):
            let who = [p.userName, p.rpId].filter { !$0.isEmpty }.joined(separator: " · ")
            return String(localized: "\(who) · créée le \(FieldDates.day(p.createdAt))")
        case .file(let f):
            return "\(f.name) · \(ByteCountFormatter.string(fromByteCount: Int64(f.size), countStyle: .file))"
        default:
            return kind == .passkey
                ? String(localized: "Aucune passkey : elle s'ajoute quand un site t'en fait créer une")
                : String(localized: "Pièces jointes au jalon 5")
        }
    }
}
