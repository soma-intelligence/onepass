import SwiftUI
import VaultKit

/// Tile data for one of the 26 item types: plural label for lists and the
/// sidebar, singular label (identical to the core's `itemTypes()` label),
/// tile color from the mockup and an SF Symbol.
public struct ItemCategory: Identifiable, Sendable {
    public let type: FfiItemType
    public let plural: String
    public let singular: String
    public let color: Color
    public let symbol: String
    /// The tile color as 0xRRGGBB (for targets that cannot link DesignKit, such as widgets).
    public let hex: UInt32

    public var id: FfiItemType { type }

    public static func of(_ t: FfiItemType) -> ItemCategory {
        if let c = byType[t] { return c }
        assertionFailure("ItemCategory: unknown item type")
        return all[0]
    }

    /// Same order as the core's `ItemType::ALL` (and `itemTypes()`).
    public static let all: [ItemCategory] = [
        make(.login, "Connexions", "Connexion", 0x0E9F9F, "person.crop.circle"),
        make(.password, "Mots de passe", "Mot de passe", 0x0F5E63, "key.fill"),
        make(.email, "Comptes email", "Compte email", 0xBE185D, "envelope.fill"),
        make(.server, "Serveurs", "Serveur", 0x5B6472, "server.rack"),
        make(.database, "Bases de données", "Base de données", 0x5B6472, "cylinder.split.1x2.fill"),
        make(.router, "Routeurs Wi-Fi", "Routeur Wi-Fi", 0x0F766E, "wifi.router.fill"),
        make(.apiCredential, "Identifiants API", "Identifiant d'API", 0x0891B2, "curlybraces"),
        make(.sshKey, "Clés SSH", "Clé SSH", 0x475569, "terminal.fill"),
        make(.creditCard, "Cartes bancaires", "Carte bancaire", 0x2F80ED, "creditcard.fill"),
        make(.bankAccount, "Comptes bancaires", "Compte bancaire", 0xE08A00, "building.columns.fill"),
        make(.cryptoWallet, "Portefeuilles crypto", "Portefeuille crypto", 0x2563EB, "bitcoinsign.circle.fill"),
        make(.subscription, "Abonnements", "Abonnement", 0x9333EA, "arrow.triangle.2.circlepath"),
        make(.identity, "Identités", "Identité", 0x22A06B, "person.text.rectangle.fill"),
        make(.idCard, "Cartes d'identité", "Carte d'identité", 0x15803D, "person.crop.rectangle.fill"),
        make(.passport, "Passeports", "Passeport", 0x1D4ED8, "airplane"),
        make(.driverLicense, "Permis de conduire", "Permis de conduire", 0xE11D48, "car.fill"),
        make(.socialSecurityNumber, "Numéros de sécu", "Numéro de sécurité sociale", 0x1E40AF, "number"),
        make(.medicalRecord, "Dossiers médicaux", "Dossier médical", 0xDC2626, "cross.case.fill"),
        make(.membership, "Cartes de membre", "Adhésion", 0x7C3AED, "person.2.fill"),
        make(.rewardProgram, "Programmes de fidélité", "Programme de fidélité", 0xDB2777, "gift.fill"),
        make(.insurance, "Assurances", "Assurance", 0x0D9488, "shield.fill"),
        make(.vehicle, "Véhicules", "Véhicule", 0x475569, "box.truck.fill"),
        make(.accessCode, "Digicodes", "Code d'accès", 0x4338CA, "lock.rectangle.fill"),
        make(.secureNote, "Notes sécurisées", "Note sécurisée", 0xD99A1E, "note.text"),
        make(.document, "Documents", "Document", 0x3478F6, "doc.fill"),
        make(.softwareLicense, "Licences logicielles", "Licence logicielle", 0x2563EB, "app.badge.checkmark.fill"),
    ]

    private static let byType: [FfiItemType: ItemCategory] =
        Dictionary(uniqueKeysWithValues: all.map { ($0.type, $0) })

    private static func make(
        _ type: FfiItemType, _ plural: String, _ singular: String, _ hex: UInt32, _ symbol: String
    ) -> ItemCategory {
        ItemCategory(
            type: type, plural: plural, singular: singular, color: Color(hex: hex), symbol: symbol, hex: hex)
    }
}
