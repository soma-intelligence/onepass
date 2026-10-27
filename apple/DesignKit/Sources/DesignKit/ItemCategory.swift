import SwiftUI
import VaultKit

/// Tile data for one of the 26 item types: plural label for lists and the
/// sidebar, singular label (the core's `itemTypes()` label in French, localized
/// from DesignKit's catalog), tile color from the mockup and an SF Symbol.
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
        make(
            .login, String(localized: "Connexions", bundle: DesignKitStrings.bundle),
            String(localized: "Connexion", bundle: DesignKitStrings.bundle), 0x0E9F9F, "person.crop.circle"),
        make(
            .password, String(localized: "Mots de passe", bundle: DesignKitStrings.bundle),
            String(localized: "Mot de passe", bundle: DesignKitStrings.bundle), 0x0F5E63, "key.fill"),
        make(
            .email, String(localized: "Comptes email", bundle: DesignKitStrings.bundle),
            String(localized: "Compte email", bundle: DesignKitStrings.bundle), 0xBE185D, "envelope.fill"),
        make(
            .server, String(localized: "Serveurs", bundle: DesignKitStrings.bundle),
            String(localized: "Serveur", bundle: DesignKitStrings.bundle), 0x5B6472, "server.rack"),
        make(
            .database, String(localized: "Bases de données", bundle: DesignKitStrings.bundle),
            String(localized: "Base de données", bundle: DesignKitStrings.bundle), 0x5B6472, "cylinder.split.1x2.fill"),
        make(
            .router, String(localized: "Routeurs Wi-Fi", bundle: DesignKitStrings.bundle),
            String(localized: "Routeur Wi-Fi", bundle: DesignKitStrings.bundle), 0x0F766E, "wifi.router.fill"),
        make(
            .apiCredential, String(localized: "Identifiants API", bundle: DesignKitStrings.bundle),
            String(localized: "Identifiant d'API", bundle: DesignKitStrings.bundle), 0x0891B2, "curlybraces"),
        make(
            .sshKey, String(localized: "Clés SSH", bundle: DesignKitStrings.bundle),
            String(localized: "Clé SSH", bundle: DesignKitStrings.bundle), 0x475569, "terminal.fill"),
        make(
            .creditCard, String(localized: "Cartes bancaires", bundle: DesignKitStrings.bundle),
            String(localized: "Carte bancaire", bundle: DesignKitStrings.bundle), 0x2F80ED, "creditcard.fill"),
        make(
            .bankAccount, String(localized: "Comptes bancaires", bundle: DesignKitStrings.bundle),
            String(localized: "Compte bancaire", bundle: DesignKitStrings.bundle), 0xE08A00, "building.columns.fill"),
        make(
            .cryptoWallet, String(localized: "Portefeuilles crypto", bundle: DesignKitStrings.bundle),
            String(localized: "Portefeuille crypto", bundle: DesignKitStrings.bundle), 0x2563EB, "bitcoinsign.circle.fill"),
        make(
            .subscription, String(localized: "Abonnements", bundle: DesignKitStrings.bundle),
            String(localized: "Abonnement", bundle: DesignKitStrings.bundle), 0x9333EA, "arrow.triangle.2.circlepath"),
        make(
            .identity, String(localized: "Identités", bundle: DesignKitStrings.bundle),
            String(localized: "Identité", bundle: DesignKitStrings.bundle), 0x22A06B, "person.text.rectangle.fill"),
        make(
            .idCard, String(localized: "Cartes d'identité", bundle: DesignKitStrings.bundle),
            String(localized: "Carte d'identité", bundle: DesignKitStrings.bundle), 0x15803D, "person.crop.rectangle.fill"),
        make(
            .passport, String(localized: "Passeports", bundle: DesignKitStrings.bundle),
            String(localized: "Passeport", bundle: DesignKitStrings.bundle), 0x1D4ED8, "airplane"),
        make(
            .driverLicense, String(localized: "Permis de conduire", bundle: DesignKitStrings.bundle),
            String(localized: "Permis de conduire", bundle: DesignKitStrings.bundle), 0xE11D48, "car.fill"),
        make(
            .socialSecurityNumber, String(localized: "Numéros de sécu", bundle: DesignKitStrings.bundle),
            String(localized: "Numéro de sécurité sociale", bundle: DesignKitStrings.bundle), 0x1E40AF, "number"),
        make(
            .medicalRecord, String(localized: "Dossiers médicaux", bundle: DesignKitStrings.bundle),
            String(localized: "Dossier médical", bundle: DesignKitStrings.bundle), 0xDC2626, "cross.case.fill"),
        make(
            .membership, String(localized: "Cartes de membre", bundle: DesignKitStrings.bundle),
            String(localized: "Adhésion", bundle: DesignKitStrings.bundle), 0x7C3AED, "person.2.fill"),
        make(
            .rewardProgram, String(localized: "Programmes de fidélité", bundle: DesignKitStrings.bundle),
            String(localized: "Programme de fidélité", bundle: DesignKitStrings.bundle), 0xDB2777, "gift.fill"),
        make(
            .insurance, String(localized: "Assurances", bundle: DesignKitStrings.bundle),
            String(localized: "Assurance", bundle: DesignKitStrings.bundle), 0x0D9488, "shield.fill"),
        make(
            .vehicle, String(localized: "Véhicules", bundle: DesignKitStrings.bundle),
            String(localized: "Véhicule", bundle: DesignKitStrings.bundle), 0x475569, "box.truck.fill"),
        make(
            .accessCode, String(localized: "Digicodes", bundle: DesignKitStrings.bundle),
            String(localized: "Code d'accès", bundle: DesignKitStrings.bundle), 0x4338CA, "lock.rectangle.fill"),
        make(
            .secureNote, String(localized: "Notes sécurisées", bundle: DesignKitStrings.bundle),
            String(localized: "Note sécurisée", bundle: DesignKitStrings.bundle), 0xD99A1E, "note.text"),
        make(
            .document, String(localized: "Documents", bundle: DesignKitStrings.bundle),
            String(localized: "Document", bundle: DesignKitStrings.bundle), 0x3478F6, "doc.fill"),
        make(
            .softwareLicense, String(localized: "Licences logicielles", bundle: DesignKitStrings.bundle),
            String(localized: "Licence logicielle", bundle: DesignKitStrings.bundle), 0x2563EB, "app.badge.checkmark.fill"),
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
