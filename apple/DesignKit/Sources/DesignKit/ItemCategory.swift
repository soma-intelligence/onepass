import SwiftUI
import OnePassCore

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
            .login, String(localized: "itemCategory.logins", bundle: DesignKitStrings.bundle),
            String(localized: "itemCategory.login", bundle: DesignKitStrings.bundle), 0x0E9F9F, "person.crop.circle"),
        make(
            .password, String(localized: "itemCategory.passwords", bundle: DesignKitStrings.bundle),
            String(localized: "Mot de passe", bundle: DesignKitStrings.bundle), 0x0F5E63, "key.fill"),
        make(
            .email, String(localized: "itemCategory.emailAccounts", bundle: DesignKitStrings.bundle),
            String(localized: "itemCategory.emailAccount", bundle: DesignKitStrings.bundle), 0xBE185D, "envelope.fill"),
        make(
            .server, String(localized: "itemCategory.servers", bundle: DesignKitStrings.bundle),
            String(localized: "itemCategory.server", bundle: DesignKitStrings.bundle), 0x5B6472, "server.rack"),
        make(
            .database, String(localized: "itemCategory.databases", bundle: DesignKitStrings.bundle),
            String(localized: "itemCategory.database", bundle: DesignKitStrings.bundle), 0x5B6472, "cylinder.split.1x2.fill"),
        make(
            .router, String(localized: "itemCategory.wiFiRouters", bundle: DesignKitStrings.bundle),
            String(localized: "itemCategory.wiFiRouter", bundle: DesignKitStrings.bundle), 0x0F766E, "wifi.router.fill"),
        make(
            .apiCredential, String(localized: "itemCategory.apiCredentials", bundle: DesignKitStrings.bundle),
            String(localized: "itemCategory.apiCredential", bundle: DesignKitStrings.bundle), 0x0891B2, "curlybraces"),
        make(
            .sshKey, String(localized: "itemCategory.sshKeys", bundle: DesignKitStrings.bundle),
            String(localized: "itemCategory.sshKey", bundle: DesignKitStrings.bundle), 0x475569, "terminal.fill"),
        make(
            .creditCard, String(localized: "itemCategory.creditCards", bundle: DesignKitStrings.bundle),
            String(localized: "designKit.creditCard", bundle: DesignKitStrings.bundle), 0x2F80ED, "creditcard.fill"),
        make(
            .bankAccount, String(localized: "itemCategory.bankAccounts", bundle: DesignKitStrings.bundle),
            String(localized: "itemCategory.bankAccount", bundle: DesignKitStrings.bundle), 0xE08A00, "building.columns.fill"),
        make(
            .cryptoWallet, String(localized: "itemCategory.cryptoWallets", bundle: DesignKitStrings.bundle),
            String(localized: "itemCategory.cryptoWallet", bundle: DesignKitStrings.bundle), 0x2563EB, "bitcoinsign.circle.fill"),
        make(
            .subscription, String(localized: "itemCategory.subscriptions", bundle: DesignKitStrings.bundle),
            String(localized: "itemCategory.subscription", bundle: DesignKitStrings.bundle), 0x9333EA, "arrow.triangle.2.circlepath"),
        make(
            .identity, String(localized: "itemCategory.identities", bundle: DesignKitStrings.bundle),
            String(localized: "itemCategory.identity", bundle: DesignKitStrings.bundle), 0x22A06B, "person.text.rectangle.fill"),
        make(
            .idCard, String(localized: "itemCategory.idCards", bundle: DesignKitStrings.bundle),
            String(localized: "itemCategory.idCard", bundle: DesignKitStrings.bundle), 0x15803D, "person.crop.rectangle.fill"),
        make(
            .passport, String(localized: "itemCategory.passports", bundle: DesignKitStrings.bundle),
            String(localized: "itemCategory.passport", bundle: DesignKitStrings.bundle), 0x1D4ED8, "airplane"),
        make(
            .driverLicense, String(localized: "itemCategory.driversLicense", bundle: DesignKitStrings.bundle),
            String(localized: "itemCategory.driversLicense", bundle: DesignKitStrings.bundle), 0xE11D48, "car.fill"),
        make(
            .socialSecurityNumber, String(localized: "itemCategory.socialSecurityNumbers", bundle: DesignKitStrings.bundle),
            String(localized: "itemCategory.socialSecurityNumber", bundle: DesignKitStrings.bundle), 0x1E40AF, "number"),
        make(
            .medicalRecord, String(localized: "itemCategory.medicalRecords", bundle: DesignKitStrings.bundle),
            String(localized: "itemCategory.medicalRecord", bundle: DesignKitStrings.bundle), 0xDC2626, "cross.case.fill"),
        make(
            .membership, String(localized: "itemCategory.memberships", bundle: DesignKitStrings.bundle),
            String(localized: "itemCategory.membership", bundle: DesignKitStrings.bundle), 0x7C3AED, "person.2.fill"),
        make(
            .rewardProgram, String(localized: "itemCategory.rewardPrograms", bundle: DesignKitStrings.bundle),
            String(localized: "itemCategory.rewardProgram", bundle: DesignKitStrings.bundle), 0xDB2777, "gift.fill"),
        make(
            .insurance, String(localized: "itemCategory.insurance2", bundle: DesignKitStrings.bundle),
            String(localized: "itemCategory.insurance", bundle: DesignKitStrings.bundle), 0x0D9488, "shield.fill"),
        make(
            .vehicle, String(localized: "itemCategory.vehicles", bundle: DesignKitStrings.bundle),
            String(localized: "itemCategory.vehicle", bundle: DesignKitStrings.bundle), 0x475569, "box.truck.fill"),
        make(
            .accessCode, String(localized: "itemCategory.accessCodes", bundle: DesignKitStrings.bundle),
            String(localized: "itemCategory.accessCode", bundle: DesignKitStrings.bundle), 0x4338CA, "lock.rectangle.fill"),
        make(
            .secureNote, String(localized: "itemCategory.secureNotes", bundle: DesignKitStrings.bundle),
            String(localized: "itemCategory.secureNote", bundle: DesignKitStrings.bundle), 0xD99A1E, "note.text"),
        make(
            .document, String(localized: "itemCategory.documents", bundle: DesignKitStrings.bundle),
            String(localized: "itemCategory.document", bundle: DesignKitStrings.bundle), 0x3478F6, "doc.fill"),
        make(
            .softwareLicense, String(localized: "itemCategory.softwareLicenses", bundle: DesignKitStrings.bundle),
            String(localized: "itemCategory.softwareLicense", bundle: DesignKitStrings.bundle), 0x2563EB, "app.badge.checkmark.fill"),
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
