import Foundation

/// Errors shown by the apps. Never carries a field value or a secret.
public enum VaultError: Error, Equatable, Sendable {
    case wrongPassword
    case lockedOut(until: Date)
    case integrity(kind: String)
    case validation(field: String, reason: String)
    case accountExists
    case notFound
    case conflict
    case biometricsUnavailable
    case passwordRequired
    case other(String)

    /// Maps a core, biometric or keychain error. Anything else becomes `.other` with a generic message.
    public init(_ error: any Error) {
        switch error {
        case let error as VaultError:
            self = error
        case let error as OnePassError:
            switch error {
            case .WrongPassword: self = .wrongPassword
            case .NotFound: self = .notFound
            case .Conflict: self = .conflict
            case .Locked: self = .passwordRequired
            case .Validation(let field, let reason): self = .validation(field: field, reason: reason)
            case .Integrity(let kind): self = .integrity(kind: kind)
            case .InvalidInput(let what):
                self = what == "account exists" ? .accountExists : .other(Self.invalidInputMessage(what))
            case .Store: self = .other(String(localized: "Le stockage local est illisible.", bundle: VaultKitStrings.bundle))
            case .Crypto: self = .other(String(localized: "Erreur de chiffrement.", bundle: VaultKitStrings.bundle))
            case .PasskeyExcluded: self = .other(String(localized: "Ce compte a déjà une passkey OnePass pour ce site.", bundle: VaultKitStrings.bundle))
            }
        case let error as BiometricError:
            switch error {
            case .unavailable: self = .biometricsUnavailable
            case .passwordRequired, .cancelled, .failed: self = .passwordRequired
            }
        case let error as KeychainError:
            self = .other(error.message)
        default:
            self = .other(String(localized: "Une erreur inattendue est survenue.", bundle: VaultKitStrings.bundle))
        }
    }

    /// French message for the UI (core validation reasons translated).
    public var localizedMessage: String {
        switch self {
        case .wrongPassword:
            String(localized: "Mot de passe incorrect.", bundle: VaultKitStrings.bundle)
        case .lockedOut(let until):
            String(localized: "Trop d'essais. Réessaie après \(until.formatted(date: .omitted, time: .standard)).", bundle: VaultKitStrings.bundle)
        case .integrity(let kind):
            String(localized: "Données refusées : \(Self.integrityLabel(kind))", bundle: VaultKitStrings.bundle)
        case .validation(_, let reason):
            Self.validationMessage(reason)
        case .accountExists:
            String(localized: "Un compte OnePass existe déjà sur cet appareil.", bundle: VaultKitStrings.bundle)
        case .notFound:
            String(localized: "Élément introuvable.", bundle: VaultKitStrings.bundle)
        case .conflict:
            String(localized: "L'élément a changé entre-temps. Réessaie.", bundle: VaultKitStrings.bundle)
        case .biometricsUnavailable:
            String(localized: "La biométrie n'est pas disponible sur cet appareil.", bundle: VaultKitStrings.bundle)
        case .passwordRequired:
            String(localized: "Saisis ton mot de passe maître.", bundle: VaultKitStrings.bundle)
        case .other(let message):
            message
        }
    }

    /// Validation reasons of a typed Secret Key (`VaultSession.restore`).
    public static let secretKeyFormat = "secret key format"
    public static let secretKeyChecksum = "secret key checksum"

    /// The message of a failed Emergency Kit restore: a wrong password there may as well be a well
    /// formed Secret Key of another account (the core cannot tell them apart).
    public var restoreMessage: String {
        self == .wrongPassword
            ? String(localized: "Cette Secret Key ne correspond pas à ce compte, ou le mot de passe est faux.", bundle: VaultKitStrings.bundle)
            : localizedMessage
    }

    /// French text for a core validation reason (English, fixed strings).
    public static func validationMessage(_ reason: String) -> String {
        switch reason {
        case secretKeyFormat: String(localized: "Format de Secret Key incorrect : 53 caractères attendus (lettres et chiffres).", bundle: VaultKitStrings.bundle)
        case secretKeyChecksum:
            String(localized: "Cette Secret Key contient une faute de frappe : vérifie chaque caractère sur ton Emergency Kit.", bundle: VaultKitStrings.bundle)
        case "is required": String(localized: "Champ obligatoire", bundle: VaultKitStrings.bundle)
        case "is not a valid card number": String(localized: "Numéro de carte invalide", bundle: VaultKitStrings.bundle)
        case "is not a valid IBAN": String(localized: "IBAN invalide", bundle: VaultKitStrings.bundle)
        case "is not a valid recovery phrase": String(localized: "Phrase de récupération invalide", bundle: VaultKitStrings.bundle)
        case "is not a valid national number": String(localized: "Numéro invalide", bundle: VaultKitStrings.bundle)
        case "must not be empty": String(localized: "Ne peut pas être vide", bundle: VaultKitStrings.bundle)
        case "too weak": String(localized: "Trop facile à deviner : allonge-la ou ajoute des mots.", bundle: VaultKitStrings.bundle)
        default: String(localized: "Valeur invalide", bundle: VaultKitStrings.bundle)
        }
    }

    /// French text for a core `InvalidInput { what }` (never a value, only what was refused).
    public static func invalidInputMessage(_ what: String) -> String {
        switch what {
        case "passkey": String(localized: "Clé d'accès inconnue.", bundle: VaultKitStrings.bundle)
        case "date", "month", "timestamp": String(localized: "Date invalide.", bundle: VaultKitStrings.bundle)
        case "recipe": String(localized: "Réglages du générateur invalides.", bundle: VaultKitStrings.bundle)
        case "passphrase": String(localized: "Phrase de passe illisible.", bundle: VaultKitStrings.bundle)
        default: importMessage(what) ?? String(localized: "Valeur invalide.", bundle: VaultKitStrings.bundle)
        }
    }

    /// French text for the refusal of an import file (core `import` reasons, English and fixed).
    /// `nil` when `what` is not an import reason.
    public static func importMessage(_ what: String) -> String? {
        let lower = what.lowercased()
        if lower.hasPrefix("encrypted bitwarden") {
            return String(localized: "Cet export Bitwarden est chiffré. Refais l'export en JSON non chiffré (ou en CSV), puis réessaie.", bundle: VaultKitStrings.bundle)
        }
        if lower.hasPrefix("encrypted dashlane") {
            return String(localized: "Cet export Dashlane est chiffré. Refais l'export en CSV, puis réessaie.", bundle: VaultKitStrings.bundle)
        }
        if lower.hasPrefix("keepass kdbx") {
            return String(localized: "Les bases KeePass (.kdbx) ne se lisent pas directement. Exporte-la en XML KeePass 2, puis réessaie.", bundle: VaultKitStrings.bundle)
        }
        if lower.hasPrefix("onepass archive") {
            return String(localized: "C'est une archive OnePass chiffrée : elle ne s'importe pas ici.", bundle: VaultKitStrings.bundle)
        }
        if lower == "import format" { return String(localized: "Format d'import inconnu.", bundle: VaultKitStrings.bundle) }
        if lower == "import file too large" || lower.hasPrefix("too many") || lower.hasSuffix("too large") {
            return String(localized: "Ce fichier est trop gros pour être importé.", bundle: VaultKitStrings.bundle)
        }
        let markers = ["csv", "json", "xml", "zip", "1pux", "utf-8", "otpauth", "wifi qr", "keepass", "dashlane"]
        if markers.contains(where: lower.contains) {
            return String(localized: "Ce fichier ne correspond pas au format choisi, ou il est abîmé.", bundle: VaultKitStrings.bundle)
        }
        return nil
    }

    /// Plain French description of a detected attack (core `Integrity { kind }`).
    public static func integrityLabel(_ kind: String) -> String {
        switch kind {
        case "account_missing": String(localized: "Le compte a disparu du stockage.", bundle: VaultKitStrings.bundle)
        case "vault_missing": String(localized: "Un vault a disparu du stockage.", bundle: VaultKitStrings.bundle)
        case "manifest_rollback": String(localized: "Ancienne version rejouée.", bundle: VaultKitStrings.bundle)
        case "manifest_missing_item": String(localized: "Un élément a été retenu ou supprimé du stockage.", bundle: VaultKitStrings.bundle)
        case "manifest_unexpected_item": String(localized: "Un élément inconnu a été ajouté au stockage.", bundle: VaultKitStrings.bundle)
        case "manifest_item_mismatch": String(localized: "Un élément ne correspond pas à la liste signée du vault.", bundle: VaultKitStrings.bundle)
        case "commitment", "aead": String(localized: "Des données chiffrées ont été modifiées.", bundle: VaultKitStrings.bundle)
        case "signature", "params_unsigned": String(localized: "Une signature est invalide.", bundle: VaultKitStrings.bundle)
        case "params_downgrade": String(localized: "Les paramètres de sécurité du compte ont été affaiblis.", bundle: VaultKitStrings.bundle)
        case "wrong_kind", "wrong_context": String(localized: "Un enregistrement a été déplacé ou substitué.", bundle: VaultKitStrings.bundle)
        case "epoch_rollback": String(localized: "Une ancienne restauration du coffre a été rejouée.", bundle: VaultKitStrings.bundle)
        default: String(localized: "Le stockage ne correspond pas à ce qui était attendu.", bundle: VaultKitStrings.bundle)
        }
    }
}
