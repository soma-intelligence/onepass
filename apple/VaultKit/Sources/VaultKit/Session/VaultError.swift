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
            case .InvalidInput(let what): self = .other("Donnée invalide (\(what)).")
            case .Store: self = .other("Le stockage local est illisible.")
            case .Crypto: self = .other("Erreur de chiffrement.")
            }
        case let error as BiometricError:
            switch error {
            case .unavailable: self = .biometricsUnavailable
            case .passwordRequired, .cancelled, .failed: self = .passwordRequired
            }
        case let error as KeychainError:
            self = .other(error.message)
        default:
            self = .other("Une erreur inattendue est survenue.")
        }
    }

    /// French message for the UI.
    public var message: String {
        switch self {
        case .wrongPassword:
            "Mot de passe incorrect."
        case .lockedOut(let until):
            "Trop d'essais. Réessayez après \(until.formatted(date: .omitted, time: .standard))."
        case .integrity(let kind):
            "Données refusées : \(Self.integrityLabel(kind))"
        case .validation(_, let reason):
            reason
        case .accountExists:
            "Un compte OnePass existe déjà sur cet appareil."
        case .notFound:
            "Élément introuvable."
        case .conflict:
            "L'élément a changé entre-temps. Réessaie."
        case .biometricsUnavailable:
            "La biométrie n'est pas disponible sur cet appareil."
        case .passwordRequired:
            "Saisissez le mot de passe maître."
        case .other(let message):
            message
        }
    }

    /// Plain French description of a detected attack (core `Integrity { kind }`).
    public static func integrityLabel(_ kind: String) -> String {
        switch kind {
        case "vault_missing": "Un vault a disparu du stockage."
        case "manifest_rollback": "Ancienne version rejouée."
        case "manifest_missing_item": "Un élément a été retenu ou supprimé du stockage."
        case "manifest_unexpected_item": "Un élément inconnu a été ajouté au stockage."
        case "manifest_item_mismatch": "Un élément ne correspond pas à la liste signée du vault."
        case "commitment", "aead": "Des données chiffrées ont été modifiées."
        case "signature", "params_unsigned": "Une signature est invalide."
        case "params_downgrade": "Les paramètres de sécurité du compte ont été affaiblis."
        case "wrong_kind", "wrong_context": "Un enregistrement a été déplacé ou substitué."
        default: "Le stockage ne correspond pas à ce qui était attendu."
        }
    }
}
