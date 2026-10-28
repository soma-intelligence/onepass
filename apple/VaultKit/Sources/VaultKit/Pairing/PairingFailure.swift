import Foundation

/// Why a pairing stopped (spec 2b section 8). Messages carry nothing secret.
public enum PairingFailure: Error, Equatable, Sendable {
    /// The QR expired before the approver scanned it.
    case expired
    /// The user said the codes differ: nothing was sent.
    case codeRejected
    /// The other device could not be reached on the local network.
    case notFound
    /// The connection closed before the pairing finished.
    case connectionLost
    /// The other device cancelled.
    case cancelledByPeer
    /// The account does not fit in a pairing snapshot.
    case snapshotTooLarge
    /// The approver syncs but its account is not on the server yet (ruling A10).
    case notSynced
    /// This device already holds an account.
    case accountExists
    /// A frame or a QR the core refused (tampered, replayed, foreign).
    case refused
    /// Approved here, but the new device did not confirm in time (L5).
    case peerTimedOut
    /// Too many wrong master passwords on the new device: the received account was dropped (M3).
    case tooManyAttempts
    /// The received account waited too long for the master password and was dropped (M3).
    case grantExpired
    /// Any other error, already in French.
    case other(String)

    public var message: String {
        switch self {
        case .expired:
            String(localized: "Le code a expiré. Un nouveau s'affiche.", bundle: VaultKitStrings.bundle)
        case .codeRejected:
            String(localized: "Appairage annulé. Rien n'a été envoyé.", bundle: VaultKitStrings.bundle)
        case .notFound:
            String(
                localized: "Rapproche les deux appareils et vérifie qu'ils sont sur le même Wi-Fi.",
                bundle: VaultKitStrings.bundle)
        case .connectionLost:
            String(localized: "La connexion avec l'autre appareil a été coupée.", bundle: VaultKitStrings.bundle)
        case .cancelledByPeer:
            String(localized: "L'autre appareil a annulé l'appairage.", bundle: VaultKitStrings.bundle)
        case .snapshotTooLarge:
            String(localized: "Ce compte est trop gros pour être copié par appairage.", bundle: VaultKitStrings.bundle)
        case .notSynced:
            String(localized: "Synchronise d'abord cet appareil.", bundle: VaultKitStrings.bundle)
        case .accountExists:
            String(localized: "Un compte OnePass existe déjà sur cet appareil.", bundle: VaultKitStrings.bundle)
        case .refused:
            String(
                localized: "L'appairage a été refusé. Recommence depuis le début.", bundle: VaultKitStrings.bundle)
        case .peerTimedOut:
            String(
                localized: "Le nouvel appareil n'a pas confirmé à temps. Recommence l'appairage.",
                bundle: VaultKitStrings.bundle)
        case .tooManyAttempts:
            String(
                localized: "Trop d'essais. Le compte reçu a été effacé de cet appareil : recommence l'appairage.",
                bundle: VaultKitStrings.bundle)
        case .grantExpired:
            String(
                localized: "Le délai est dépassé. Le compte reçu a été effacé de cet appareil : recommence l'appairage.",
                bundle: VaultKitStrings.bundle)
        case .other(let message):
            message
        }
    }

    /// Maps a transport, core or session error.
    init(_ error: any Error) {
        switch error {
        case let failure as PairingFailure:
            self = failure
        case let error as PairingTransportError:
            switch error {
            case .notFound: self = .notFound
            case .closed, .frameTooLarge: self = .connectionLost
            }
        case OnePassError.Validation(let field, let reason) where field == "pairing" && reason == "qr expired":
            self = .expired
        case OnePassError.InvalidInput(let what) where what == "account not synced":
            self = .notSynced
        case OnePassError.InvalidInput(let what) where what == "pairing snapshot too large":
            self = .snapshotTooLarge
        case OnePassError.InvalidInput(let what) where what == "store not empty":
            self = .accountExists
        case let error as OnePassError:
            switch error {
            case .Integrity, .Crypto, .Validation: self = .refused
            case .InvalidInput(let what) where what.lowercased().contains("pairing"): self = .refused
            default: self = .other(VaultError(error).localizedMessage)
            }
        default:
            self = .other(VaultError(error).localizedMessage)
        }
    }
}
