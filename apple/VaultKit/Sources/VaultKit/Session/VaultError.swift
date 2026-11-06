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
    /// The signed device list marks this device revoked: everything was erased from it.
    case deviceRevoked
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
            case .Store:
                self = .other(String(localized: "session.onepasssLocalStorageCant", bundle: VaultKitStrings.bundle))
            case .Crypto:
                self = .other(String(localized: "session.onepassCouldntEncryptOr", bundle: VaultKitStrings.bundle))
            case .PasskeyExcluded: self = .other(String(localized: "session.accountAlreadyHasOnepass", bundle: VaultKitStrings.bundle))
            // The remote unlock envelope no longer opens the account: unlock here.
            case .RemoteUnlockStale: self = .passwordRequired
            // Key rotation v2 (core spec 8.1, 8.4): the app has no screens for these yet.
            case .ReadOnly:
                self = .other(String(localized: "Lecture seule jusqu'à ta réponse à la rotation des clés.", bundle: VaultKitStrings.bundle))
            case .OutdatedKit:
                self = .other(String(localized: "Ce kit de secours date d'avant un changement des clés du compte.", bundle: VaultKitStrings.bundle))
            case .RotationPending:
                self = .other(String(localized: "Une rotation des clés est en cours.", bundle: VaultKitStrings.bundle))
            case .Quarantined:
                self = .deviceRevoked
            case .Orphaned:
                self = .other(String(localized: "Cet appareil ne figure pas dans les clés du compte.", bundle: VaultKitStrings.bundle))
            case .IdentityLeft:
                self = .passwordRequired
            // The mailbox (spec 4.6, 4.13): the sync status carries the details.
            case .ClockSkew:
                self = .other(MailboxSyncCoordinator.clockSkewMessage)
            case .MailboxUnavailable:
                self = .other(MailboxSyncCoordinator.retryingMessage)
            case .Forbidden:
                self = .other(String(localized: "sync.mailbox.forbidden", bundle: VaultKitStrings.bundle))
            // Sharing (sharing spec 7, 9, 12): refusals the screens tell apart.
            case .ReadOnlyRole:
                self = .other(String(localized: "sharing.error.readOnlyRole", bundle: VaultKitStrings.bundle))
            case .ContactNotVerified:
                self = .other(String(localized: "sharing.error.contactNotVerified", bundle: VaultKitStrings.bundle))
            case .MembershipFork:
                self = .integrity(kind: "membership_fork")
            case .IdentityPending:
                self = .other(String(localized: "sharing.error.identityPending", bundle: VaultKitStrings.bundle))
            }
        case let error as BiometricError:
            switch error {
            case .unavailable: self = .biometricsUnavailable
            case .passwordRequired, .cancelled, .failed: self = .passwordRequired
            }
        case let error as KeychainError:
            self = .other(error.message)
        case let error as EnclaveError:
            switch error {
            case .unavailable, .biometryNotEnrolled: self = .biometricsUnavailable
            case .userFallback, .authenticationFailed: self = .passwordRequired
            case .cancelled, .interrupted: self = .other(ErrorText.cancelled(VaultKitStrings.bundle))
            case .biometryLockout: self = .other(PasswordReason.lockedOut.message)
            case .keyInvalidated: self = .other(PasswordReason.invalidated.message)
            case .failed(let code): self = .other(ErrorText.keychain(code).text)
            }
        default:
            // A system error (file, keychain, network...) in words, never its bare code.
            self = .other(ErrorText.describe(error)?.text ?? Self.unexpectedMessage)
        }
    }

    /// The message of an error nothing else words.
    static var unexpectedMessage: String {
        String(localized: "session.somethingUnexpectedWentWrong", bundle: VaultKitStrings.bundle)
    }

    /// French message for the UI (core validation reasons translated).
    public var localizedMessage: String {
        switch self {
        case .wrongPassword:
            String(localized: "session.incorrectPassword", bundle: VaultKitStrings.bundle)
        case .lockedOut(let until):
            String(localized: "session.tooManyAttemptsTry \(until.formatted(date: .omitted, time: .standard))", bundle: VaultKitStrings.bundle)
        case .integrity(let kind):
            String(localized: "vaultKit.dataRefused \(Self.integrityLabel(kind))", bundle: VaultKitStrings.bundle)
        case .validation(_, let reason):
            Self.validationMessage(reason)
        case .accountExists:
            String(localized: "vaultKit.onepassAccountAlreadyExists", bundle: VaultKitStrings.bundle)
        case .notFound:
            String(localized: "session.itemNotFound", bundle: VaultKitStrings.bundle)
        case .conflict:
            String(localized: "session.itemChangedInMeantime", bundle: VaultKitStrings.bundle)
        case .biometricsUnavailable:
            String(localized: "session.biometricsArentAvailableOn", bundle: VaultKitStrings.bundle)
        case .passwordRequired:
            String(localized: "vaultKit.enterMasterPassword", bundle: VaultKitStrings.bundle)
        case .deviceRevoked:
            String(localized: "session.deviceWasRemovedFrom", bundle: VaultKitStrings.bundle)
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
            ? String(localized: "session.secretKeyDoesntMatch", bundle: VaultKitStrings.bundle)
            : localizedMessage
    }

    /// French text for a core validation reason (English, fixed strings).
    public static func validationMessage(_ reason: String) -> String {
        switch reason {
        case secretKeyFormat: String(localized: "session.incorrectSecretKeyFormat", bundle: VaultKitStrings.bundle)
        case secretKeyChecksum:
            String(localized: "session.secretKeyHasTypo", bundle: VaultKitStrings.bundle)
        case "is required": String(localized: "session.requiredField", bundle: VaultKitStrings.bundle)
        case "is not a valid card number": String(localized: "session.invalidCardNumber", bundle: VaultKitStrings.bundle)
        case "is not a valid IBAN": String(localized: "session.invalidIban", bundle: VaultKitStrings.bundle)
        case "is not a valid recovery phrase": String(localized: "session.invalidRecoveryPhrase", bundle: VaultKitStrings.bundle)
        case "is not a valid national number": String(localized: "session.invalidNumber", bundle: VaultKitStrings.bundle)
        case "must not be empty": String(localized: "session.cantEmpty", bundle: VaultKitStrings.bundle)
        case "too weak": String(localized: "session.tooEasyToGuess", bundle: VaultKitStrings.bundle)
        case "this device": String(localized: "session.deviceCannotRemoveItself", bundle: VaultKitStrings.bundle)
        default: String(localized: "session.invalidValue", bundle: VaultKitStrings.bundle)
        }
    }

    /// French text for a core `InvalidInput { what }` (never a value, only what was refused).
    public static func invalidInputMessage(_ what: String) -> String {
        switch what {
        case "passkey": String(localized: "session.unknownPasskey", bundle: VaultKitStrings.bundle)
        case "date", "month", "timestamp": String(localized: "session.invalidDate", bundle: VaultKitStrings.bundle)
        case "recipe": String(localized: "session.invalidGeneratorSettings", bundle: VaultKitStrings.bundle)
        case "passphrase": String(localized: "session.unreadablePassphrase", bundle: VaultKitStrings.bundle)
        case "last vault": String(localized: "session.lastVaultCannotDeleted", bundle: VaultKitStrings.bundle)
        case "vault not empty": String(localized: "session.emptyVaultBeforeDeleting", bundle: VaultKitStrings.bundle)
        case "account not synced": String(localized: "vaultKit.syncDeviceFirst", bundle: VaultKitStrings.bundle)
        case "pairing snapshot too large":
            String(localized: "vaultKit.accountTooLargeTo", bundle: VaultKitStrings.bundle)
        default: developerMessage(what) ?? importMessage(what) ?? String(localized: "session.invalidValue2", bundle: VaultKitStrings.bundle)
        }
    }

    /// French text for a refusal of Travel Mode, the SSH agent or the MCP server (milestone 7). `nil`
    /// when `what` is none of them.
    public static func developerMessage(_ what: String) -> String? {
        if what.hasPrefix("SSH key: ") {
            let reason = what.dropFirst("SSH key: ".count)
            if reason == "wrong passphrase" {
                return String(localized: "session.wrongPassphrase", bundle: VaultKitStrings.bundle)
            }
            if reason.hasPrefix("the key is encrypted") {
                return String(localized: "session.keyEncryptedEnterPassphrase", bundle: VaultKitStrings.bundle)
            }
            if reason.hasPrefix("unsupported") {
                return String(localized: "session.sshKeyTypeNot", bundle: VaultKitStrings.bundle)
            }
            return String(localized: "session.unreadableSshKey", bundle: VaultKitStrings.bundle)
        }
        switch what {
        case "unsynced changes":
            return String(localized: "session.someChangesToThese", bundle: VaultKitStrings.bundle)
        case "upstream does not hold the vault":
            return String(localized: "session.icloudDoesNotHold", bundle: VaultKitStrings.bundle)
        case "no vault leaves", "nothing leaves":
            return String(localized: "travel.error.nothingLeaves", bundle: VaultKitStrings.bundle)
        case "travel mode already on":
            return String(localized: "session.travelModeAlreadyOn", bundle: VaultKitStrings.bundle)
        case "travel mode off":
            return String(localized: "session.travelModeNotOn", bundle: VaultKitStrings.bundle)
        case "another agent is serving this socket":
            return String(localized: "session.anotherSshAgentAlready", bundle: VaultKitStrings.bundle)
        case "socket path too long":
            return String(localized: "session.socketPathTooLong", bundle: VaultKitStrings.bundle)
        case "cannot listen on the agent socket", "cannot listen on the MCP socket":
            return String(localized: "session.socketCouldNotOpened", bundle: VaultKitStrings.bundle)
        case "program identity":
            return String(localized: "session.signatureOfProgramCould", bundle: VaultKitStrings.bundle)
        case "scope":
            return String(localized: "session.unknownPermission", bundle: VaultKitStrings.bundle)
        case "host bookmark":
            return String(localized: "session.hostOneWordWithout", bundle: VaultKitStrings.bundle)
        case "key comment":
            return String(localized: "session.keyCommentMustNot", bundle: VaultKitStrings.bundle)
        default:
            return nil
        }
    }

    /// French text for the refusal of an import file (core `import` reasons, English and fixed).
    /// `nil` when `what` is not an import reason.
    public static func importMessage(_ what: String) -> String? {
        let lower = what.lowercased()
        if lower.hasPrefix("encrypted bitwarden") {
            return String(localized: "session.bitwardenExportEncryptedExport", bundle: VaultKitStrings.bundle)
        }
        if lower.hasPrefix("encrypted dashlane") {
            return String(localized: "session.dashlaneExportEncryptedExport", bundle: VaultKitStrings.bundle)
        }
        if lower.hasPrefix("keepass kdbx") {
            return String(localized: "session.keepassDatabasesKdbxCant", bundle: VaultKitStrings.bundle)
        }
        if lower.hasPrefix("onepass archive") {
            return String(localized: "session.encryptedOnepassArchiveIt", bundle: VaultKitStrings.bundle)
        }
        if lower == "import format" { return String(localized: "session.unknownImportFormat", bundle: VaultKitStrings.bundle) }
        if lower == "import file too large" || lower.hasPrefix("too many") || lower.hasSuffix("too large") {
            return String(localized: "session.fileTooLargeTo", bundle: VaultKitStrings.bundle)
        }
        let markers = ["csv", "json", "xml", "zip", "1pux", "utf-8", "otpauth", "wifi qr", "keepass", "dashlane"]
        if markers.contains(where: lower.contains) {
            return String(localized: "session.fileDoesntMatchChosen", bundle: VaultKitStrings.bundle)
        }
        return nil
    }

    /// Plain French description of a detected attack (core `Integrity { kind }`).
    public static func integrityLabel(_ kind: String) -> String {
        switch kind {
        case "account_missing": String(localized: "session.accountDisappearedFromStorage", bundle: VaultKitStrings.bundle)
        case "vault_missing": String(localized: "integrity.vaultMissing", bundle: VaultKitStrings.bundle)
        case "manifest_rollback": String(localized: "session.oldVersionWasReplayed", bundle: VaultKitStrings.bundle)
        case "manifest_missing_item": String(localized: "session.itemWasHeldBack", bundle: VaultKitStrings.bundle)
        case "manifest_unexpected_item": String(localized: "session.unknownItemWasAdded", bundle: VaultKitStrings.bundle)
        case "manifest_item_mismatch": String(localized: "integrity.manifestItemMismatch", bundle: VaultKitStrings.bundle)
        case "commitment", "aead": String(localized: "session.encryptedDataWasModified", bundle: VaultKitStrings.bundle)
        case "signature", "params_unsigned": String(localized: "session.signatureInvalid", bundle: VaultKitStrings.bundle)
        case "params_downgrade": String(localized: "session.accountsSecuritySettingsWere", bundle: VaultKitStrings.bundle)
        case "wrong_kind", "wrong_context": String(localized: "session.recordWasMovedOr", bundle: VaultKitStrings.bundle)
        case "epoch_rollback": String(localized: "session.oldRestoreOfVault", bundle: VaultKitStrings.bundle)
        case "membership_fork": String(localized: "sharing.error.membershipFork", bundle: VaultKitStrings.bundle)
        default: String(localized: "session.storageDoesntMatchWhat", bundle: VaultKitStrings.bundle)
        }
    }
}
