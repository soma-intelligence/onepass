import CloudKit
import Foundation
import Security
import Testing

@testable import VaultKit

/// Every system error the apps can show is a sentence in French and in English, with the raw code
/// only as the "(code N)" note after it, never as the message.
@Suite("Readable error text")
struct ErrorTextTests {
    private static func lproj(_ language: String) -> Bundle? {
        Bundle.module.path(forResource: language, ofType: "lproj").flatMap(Bundle.init(path:))
    }

    /// The code as it could leak into a sentence: plain, without its sign, or grouped ("34,018", "34 018").
    private static func spellings(_ code: Int) -> [String] {
        let digits = String(abs(code))
        var forms = [String(code), digits]
        if digits.count > 3 {
            let head = digits.dropLast(3), tail = digits.suffix(3)
            forms += ["\(head),\(tail)", "\(head) \(tail)", "\(head)\u{202F}\(tail)", "\(head)\u{00A0}\(tail)"]
        }
        return forms
    }

    /// The sentence says something, holds no digit of the code, and the full text ends with the note.
    private static func checkReadable(_ text: ErrorText, code: Int, bundle: Bundle, _ label: String) {
        #expect(text.sentence.count > 20, "\(label): sentence too short: \(text.sentence)")
        #expect(text.sentence.hasSuffix("."), "\(label): not a sentence: \(text.sentence)")
        for spelling in spellings(code) where spelling.count > 1 {
            #expect(!text.sentence.contains(spelling), "\(label): the sentence shows the code: \(text.sentence)")
        }
        #expect(text.code == code)
        let full = text.text(bundle: bundle)
        #expect(full.hasPrefix(text.sentence))
        #expect(full.contains("(code \(code)"), "\(label): code note missing: \(full)")
    }

    static let keychainStatuses: [OSStatus] = [
        errSecMissingEntitlement, errSecItemNotFound, errSecDuplicateItem, errSecInteractionNotAllowed,
        errSecUserCanceled, errSecAuthFailed, errSecDecode, errSecNotAvailable, errSecNoAccessForItem,
        errSecInvalidOwnerEdit, errSecNoSuchKeychain, errSecInvalidKeychain, errSecParam, errSecDiskFull,
        errSecIO, errSecWrPerm,
        -67_000,  // unknown to the table: generic keychain sentence
    ]

    @Test(arguments: ["fr", "en"])
    func everyKeychainStatusIsASentence(language: String) throws {
        let bundle = try #require(Self.lproj(language))
        for status in Self.keychainStatuses {
            Self.checkReadable(ErrorText.keychain(status, bundle: bundle), code: Int(status), bundle: bundle, "\(language) \(status)")
        }
    }

    @Test func englishIsTranslated() throws {
        let fr = try #require(Self.lproj("fr")), en = try #require(Self.lproj("en"))
        for status in Self.keychainStatuses {
            #expect(ErrorText.keychain(status, bundle: fr).sentence != ErrorText.keychain(status, bundle: en).sentence, "\(status)")
        }
        for code in Self.cocoaCodes {
            #expect(ErrorText.cocoa(code, bundle: fr)?.sentence != ErrorText.cocoa(code, bundle: en)?.sentence, "cocoa \(code)")
        }
        for code in Self.cloudKitCodes {
            #expect(ErrorText.cloudKit(code, bundle: fr).sentence != ErrorText.cloudKit(code, bundle: en).sentence, "ck \(code)")
        }
    }

    @Test func missingEntitlementSaysToReinstall() throws {
        let fr = try #require(Self.lproj("fr")), en = try #require(Self.lproj("en"))
        let french = ErrorText.keychain(-34018, bundle: fr)
        #expect(french.sentence.contains("trousseau"))
        #expect(french.sentence.contains("Réinstalle OnePass"))
        #expect(french.text(bundle: fr).hasSuffix("(code -34018)"))
        let english = ErrorText.keychain(-34018, bundle: en)
        #expect(english.sentence.contains("Reinstall OnePass"))
        #expect(english.text(bundle: en).hasSuffix("(code -34018)"))
    }

    @Test func unknownKeychainStatusKeepsTheSystemDescriptionInTheNoteOnly() throws {
        let fr = try #require(Self.lproj("fr"))
        let text = ErrorText.keychain(-67_000, bundle: fr)
        #expect(text.sentence.hasPrefix("Le trousseau a refusé l'opération."))
        if let detail = text.systemDetail {
            #expect(!text.sentence.contains(detail))
            #expect(text.text(bundle: fr).hasSuffix("(code -67000 : \(detail))"))
        }
    }

    static let cocoaCodes: [Int] = [
        CocoaError.fileNoSuchFile.rawValue, CocoaError.fileReadNoSuchFile.rawValue, CocoaError.fileReadNoPermission.rawValue,
        CocoaError.fileWriteNoPermission.rawValue, CocoaError.fileWriteOutOfSpace.rawValue,
        CocoaError.fileWriteVolumeReadOnly.rawValue, CocoaError.fileWriteFileExists.rawValue,
        CocoaError.fileWriteInvalidFileName.rawValue, CocoaError.fileReadCorruptFile.rawValue,
        CocoaError.fileReadUnknownStringEncoding.rawValue, CocoaError.fileReadTooLarge.rawValue,
        CocoaError.fileLocking.rawValue, CocoaError.userCancelled.rawValue, CocoaError.fileReadUnknown.rawValue,
        CocoaError.fileWriteUnknown.rawValue,
    ]

    static let posixCodes: [Int32] = [ENOENT, ENOTDIR, ENOSPC, EDQUOT, EACCES, EPERM, EROFS, EEXIST, ENAMETOOLONG, EIO, EBUSY, ECANCELED, ETIMEDOUT]

    static let cloudKitCodes: [Int] = [1, 3, 5, 8, 9, 10, 15, 18, 20, 25, 32, 34, 36, 99]

    @Test(arguments: ["fr", "en"])
    func fileErrorsAreSentences(language: String) throws {
        let bundle = try #require(Self.lproj(language))
        // -43 (fnfErr) and the classic file manager codes, as NSOSStatusErrorDomain errors.
        for status in [-43, -120, -34, -36, -44, -48, -54, -61, -128, -5000] {
            let error = NSError(domain: NSOSStatusErrorDomain, code: status)
            let text = try #require(ErrorText.describe(error, bundle: bundle), "\(status)")
            Self.checkReadable(text, code: status, bundle: bundle, "\(language) OSStatus \(status)")
        }
        for code in Self.cocoaCodes {
            let text = try #require(ErrorText.describe(NSError(domain: NSCocoaErrorDomain, code: code), bundle: bundle), "\(code)")
            Self.checkReadable(text, code: code, bundle: bundle, "\(language) Cocoa \(code)")
        }
        for code in Self.posixCodes {
            let text = try #require(ErrorText.describe(POSIXError(POSIXErrorCode(rawValue: code)!), bundle: bundle), "\(code)")
            Self.checkReadable(text, code: Int(code), bundle: bundle, "\(language) POSIX \(code)")
        }
    }

    @Test func fileNotFoundReadsTheSameWhateverTheDomain() throws {
        let fr = try #require(Self.lproj("fr"))
        let fnf = try #require(ErrorText.describe(NSError(domain: NSOSStatusErrorDomain, code: -43), bundle: fr))
        #expect(fnf.sentence.hasPrefix("Fichier introuvable."))
        #expect(fnf.text(bundle: fr) == fnf.sentence + " (code -43)")
        #expect(ErrorText.describe(CocoaError(.fileReadNoSuchFile), bundle: fr)?.sentence == fnf.sentence)
        #expect(ErrorText.describe(POSIXError(.ENOENT), bundle: fr)?.sentence == fnf.sentence)
        #expect(ErrorText.describe(POSIXError(.ENOSPC), bundle: fr)?.sentence.contains("espace") == true)
        #expect(ErrorText.describe(POSIXError(.EACCES), bundle: fr)?.sentence.contains("le droit") == true)
    }

    @Test func underlyingErrorIsUsedWhenTheOuterOneIsUnknown() throws {
        let fr = try #require(Self.lproj("fr"))
        let outer = NSError(domain: "me.somalabs.onepass.tests", code: 7, userInfo: [NSUnderlyingErrorKey: POSIXError(.ENOSPC)])
        let text = try #require(ErrorText.describe(outer, bundle: fr))
        #expect(text.code == Int(ENOSPC))
    }

    @Test func unknownErrorsAreLeftToTheCaller() {
        struct Custom: Error {}
        #expect(ErrorText.describe(Custom()) == nil)
        #expect(ErrorText.describe(NSError(domain: NSCocoaErrorDomain, code: 4097)) == nil)
    }

    @Test(arguments: ["fr", "en"])
    func cloudKitCodesAreSentences(language: String) throws {
        let bundle = try #require(Self.lproj(language))
        for code in Self.cloudKitCodes {
            Self.checkReadable(ErrorText.cloudKit(code, bundle: bundle), code: code, bundle: bundle, "\(language) CK \(code)")
        }
    }

    // MARK: - What the apps show

    @Test func keychainErrorMessageIsASentence() {
        VaultKitStrings.pinSourceLanguage()
        let message = KeychainError.unexpectedStatus(-34018).message
        #expect(message.hasPrefix("Cette version de OnePass n'a pas accès au trousseau"))
        #expect(message.hasSuffix("(code -34018)"))
        #expect(!message.contains("34,018") && !message.contains("34 018"))
        let vault = VaultError(KeychainError.unexpectedStatus(-25308)).localizedMessage
        #expect(vault.hasPrefix("Le trousseau reste fermé tant que l'appareil est verrouillé."))
    }

    @Test func systemErrorsReachingTheSessionAreWorded() {
        VaultKitStrings.pinSourceLanguage()
        let file = VaultError(NSError(domain: NSOSStatusErrorDomain, code: -43)).localizedMessage
        #expect(file.hasPrefix("Fichier introuvable."))
        #expect(file.hasSuffix("(code -43)"))
        let enclave = VaultError(EnclaveError.failed(code: -34018)).localizedMessage
        #expect(enclave.hasPrefix("Cette version de OnePass n'a pas accès au trousseau"))
        struct Custom: Error {}
        let other = VaultError(Custom()).localizedMessage
        #expect(other.hasPrefix("Une erreur inattendue est survenue."))
        #expect(!other.contains("code"))
    }

    @Test func cloudKitStoreErrorsAreSentences() {
        VaultKitStrings.pinSourceLanguage()
        guard case .other(let text) = CloudKitMapping.storeError(for: CKError(.serverRejectedRequest)) else {
            Issue.record("not an .other")
            return
        }
        #expect(text.hasPrefix("iCloud a refusé la synchronisation."))
        #expect(text.hasSuffix("(code 15)"))
        guard case .other(let entitlement) = CloudKitMapping.storeError(for: CKError(.missingEntitlement)) else {
            Issue.record("not an .other")
            return
        }
        #expect(entitlement.contains("n'est pas configurée pour iCloud"))
    }

    @Test func coreErrorKindsAreSentences() {
        VaultKitStrings.pinSourceLanguage()
        let errors: [OnePassError] = [
            .WrongPassword, .NotFound, .Conflict, .Locked, .Store, .Crypto, .PasskeyExcluded, .ReadOnly,
            .RotationPending, .Quarantined, .Orphaned, .IdentityLeft, .RemoteUnlockStale,
            .Integrity(kind: "aead"), .InvalidInput(what: "something new"),
            .Validation(field: "x", reason: "something new"), .OutdatedKit(rotator: "Mac", at: 0),
        ]
        for error in errors {
            let message = VaultError(error).localizedMessage
            #expect(message.count > 10, "\(error): \(message)")
            #expect(message.rangeOfCharacter(from: .decimalDigits) == nil, "\(error): \(message)")
        }
    }
}
