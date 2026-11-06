import Foundation
import Security

/// A system error put in words for the user: a plain sentence that says what happened and what to
/// do, in the app's language, and the raw code only as a small note for support ("(code -34018)").
/// Never a bare number as the message.
public struct ErrorText: Equatable, Sendable {
    /// What happened and what to do. Never carries the raw code.
    public let sentence: String
    /// The raw code (OSStatus, Cocoa, POSIX, CloudKit...), shown after the sentence.
    public let code: Int?
    /// The system's own description of an unknown keychain status (`SecCopyErrorMessageString`),
    /// added to the code note only.
    public let systemDetail: String?

    /// The sentence, then the code note when there is a code.
    public var text: String { text(bundle: VaultKitStrings.bundle) }

    public func text(bundle: Bundle) -> String {
        guard let code else { return sentence }
        return sentence + " " + Self.codeNote(code, detail: systemDetail, bundle: bundle)
    }

    /// "(code -34018)", digits never grouped, with the system's description when there is one.
    public static func codeNote(_ code: Int, detail: String? = nil, bundle given: Bundle? = nil) -> String {
        let bundle = given ?? VaultKitStrings.bundle
        let number = String(code)
        if let detail, !detail.isEmpty {
            return String(localized: "errorText.code \(number) \(detail)", bundle: bundle)
        }
        return String(localized: "errorText.code \(number)", bundle: bundle)
    }

    /// `base`, then the readable reason of `error` when there is one (file errors behind "Le fichier
    /// n'a pas pu être enregistré.", for example).
    public static func appending(_ error: any Error, to base: String, bundle given: Bundle? = nil) -> String {
        let bundle = given ?? VaultKitStrings.bundle
        guard let reason = describe(error, bundle: bundle) else { return base }
        return base + " " + reason.text(bundle: bundle)
    }

    // MARK: - Any error

    /// The readable form of a system error (OSStatus, Cocoa, POSIX, URL, CloudKit, also when it is the
    /// underlying error of another one). nil for anything else, which the caller words itself.
    public static func describe(_ error: any Error, bundle given: Bundle? = nil) -> ErrorText? {
        let bundle = given ?? VaultKitStrings.bundle
        if let keychain = error as? KeychainError, case .unexpectedStatus(let status) = keychain {
            return self.keychain(status, bundle: bundle)
        }
        let ns = error as NSError
        if let found = describe(domain: ns.domain, code: ns.code, bundle: bundle) { return found }
        if let underlying = ns.userInfo[NSUnderlyingErrorKey] as? NSError, underlying !== ns {
            return describe(underlying, bundle: bundle)
        }
        return nil
    }

    static func describe(domain: String, code: Int, bundle: Bundle) -> ErrorText? {
        switch domain {
        case NSOSStatusErrorDomain:
            return osStatus(OSStatus(truncatingIfNeeded: code), keychain: false, bundle: bundle)
        case NSCocoaErrorDomain:
            return cocoa(code, bundle: bundle)
        case NSPOSIXErrorDomain:
            return posix(code, bundle: bundle)
        case NSURLErrorDomain:
            return url(code, bundle: bundle)
        case "CKErrorDomain":
            return cloudKit(code, bundle: bundle)
        default:
            return nil
        }
    }

    // MARK: - Keychain and OSStatus

    /// The keychain status `status` in words. Always a sentence: an unknown status says the keychain
    /// refused, with the system's description in the code note.
    public static func keychain(_ status: OSStatus, bundle given: Bundle? = nil) -> ErrorText {
        let bundle = given ?? VaultKitStrings.bundle
        return osStatus(status, keychain: true, bundle: bundle)
            ?? ErrorText(
                sentence: String(localized: "errorText.keychainRefusedOperationTry", bundle: bundle),
                code: Int(status), systemDetail: systemMessage(status))
    }

    /// Known OSStatus values (Security and the classic file manager codes). nil for an unknown one
    /// outside the keychain; `keychain` only changes how that unknown one is worded by the caller.
    static func osStatus(_ status: OSStatus, keychain: Bool, bundle: Bundle) -> ErrorText? {
        let sentence: String?
        switch status {
        case errSecMissingEntitlement:  // -34018
            sentence = String(localized: "errorText.copyOfOnepassCant", bundle: bundle)
        case errSecItemNotFound:  // -25300
            sentence = String(localized: "errorText.onepassEntryMissingFrom", bundle: bundle)
        case errSecDuplicateItem:  // -25299
            sentence = String(localized: "errorText.entryAlreadyExistsIn", bundle: bundle)
        case errSecInteractionNotAllowed:  // -25308
            sentence = String(localized: "errorText.keychainStaysClosedWhile", bundle: bundle)
        case errSecUserCanceled:  // -128, also userCanceledErr
            sentence = cancelled(bundle)
        case errSecAuthFailed:  // -25293
            sentence = String(localized: "errorText.keychainRefusedAuthenticationCheck", bundle: bundle)
        case errSecDecode:  // -26275
            sentence = String(localized: "errorText.keychainEntryCantRead", bundle: bundle)
        case errSecNotAvailable:  // -25291
            sentence = String(localized: "errorText.keychainIsntAvailableRight", bundle: bundle)
        case errSecNoAccessForItem, errSecInvalidOwnerEdit:  // -25243, -25244
            sentence = String(localized: "errorText.onepassIsntAllowedTo2", bundle: bundle)
        case errSecNoSuchKeychain, errSecInvalidKeychain:  // -25294, -25295
            sentence = String(localized: "errorText.sessionsKeychainMissingOr", bundle: bundle)
        case errSecParam:  // -50
            sentence = String(localized: "errorText.onepassMadeRequestSystem", bundle: bundle)
        case errSecDiskFull:  // -34, also dskFulErr
            sentence = diskFull(bundle)
        case errSecIO:  // -36, also ioErr
            sentence = io(bundle)
        case errSecWrPerm, -54, -5000:  // -61 wrPermErr, -54 permErr, -5000 afpAccessDenied
            sentence = noPermission(bundle)
        case -43:  // fnfErr
            sentence = fileNotFound(bundle)
        case -120:  // dirNFErr
            sentence = folderNotFound(bundle)
        case -44, -46:  // wPrErr, vLckdErr
            sentence = readOnly(bundle)
        case -48:  // dupFNErr
            sentence = fileExists(bundle)
        default:
            sentence = nil
        }
        if let sentence { return ErrorText(sentence: sentence, code: Int(status), systemDetail: nil) }
        if keychain { return nil }
        return ErrorText(
            sentence: String(localized: "errorText.systemRefusedOperationTry", bundle: bundle),
            code: Int(status), systemDetail: nil)
    }

    /// The system's description of a keychain status, nil when it has none.
    static func systemMessage(_ status: OSStatus) -> String? {
        guard let message = SecCopyErrorMessageString(status, nil) as String? else { return nil }
        let trimmed = message.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    // MARK: - Files

    /// `NSCocoaErrorDomain` codes (file reading and writing, cancellation). nil for the others.
    static func cocoa(_ code: Int, bundle: Bundle) -> ErrorText? {
        let sentence: String
        switch CocoaError.Code(rawValue: code) {
        case .fileNoSuchFile, .fileReadNoSuchFile: sentence = fileNotFound(bundle)
        case .fileReadNoPermission, .fileWriteNoPermission: sentence = noPermission(bundle)
        case .fileWriteOutOfSpace: sentence = diskFull(bundle)
        case .fileWriteVolumeReadOnly: sentence = readOnly(bundle)
        case .fileWriteFileExists: sentence = fileExists(bundle)
        case .fileReadInvalidFileName, .fileWriteInvalidFileName: sentence = invalidName(bundle)
        case .fileReadCorruptFile:
            sentence = String(localized: "errorText.fileDamagedOrIsnt", bundle: bundle)
        case .fileReadInapplicableStringEncoding, .fileReadUnknownStringEncoding, .fileWriteInapplicableStringEncoding:
            sentence = String(localized: "errorText.filesTextCantRead", bundle: bundle)
        case .fileReadTooLarge:
            sentence = String(localized: "errorText.fileTooLargeTo", bundle: bundle)
        case .fileLocking: sentence = inUse(bundle)
        case .userCancelled: sentence = cancelled(bundle)
        case .fileReadUnknown:
            sentence = String(localized: "errorText.fileCouldntReadTry", bundle: bundle)
        case .fileWriteUnknown:
            sentence = String(localized: "errorText.fileCouldntSavedTry", bundle: bundle)
        default: return nil
        }
        return ErrorText(sentence: sentence, code: code, systemDetail: nil)
    }

    /// `NSPOSIXErrorDomain` codes (files, disk, network). nil for the others.
    static func posix(_ code: Int, bundle: Bundle) -> ErrorText? {
        let sentence: String
        switch Int32(truncatingIfNeeded: code) {
        case ENOENT: sentence = fileNotFound(bundle)
        case ENOTDIR: sentence = folderNotFound(bundle)
        case ENOSPC, EDQUOT: sentence = diskFull(bundle)
        case EACCES, EPERM: sentence = noPermission(bundle)
        case EROFS: sentence = readOnly(bundle)
        case EEXIST: sentence = fileExists(bundle)
        case ENAMETOOLONG: sentence = invalidName(bundle)
        case EIO: sentence = io(bundle)
        case EBUSY: sentence = inUse(bundle)
        case ECANCELED: sentence = cancelled(bundle)
        case ETIMEDOUT, ECONNREFUSED, ENETDOWN, ENETUNREACH, EHOSTUNREACH, ECONNRESET: sentence = network(bundle)
        default: return nil
        }
        return ErrorText(sentence: sentence, code: code, systemDetail: nil)
    }

    /// `NSURLErrorDomain` codes about the connection. nil for the others.
    static func url(_ code: Int, bundle: Bundle) -> ErrorText? {
        let sentence: String
        switch URLError.Code(rawValue: code) {
        case .notConnectedToInternet, .networkConnectionLost, .timedOut, .cannotFindHost, .cannotConnectToHost,
            .dnsLookupFailed, .dataNotAllowed, .internationalRoamingOff:
            sentence = network(bundle)
        case .cancelled: sentence = cancelled(bundle)
        default: return nil
        }
        return ErrorText(sentence: sentence, code: code, systemDetail: nil)
    }

    // MARK: - CloudKit

    /// A CloudKit error code (`CKError.Code` raw value) in words. Always a sentence.
    public static func cloudKit(_ code: Int, bundle given: Bundle? = nil) -> ErrorText {
        let bundle = given ?? VaultKitStrings.bundle
        let sentence: String
        switch code {
        case 3, 4:  // networkUnavailable, networkFailure
            sentence = network(bundle)
        case 5, 8, 24:  // badContainer, missingEntitlement, badDatabase
            sentence = String(localized: "errorText.copyOfOnepassIsnt", bundle: bundle)
        case 9, 36:  // notAuthenticated, accountTemporarilyUnavailable
            sentence = String(localized: "errorText.noIcloudAccountAvailable", bundle: bundle)
        case 10, 32:  // permissionFailure, managedAccountRestricted
            sentence = String(localized: "errorText.icloudDeniesOnepassAccess", bundle: bundle)
        case 18:  // incompatibleVersion
            sentence = String(localized: "errorText.versionOfOnepassToo", bundle: bundle)
        case 1, 6, 7, 23, 34:  // internalError, serviceUnavailable, requestRateLimited, zoneBusy, serverResponseLost
            sentence = String(localized: "errorText.icloudIsntRespondingRight", bundle: bundle)
        case 25:  // quotaExceeded
            sentence = String(localized: "errorText.icloudStorageFullFree", bundle: bundle)
        case 20:  // operationCancelled
            sentence = cancelled(bundle)
        default:
            sentence = String(localized: "errorText.icloudRefusedToSync", bundle: bundle)
        }
        return ErrorText(sentence: sentence, code: code, systemDetail: nil)
    }

    // MARK: - Shared sentences

    static func cancelled(_ bundle: Bundle) -> String {
        String(localized: "errorText.cancelledStartAgainWhenever", bundle: bundle)
    }

    static func diskFull(_ bundle: Bundle) -> String {
        String(localized: "errorText.deviceOutOfSpace", bundle: bundle)
    }

    static func io(_ bundle: Bundle) -> String {
        String(localized: "errorText.deviceCouldntReadOr", bundle: bundle)
    }

    static func noPermission(_ bundle: Bundle) -> String {
        String(localized: "errorText.onepassIsntAllowedTo", bundle: bundle)
    }

    static func fileNotFound(_ bundle: Bundle) -> String {
        String(localized: "errorText.fileNotFoundIt", bundle: bundle)
    }

    static func folderNotFound(_ bundle: Bundle) -> String {
        String(localized: "errorText.folderNotFoundIt", bundle: bundle)
    }

    static func readOnly(_ bundle: Bundle) -> String {
        String(localized: "errorText.locationReadOnlyPick", bundle: bundle)
    }

    static func fileExists(_ bundle: Bundle) -> String {
        String(localized: "errorText.fileWithNameAlready", bundle: bundle)
    }

    static func invalidName(_ bundle: Bundle) -> String {
        String(localized: "errorText.fileNameIsntAllowed", bundle: bundle)
    }

    static func inUse(_ bundle: Bundle) -> String {
        String(localized: "errorText.anotherAppUsingFile", bundle: bundle)
    }

    static func network(_ bundle: Bundle) -> String {
        String(localized: "errorText.cantReachNetworkCheck", bundle: bundle)
    }
}
