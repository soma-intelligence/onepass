import Foundation

/// A passkey assertion asked by the system (sign-in with a passkey).
public struct PasskeyRequest: Sendable, Equatable {
    /// Relying party id, checked by the system against the page or the app.
    public var rpID: String
    public var clientDataHash: Data
    /// Credentials the relying party accepts; empty means any passkey of `rpID` in a list. A direct
    /// request (`AutoFillRequest.credential`) needs the identity's credential id here: empty ends it
    /// with `credentialNotFound`.
    public var allowedCredentialIDs: [Data]

    public init(rpID: String, clientDataHash: Data, allowedCredentialIDs: [Data]) {
        self.rpID = rpID
        self.clientDataHash = clientDataHash
        self.allowedCredentialIDs = allowedCredentialIDs
    }
}

/// A passkey creation asked by a site or an app.
public struct PasskeyRegistrationRequest: Sendable, Equatable {
    public var rpID: String
    public var userName: String
    public var userHandle: Data
    public var clientDataHash: Data
    /// Credentials the relying party already holds for this user: creation refused if OnePass has one.
    public var excludedCredentialIDs: [Data]
    /// ES256 (P-256) is among the accepted algorithms. OnePass creates ES256 passkeys only.
    public var supportsES256: Bool

    public init(
        rpID: String, userName: String, userHandle: Data, clientDataHash: Data,
        excludedCredentialIDs: [Data], supportsES256: Bool
    ) {
        self.rpID = rpID
        self.userName = userName
        self.userHandle = userHandle
        self.clientDataHash = clientDataHash
        self.excludedCredentialIDs = excludedCredentialIDs
        self.supportsES256 = supportsES256
    }
}

/// A service the system names: a site (domain or URL), or an app (its App ID, iOS and macOS 26.2+).
/// The type is kept end to end: an app identifier is never read as a host (`com.example.app` is not
/// the site `example.app`), it only matches a Login's `apps` (G1, G2). A string literal is a site.
public struct AutoFillService: Sendable, Hashable, ExpressibleByStringLiteral {
    public var identifier: String
    public var isApp: Bool
    /// The name the system gives for display ("Instagram"), never used to match.
    public var displayName: String?

    public init(identifier: String, isApp: Bool, displayName: String? = nil) {
        self.identifier = identifier
        self.isApp = isApp
        self.displayName = displayName
    }

    public init(stringLiteral value: String) {
        self.init(identifier: value, isApp: false)
    }

    public static func site(_ value: String) -> AutoFillService { AutoFillService(identifier: value, isApp: false) }

    public static func app(_ id: String, displayName: String? = nil) -> AutoFillService {
        AutoFillService(identifier: id, isApp: true, displayName: displayName)
    }

    /// The core's typed service.
    public var ffi: FfiAutofillService {
        isApp ? .app(id: identifier) : .site(value: identifier)
    }

    /// What headings show: the app's name (else the last part of its App ID, `instagram` for
    /// `com.burbn.instagram`), or the site's host without `www.` (G12).
    public var shownName: String {
        let trimmed = identifier.trimmingCharacters(in: .whitespacesAndNewlines)
        if isApp {
            if let name = displayName?.trimmingCharacters(in: .whitespacesAndNewlines), !name.isEmpty { return name }
            let last = trimmed.split(separator: ".").last.map(String.init) ?? trimmed
            return last.prefix(1).uppercased() + last.dropFirst()
        }
        let host = URL(string: trimmed.contains("://") ? trimmed : "https://\(trimmed)")?.host() ?? trimmed
        return host.hasPrefix("www.") ? String(host.dropFirst(4)) : host
    }
}

/// Why the system asks to save a password (iOS 26.2+).
public enum SaveEvent: Sendable, Equatable {
    case userInitiated
    case formDidDisappear
    /// A generated password was filled: the next event carries the same value, nothing is written.
    case generatedPasswordFilled
}

/// A password typed in an app or a page that the system offers to save.
public struct SavePasswordRequest: Sendable, Equatable {
    /// A domain or URL, or an app identifier when `serviceIsApp`.
    public var service: String
    public var serviceIsApp: Bool
    public var user: String
    public var password: String
    /// Title suggested by the system, if any.
    public var title: String?
    public var event: SaveEvent
    /// The app's name from the system (an app service), for display only.
    public var displayName: String?

    public init(
        service: String, serviceIsApp: Bool, user: String, password: String, title: String?, event: SaveEvent,
        displayName: String? = nil
    ) {
        self.service = service
        self.serviceIsApp = serviceIsApp
        self.user = user
        self.password = password
        self.title = title
        self.event = event
        self.displayName = displayName
    }

    /// The typed service of the request.
    public var typedService: AutoFillService {
        AutoFillService(identifier: service, isApp: serviceIsApp, displayName: displayName)
    }
}

/// What the system asks the AutoFill extension, translated from AuthenticationServices by the
/// controller. Password generation requests never reach the model (the controller answers them with
/// `passwordForContext`, no vault data read).
public enum AutoFillRequest: Sendable, Equatable {
    /// Manual choice (key button): passwords of `services`, and passkeys of `passkey.rpID` if asked.
    case credentialList(services: [AutoFillService], passkey: PasskeyRequest?)
    /// A QuickType suggestion: the record `"<vault id>:<item id>"` from the identity store, and the
    /// identity's service (host) for a password or a one-time code: the Login must still match it
    /// (a stale identity store entry falls back to the list). Nil skips that check.
    case credential(
        recordID: String, kind: FfiAutofillKind, passkey: PasskeyRequest?, service: AutoFillService? = nil)
    case oneTimeCodeList(services: [AutoFillService])
    case passkeyRegistration(PasskeyRegistrationRequest)
    case savePassword(SavePasswordRequest)
    case textToInsert
    case configuration
}

extension AutoFillRequest {
    /// The first service the request names (the passkey's relying party first), for headings.
    public var primaryService: AutoFillService? {
        switch self {
        case .credentialList(let services, let passkey): passkey.map { AutoFillService.site($0.rpID) } ?? services.first
        case .oneTimeCodeList(let services): services.first
        case .credential(_, _, let passkey, let service): passkey.map { AutoFillService.site($0.rpID) } ?? service
        case .passkeyRegistration(let registration): .site(registration.rpID)
        case .savePassword(let save): save.typedService
        case .textToInsert, .configuration: nil
        }
    }
}

/// Why a request ended without a credential. The controller maps it to `ASExtensionError`.
public enum AutoFillFailure: Sendable, Equatable {
    case userCanceled
    case userInteractionRequired
    case credentialNotFound
    case excludedCredential
    case failed
}

/// How a request ends. The controller turns it into the matching `extensionContext` call.
public enum AutoFillResult: Sendable, Equatable {
    case password(user: String, password: String)
    case oneTimeCode(String)
    case passkeyAssertion(FfiPasskeyAssertion, rpID: String, clientDataHash: Data)
    case passkeyRegistration(FfiPasskeyRegistration, rpID: String, clientDataHash: Data)
    case text(String)
    case saved
    case cancelled(AutoFillFailure)
}
