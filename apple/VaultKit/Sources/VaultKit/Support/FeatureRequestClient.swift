import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// Réglages > Suggérer une fonctionnalité: one idea sent to the Soma Labs feature request
/// function. The body carries the typed idea, the optional email and a few facts about the app
/// and the device (version, system, model, locale, a random install id). Nothing from the vault,
/// the account or the items is ever part of it.
public struct FeatureRequest: Sendable, Equatable {
    public var message: String
    public var email: String?
    public var platform: String
    public var installID: String?
    public var appVersion: String?
    public var osVersion: String?
    public var deviceModel: String?
    public var locale: String?

    public init(
        message: String, email: String? = nil, platform: String, installID: String? = nil, appVersion: String? = nil,
        osVersion: String? = nil, deviceModel: String? = nil, locale: String? = nil
    ) {
        self.message = message
        self.email = email
        self.platform = platform
        self.installID = installID
        self.appVersion = appVersion
        self.osVersion = osVersion
        self.deviceModel = deviceModel
        self.locale = locale
    }
}

/// Why an idea was not saved. The sheet keeps the text in every case.
public enum FeatureRequestError: Error, Equatable, Sendable {
    case messageTooShort
    case messageTooLong
    case invalidEmail
    case rateLimited
    case server
    case network
}

public struct FeatureRequestClient: Sendable {
    /// The public function (no auth header, verify_jwt off).
    public static let endpoint = URL(string: "https://uchdtnhkkclhvnnqclht.supabase.co/functions/v1/feature-request")!
    public static let appID = "onepass"
    public static let minimumLength = 3
    public static let maximumLength = 4000
    static let maximumEmailLength = 320

    public typealias Transport = @Sendable (URLRequest) async throws -> (Data, URLResponse)

    let endpoint: URL
    let transport: Transport

    public init(endpoint: URL = FeatureRequestClient.endpoint, transport: Transport? = nil) {
        self.endpoint = endpoint
        self.transport = transport ?? { request in try await URLSession.shared.data(for: request) }
    }

    /// True once the idea holds at least three characters other than spaces and line breaks.
    public static func canSend(_ message: String) -> Bool {
        message.unicodeScalars.lazy.filter { !CharacterSet.whitespacesAndNewlines.contains($0) }.count >= minimumLength
    }

    /// The email as sent: trimmed, nil when empty.
    static func normalizedEmail(_ email: String?) -> String? {
        guard let trimmed = email?.trimmingCharacters(in: .whitespacesAndNewlines), !trimmed.isEmpty else { return nil }
        return trimmed
    }

    /// A light check before sending (the server has the last word): one @, a dot in the domain, no spaces.
    static func looksLikeEmail(_ email: String) -> Bool {
        guard email.count <= maximumEmailLength, !email.contains(where: \.isWhitespace) else { return false }
        let parts = email.split(separator: "@", omittingEmptySubsequences: false)
        guard parts.count == 2, !parts[0].isEmpty else { return false }
        let domain = parts[1]
        guard let dot = domain.lastIndex(of: "."), dot != domain.startIndex, domain.index(after: dot) != domain.endIndex
        else { return false }
        return true
    }

    /// The POST of one idea. Throws the same errors the server would answer, so nothing invalid leaves the device.
    public func makeRequest(_ idea: FeatureRequest) throws(FeatureRequestError) -> URLRequest {
        let message = idea.message.trimmingCharacters(in: .whitespacesAndNewlines)
        guard Self.canSend(message) else { throw .messageTooShort }
        guard message.count <= Self.maximumLength else { throw .messageTooLong }
        let email = Self.normalizedEmail(idea.email)
        if let email, !Self.looksLikeEmail(email) { throw .invalidEmail }

        var body: [String: String] = [
            "app": Self.appID,
            "platform": idea.platform,
            "message": message,
        ]
        body["email"] = email
        body["install_id"] = Self.clipped(idea.installID?.lowercased(), 64)
        body["app_version"] = Self.clipped(idea.appVersion, 40)
        body["os_version"] = Self.clipped(idea.osVersion, 40)
        body["device_model"] = Self.clipped(idea.deviceModel, 60)
        body["locale"] = Self.clipped(idea.locale, 20)

        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = 20
        // A [String: String] always encodes.
        request.httpBody = try? JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
        return request
    }

    /// Sends one idea; returns the id of the saved row.
    @discardableResult
    public func send(_ idea: FeatureRequest) async throws(FeatureRequestError) -> Int {
        let request = try makeRequest(idea)
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await transport(request)
        } catch {
            throw .network
        }
        return try Self.parse(data: data, response: response)
    }

    /// 201 {"id": N}, or the error the body names (400), 429, else a server error.
    public static func parse(data: Data, response: URLResponse) throws(FeatureRequestError) -> Int {
        guard let http = response as? HTTPURLResponse else { throw .network }
        let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        switch http.statusCode {
        case 200, 201:
            if let id = json?["id"] as? Int { return id }
            if let id = (json?["id"] as? NSNumber)?.intValue { return id }
            throw .server
        case 429:
            throw .rateLimited
        case 400 ..< 500:
            switch json?["error"] as? String {
            case "message_too_short": throw .messageTooShort
            case "message_too_long": throw .messageTooLong
            case "invalid_email": throw .invalidEmail
            case "rate_limited": throw .rateLimited
            default: throw .server
            }
        default:
            throw .server
        }
    }

    private static func clipped(_ value: String?, _ limit: Int) -> String? {
        guard let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines), !trimmed.isEmpty else { return nil }
        return String(trimmed.prefix(limit))
    }
}

// MARK: - The facts sent with an idea

public extension FeatureRequest {
    /// An idea with this device's facts: platform, app version, system, model, locale and the
    /// install id (made once, kept in `defaults`).
    @MainActor
    static func current(message: String, email: String?, bundle: Bundle = .main,
                        defaults: UserDefaults = .standard) -> FeatureRequest {
        let info = bundle.infoDictionary
        let short = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        let os = ProcessInfo.processInfo.operatingSystemVersion
        return FeatureRequest(
            message: message,
            email: email,
            platform: currentPlatform,
            installID: installID(defaults),
            appVersion: "\(short) (\(build))",
            osVersion: "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)",
            deviceModel: deviceModel,
            locale: Locale.current.identifier)
    }

    static let installIDKey = "onepass.featureRequest.installID"

    /// A random lowercase UUID, made on the first idea and kept.
    static func installID(_ defaults: UserDefaults) -> String {
        if let saved = defaults.string(forKey: installIDKey), UUID(uuidString: saved) != nil { return saved }
        let made = UUID().uuidString.lowercased()
        defaults.set(made, forKey: installIDKey)
        return made
    }

    @MainActor
    static var currentPlatform: String {
        #if os(visionOS)
        "visionos"
        #elseif os(watchOS)
        "watchos"
        #elseif os(macOS)
        "macos"
        #elseif os(iOS)
        UIDevice.current.userInterfaceIdiom == .pad ? "ipados" : "ios"
        #else
        "ios"
        #endif
    }

    /// The model id ("iPhone17,1", "Mac15,3"); the simulated one in the Simulator.
    static var deviceModel: String? {
        if let simulated = ProcessInfo.processInfo.environment["SIMULATOR_MODEL_IDENTIFIER"], !simulated.isEmpty {
            return simulated
        }
        #if os(macOS)
        var size = 0
        if sysctlbyname("hw.model", nil, &size, nil, 0) == 0, size > 0 {
            var bytes = [CChar](repeating: 0, count: size)
            if sysctlbyname("hw.model", &bytes, &size, nil, 0) == 0 {
                return String(decoding: bytes.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
            }
        }
        #endif
        var system = utsname()
        uname(&system)
        let machine = withUnsafeBytes(of: &system.machine) { raw in
            String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
        }
        return machine.isEmpty ? nil : machine
    }
}
