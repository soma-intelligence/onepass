import Foundation

/// The OnePass server URLs the app accepts.
public enum MailboxEndpoints {
    /// Info.plist key of the hosted instance's base URL.
    public static let infoKey = "OnePassMailboxURL"
    /// The local Supabase stack, accepted by Debug builds only.
    public static let localDebugURL = URL(string: "http://127.0.0.1:54321/functions/v1/mailbox")!

    public static var hostedName: String {
        String(localized: "sync.server.hosted", bundle: VaultKitStrings.bundle)
    }

    /// The hosted instance from the bundle's Info.plist, when valid for this build.
    public static func hosted(bundle: Bundle = .main) -> URL? {
        guard let text = bundle.object(forInfoDictionaryKey: infoKey) as? String,
              let url = URL(string: text)
        else { return nil }
        return validate(url, allowHTTP: allowsLocalHTTP) ? url : nil
    }

    /// Debug builds talk to the local Supabase stack over plain HTTP; Release never.
    public static var allowsLocalHTTP: Bool {
        #if DEBUG
        true
        #else
        false
        #endif
    }

    /// `https`, a host, no user info, query or fragment, at most 256 bytes (the core's rule for a
    /// signed home). With `allowHTTP`, the local Supabase URL also passes.
    public static func validate(_ url: URL, allowHTTP: Bool) -> Bool {
        if allowHTTP, url == localDebugURL { return true }
        let text = url.absoluteString
        guard url.scheme == "https", let host = url.host(), !host.isEmpty,
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
              text.utf8.count <= 256, !text.contains("\\")
        else { return false }
        return text.unicodeScalars.allSatisfy { (0x21...0x7e).contains($0.value) }
    }

    static func displayName(_ url: URL, hosted: URL?) -> String {
        url == hosted ? hostedName : (url.host() ?? url.absoluteString)
    }
}
