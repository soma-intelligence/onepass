import Foundation
import OnePassCore
import dnssd

/// What the device management profile says about the organisation: the server and the pinned
/// fingerprint, delivered through the `com.apple.configuration.managed` defaults dictionary.
public struct ManagedOrgConfig: Equatable, Sendable {
    public static let defaultsKey = "com.apple.configuration.managed"
    static let fingerprintKey = "org_fpr"
    static let serverKey = "server_url"

    public let serverURL: URL
    public let fingerprint: Data

    public enum Reading: Equatable, Sendable {
        /// No managed configuration for the organisation: neither key is present.
        case none
        case valid(ManagedOrgConfig)
        /// One key or both are present but the pair is not a usable server and fingerprint.
        case invalid
    }

    public static func read(
        _ defaults: UserDefaults = .standard,
        allowHTTP: Bool = MailboxEndpoints.allowsLocalHTTP
    ) -> Reading {
        guard let dictionary = defaults.dictionary(forKey: defaultsKey),
              dictionary[serverKey] != nil || dictionary[fingerprintKey] != nil
        else { return .none }
        guard let text = dictionary[serverKey] as? String,
              let url = URL(string: text),
              MailboxEndpoints.validate(url, allowHTTP: allowHTTP),
              let fingerprintText = dictionary[fingerprintKey] as? String,
              let fingerprint = try? orgParseFingerprint(text: fingerprintText)
        else { return .invalid }
        return .valid(ManagedOrgConfig(serverURL: url, fingerprint: fingerprint))
    }
}

/// Resolves the TXT records of a name. Never throws: silence, an error and a timeout all give `[]`.
public protocol DNSTXTResolver: Sendable {
    func txtRecords(name: String, timeout: Duration) async -> [String]
}

/// The system resolver, through `DNSServiceQueryRecord` (class IN, type TXT).
public struct SystemDNSTXTResolver: DNSTXTResolver {
    public init() {}

    public func txtRecords(name: String, timeout: Duration) async -> [String] {
        await Self.gather(timeout: timeout) { collector in
            Self.startQuery(name: name, collector: collector)
        }
    }

    /// Concatenates the length-prefixed character strings of one TXT record. Nil when a length
    /// runs past the end, or when the bytes are not UTF-8.
    static func decodeTXT(_ rdata: Data) -> String? {
        let bytes = [UInt8](rdata)
        var joined = [UInt8]()
        var index = 0
        while index < bytes.count {
            let length = Int(bytes[index])
            index += 1
            guard index + length <= bytes.count else { return nil }
            joined.append(contentsOf: bytes[index..<index + length])
            index += length
        }
        return String(bytes: joined, encoding: .utf8)
    }

    // MARK: Collection

    /// Starts a query and returns how to stop it. Called once, before any record can arrive.
    typealias Starter = @Sendable (TXTCollector) -> @Sendable () -> Void

    /// Runs `start`, then waits for the first of: the collector finishing (a final batch or an
    /// error), the timeout, or the caller's cancellation. Resumes exactly once and always calls the
    /// stop closure `start` returned, exactly once. Split from the dnssd calls so the timeout is
    /// testable with a query that never answers.
    static func gather(timeout: Duration, start: Starter) async -> [String] {
        let collector = TXTCollector()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<[String], Never>) in
                collector.install(continuation)
                collector.setStop(start(collector))
                let timer = Task {
                    try? await Task.sleep(for: timeout)
                    collector.finish()
                }
                collector.setTimer(timer)
            }
        } onCancel: {
            collector.finish()
        }
    }

    // MARK: dnssd

    /// The per-query state the dnssd callback reaches through an unmanaged pointer.
    ///
    /// Pointer handling, all of it in `startQuery` and the callback below:
    /// - `Unmanaged.passRetained(collector)` gives the callback context one strong reference. It is
    ///   released in the stop closure, after `DNSServiceRefDeallocate`, never earlier.
    /// - The callback runs on `queue` only (`DNSServiceSetDispatchQueue`). The stop closure also runs
    ///   its deallocate-then-release on `queue`, so it can never overlap a callback and the context is
    ///   never used after release.
    /// - `rdata` is only valid during the callback: it is copied into `Data` before returning.
    private static let callback: DNSServiceQueryRecordReply = {
        _, flags, _, errorCode, _, _, _, rdlen, rdata, _, context in
        guard let context else { return }
        let collector = Unmanaged<TXTCollector>.fromOpaque(context).takeUnretainedValue()
        guard errorCode == kDNSServiceErr_NoError else {
            collector.finish()
            return
        }
        if flags & kDNSServiceFlagsAdd != 0, let rdata, rdlen > 0,
           let text = decodeTXT(Data(bytes: rdata, count: Int(rdlen)))
        {
            collector.add(text)
        }
        if flags & kDNSServiceFlagsMoreComing == 0 {
            collector.finish()
        }
    }

    private static func startQuery(name: String, collector: TXTCollector) -> @Sendable () -> Void {
        let queue = DispatchQueue(label: "me.somalabs.onepass.dns-txt")
        var ref: DNSServiceRef?
        let context = Unmanaged.passRetained(collector)
        let status = DNSServiceQueryRecord(
            &ref, 0, 0, name, UInt16(kDNSServiceType_TXT), UInt16(kDNSServiceClass_IN),
            callback, context.toOpaque())
        guard status == kDNSServiceErr_NoError, let ref else {
            context.release()
            collector.finish()
            return {}
        }
        guard DNSServiceSetDispatchQueue(ref, queue) == kDNSServiceErr_NoError else {
            DNSServiceRefDeallocate(ref)
            context.release()
            collector.finish()
            return {}
        }
        let handle = SendableRef(ref)
        return {
            queue.async {
                DNSServiceRefDeallocate(handle.ref)
                context.release()
            }
        }
    }

    /// `DNSServiceRef` is a plain pointer that is only touched on the query's own serial queue.
    private struct SendableRef: @unchecked Sendable {
        let ref: DNSServiceRef
        init(_ ref: DNSServiceRef) { self.ref = ref }
    }
}

/// Gathers the records of one query and resumes the waiting continuation exactly once.
final class TXTCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var records: [String] = []
    private var continuation: CheckedContinuation<[String], Never>?
    private var stop: (@Sendable () -> Void)?
    private var timer: Task<Void, Never>?
    private var finished = false

    func install(_ continuation: CheckedContinuation<[String], Never>) {
        lock.lock()
        self.continuation = continuation
        let done = finished
        lock.unlock()
        if done { complete() }
    }

    func setStop(_ stop: @escaping @Sendable () -> Void) {
        lock.lock()
        let done = finished
        if !done { self.stop = stop }
        lock.unlock()
        if done { stop() }
    }

    func setTimer(_ timer: Task<Void, Never>) {
        lock.lock()
        let done = finished
        if !done { self.timer = timer }
        lock.unlock()
        if done { timer.cancel() }
    }

    func add(_ text: String) {
        lock.lock()
        if !finished { records.append(text) }
        lock.unlock()
    }

    /// Idempotent: the first call wins, later ones do nothing.
    func finish() {
        lock.lock()
        guard !finished else {
            lock.unlock()
            return
        }
        finished = true
        lock.unlock()
        complete()
    }

    /// Runs after `finished` is set; resumes the continuation once it is installed, and tears down.
    private func complete() {
        lock.lock()
        let continuation = self.continuation
        self.continuation = nil
        let stop = self.stop
        self.stop = nil
        let timer = self.timer
        self.timer = nil
        let result = records
        lock.unlock()
        timer?.cancel()
        stop?()
        continuation?.resume(returning: result)
    }
}

public enum OrgPinRefusal: Equatable, Sendable {
    case mdmInvalid
    case mdmMismatch
    case dnsMismatch
}

public enum OrgPinPlan: Equatable, Sendable {
    case pin(source: FfiPinSource, expected: Data)
    case refuse(OrgPinRefusal)
}

/// Decides how an invite's organisation fingerprint is pinned: MDM first, then DNS, then first use.
public struct OrgPinResolver: Sendable {
    public static let dnsTimeout: Duration = .seconds(5)

    private let mdm: ManagedOrgConfig.Reading
    private let dns: any DNSTXTResolver
    private let timeout: Duration

    public init(mdm: ManagedOrgConfig.Reading, dns: any DNSTXTResolver) {
        self.init(mdm: mdm, dns: dns, timeout: Self.dnsTimeout)
    }

    init(mdm: ManagedOrgConfig.Reading, dns: any DNSTXTResolver, timeout: Duration) {
        self.mdm = mdm
        self.dns = dns
        self.timeout = timeout
    }

    public func plan(for invite: FfiOrgInvite) async -> OrgPinPlan {
        switch mdm {
        case .invalid:
            return .refuse(.mdmInvalid)
        case .valid(let config):
            guard config.serverURL.absoluteString == invite.serverUrl,
                  config.fingerprint == invite.fingerprint
            else { return .refuse(.mdmMismatch) }
            return .pin(source: .mdm, expected: config.fingerprint)
        case .none:
            break
        }
        guard let domain = invite.domain, !domain.isEmpty else {
            return .pin(source: .tofu(verified: false), expected: invite.fingerprint)
        }
        let texts = await dns.txtRecords(name: "_onepass.\(domain)", timeout: timeout)
        var values: [Data] = []
        for text in texts {
            if let value = try? orgParseDnsTxt(text: text), !values.contains(value) {
                values.append(value)
            }
        }
        guard let value = values.first else {
            return .pin(source: .tofu(verified: false), expected: invite.fingerprint)
        }
        guard values.count == 1, value == invite.fingerprint else { return .refuse(.dnsMismatch) }
        return .pin(source: .dns, expected: value)
    }
}
