import Foundation
import Synchronization

/// An address a host name resolved to: 4 bytes (IPv4) or 16 bytes (IPv6).
public struct ResolvedAddress: Equatable, Sendable, CustomStringConvertible {
    public let bytes: [UInt8]

    public init?(bytes: [UInt8]) {
        guard bytes.count == 4 || bytes.count == 16 else { return nil }
        self.bytes = bytes
    }

    /// Dotted IPv4 (`192.0.2.1`) or IPv6 text, for tests.
    public init?(_ text: String) {
        var v4 = in_addr()
        var v6 = in6_addr()
        if inet_pton(AF_INET, text, &v4) == 1 {
            self.init(bytes: withUnsafeBytes(of: &v4) { Array($0) })
        } else if inet_pton(AF_INET6, text, &v6) == 1 {
            self.init(bytes: withUnsafeBytes(of: &v6) { Array($0) })
        } else {
            return nil
        }
    }

    public var description: String { bytes.map(String.init).joined(separator: ".") }

    /// Reachable on the public internet: not private, loopback, link-local, CGNAT (100.64.0.0/10),
    /// unique-local IPv6 (fc00::/7), multicast, unspecified, reserved, documentation or broadcast. An
    /// IPv4 address embedded in IPv6 (mapped `::ffff:0:0/96`, compatible `::/96`, NAT64
    /// `64:ff9b::/96`, 6to4 `2002::/16`) is judged as IPv4; SIIT `::ffff:0:0:0/96`, local NAT64
    /// `64:ff9b:1::/48`, Teredo `2001::/32`, discard `100::/64` and `2001:db8::/32` are refused.
    public var isPublic: Bool {
        bytes.count == 4 ? Self.isPublicV4(bytes) : Self.isPublicV6(bytes)
    }

    static func isPublicV4(_ b: [UInt8]) -> Bool {
        switch (b[0], b[1]) {
        case (0, _): return false  // "this network"
        case (10, _): return false  // private
        case (100, 64...127): return false  // CGNAT
        case (127, _): return false  // loopback
        case (169, 254): return false  // link-local
        case (172, 16...31): return false  // private
        case (192, 168): return false  // private
        case (192, 0) where b[2] == 0: return false  // IETF protocol assignments
        case (192, 0) where b[2] == 2: return false  // documentation TEST-NET-1
        case (198, 51) where b[2] == 100: return false  // documentation TEST-NET-2
        case (203, 0) where b[2] == 113: return false  // documentation TEST-NET-3
        case (198, 18...19): return false  // benchmarking
        case (224...255, _): return false  // multicast, reserved, broadcast
        default: return true
        }
    }

    static func isPublicV6(_ b: [UInt8]) -> Bool {
        let prefix96 = Array(b[0..<12])
        let v4 = Array(b[12..<16])
        // Mapped (::ffff:a.b.c.d), compatible (::a.b.c.d), NAT64 (64:ff9b::a.b.c.d).
        if prefix96 == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF]
            || prefix96 == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            || prefix96 == [0, 0x64, 0xFF, 0x9B, 0, 0, 0, 0, 0, 0, 0, 0]
        {
            // `::` and `::1` land here too: 0.0.0.0 and 0.0.0.1 are not public.
            return isPublicV4(v4)
        }
        // SIIT translated (::ffff:0:a.b.c.d): an IPv4 host behind a translator, refused outright.
        if prefix96 == [0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0] { return false }
        // 6to4 (2002:a.b.c.d::/48): the IPv4 address is in bytes 2 to 5.
        if b[0] == 0x20, b[1] == 0x02 { return isPublicV4(Array(b[2..<6])) }
        // Local-use NAT64 (64:ff9b:1::/48), Teredo (2001::/32), discard-only (100::/64) and
        // documentation (2001:db8::/32): never a site's own address.
        if b[0..<6] == [0, 0x64, 0xFF, 0x9B, 0, 0x01] { return false }
        if b[0..<4] == [0x20, 0x01, 0, 0] { return false }
        if b[0..<8] == [0x01, 0, 0, 0, 0, 0, 0, 0] { return false }
        if b[0..<4] == [0x20, 0x01, 0x0D, 0xB8] { return false }
        if b[0] == 0xFF { return false }  // multicast
        if b[0] & 0xFE == 0xFC { return false }  // unique-local fc00::/7
        if b[0] == 0xFE, b[1] & 0xC0 == 0x80 { return false }  // link-local fe80::/10
        if b[0] == 0xFE, b[1] & 0xC0 == 0xC0 { return false }  // site-local fec0::/10 (deprecated)
        return true
    }
}

/// Resolves a host name before any request of `SiteIconLoader`.
public protocol HostResolver: Sendable {
    /// Every address of `host`, or nil when it could not be resolved in time (no request is made).
    func addresses(for host: String) async -> [ResolvedAddress]?
}

/// `getaddrinfo` on a background thread (never the main thread), with a short timeout: a slow resolver
/// answers nil (the lookup itself cannot be cancelled and finishes in the background).
public struct SystemHostResolver: HostResolver {
    public let timeout: Duration

    public init(timeout: Duration = .seconds(3)) {
        self.timeout = timeout
    }

    public func addresses(for host: String) async -> [ResolvedAddress]? {
        let once = Mutex<CheckedContinuation<[ResolvedAddress]?, Never>?>(nil)
        let finish: @Sendable ([ResolvedAddress]?) -> Void = { result in
            once.withLock { pending in
                pending?.resume(returning: result)
                pending = nil
            }
        }
        let seconds = Double(timeout.components.seconds) + Double(timeout.components.attoseconds) / 1e18
        return await withCheckedContinuation { continuation in
            once.withLock { $0 = continuation }
            DispatchQueue.global(qos: .utility).async { finish(Self.lookup(host)) }
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + seconds) { finish(nil) }
        }
    }

    static func lookup(_ host: String) -> [ResolvedAddress]? {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        var list: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, "443", &hints, &list) == 0, let first = list else { return nil }
        defer { freeaddrinfo(list) }
        var result: [ResolvedAddress] = []
        var node: UnsafeMutablePointer<addrinfo>? = first
        while let entry = node {
            if let sockaddr = entry.pointee.ai_addr {
                switch Int32(entry.pointee.ai_family) {
                case AF_INET:
                    var address = sockaddr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
                    if let resolved = ResolvedAddress(bytes: withUnsafeBytes(of: &address) { Array($0) }) {
                        result.append(resolved)
                    }
                case AF_INET6:
                    var address = sockaddr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
                    if let resolved = ResolvedAddress(bytes: withUnsafeBytes(of: &address) { Array($0) }) {
                        result.append(resolved)
                    }
                default:
                    break
                }
            }
            node = entry.pointee.ai_next
        }
        return result
    }
}
