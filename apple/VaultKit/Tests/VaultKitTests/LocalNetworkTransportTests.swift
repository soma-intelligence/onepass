import Foundation
import Testing

@testable import VaultKit

@Suite("Local network pairing transport")
struct LocalNetworkTransportTests {
    /// Listener and connector on this Mac, over Bonjour on the loopback. Where Bonjour cannot publish
    /// or resolve (a sandbox without local network access), the test is skipped, not failed.
    @Test(.timeLimit(.minutes(1))) func localNetworkTransportRoundTrip() async throws {
        let service = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let listening = Task { try await LocalNetworkPairingListener().listen(serviceName: service) }
        let client: any PairingTransport
        do {
            client = try await LocalNetworkPairingConnector(timeout: .seconds(15)).connect(serviceName: service)
        } catch {
            listening.cancel()
            try Test.cancel(
                "Bonjour unavailable here (\(error)): the service could not be published or resolved on this Mac.")
        }
        let server = try await listening.value
        defer {
            client.close()
            server.close()
        }

        try await server.send(Data("hello".utf8))
        #expect(try await client.receive() == Data("hello".utf8))
        let big = Data((0..<(3 << 20)).map { UInt8(truncatingIfNeeded: $0) })
        // The receiver reads while the sender writes (TCP backpressure holds a send otherwise).
        async let received = server.receive()
        try await client.send(big)
        #expect(try await received == big)
        try await client.send(Data())
        #expect(try await server.receive() == Data())

        // A frame above 64 MiB is refused before it leaves.
        await #expect(throws: PairingTransportError.frameTooLarge) {
            try await client.send(Data(count: PairingFrame.maxBytes + 1))
        }
        // That closed the connection: the other side sees it.
        await #expect(throws: PairingTransportError.closed) { _ = try await server.receive() }
    }

    @Test func inMemoryTransportClosesBothWays() async throws {
        let (a, b) = InMemoryPairingTransport.pair()
        try await a.send(Data([1]))
        a.close()
        // A frame already delivered is still read, then the close.
        #expect(try await b.receive() == Data([1]))
        await #expect(throws: PairingTransportError.closed) { _ = try await b.receive() }
        await #expect(throws: PairingTransportError.closed) { try await b.send(Data([2])) }
    }
}
