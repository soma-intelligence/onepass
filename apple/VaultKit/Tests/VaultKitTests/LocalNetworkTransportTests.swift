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

    /// The transport contract: a `receive` whose task is cancelled throws `CancellationError`, not
    /// `closed`. The flows read `closed` as "the other device left" and would replace the reason they
    /// stopped for ("Ils sont différents") with "La connexion a été coupée".
    @Test(.timeLimit(.minutes(1))) func localNetworkReceiveCancelledThrowsCancellation() async throws {
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
        defer { server.close() }

        let reading = Task { try await client.receive() }
        try await Task.sleep(for: .milliseconds(200))
        reading.cancel()
        await #expect(throws: CancellationError.self) { _ = try await reading.value }
        // The cancelled read closed the connection: the other side sees it.
        await #expect(throws: PairingTransportError.closed) { _ = try await server.receive() }
    }

    /// The listener stays published while a first connection is being checked, and a reader's cap
    /// refuses a longer frame before its body is read (M2).
    @Test(.timeLimit(.minutes(1))) func localNetworkListenerKeepsServiceAndCapsFrames() async throws {
        let service = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let stream = LocalNetworkPairingListener().connections(serviceName: service)
        let accepted = Task { () -> [any PairingTransport] in
            var out: [any PairingTransport] = []
            for try await t in stream {
                out.append(t)
                if out.count == 2 { break }
            }
            return out
        }
        let connector = LocalNetworkPairingConnector(timeout: .seconds(15))
        let first: any PairingTransport
        do {
            first = try await connector.connect(serviceName: service)
        } catch {
            accepted.cancel()
            try Test.cancel(
                "Bonjour unavailable here (\(error)): the service could not be published or resolved on this Mac.")
        }
        // The first connection stays open and silent; a second one still finds the service.
        let second = try await connector.connect(serviceName: service)
        let servers = try await accepted.value
        defer {
            for t in servers + [first, second] { t.close() }
        }
        #expect(servers.count == 2)
        try await second.send(Data(count: PairingFrame.maxHandshakeBytes + 1))
        var refused = false
        for server in servers {
            do {
                async let read = server.receive(maxBytes: PairingFrame.maxHandshakeBytes)
                try await first.send(Data([1]))
                let frame = try await read
                #expect(frame == Data([1]))
            } catch PairingTransportError.frameTooLarge {
                refused = true
            }
        }
        #expect(refused, "the frame above 16 KiB was refused")
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
