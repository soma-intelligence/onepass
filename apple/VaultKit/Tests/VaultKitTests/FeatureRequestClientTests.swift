import Foundation
import Synchronization
import Testing
@testable import VaultKit

/// The feature request client against a fake transport: no request ever reaches the real function.
@Suite("FeatureRequestClient")
struct FeatureRequestClientTests {
    private static let fakeEndpoint = URL(string: "https://example.test/functions/v1/feature-request")!

    private func response(_ status: Int) -> HTTPURLResponse {
        HTTPURLResponse(url: Self.fakeEndpoint, statusCode: status, httpVersion: "HTTP/1.1", headerFields: nil)!
    }

    private func idea(_ message: String = "  Dark mode for the watch  ", email: String? = nil) -> FeatureRequest {
        FeatureRequest(
            message: message, email: email, platform: "ios", installID: "0F8E2A4C-1B3D-4E5F-8A9B-C0D1E2F3A4B5",
            appVersion: "0.3.0 (1)", osVersion: "26.1.0", deviceModel: "iPhone17,1", locale: "fr_FR")
    }

    private func body(_ request: URLRequest) throws -> [String: String] {
        let object = try JSONSerialization.jsonObject(with: try #require(request.httpBody))
        return try #require(object as? [String: String])
    }

    @Test func buildsThePostWithTheAppAndTrimmedMessage() throws {
        let client = FeatureRequestClient(endpoint: Self.fakeEndpoint)
        let request = try client.makeRequest(idea(email: " me@example.com "))
        #expect(request.httpMethod == "POST")
        #expect(request.url == Self.fakeEndpoint)
        #expect(request.value(forHTTPHeaderField: "Content-Type") == "application/json")
        #expect(request.value(forHTTPHeaderField: "Authorization") == nil)
        let json = try body(request)
        #expect(json == [
            "app": "onepass",
            "platform": "ios",
            "message": "Dark mode for the watch",
            "email": "me@example.com",
            "install_id": "0f8e2a4c-1b3d-4e5f-8a9b-c0d1e2f3a4b5",
            "app_version": "0.3.0 (1)",
            "os_version": "26.1.0",
            "device_model": "iPhone17,1",
            "locale": "fr_FR",
        ])
    }

    @Test func leavesOutAnEmptyEmailAndClipsLongFacts() throws {
        var long = idea(email: "   ")
        long.deviceModel = String(repeating: "m", count: 80)
        long.locale = String(repeating: "l", count: 30)
        let json = try body(FeatureRequestClient(endpoint: Self.fakeEndpoint).makeRequest(long))
        #expect(json["email"] == nil)
        #expect(json["device_model"]?.count == 60)
        #expect(json["locale"]?.count == 20)
    }

    @Test func refusesShortLongAndBadEmailBeforeSending() {
        let client = FeatureRequestClient(endpoint: Self.fakeEndpoint)
        #expect(throws: FeatureRequestError.messageTooShort) { try client.makeRequest(idea(" a  b \n")) }
        #expect(throws: FeatureRequestError.messageTooLong) {
            try client.makeRequest(idea(String(repeating: "x", count: 4001)))
        }
        #expect(throws: FeatureRequestError.invalidEmail) { try client.makeRequest(idea(email: "not an email")) }
        #expect(throws: FeatureRequestError.invalidEmail) { try client.makeRequest(idea(email: "me@example")) }
        #expect((try? client.makeRequest(idea(String(repeating: "x", count: 4000)))) != nil)
    }

    @Test func sendButtonNeedsThreeNonSpaceCharacters() {
        #expect(!FeatureRequestClient.canSend(""))
        #expect(!FeatureRequestClient.canSend("a b\n\t"))
        #expect(FeatureRequestClient.canSend(" a b c "))
        #expect(FeatureRequestClient.canSend("idée"))
    }

    @Test func parsesTheCreatedID() throws {
        let data = Data(#"{"id":42}"#.utf8)
        #expect(try FeatureRequestClient.parse(data: data, response: response(201)) == 42)
    }

    @Test func mapsEveryErrorAnswer() {
        func parse(_ status: Int, _ body: String) throws(FeatureRequestError) {
            _ = try FeatureRequestClient.parse(data: Data(body.utf8), response: response(status))
        }
        #expect(throws: FeatureRequestError.messageTooShort) { try parse(400, #"{"error":"message_too_short"}"#) }
        #expect(throws: FeatureRequestError.messageTooLong) { try parse(400, #"{"error":"message_too_long"}"#) }
        #expect(throws: FeatureRequestError.invalidEmail) { try parse(400, #"{"error":"invalid_email"}"#) }
        #expect(throws: FeatureRequestError.server) { try parse(400, #"{"error":"invalid_platform"}"#) }
        #expect(throws: FeatureRequestError.rateLimited) { try parse(429, #"{"error":"rate_limited"}"#) }
        #expect(throws: FeatureRequestError.server) { try parse(500, #"{"error":"server_error"}"#) }
        #expect(throws: FeatureRequestError.server) { try parse(201, "not json") }
    }

    @Test func sendsThroughTheTransportOnce() async throws {
        let seen = Mutex<[URLRequest]>([])
        let client = FeatureRequestClient(endpoint: Self.fakeEndpoint) { request in
            seen.withLock { $0.append(request) }
            return (Data(#"{"id":7}"#.utf8),
                    HTTPURLResponse(url: request.url!, statusCode: 201, httpVersion: nil, headerFields: nil)!)
        }
        let id = try await client.send(idea())
        #expect(id == 7)
        #expect(seen.withLock { $0.count } == 1)
    }

    @Test func aTransportFailureIsANetworkError() async {
        let client = FeatureRequestClient(endpoint: Self.fakeEndpoint) { _ in throw URLError(.notConnectedToInternet) }
        await #expect(throws: FeatureRequestError.network) { try await client.send(idea()) }
    }

    @Test func nothingIsSentForAnInvalidIdea() async {
        let calls = Mutex(0)
        let client = FeatureRequestClient(endpoint: Self.fakeEndpoint) { request in
            calls.withLock { $0 += 1 }
            return (Data(), HTTPURLResponse(url: request.url!, statusCode: 201, httpVersion: nil, headerFields: nil)!)
        }
        await #expect(throws: FeatureRequestError.messageTooShort) { try await client.send(idea("  ")) }
        #expect(calls.withLock { $0 } == 0)
    }

    @Test func installIDIsMadeOnceAndKept() throws {
        let defaults = try #require(UserDefaults(suiteName: "feature-request-\(UUID().uuidString)"))
        let first = FeatureRequest.installID(defaults)
        #expect(first == first.lowercased())
        #expect(UUID(uuidString: first) != nil)
        #expect(FeatureRequest.installID(defaults) == first)
    }

    @MainActor @Test func currentIdeaCarriesTheDeviceFacts() {
        let defaults = UserDefaults(suiteName: "feature-request-\(UUID().uuidString)")!
        let current = FeatureRequest.current(message: "Hello", email: nil, defaults: defaults)
        #expect(["ios", "ipados", "macos", "visionos", "watchos"].contains(current.platform))
        #expect(current.installID != nil)
        #expect(current.osVersion?.isEmpty == false)
        #expect(current.deviceModel?.isEmpty == false)
    }
}
