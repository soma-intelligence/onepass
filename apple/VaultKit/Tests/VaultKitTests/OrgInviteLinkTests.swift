import Foundation
import Testing

@testable import VaultKit

@Suite("Organisation invitation links")
struct OrgInviteLinkTests {
    @Test func onlyOnepassOrgJoinIsAJoinLink() throws {
        let yes = [
            "onepass://org/join?v=1&s=https%3A%2F%2Forg.example.com",
            "onepass://org/join",
            "OnePass://ORG/join?v=1",
            "onepass://org/join/?v=1",
        ]
        for text in yes {
            #expect(OrgInviteLink.isJoinLink(try #require(URL(string: text))), "\(text)")
        }
        let no = [
            "onepass://item/abc",
            "onepass://generator",
            "onepass://org/leave",
            "onepass://org/joined",
            "onepass://other/join",
            "https://org/join",
            "otpauth://totp/x?secret=ABC",
        ]
        for text in no {
            #expect(!OrgInviteLink.isJoinLink(try #require(URL(string: text))), "\(text)")
        }
    }

    @Test func eachRefusalSaysWhatToDo() {
        let keys: [(OrgPinRefusal, String)] = [
            (.mdmInvalid, "org.refusal.mdmInvalid"),
            (.mdmMismatch, "org.refusal.mdmMismatch"),
            (.dnsMismatch, "org.refusal.dnsMismatch"),
        ]
        var messages = Set<String>()
        for (refusal, key) in keys {
            let message = refusal.message
            #expect(!message.isEmpty)
            #expect(message != key, "\(key) missing from the catalog")
            messages.insert(message)
        }
        #expect(messages.count == 3)
    }

    /// A join link waiting for the unlock lasts as long as a code link (it holds the invitation's
    /// credential and member token), and a clock moved back drops it.
    @Test func aWaitingInvitationExpiresLikeACodeLink() {
        let queued = Date(timeIntervalSince1970: 1_000_000)
        #expect(!PendingRequest.isExpired(queuedAt: queued, now: queued.addingTimeInterval(PendingRequest.lifetime)))
        #expect(PendingRequest.isExpired(queuedAt: queued, now: queued.addingTimeInterval(PendingRequest.lifetime + 1)))
        #expect(PendingRequest.isExpired(queuedAt: queued, now: queued.addingTimeInterval(-1)))
    }
}
