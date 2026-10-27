import Foundation
import Testing

@testable import VaultKit

@Suite("Intent authentication")
struct IntentAuthenticationTests {
    @Test func onlyALaterUnlockIsFresh() {
        #expect(IntentAuthentication.isFreshUnlockRequest(state: .locked, onboarding: false))
        // Queued while unlocked during the onboarding (restored account).
        #expect(!IntentAuthentication.isFreshUnlockRequest(state: .unlocked, onboarding: true))
        #expect(!IntentAuthentication.isFreshUnlockRequest(state: .locked, onboarding: true))
        // An unlock already in flight was confirmed before the request.
        #expect(!IntentAuthentication.isFreshUnlockRequest(state: .unlocking, onboarding: false))
        #expect(!IntentAuthentication.isFreshUnlockRequest(state: .unlocked, onboarding: false))
        #expect(!IntentAuthentication.isFreshUnlockRequest(state: .noAccount, onboarding: false))
        #expect(!IntentAuthentication.isFreshUnlockRequest(state: .failed(.wrongPassword), onboarding: false))
    }
}
