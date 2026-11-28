import Testing
@testable import VaultKit

struct PairingScanTextTests {
    @Test func rendezvousCodeJoinsTheCode() {
        #expect(PairingScanText.route("OPPAIR2:ABCDEFGH") == .rendezvous("OPPAIR2:ABCDEFGH"))
    }

    /// The Mac's Réglages > Appareils > Ajouter shows an invite: it used to be dropped silently.
    @Test func inviteFromTheMacIsAccepted() {
        #expect(PairingScanText.route(" OPPAIR1:AAAABBBB\n") == .invite("OPPAIR1:AAAABBBB"))
    }

    @Test func anythingElseIsRefused() {
        #expect(PairingScanText.route("https://example.com/OPPAIR1:AAAA") == nil)
        #expect(PairingScanText.route("OPPAIR1:") == nil)
        #expect(PairingScanText.route("OPPAIR3:AAAA") == nil)
        #expect(PairingScanText.route("") == nil)
    }
}
