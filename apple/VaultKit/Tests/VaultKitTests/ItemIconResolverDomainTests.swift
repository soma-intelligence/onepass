import Testing

@testable import VaultKit

@Suite struct ItemIconResolverDomainTests {
    @Test func subdomainsShareTheirRegistrableDomain() {
        #expect(ItemIconResolver.registrableDomain("https://accounts.atlas-cloud.example/login") == "atlas-cloud.example")
        #expect(ItemIconResolver.registrableDomain("atlas-cloud.example") == "atlas-cloud.example")
        #expect(ItemIconResolver.registrableDomain("https://www.boutique.co.uk") == "boutique.co.uk")
        #expect(ItemIconResolver.registrableDomain("HTTPS://Mail.Exemple.FR") == "exemple.fr")
    }

    @Test func addressesAndLocalNamesAreTheirOwnDomain() {
        #expect(ItemIconResolver.registrableDomain("http://192.168.1.1/admin") == "192.168.1.1")
        #expect(ItemIconResolver.registrableDomain("http://nas:5000") == "nas")
    }

    @Test func noDomainWithoutAWebAddress() {
        #expect(ItemIconResolver.registrableDomain(nil) == nil)
        #expect(ItemIconResolver.registrableDomain("") == nil)
        #expect(ItemIconResolver.registrableDomain("ftp://files.example.com") == nil)
        #expect(ItemIconResolver.registrableDomain("https://co.uk") == nil)
    }
}
