import Foundation
import Testing

@testable import VaultKit

@Suite("Generator profile store")
struct GeneratorProfileStoreTests {
    private func withSuite(_ body: (UserDefaults) throws -> Void) rethrows {
        let suite = "onepass.tests.generator.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        try body(defaults)
    }

    @Test func roundTrip() {
        withSuite { defaults in
            let store = GeneratorProfileStore(defaults: defaults)
            for profile in [
                GeneratorProfile.readable, .custom(length: 12, digits: false, symbols: true), .strong,
            ] {
                store.profile = profile
                #expect(GeneratorProfileStore(defaults: defaults).profile == profile)
            }
            #expect(defaults.data(forKey: "generator.profile") != nil)
        }
    }

    @Test func missingOrUnreadableIsStrong() {
        withSuite { defaults in
            let store = GeneratorProfileStore(defaults: defaults)
            #expect(store.profile == .strong)
            defaults.set(Data("not json".utf8), forKey: "generator.profile")
            #expect(store.profile == .strong)
            defaults.set("readable", forKey: "generator.profile")
            #expect(store.profile == .strong)
        }
    }

    @Test func ffiProfileClampsCustomLength() {
        #expect(GeneratorProfile.strong.ffi == .strong)
        #expect(GeneratorProfile.readable.ffi == .readable)
        #expect(
            GeneratorProfile.custom(length: 3, digits: true, symbols: false).ffi
                == .custom(length: 8, digits: true, symbols: false))
        #expect(
            GeneratorProfile.custom(length: 500, digits: false, symbols: true).ffi
                == .custom(length: 64, digits: false, symbols: true))
    }

    @Test func generatesThroughTheCore() throws {
        let context = FfiPasswordContext(
            rules: ["required: lower; required: digit; maxlength: 16;"], quirkRules: nil, minLength: nil,
            maxLength: nil, hintText: nil)
        let generated = try passwordForContext(context: context, profile: GeneratorProfile.strong.ffi)
        #expect(generated.password.count == 16)
        #expect(!generated.fallback)
    }
}
