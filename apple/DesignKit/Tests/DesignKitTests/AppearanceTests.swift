import SwiftUI
import Testing

@testable import DesignKit

@Suite("Appearance")
struct AppearanceTests {
    @Test("System follows the system, light and dark force their scheme")
    func colorSchemes() {
        #expect(Appearance.system.colorScheme == nil)
        #expect(Appearance.light.colorScheme == .light)
        #expect(Appearance.dark.colorScheme == .dark)
    }

    @Test("A stored value round-trips, anything else follows the system")
    func stored() {
        for appearance in Appearance.allCases {
            #expect(Appearance(stored: appearance.rawValue) == appearance)
        }
        #expect(Appearance(stored: nil) == .system)
        #expect(Appearance(stored: "") == .system)
        #expect(Appearance(stored: "sepia") == .system)
    }

    @Test("The three choices, in picker order")
    func order() {
        #expect(Appearance.allCases == [.system, .light, .dark])
    }
}
