import Foundation
import Testing
import VaultKit

@testable import DesignKit

@Suite struct ItemCategoryTests {
    @Test func everyTypeHasACategory() {
        #expect(ItemCategory.all.count == 26)
        #expect(Set(ItemCategory.all.map(\.plural)).count == 26)
        #expect(Set(ItemCategory.all.map(\.singular)).count == 26)
        for info in itemTypes() {
            #expect(ItemCategory.of(info.itemType).type == info.itemType)
            #expect(!ItemCategory.of(info.itemType).symbol.isEmpty)
        }
    }

    @Test func orderMatchesCore() {
        #expect(ItemCategory.all.map(\.type) == itemTypes().map(\.itemType))
    }

    @Test func singularMatchesCoreLabels() {
        for info in itemTypes() {
            #expect(ItemCategory.of(info.itemType).singular == info.label)
        }
    }

    @Test func strengthLabels() {
        #expect(StrengthMeter.label(forBits: 0) == "trop court")
        #expect(StrengthMeter.label(forBits: 39.9) == "trop court")
        #expect(StrengthMeter.label(forBits: 40) == "faible")
        #expect(StrengthMeter.label(forBits: 60) == "moyen")
        #expect(StrengthMeter.label(forBits: 80) == "bon")
        #expect(StrengthMeter.label(forBits: 99.9) == "bon")
        #expect(StrengthMeter.label(forBits: 100) == "excellent")
        #expect(StrengthMeter.level(forBits: 39) == 0)
        #expect(StrengthMeter.level(forBits: 250) == 4)
    }

    @Test func integrityTexts() {
        #expect(IntegrityBanner.message(for: "unknown") == "Le stockage a renvoyé des données altérées.")
        #expect(IntegrityBanner.message(for: "manifest_rollback") != IntegrityBanner.message(for: "unknown"))
    }

    @Test func noEmDashInTexts() {
        for c in ItemCategory.all {
            #expect(!c.plural.contains("\u{2014}"))
        }
    }

    @Test func vaultColorsResolve() {
        for name in ["blue", "teal", "orange", "green", "purple", "pink", "gray", "inconnu"] {
            _ = VaultBadge.color(named: name)
        }
        #expect(VaultBadge.initial(of: "  projet Atlas") == "P")
        #expect(VaultBadge.initial(of: "") == "?")
    }
}

@Suite struct ItemIconTests {
    // 1x1 PNG.
    static let png = Data(
        base64Encoded:
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==")!

    @Test func decodesPNGAndRejectsGarbage() {
        #expect(ItemIcon.decode(Self.png) != nil)
        #expect(ItemIcon.decode(Data([1, 2, 3])) == nil)
        #expect(ItemIcon.decode(Data()) == nil)
    }
}
