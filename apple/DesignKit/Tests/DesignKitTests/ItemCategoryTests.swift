import Foundation
import Testing
import VaultKit

@testable import DesignKit

@Suite struct ItemCategoryTests {
    /// Labels are compared in French, the source language, whatever the machine's language.
    init() { DesignKitStrings.pinSourceLanguage() }

    @Test func everyTypeHasACategory() {
        #expect(ItemCategory.all.count == 26)
        #expect(Set(ItemCategory.all.map(\.plural)).count == 26)
        #expect(Set(ItemCategory.all.map(\.singular)).count == 26)
        for info in itemTypes() {
            #expect(ItemCategory.of(info.itemType).type == info.itemType)
            #expect(!ItemCategory.of(info.itemType).symbol.isEmpty)
        }
    }

    @Test func hexMatchesTileColor() {
        #expect(ItemCategory.of(.login).hex == 0x0E9F9F)
        #expect(ItemCategory.all.allSatisfy { $0.hex <= 0xFFFFFF })
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
        #expect(IntegrityBanner.message(for: "account_missing") == "Le compte a disparu du stockage.")
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

@Suite struct FieldDisclosureTests {
    @Test func largeOnSecretRevealsAndNotifies() {
        var d = FieldDisclosure()
        let n = d.showLarge(isSecret: true)
        #expect(n)
        #expect(d.revealed && d.large)
    }

    @Test func remaskClosesLarge() {
        var d = FieldDisclosure()
        _ = d.showLarge(isSecret: true)
        let n = d.reveal(false, isSecret: true)
        #expect(n)
        #expect(!d.revealed && !d.large)
    }

    @Test func plainFieldNeverNotifies() {
        var d = FieldDisclosure()
        let n = d.showLarge(isSecret: false)
        #expect(!n)
        #expect(d.large && !d.revealed)
        let m = d.reveal(true, isSecret: false)
        #expect(!m)
    }
}

@Suite struct FieldAutoRemaskTests {
    @Test func remasksAfterDelayOnly() {
        let t0 = Date(timeIntervalSince1970: 1000)
        var d = FieldDisclosure()
        _ = d.reveal(true, isSecret: true, now: t0)
        #expect(!d.shouldRemask(now: t0.addingTimeInterval(29.9), after: 30))
        #expect(d.shouldRemask(now: t0.addingTimeInterval(30), after: 30))
    }

    @Test func largeDisplayCountsAndRemaskClosesIt() {
        let t0 = Date(timeIntervalSince1970: 0)
        var d = FieldDisclosure()
        _ = d.showLarge(isSecret: true, now: t0)
        #expect(d.shouldRemask(now: t0.addingTimeInterval(31), after: 30))
        _ = d.reveal(false, isSecret: true, now: t0.addingTimeInterval(31))
        #expect(!d.large && d.revealedAt == nil)
        #expect(!d.shouldRemask(now: t0.addingTimeInterval(99), after: 30))
    }

    @Test func maskedOrPlainNeverRemask() {
        let d = FieldDisclosure()
        #expect(!d.shouldRemask(now: Date.distantFuture, after: 30))
    }
}
