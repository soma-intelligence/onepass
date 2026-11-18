import Testing
@testable import DesignBridgeSnapshots

@Suite("Pseudo-locale")
struct PseudoLocalizerTests {
    let p = PseudoLocalizer.standard

    @Test(arguments: ["Settings", "Copy password", "Your vault is locked. Unlock it with Face ID to continue.", "OK", "a"])
    func growsByAtLeastFortyPercent(source: String) {
        let out = p.localize(source)
        let ratio = Double(out.count) / Double(source.count)
        #expect(ratio >= 1.4, "\(source) -> \(out) grew \(ratio)")
        // Not runaway: long strings stay close to the 40% target.
        if source.count >= 20 { #expect(ratio <= 1.5) }
    }

    @Test func accentsLettersAndBrackets() {
        let out = p.localize("Settings")
        #expect(out.hasPrefix("[Šéţţîñĝš"))
        #expect(out.hasSuffix("]"))
        #expect(!out.contains("Settings"))
    }

    @Test func keepsDigitsAndPunctuation() {
        let out = p.localize("3 items, 42%!")
        #expect(out.contains("3 "))
        #expect(out.contains("42"))
    }

    @Test(arguments: ["%@", "%d", "%1$@", "%2$ld", "%.2f", "%%", "{name}", "%lld"])
    func preservesPlaceholders(token: String) {
        let out = p.localize("Hello \(token) there")
        #expect(out.contains(token), "\(token) lost in \(out)")
    }

    @Test func placeholdersDoNotCountTowardsGrowth() {
        let withToken = p.localize("Hi %@")
        let without = p.localize("Hi ")
        #expect(withToken.count - 2 == without.count)
    }

    @Test func emptyStaysEmpty() {
        #expect(p.localize("") == "")
    }

    @Test func noBracketsOption() {
        let out = PseudoLocalizer(expansion: 0.4, brackets: false).localize("Settings")
        #expect(!out.hasPrefix("["))
        #expect(out.count >= Int((8 * 1.4).rounded(.up)))
    }

    @Test func zeroExpansionOnlyAccents() {
        #expect(PseudoLocalizer(expansion: 0, brackets: false).localize("abc") == "áƀç")
    }

    @Test func isDeterministic() {
        #expect(p.localize("Copy password") == p.localize("Copy password"))
    }

    @Test func localeTextAppliesOnlyToPseudo() {
        #expect(SnapshotLocale.en.text("Settings") == "Settings")
        #expect(SnapshotLocale.fr.text("Réglages") == "Réglages")
        #expect(SnapshotLocale.pseudo.text("Settings") == p.localize("Settings"))
    }
}
