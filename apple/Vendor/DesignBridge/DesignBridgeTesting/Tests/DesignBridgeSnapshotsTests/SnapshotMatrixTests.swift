import Testing
@testable import DesignBridgeSnapshots

@Suite("Snapshot matrix")
struct SnapshotMatrixTests {
    @Test func standardMatrixCoversEveryAxis() {
        let m = SnapshotMatrix.standard
        #expect(m.appearances == [.light, .dark])
        #expect(m.contentSizes == [.xSmall, .large, .accessibility3, .accessibility5])
        #expect(m.devices.map(\.id) == ["iPhone17Pro", "iPhone17ProMax", "FoldableUnfolded", "iPad11"])
        #expect(m.locales.map(\.id) == ["en", "fr", "pseudo"])
        #expect(m.count == 96)
        #expect(m.variants.count == 96)
    }

    @Test func variantNamesAreUniqueAndFileSafe() {
        let names = SnapshotMatrix.standard.variants.map(\.name)
        #expect(Set(names).count == names.count)
        #expect(names.allSatisfy { $0.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" } })
        #expect(names.first == "iPhone17Pro-light-xs-en")
        #expect(names.contains("iPad11-dark-ax5-pseudo"))
    }

    @Test func narrowingKeepsOrder() {
        let m = SnapshotMatrix.standard.with(devices: [.iPhone17Pro]).with(locales: [.pseudo])
        #expect(m.count == 8)
        #expect(m.variants.map(\.name).prefix(2) == ["iPhone17Pro-light-xs-pseudo", "iPhone17Pro-light-l-pseudo"])
    }

    @Test func smokeMatrixIsSmall() {
        #expect(SnapshotMatrix.smoke.count == 8)
    }

    @Test func devicesHaveExpectedFrames() {
        #expect(SnapshotDevice.iPhone17Pro.size.width == 402 && SnapshotDevice.iPhone17Pro.size.height == 874)
        #expect(SnapshotDevice.iPhone17ProMax.size.width == 440)
        #expect(SnapshotDevice.foldableUnfolded.size.width == 669)
        #expect(SnapshotDevice.foldableUnfolded.horizontalSizeClass == .regular)
        #expect(SnapshotDevice.iPad.idiom == .pad && SnapshotDevice.iPad.scale == 2)
    }

    @Test func contentSizesMapToDynamicType() {
        #expect(SnapshotContentSize.accessibility5.dynamicTypeSize == .accessibility5)
        #expect(SnapshotContentSize.xSmall.dynamicTypeSize == .xSmall)
    }

    @Test func pseudoLocaleReadsEnglishStrings() {
        #expect(SnapshotLocale.pseudo.stringsLanguage == "en")
        #expect(SnapshotLocale.fr.stringsLanguage == "fr")
        #expect(SnapshotLocale.pseudo.identifier == "en_XA")
    }

    @Test func defaultPrecisions() {
        #expect(SnapshotMatrixDefaults.perceptualPrecision == 0.98)
        #expect(SnapshotMatrixDefaults.precision == 0.99)
    }
}
