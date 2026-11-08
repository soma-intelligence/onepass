import Testing

@testable import DesignKit

@Suite("Fold layout")
struct FoldLayoutTests {
    @Test("The iPhone Duo inner screen in portrait is unfolded")
    func duoInner() {
        #expect(FoldLayout.isUnfolded(width: 669))
        #expect(FoldLayout.isUnfolded(width: 951))
    }

    @Test("The Duo cover screen and every other iPhone in portrait stay folded")
    func folded() {
        #expect(!FoldLayout.isUnfolded(width: 466))
        #expect(!FoldLayout.isUnfolded(width: 440))
        #expect(!FoldLayout.isUnfolded(width: 375))
        #expect(!FoldLayout.isUnfolded(width: 0))
    }

    @Test("The threshold sits between the widest folded and narrowest unfolded width")
    func threshold() {
        #expect(FoldLayout.minWidth > 466)
        #expect(FoldLayout.minWidth <= 669)
    }
}
