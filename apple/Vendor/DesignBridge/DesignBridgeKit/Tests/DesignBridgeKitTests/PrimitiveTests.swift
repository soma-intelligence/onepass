import SwiftUI
import Testing
@testable import DesignBridgeKit

@Suite("Motion tokens (UX-MOT-01, UX-PRESS-01)")
struct MotionTests {
    @Test(arguments: DBSpring.all)
    func springDurationsStayShort(spring: DBSpring) {
        #expect((0.15...0.5).contains(spring.duration))
    }

    @Test func functionalSpringsDoNotBounce() {
        #expect(DBSpring.snappy.bounce == 0)
        #expect(DBSpring.smooth.bounce == 0)
        #expect((0.15...0.3).contains(DBSpring.bouncy.bounce))
    }

    @Test func pressScaleIs097() {
        #expect(DBMotion.pressScale == 0.97)
    }

    @Test func reduceMotionFallsBackToCrossfade() {
        for spring in DBSpring.all {
            #expect(spring.animation(reduceMotion: true) == DBMotion.crossfade)
            #expect(spring.animation(reduceMotion: false) == spring.animation)
        }
    }
}

@Suite("Haptics map (UX-HAPT-01)")
struct HapticsTests {
    @Test func mapIsFixed() {
        #expect(DBHapticEvent.selection.feedback == .selection)
        #expect(DBHapticEvent.snap.feedback == .impact(weight: .light))
        #expect(DBHapticEvent.commit.feedback == .impact(weight: .medium))
        #expect(DBHapticEvent.success.feedback == .success)
        #expect(DBHapticEvent.warning.feedback == .warning)
        #expect(DBHapticEvent.error.feedback == .error)
        #expect(DBHapticEvent.increase.feedback == .increase)
        #expect(DBHapticEvent.decrease.feedback == .decrease)
        #expect(DBHapticEvent.levelChange.feedback == .levelChange)
    }

    // Note: SensoryFeedback equality cannot tell impact weights apart (every
    // weight reads back as `light` in the iOS 26 and macOS 26 SDKs), so the
    // two impact rows above are checked by reading the code, not by equality.

    @Test func toastsPairWithMatchingHaptic() {
        #expect(DBHapticEvent.forToast(.success) == .success)
        #expect(DBHapticEvent.forToast(.error) == .error)
        #expect(DBHapticEvent.forToast(.info) == nil)
    }
}

@Suite("Scroll hero geometry (UX-SCROLL-03, UX-MOT-03)")
struct ScrollHeroTests {
    private func metrics(offset: CGFloat, parallax: CGFloat? = 0.4, reduceMotion: Bool = false) -> DBScrollHeroMetrics {
        DBScrollHeroMetrics(offset: offset, heroHeight: 300, fadeDistance: 180, parallax: parallax, reduceMotion: reduceMotion)
    }

    @Test func atRestHeaderIsFullyVisible() {
        let m = metrics(offset: 0)
        #expect(m.headerOpacity == 1)
        #expect(m.headerScale == 1)
        #expect(m.backdropOffset == 0)
        #expect(m.backdropScale == 1)
    }

    @Test func headerFadesAndScalesWithScroll() {
        let half = metrics(offset: 90)
        #expect(half.progress == 0.5)
        #expect(half.headerOpacity == 0.5)
        #expect(abs(half.headerScale - 0.95) < 0.0001)
        let gone = metrics(offset: 400)
        #expect(gone.headerOpacity == 0)
        #expect(gone.headerScale == DBScrollHeroMetrics.minimumHeaderScale)
    }

    @Test func headerStaysPinned() {
        #expect(metrics(offset: 120).headerOffset == 120)
    }

    @Test func pullDownMovesHeaderWithContent() {
        // Negative offset: no counter-offset, so the header rides down with the sheet.
        #expect(metrics(offset: -80).headerOffset == 0)
        #expect(metrics(offset: -80).headerOpacity == 1)
        #expect(metrics(offset: -80).headerScale == 1)
        #expect(metrics(offset: -80).backdropScale > 1)
    }

    @Test func headerScalesFromBottomCentreByDefault() {
        #expect(DBScrollHeroMetrics.defaultHeaderAnchor == .bottom)
    }

    @Test func parallaxMovesBackdropSlower() {
        #expect(metrics(offset: 100).backdropOffset == -40)
    }

    @Test func parallaxIsClampedToRange() {
        #expect(metrics(offset: 0, parallax: 0.9).parallax == 0.5)
        #expect(metrics(offset: 0, parallax: 0.1).parallax == 0.3)
        #expect(metrics(offset: 100, parallax: nil).backdropOffset == 0)
    }

    @Test func pullDownStretchesBackdrop() {
        #expect(metrics(offset: -150).backdropScale == 1.5)
        #expect(metrics(offset: -150).headerOpacity == 1)
    }

    @Test func reduceMotionKeepsOnlyTheCrossfade() {
        let m = metrics(offset: 90, reduceMotion: true)
        #expect(m.headerOpacity == 0.5)
        #expect(m.headerScale == 1)
        #expect(m.backdropOffset == 0)
        #expect(metrics(offset: -150, reduceMotion: true).backdropScale == 1)
    }
}

@Suite("Text fit (UX-TEXT-01)")
struct TextFitTests {
    @Test func budgetAccountsForLinesAndScale() {
        // 400 pt on one line, two lines at 0.85: 400 * 0.85 / (2 * 0.9).
        let budget = DBTextFit.budgetWidth(singleLineWidth: 400, maxLines: 2, minimumScale: 0.85)
        #expect(abs(budget - 188.888) < 0.01)
        #expect(DBTextFit.fits(singleLineWidth: 400, availableWidth: 200, maxLines: 2, minimumScale: 0.85))
        #expect(!DBTextFit.fits(singleLineWidth: 400, availableWidth: 150, maxLines: 2, minimumScale: 0.85))
    }

    @Test func scaleNeverGoesBelowFloor() {
        let floor = DBTextFit.budgetWidth(singleLineWidth: 100, maxLines: 1, minimumScale: 0.7)
        #expect(DBTextFit.budgetWidth(singleLineWidth: 100, maxLines: 1, minimumScale: 0.1) == floor)
    }

    @Test func zeroLinesCountsAsOne() {
        #expect(DBTextFit.budgetWidth(singleLineWidth: 90, maxLines: 0, minimumScale: 1) == 100)
    }
}

@Suite("Truncation probe")
struct TruncationProbeTests {
    private let line = CGSize(width: 300, height: 20)

    @Test func fullTextIsNotReported() {
        #expect(DBTruncationReport.evaluate(id: "a", actual: CGSize(width: 300, height: 20), wrappedIdeal: CGSize(width: 300, height: 20), singleLineIdeal: line) == nil)
    }

    @Test func wrappedTextShownInFullIsNotReported() {
        #expect(DBTruncationReport.evaluate(id: "a", actual: CGSize(width: 160, height: 40), wrappedIdeal: CGSize(width: 160, height: 40), singleLineIdeal: line) == nil)
    }

    @Test func lostLinesAreClipped() {
        let report = DBTruncationReport.evaluate(id: "a", actual: CGSize(width: 160, height: 40), wrappedIdeal: CGSize(width: 160, height: 60), singleLineIdeal: line)
        #expect(report?.kind == .clipped)
    }

    @Test func singleLineTooNarrowIsCompressed() {
        let report = DBTruncationReport.evaluate(id: "a", actual: CGSize(width: 160, height: 20), wrappedIdeal: CGSize(width: 160, height: 20), singleLineIdeal: line)
        #expect(report?.kind == .compressed)
        #expect(report?.id == "a")
    }

    @Test func unmeasuredViewIsIgnored() {
        #expect(DBTruncationReport.evaluate(id: "a", actual: .zero, wrappedIdeal: line, singleLineIdeal: line) == nil)
    }
}

@Suite("Theme")
struct ThemeTests {
    @Test func defaultsComeFromTheProtocol() {
        struct Minimal: DBTheme {}
        let theme = Minimal()
        #expect(theme.sheetCornerRadius == 28)
        #expect(theme.spacing == DBSpacing())
    }

    @Test func spacingStaysOnTheFourPointGrid() {
        let s = DBSpacing()
        for value in [s.xs, s.s, s.m, s.l, s.xl, s.xxl] {
            #expect(value.truncatingRemainder(dividingBy: 4) == 0)
        }
    }
}

@Suite("Press style respects isEnabled")
struct PressMetricsTests {
    @Test func disabledNeverScalesAndDrawsDimmed() {
        #expect(DBPressMetrics.opacity(pressed: false, reduceMotion: false, isEnabled: false) == DBMotion.disabledOpacity)
        #expect(DBPressMetrics.opacity(pressed: true, reduceMotion: true, isEnabled: false) == DBMotion.disabledOpacity)
    }

    @Test func enabledPressScalesOrDims() {
        #expect(DBPressMetrics.scale(pressed: true, reduceMotion: false) == DBMotion.pressScale)
        #expect(DBPressMetrics.scale(pressed: true, reduceMotion: true) == 1)
        #expect(DBPressMetrics.opacity(pressed: true, reduceMotion: true, isEnabled: true) == DBMotion.pressOpacityReduced)
        #expect(DBPressMetrics.opacity(pressed: false, reduceMotion: false, isEnabled: true) == 1)
    }
}
