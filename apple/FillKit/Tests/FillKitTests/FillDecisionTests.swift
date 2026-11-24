import CoreGraphics
import Testing

@testable import FillKit

@Suite struct FillDecisionTests {
    @Test func strategiesRunInOrder() {
        #expect(FillDecision.next(after: .start) == .accessibility)
        #expect(FillDecision.next(after: .failed(.accessibility)) == .typing)
        #expect(FillDecision.next(after: .failed(.typing)) == .clipboard)
        #expect(FillDecision.next(after: .failed(.clipboard)) == nil)
    }

    @Test func aStrategyThatWorkedEndsTheChain() {
        for strategy in FillStrategy.allCases {
            #expect(FillDecision.next(after: .worked(strategy)) == nil)
        }
    }

    @Test func rawValuesNameTheStrategyInTheLog() {
        #expect(FillStrategy.accessibility.rawValue == "accessibility")
        #expect(FillStrategy.typing.rawValue == "typing")
        #expect(FillStrategy.clipboard.rawValue == "clipboard")
    }

    @Test func secureInputBlocksTyping() {
        // Owned by another process: typing is not chosen, the clipboard is offered.
        let elsewhere = SecureInput.owned(by: 42)
        #expect(FillDecision.secureInputBlocksTyping(elsewhere, targetPID: 7))
        #expect(FillDecision.next(after: .failed(.accessibility), typingBlocked: true) == .clipboard)
        #expect(FillDecision.next(after: .start, typingBlocked: true) == .accessibility)
        #expect(FillDecision.next(after: .failed(.clipboard), typingBlocked: true) == nil)
    }

    @Test func secureInputOfTheTargetItselfAllowsTyping() {
        #expect(!FillDecision.secureInputBlocksTyping(.owned(by: 7), targetPID: 7))
        #expect(!FillDecision.secureInputBlocksTyping(.off, targetPID: 7))
    }

    @Test func secureInputWithNoKnownOwnerCountsAsElsewhere() {
        #expect(FillDecision.secureInputBlocksTyping(.ownerUnknown, targetPID: 7))
    }

    @Test func keysGoInBatchesOfEight() {
        #expect(FillDecision.keysPerBatch == 8)
        #expect(FillDecision.batches(of: 0).isEmpty)
        #expect(FillDecision.batches(of: 3) == [0..<3])
        #expect(FillDecision.batches(of: 8) == [0..<8])
        #expect(FillDecision.batches(of: 17) == [0..<8, 8..<16, 16..<17])
    }
}

@Suite struct ScreenGeometryTests {
    @Test func axTopLeftBecomesAppKitBottomLeftOnTheMainScreen() {
        // A 1440 x 900 main screen: a field 100 pt from the top is 900 - 100 - 24 from the bottom.
        let ax = CGRect(x: 200, y: 100, width: 300, height: 24)
        let appKit = ScreenGeometry.appKitRect(fromAX: ax, primaryScreenHeight: 900)
        #expect(appKit == CGRect(x: 200, y: 776, width: 300, height: 24))
    }

    @Test func screenAboveTheMainOneHasNegativeAXY() {
        // A second screen above the main one: AX y is negative there, AppKit y above 900.
        let ax = CGRect(x: 10, y: -500, width: 100, height: 20)
        let appKit = ScreenGeometry.appKitRect(fromAX: ax, primaryScreenHeight: 900)
        #expect(appKit == CGRect(x: 10, y: 1380, width: 100, height: 20))
    }

    @Test func screenBelowAndLeftKeepsItsOffsets() {
        let ax = CGRect(x: -1200, y: 1000, width: 100, height: 20)
        let appKit = ScreenGeometry.appKitRect(fromAX: ax, primaryScreenHeight: 900)
        #expect(appKit == CGRect(x: -1200, y: -120, width: 100, height: 20))
    }

    @Test func conversionIsItsOwnInverse() {
        let ax = CGRect(x: 33, y: 44, width: 55, height: 66)
        let there = ScreenGeometry.appKitRect(fromAX: ax, primaryScreenHeight: 1117)
        #expect(ScreenGeometry.appKitRect(fromAX: there, primaryScreenHeight: 1117) == ax)
    }

    @Test func pillSitsInsideTheTrailingEdgeCentredVertically() {
        let field = CGRect(x: 100, y: 500, width: 300, height: 30)
        let origin = ScreenGeometry.pillOrigin(
            field: field, pill: CGSize(width: 24, height: 24),
            visible: CGRect(x: 0, y: 0, width: 1440, height: 900))
        #expect(origin == CGPoint(x: 400 - 24 - 4, y: 503))
    }

    @Test func pillStaysOnTheFieldsScreen() {
        let visible = CGRect(x: 0, y: 0, width: 1440, height: 900)
        let origin = ScreenGeometry.pillOrigin(
            field: CGRect(x: 1430, y: 890, width: 40, height: 30), pill: CGSize(width: 24, height: 24),
            visible: visible)
        #expect(origin.x + 24 <= visible.maxX)
        #expect(origin.y + 24 <= visible.maxY)
        #expect(origin.x >= visible.minX && origin.y >= visible.minY)
    }
}

@Suite struct FillFixRoundOneTests {
    @Test func knownPasswordElementIsFocusedNotTabbed() {
        #expect(
            FillFlow.steps(focused: .username, hasPasswordBelow: true, hasTotp: false, passwordKnown: true)
                == [.value(.username), .focusPassword, .value(.password)])
        #expect(
            FillFlow.steps(focused: .username, hasPasswordBelow: true, hasTotp: true, passwordKnown: true)
                == [.value(.username), .focusPassword, .value(.password), .value(.oneTimeCode)])
        // Unknown password element: Tab, as before.
        #expect(
            FillFlow.steps(focused: .username, hasPasswordBelow: true, hasTotp: false, passwordKnown: false)
                == [.value(.username), .tab, .value(.password)])
        // A known element changes nothing when the focus is already on the password.
        #expect(
            FillFlow.steps(focused: .password, hasPasswordBelow: false, hasTotp: false, passwordKnown: true)
                == [.value(.password)])
    }

    @Test func afterTabOnlyAPasswordFieldTakesThePassword() {
        let secure = FieldSnapshot(role: "AXSecureTextField", bundleID: "x")
        let secureSubrole = FieldSnapshot(role: "AXTextField", subrole: "AXSecureTextField", bundleID: "x")
        let labelled = FieldSnapshot(role: "AXTextField", placeholder: "Password", bundleID: "x")
        let search = FieldSnapshot(role: "AXTextField", placeholder: "Search", bundleID: "x")
        let button = FieldSnapshot(role: "AXButton", title: "Sign in", bundleID: "x")
        #expect(FillDecision.acceptsAfterTab(secure, for: .password))
        #expect(FillDecision.acceptsAfterTab(secureSubrole, for: .password))
        #expect(FillDecision.acceptsAfterTab(labelled, for: .password))
        #expect(!FillDecision.acceptsAfterTab(search, for: .password))
        #expect(!FillDecision.acceptsAfterTab(button, for: .password))
    }

    @Test func afterTabOtherKindsMustClassifyAsThatKind() {
        let code = FieldSnapshot(role: "AXTextField", domIdentifier: "otp", bundleID: "x")
        #expect(FillDecision.acceptsAfterTab(code, for: .oneTimeCode))
        #expect(!FillDecision.acceptsAfterTab(code, for: .password))
        #expect(!FillDecision.acceptsAfterTab(code, for: .other))
    }

    @Test func accessibilitySetOnlyOnTextRoles() {
        #expect(FillDecision.allowsAccessibilitySet(role: "AXTextField", subrole: nil))
        #expect(FillDecision.allowsAccessibilitySet(role: "AXSecureTextField", subrole: nil))
        #expect(FillDecision.allowsAccessibilitySet(role: "AXComboBox", subrole: nil))
        #expect(FillDecision.allowsAccessibilitySet(role: "AXTextArea", subrole: nil))
        #expect(FillDecision.allowsAccessibilitySet(role: "AXGroup", subrole: "AXSecureTextField"))
        // A remote desktop canvas or a custom view: typing only.
        #expect(!FillDecision.allowsAccessibilitySet(role: "AXGroup", subrole: nil))
        #expect(!FillDecision.allowsAccessibilitySet(role: "AXScrollArea", subrole: nil))
        #expect(!FillDecision.allowsAccessibilitySet(role: nil, subrole: nil))
    }

    @Test func guardOnANonTextElementHoldsWhileItKeepsFocus() {
        // The shortcut on a canvas: the guard names the canvas, not "no element".
        let canvas = FocusGuard(pid: 30, elementID: "canvas")
        #expect(canvas.holds(pid: 30, elementID: "canvas"))
        #expect(!canvas.holds(pid: 30, elementID: "sidebar"))
        #expect(!canvas.holds(pid: 31, elementID: "canvas"))
    }

    @Test func typingFailureMidwayOffersCopyNotTheClipboard() {
        #expect(FillDecision.next(after: .failed(.typing)) == .clipboard)
        #expect(FillDecision.next(after: .failed(.typing), typingStarted: true) == nil)
        #expect(FillDecision.next(after: .failed(.accessibility), typingStarted: true) == .typing)
    }
}

@Suite struct FocusTargetTests {
    @Test func windowIsPartOfTheGuard() {
        let picked = FocusTarget(element: "field", window: "login")
        #expect(FocusGuard(pid: 5, elementID: picked).holds(pid: 5, elementID: FocusTarget(element: "field", window: "login")))
        // Same element id, another window of the same app.
        #expect(!FocusGuard(pid: 5, elementID: picked).holds(pid: 5, elementID: FocusTarget(element: "field", window: "prefs")))
    }

    @Test func noElementFallsBackToTheWindowNotThePid() {
        let canvas = FocusTarget<String>(element: nil, window: "vm")
        #expect(canvas.isGuardable)
        let g = FocusGuard(pid: 5, elementID: canvas)
        #expect(g.holds(pid: 5, elementID: FocusTarget<String>(element: nil, window: "vm")))
        // The user switched windows during Touch ID: the fill stops.
        #expect(!g.holds(pid: 5, elementID: FocusTarget<String>(element: nil, window: "other")))
        #expect(!g.holds(pid: 5, elementID: FocusTarget<String>(element: "field", window: "vm")))
    }

    @Test func neitherElementNorWindowIsNotGuardable() {
        #expect(!FocusTarget<String>(element: nil, window: nil).isGuardable)
        #expect(FocusTarget<String>(element: "field", window: nil).isGuardable)
    }

    @Test func oneListOfTextRoles() {
        for role in ["AXTextField", "AXSecureTextField", "AXComboBox", "AXTextArea", "AXSearchField"] {
            #expect(FillDecision.textInputRoles.contains(role))
            #expect(FillDecision.isTextInput(role: role, subrole: nil))
        }
        #expect(FillDecision.isTextInput(role: "AXGroup", subrole: "AXSecureTextField"))
        #expect(!FillDecision.isTextInput(role: "AXButton", subrole: nil))
    }
}
